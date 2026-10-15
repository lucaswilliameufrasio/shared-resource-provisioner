package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

func TestGrantAndAuditPersistAcrossReopen(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "control.db")
	store, err := Open(databasePath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	created, err := store.CreateGrant(context.Background(), authorization.GrantRecord{
		Subject:     "caller-subject",
		Application: "orders",
		Environment: "production",
		Action:      authorization.ActionPlanResource,
	}, audit.Event{
		At:          time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC),
		Subject:     "admin-subject",
		Action:      "grant.create",
		Application: "orders",
		Environment: "production",
		Outcome:     audit.OutcomeAllowed,
	})
	if err != nil {
		_ = store.Close()
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if created.ID == "" || created.CreatedBy != "admin-subject" {
		_ = store.Close()
		t.Fatalf("created grant = %+v, missing stable identity or actor", created)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	store, err = Open(databasePath)
	if err != nil {
		t.Fatalf("reopen database error = %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	allowed, err := store.HasGrant(context.Background(), "caller-subject", authorization.ActionPlanResource, domain.Scope{
		Application: "orders",
		Environment: "production",
	})
	if err != nil {
		t.Fatalf("HasGrant() error = %v", err)
	}
	if !allowed {
		t.Fatal("grant was not available after reopening the database")
	}

	page, err := store.ListGrants(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("ListGrants() error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != created.ID || page.HasMore {
		t.Fatalf("grant page = %+v, want the created grant and no next page", page)
	}

	var auditCount int
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM audit_events").Scan(&auditCount); err != nil {
		t.Fatalf("count audit events error = %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("audit event count = %d, want 1", auditCount)
	}
}

func TestGrantPaginationUsesStableCursor(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	createdAt := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	for _, subject := range []string{"caller-a", "caller-b", "caller-c"} {
		_, err := store.CreateGrant(context.Background(), authorization.GrantRecord{
			Subject:     subject,
			Application: "orders",
			Environment: "production",
			Action:      authorization.ActionPlanResource,
		}, audit.Event{At: createdAt, Subject: "admin-subject", Outcome: audit.OutcomeAllowed})
		if err != nil {
			t.Fatalf("CreateGrant(%q) error = %v", subject, err)
		}
	}

	firstPage, err := store.ListGrants(context.Background(), "", 2)
	if err != nil {
		t.Fatalf("first ListGrants() error = %v", err)
	}
	if len(firstPage.Items) != 2 || !firstPage.HasMore || firstPage.NextCursor == "" {
		t.Fatalf("first page = %+v, want two items and a cursor", firstPage)
	}

	secondPage, err := store.ListGrants(context.Background(), firstPage.NextCursor, 2)
	if err != nil {
		t.Fatalf("second ListGrants() error = %v", err)
	}
	if len(secondPage.Items) != 1 || secondPage.HasMore || secondPage.NextCursor != "" {
		t.Fatalf("second page = %+v, want one final item", secondPage)
	}
	seen := map[string]bool{}
	for _, grant := range append(firstPage.Items, secondPage.Items...) {
		if seen[grant.ID] {
			t.Fatalf("grant %q repeated across cursor pages", grant.ID)
		}
		seen[grant.ID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("unique grant count = %d, want 3", len(seen))
	}
}

func TestDuplicateGrantDoesNotAppendAudit(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	grant := authorization.GrantRecord{
		Subject:     "caller-subject",
		Application: "orders",
		Environment: "production",
		Action:      authorization.ActionPlanResource,
	}
	event := audit.Event{Subject: "admin-subject", Outcome: audit.OutcomeAllowed}
	if _, err := store.CreateGrant(context.Background(), grant, event); err != nil {
		t.Fatalf("initial CreateGrant() error = %v", err)
	}
	if _, err := store.CreateGrant(context.Background(), grant, event); !errors.Is(err, authorization.ErrGrantExists) {
		t.Fatalf("duplicate CreateGrant() error = %v, want ErrGrantExists", err)
	}

	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&count); err != nil {
		t.Fatalf("count audit events error = %v", err)
	}
	if count != 1 {
		t.Fatalf("audit event count = %d, want 1 after duplicate", count)
	}
}

func TestAuditEventsRejectUpdateAndDelete(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	if err := store.Record(context.Background(), audit.Event{
		At:      time.Now().UTC(),
		Subject: "caller-subject",
		Action:  "plan_resource",
		Outcome: audit.OutcomeAllowed,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if _, err := store.db.Exec("UPDATE audit_events SET action = 'changed'"); err == nil {
		t.Fatal("audit event update unexpectedly succeeded")
	}
	if _, err := store.db.Exec("DELETE FROM audit_events"); err == nil {
		t.Fatal("audit event deletion unexpectedly succeeded")
	}
}

func TestOpenRejectsDatabaseWithBroadPermissions(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "control.db")
	if err := os.WriteFile(databasePath, []byte("not a database"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(databasePath, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := Open(databasePath); !errors.Is(err, ErrInsecureDatabase) {
		t.Fatalf("Open() error = %v, want ErrInsecureDatabase", err)
	}
}

func TestBackupCreatesProtectedConsistentSnapshot(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "source", "control.db")
	store := mustOpen(t, databasePath)
	grant, err := store.CreateGrant(context.Background(), authorization.GrantRecord{
		Subject:     "caller-subject",
		Application: "orders",
		Environment: "production",
		Action:      authorization.ActionPlanResource,
	}, audit.Event{Subject: "admin-subject", Outcome: audit.OutcomeAllowed})
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	backupDirectory := filepath.Join(t.TempDir(), "backup")
	if err := os.Mkdir(backupDirectory, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	backupPath := filepath.Join(backupDirectory, "control.db")
	if err := store.Backup(context.Background(), backupPath); err != nil {
		t.Fatalf("Backup() error = %v", err)
	}
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("Stat(backup) error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup permissions = %04o, want 0600", info.Mode().Perm())
	}

	restored := mustOpen(t, backupPath)
	allowed, err := restored.HasGrant(context.Background(), "caller-subject", authorization.ActionPlanResource, domain.Scope{
		Application: "orders",
		Environment: "production",
	})
	if err != nil || !allowed {
		t.Fatalf("restored HasGrant() = %t, %v; want true", allowed, err)
	}
	page, err := restored.ListGrants(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("restored ListGrants() error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != grant.ID {
		t.Fatalf("restored grant page = %+v", page)
	}
	if err := store.Backup(context.Background(), backupPath); !errors.Is(err, ErrBackupExists) {
		t.Fatalf("Backup(existing) error = %v, want ErrBackupExists", err)
	}
}

func TestBackupRejectsSharedDirectory(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "source", "control.db"))
	sharedDirectory := t.TempDir()
	if err := os.Chmod(sharedDirectory, 0o755); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if err := store.Backup(context.Background(), filepath.Join(sharedDirectory, "backup.db")); !errors.Is(err, ErrInsecureBackupDir) {
		t.Fatalf("Backup(shared directory) error = %v, want ErrInsecureBackupDir", err)
	}
}

func TestListGrantsRejectsMalformedCursor(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	_, err := store.ListGrants(context.Background(), "not-a-cursor", 10)
	if !errors.Is(err, authorization.ErrInvalidGrantCursor) {
		t.Fatalf("ListGrants() error = %v, want ErrInvalidGrantCursor", err)
	}
}

func TestAuthorizationPolicyIsSeededOnlyOnce(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	policy := []authorization.Grant{{
		Subject:      "caller-subject",
		Applications: []string{"orders"},
		Environments: []string{"production"},
		Actions:      []authorization.Action{authorization.ActionPlanResource},
	}}
	if err := store.SeedPolicyOnce(context.Background(), policy); err != nil {
		t.Fatalf("initial SeedPolicyOnce() error = %v", err)
	}
	grants, err := store.ListGrants(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("ListGrants() error = %v", err)
	}
	if len(grants.Items) != 1 {
		t.Fatalf("seeded grant count = %d, want 1", len(grants.Items))
	}
	if _, err := store.DeleteGrant(context.Background(), grants.Items[0].ID, audit.Event{Subject: "admin-subject"}); err != nil {
		t.Fatalf("DeleteGrant() error = %v", err)
	}
	if err := store.SeedPolicyOnce(context.Background(), policy); err != nil {
		t.Fatalf("repeat SeedPolicyOnce() error = %v", err)
	}
	allowed, err := store.HasGrant(context.Background(), "caller-subject", authorization.ActionPlanResource, domain.Scope{
		Application: "orders",
		Environment: "production",
	})
	if err != nil {
		t.Fatalf("HasGrant() error = %v", err)
	}
	if allowed {
		t.Fatal("deleted grant was re-seeded on a later start")
	}
}

func TestGrantChangesRollBackWhenAuditAppendFails(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	if _, err := store.db.Exec(`
		CREATE TRIGGER reject_audit_insert
		BEFORE INSERT ON audit_events
		BEGIN
			SELECT RAISE(ABORT, 'audit unavailable');
		END;
	`); err != nil {
		t.Fatalf("create audit failure trigger error = %v", err)
	}
	grant := authorization.GrantRecord{
		Subject:     "caller-subject",
		Application: "orders",
		Environment: "production",
		Action:      authorization.ActionPlanResource,
	}
	if _, err := store.CreateGrant(context.Background(), grant, audit.Event{Subject: "admin-subject"}); err == nil {
		t.Fatal("CreateGrant() succeeded while audit was unavailable")
	}
	allowed, err := store.HasGrant(context.Background(), "caller-subject", authorization.ActionPlanResource, domain.Scope{
		Application: "orders",
		Environment: "production",
	})
	if err != nil || allowed {
		t.Fatalf("HasGrant() after failed create = %t, %v; want false", allowed, err)
	}
	if _, err := store.db.Exec("DROP TRIGGER reject_audit_insert"); err != nil {
		t.Fatalf("drop audit failure trigger error = %v", err)
	}
	created, err := store.CreateGrant(context.Background(), grant, audit.Event{Subject: "admin-subject"})
	if err != nil {
		t.Fatalf("CreateGrant() after audit recovery error = %v", err)
	}
	if _, err := store.db.Exec(`
		CREATE TRIGGER reject_audit_insert
		BEFORE INSERT ON audit_events
		BEGIN
			SELECT RAISE(ABORT, 'audit unavailable');
		END;
	`); err != nil {
		t.Fatalf("recreate audit failure trigger error = %v", err)
	}
	if _, err := store.DeleteGrant(context.Background(), created.ID, audit.Event{Subject: "admin-subject"}); err == nil {
		t.Fatal("DeleteGrant() succeeded while audit was unavailable")
	}
	allowed, err = store.HasGrant(context.Background(), "caller-subject", authorization.ActionPlanResource, domain.Scope{
		Application: "orders",
		Environment: "production",
	})
	if err != nil || !allowed {
		t.Fatalf("HasGrant() after failed delete = %t, %v; want true", allowed, err)
	}
}

func mustOpen(t *testing.T, path string) *Store {
	t.Helper()

	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store
}

func TestCursorDoesNotExposeGrantSubject(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	createdAt := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	for index, subject := range []string{"caller-a", "caller-b"} {
		_, err := store.CreateGrant(context.Background(), authorization.GrantRecord{
			Subject:     subject,
			Application: "orders",
			Environment: "production",
			Action:      authorization.ActionPlanResource,
		}, audit.Event{At: createdAt.Add(time.Duration(index) * time.Nanosecond), Subject: "admin-subject"})
		if err != nil {
			t.Fatalf("CreateGrant() error = %v", err)
		}
	}
	page, err := store.ListGrants(context.Background(), "", 1)
	if err != nil {
		t.Fatalf("ListGrants() error = %v", err)
	}
	if !page.HasMore || page.NextCursor == "" {
		t.Fatalf("page = %+v, want a next cursor", page)
	}
	if strings.Contains(page.NextCursor, "caller-") || strings.Contains(page.NextCursor, "admin-") {
		t.Fatalf("cursor contains subject data: %q", page.NextCursor)
	}
}
