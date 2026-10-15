package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
	_ "modernc.org/sqlite"
)

const maxGrantPageSize = 100

var (
	ErrInvalidDatabasePath = errors.New("INVALID_DATABASE_PATH")
	ErrInsecureDatabase    = errors.New("INSECURE_DATABASE_PERMISSIONS")
	ErrInvalidPageSize     = errors.New("INVALID_PAGE_SIZE")
)

//go:embed migrations/0001_initial.sql
var migrationFiles embed.FS

type Store struct {
	db   *sql.DB
	path string
}

func Open(path string) (*Store, error) {
	if path == "" || strings.TrimSpace(path) != path || path == ":memory:" {
		return nil, ErrInvalidDatabasePath
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrInvalidDatabasePath
	}
	if err := os.MkdirAll(filepath.Dir(absolutePath), 0o700); err != nil {
		return nil, errors.New("unable to prepare SQLite directory")
	}

	file, err := os.OpenFile(absolutePath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.New("unable to prepare SQLite database")
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil {
		return nil, errors.New("unable to inspect SQLite database")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, ErrInsecureDatabase
	}

	databaseURL := url.URL{Scheme: "file", Path: filepath.ToSlash(absolutePath)}
	query := url.Values{}
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "synchronous(FULL)")
	databaseURL.RawQuery = query.Encode()

	db, err := sql.Open("sqlite", databaseURL.String())
	if err != nil {
		return nil, errors.New("unable to open SQLite database")
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, errors.New("unable to connect to SQLite database")
	}
	if err := migrate(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{db: db, path: absolutePath}, nil
}

func (store *Store) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	if err := store.db.Close(); err != nil {
		return errors.New("unable to close SQLite database")
	}
	return nil
}

func (store *Store) HasGrant(ctx context.Context, subject string, action authorization.Action, scope domain.Scope) (bool, error) {
	var exists bool
	err := store.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM grants
			WHERE subject = ? AND application = ? AND environment = ? AND action = ?
		)
	`, subject, scope.Application, scope.Environment, string(action)).Scan(&exists)
	if err != nil {
		return false, errors.New("unable to read authorization grant")
	}
	return exists, nil
}

func (store *Store) CreateGrant(ctx context.Context, grant authorization.GrantRecord, event audit.Event) (authorization.GrantRecord, error) {
	if err := authorization.ValidateGrantRecord(grant); err != nil {
		return authorization.GrantRecord{}, err
	}
	if !identity.ValidSubject(event.Subject) {
		return authorization.GrantRecord{}, errors.New("grant actor is required")
	}
	grantID, err := newID()
	if err != nil {
		return authorization.GrantRecord{}, errors.New("unable to create authorization grant")
	}
	createdAt := event.At.UTC()
	if event.At.IsZero() {
		createdAt = time.Now().UTC()
	}
	grant.ID = grantID
	grant.CreatedAt = createdAt
	grant.CreatedBy = event.Subject

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return authorization.GrantRecord{}, errors.New("unable to begin authorization grant transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	result, err := tx.ExecContext(ctx, `
		INSERT INTO grants (
			id, subject, application, environment, action, created_at_ns, created_by
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(subject, application, environment, action) DO NOTHING
	`, grant.ID, grant.Subject, grant.Application, grant.Environment, string(grant.Action), grant.CreatedAt.UnixNano(), grant.CreatedBy)
	if err != nil {
		return authorization.GrantRecord{}, errors.New("unable to create authorization grant")
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return authorization.GrantRecord{}, errors.New("unable to inspect authorization grant result")
	}
	if rows == 0 {
		return authorization.GrantRecord{}, authorization.ErrGrantExists
	}

	event.At = createdAt
	event.TargetSubject = grant.Subject
	event.EntityID = grant.ID
	event.Application = grant.Application
	event.Environment = grant.Environment
	if event.Action == "" {
		event.Action = "grant.create"
	}
	if event.Outcome == "" {
		event.Outcome = audit.OutcomeAllowed
	}
	if err := recordEvent(ctx, tx, event); err != nil {
		return authorization.GrantRecord{}, errors.New("unable to record authorization grant audit")
	}
	if err := tx.Commit(); err != nil {
		return authorization.GrantRecord{}, errors.New("unable to commit authorization grant")
	}
	return grant, nil
}

func (store *Store) SeedPolicyOnce(ctx context.Context, grants []authorization.Grant) error {
	if len(grants) > 0 {
		if _, err := authorization.NewPolicy(grants); err != nil {
			return errors.New("bootstrap authorization policy is invalid")
		}
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("unable to begin authorization bootstrap")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var seeded bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM control_metadata WHERE key = 'authorization_seeded')").Scan(&seeded); err != nil {
		return errors.New("unable to read authorization bootstrap state")
	}
	if seeded {
		return tx.Commit()
	}

	seededAt := time.Now().UTC()
	for _, policyGrant := range grants {
		for _, application := range policyGrant.Applications {
			for _, environment := range policyGrant.Environments {
				for _, action := range policyGrant.Actions {
					grant := authorization.GrantRecord{
						Subject:     policyGrant.Subject,
						Application: application,
						Environment: environment,
						Action:      action,
					}
					if err := authorization.ValidateGrantRecord(grant); err != nil {
						return errors.New("bootstrap authorization grant is invalid")
					}
					grant.ID, err = newID()
					if err != nil {
						return errors.New("unable to create bootstrap authorization grant")
					}
					grant.CreatedAt = seededAt
					grant.CreatedBy = "system-bootstrap"
					result, err := tx.ExecContext(ctx, `
						INSERT INTO grants (
							id, subject, application, environment, action, created_at_ns, created_by
						) VALUES (?, ?, ?, ?, ?, ?, ?)
						ON CONFLICT(subject, application, environment, action) DO NOTHING
					`, grant.ID, grant.Subject, grant.Application, grant.Environment, string(grant.Action), grant.CreatedAt.UnixNano(), grant.CreatedBy)
					if err != nil {
						return errors.New("unable to bootstrap authorization grant")
					}
					rows, err := result.RowsAffected()
					if err != nil {
						return errors.New("unable to inspect bootstrap authorization grant")
					}
					if rows == 0 {
						continue
					}
					if err := recordEvent(ctx, tx, audit.Event{
						At:            seededAt,
						Subject:       "system-bootstrap",
						TargetSubject: grant.Subject,
						Action:        "grant.bootstrap",
						EntityID:      grant.ID,
						Application:   grant.Application,
						Environment:   grant.Environment,
						Outcome:       audit.OutcomeAllowed,
					}); err != nil {
						return errors.New("unable to audit bootstrap authorization grant")
					}
				}
			}
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO control_metadata(key, value) VALUES('authorization_seeded', 'true')"); err != nil {
		return errors.New("unable to record authorization bootstrap state")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("unable to commit authorization bootstrap")
	}
	return nil
}

func (store *Store) DeleteGrant(ctx context.Context, id string, event audit.Event) (authorization.GrantRecord, error) {
	if id == "" || !identity.ValidSubject(event.Subject) {
		return authorization.GrantRecord{}, errors.New("invalid authorization grant deletion")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return authorization.GrantRecord{}, errors.New("unable to begin authorization grant transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	grant, err := scanGrant(tx.QueryRowContext(ctx, `
		SELECT id, subject, application, environment, action, created_at_ns, created_by
		FROM grants WHERE id = ?
	`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return authorization.GrantRecord{}, authorization.ErrGrantNotFound
	}
	if err != nil {
		return authorization.GrantRecord{}, errors.New("unable to read authorization grant")
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM grants WHERE id = ?", id); err != nil {
		return authorization.GrantRecord{}, errors.New("unable to delete authorization grant")
	}

	event.At = time.Now().UTC()
	event.TargetSubject = grant.Subject
	event.EntityID = grant.ID
	event.Application = grant.Application
	event.Environment = grant.Environment
	if event.Action == "" {
		event.Action = "grant.delete"
	}
	if event.Outcome == "" {
		event.Outcome = audit.OutcomeAllowed
	}
	if err := recordEvent(ctx, tx, event); err != nil {
		return authorization.GrantRecord{}, errors.New("unable to record authorization grant audit")
	}
	if err := tx.Commit(); err != nil {
		return authorization.GrantRecord{}, errors.New("unable to commit authorization grant deletion")
	}
	return grant, nil
}

func (store *Store) ListGrants(ctx context.Context, cursor string, limit int) (authorization.GrantPage, error) {
	if limit < 1 || limit > maxGrantPageSize {
		return authorization.GrantPage{}, ErrInvalidPageSize
	}
	createdAt, id, err := decodeCursor(cursor)
	if err != nil {
		return authorization.GrantPage{}, err
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, subject, application, environment, action, created_at_ns, created_by
		FROM grants
		WHERE created_at_ns > ? OR (created_at_ns = ? AND id > ?)
		ORDER BY created_at_ns, id
		LIMIT ?
	`, createdAt, createdAt, id, limit+1)
	if err != nil {
		return authorization.GrantPage{}, errors.New("unable to list authorization grants")
	}
	defer func() {
		_ = rows.Close()
	}()

	items := make([]authorization.GrantRecord, 0, limit+1)
	for rows.Next() {
		grant, err := scanGrant(rows)
		if err != nil {
			return authorization.GrantPage{}, errors.New("unable to read authorization grant page")
		}
		items = append(items, grant)
	}
	if err := rows.Err(); err != nil {
		return authorization.GrantPage{}, errors.New("unable to read authorization grant page")
	}

	page := authorization.GrantPage{Items: items}
	if len(items) > limit {
		page.HasMore = true
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeCursor(last.CreatedAt, last.ID)
	}
	return page, nil
}

func (store *Store) Record(ctx context.Context, event audit.Event) error {
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	if !identity.ValidSubject(event.Subject) || event.Action == "" {
		return errors.New("audit event is invalid")
	}
	if err := recordEvent(ctx, store.db, event); err != nil {
		return errors.New("unable to persist audit event")
	}
	return nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at_ns INTEGER NOT NULL
		)
	`); err != nil {
		return errors.New("unable to initialize SQLite migrations")
	}

	var applied bool
	if err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 1)").Scan(&applied); err != nil {
		return errors.New("unable to read SQLite migration state")
	}
	if applied {
		return nil
	}

	migration, err := migrationFiles.ReadFile("migrations/0001_initial.sql")
	if err != nil {
		return errors.New("unable to read SQLite migration")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("unable to begin SQLite migration")
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, string(migration)); err != nil {
		return errors.New("unable to apply SQLite migration")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at_ns) VALUES(1, ?)", time.Now().UTC().UnixNano()); err != nil {
		return errors.New("unable to record SQLite migration")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("unable to commit SQLite migration")
	}
	return nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanGrant(scanner rowScanner) (authorization.GrantRecord, error) {
	var grant authorization.GrantRecord
	var action string
	var createdAt int64
	if err := scanner.Scan(&grant.ID, &grant.Subject, &grant.Application, &grant.Environment, &action, &createdAt, &grant.CreatedBy); err != nil {
		return authorization.GrantRecord{}, err
	}
	grant.Action = authorization.Action(action)
	grant.CreatedAt = time.Unix(0, createdAt).UTC()
	return grant, nil
}

func recordEvent(ctx context.Context, executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, event audit.Event) error {
	_, err := executor.ExecContext(ctx, `
		INSERT INTO audit_events (
			event_at_ns, actor_subject, target_subject, transport, action, entity_id,
			application, environment, resource_type, outcome, error_code
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.At.UTC().UnixNano(), event.Subject, event.TargetSubject, string(event.Transport), event.Action, event.EntityID,
		event.Application, event.Environment, string(event.Resource), string(event.Outcome), event.ErrorCode)
	return err
}

func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func encodeCursor(createdAt time.Time, id string) string {
	value := strconv.FormatInt(createdAt.UnixNano(), 10) + "\n" + id
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeCursor(cursor string) (int64, string, error) {
	if cursor == "" {
		return 0, "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, "", authorization.ErrInvalidGrantCursor
	}
	parts := strings.SplitN(string(decoded), "\n", 2)
	if len(parts) != 2 || parts[1] == "" {
		return 0, "", authorization.ErrInvalidGrantCursor
	}
	createdAt, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", authorization.ErrInvalidGrantCursor
	}
	return createdAt, parts[1], nil
}
