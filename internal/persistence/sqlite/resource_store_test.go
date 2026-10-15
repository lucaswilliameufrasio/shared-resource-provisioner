package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

func TestResourceReservationIsIdempotentAndRejectsKeyReuse(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	operation := domain.Operation{
		IdempotencyKey: "request-1234567890",
		Subject:        "caller-subject",
		Action:         "create_resource",
		RequestHash:    "request-hash-one",
	}
	resource := domain.Resource{
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        domain.Scope{Application: "orders", Environment: "production"},
		LogicalName:  "orders__production",
		TargetID:     "postgres-primary",
	}
	event := audit.Event{Subject: operation.Subject, Outcome: audit.OutcomeAllowed}
	firstOperation, firstResource, wasExisting, err := store.ReserveCreate(context.Background(), operation, resource, 5, event)
	if err != nil {
		t.Fatalf("first ReserveCreate() error = %v", err)
	}
	if wasExisting || firstOperation.Status != domain.OperationAccepted || firstResource.Status != domain.ResourceProvisioning {
		t.Fatalf("initial reservation = %+v, %+v, existing=%t", firstOperation, firstResource, wasExisting)
	}

	secondOperation, secondResource, wasExisting, err := store.ReserveCreate(context.Background(), operation, resource, 5, event)
	if err != nil {
		t.Fatalf("repeat ReserveCreate() error = %v", err)
	}
	if !wasExisting || secondOperation.ID != firstOperation.ID || secondResource.ID != firstResource.ID {
		t.Fatalf("repeat reservation = %+v, %+v, existing=%t", secondOperation, secondResource, wasExisting)
	}

	changedOperation := operation
	changedOperation.RequestHash = "request-hash-two"
	if _, _, _, err := store.ReserveCreate(context.Background(), changedOperation, resource, 5, event); !errors.Is(err, domain.ErrIdempotencyConflict) {
		t.Fatalf("ReserveCreate(reused key) error = %v, want idempotency conflict", err)
	}
	var resourceCount int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM resources").Scan(&resourceCount); err != nil {
		t.Fatalf("count resources error = %v", err)
	}
	if resourceCount != 1 {
		t.Fatalf("resource count = %d, want 1", resourceCount)
	}
}

func TestClaimLeaseAndCompleteCreateTransitions(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	operation, resource := reserveResourceForTest(t, store)
	start := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	claimed, reserved, err := store.ClaimOperation(context.Background(), operation.ID, start, 30*time.Second, 5, audit.Event{Subject: operation.Subject})
	if err != nil {
		t.Fatalf("ClaimOperation() error = %v", err)
	}
	if claimed.Status != domain.OperationRunning || reserved.ID != resource.ID || !claimed.LeaseExpiresAt.Equal(start.Add(30*time.Second)) {
		t.Fatalf("claimed operation/resource = %+v, %+v", claimed, reserved)
	}
	if _, _, err := store.ClaimOperation(context.Background(), operation.ID, start.Add(time.Second), 30*time.Second, 5, audit.Event{Subject: operation.Subject}); !errors.Is(err, domain.ErrOperationInProgress) {
		t.Fatalf("concurrent ClaimOperation() error = %v, want in progress", err)
	}
	reclaimed, _, err := store.ClaimOperation(context.Background(), operation.ID, start.Add(31*time.Second), 30*time.Second, 5, audit.Event{Subject: operation.Subject})
	if err != nil {
		t.Fatalf("expired lease ClaimOperation() error = %v", err)
	}
	if reclaimed.Status != domain.OperationRunning {
		t.Fatalf("reclaimed operation status = %q", reclaimed.Status)
	}

	completed, err := store.CompleteCreate(context.Background(), operation.ID, "ciphera://project/production/POSTGRESQL__DATABASE_URL", "", audit.Event{Subject: operation.Subject})
	if err != nil {
		t.Fatalf("CompleteCreate() error = %v", err)
	}
	if completed.Status != domain.ResourceActive || completed.SecretURI == "" {
		t.Fatalf("completed resource = %+v", completed)
	}
	completedAgain, err := store.CompleteCreate(context.Background(), operation.ID, "ciphera://project/production/OTHER", "", audit.Event{Subject: operation.Subject})
	if err != nil {
		t.Fatalf("idempotent CompleteCreate() error = %v", err)
	}
	if completedAgain.SecretURI != completed.SecretURI {
		t.Fatal("repeat completion changed the committed secret reference")
	}
	storedOperation, err := store.GetOperation(context.Background(), operation.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if storedOperation.Status != domain.OperationSucceeded || !storedOperation.LeaseExpiresAt.IsZero() {
		t.Fatalf("stored operation = %+v", storedOperation)
	}
}

func TestFailedCreateRecordsSafeTerminalState(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	operation, _ := reserveResourceForTest(t, store)
	if _, _, err := store.ClaimOperation(context.Background(), operation.ID, time.Now().UTC(), time.Minute, 5, audit.Event{Subject: operation.Subject}); err != nil {
		t.Fatalf("ClaimOperation() error = %v", err)
	}
	if err := store.FailCreate(context.Background(), operation.ID, "raw upstream message", false, audit.Event{Subject: operation.Subject}); err == nil {
		t.Fatal("FailCreate() accepted an unsafe error code")
	}
	if err := store.FailCreate(context.Background(), operation.ID, "DRIVER_UNAVAILABLE", true, audit.Event{Subject: operation.Subject}); err != nil {
		t.Fatalf("FailCreate() error = %v", err)
	}
	storedOperation, err := store.GetOperation(context.Background(), operation.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	storedResource, err := store.GetResource(context.Background(), operation.ResourceID)
	if err != nil {
		t.Fatalf("GetResource() error = %v", err)
	}
	if storedOperation.Status != domain.OperationReconciliationRequired || storedOperation.ErrorCode != "DRIVER_UNAVAILABLE" {
		t.Fatalf("stored operation = %+v", storedOperation)
	}
	if storedResource.Status != domain.ResourceReconciliation || storedResource.ErrorCode != "DRIVER_UNAVAILABLE" {
		t.Fatalf("stored resource = %+v", storedResource)
	}
}

func TestCreateCompletionRollsBackIfAuditCannotBeWritten(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	operation, resource := reserveResourceForTest(t, store)
	if _, _, err := store.ClaimOperation(context.Background(), operation.ID, time.Now().UTC(), time.Minute, 5, audit.Event{Subject: operation.Subject}); err != nil {
		t.Fatalf("ClaimOperation() error = %v", err)
	}
	if _, err := store.db.Exec(`
		CREATE TRIGGER reject_audit_insert
		BEFORE INSERT ON audit_events
		BEGIN
			SELECT RAISE(ABORT, 'audit unavailable');
		END;
	`); err != nil {
		t.Fatalf("create audit failure trigger error = %v", err)
	}
	if _, err := store.CompleteCreate(context.Background(), operation.ID, "ciphera://project/production/POSTGRESQL__DATABASE_URL", "", audit.Event{Subject: operation.Subject}); err == nil {
		t.Fatal("CompleteCreate() succeeded while audit was unavailable")
	}
	storedOperation, err := store.GetOperation(context.Background(), operation.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	storedResource, err := store.GetResource(context.Background(), resource.ID)
	if err != nil {
		t.Fatalf("GetResource() error = %v", err)
	}
	if storedOperation.Status != domain.OperationRunning || storedResource.Status != domain.ResourceProvisioning || storedResource.SecretURI != "" {
		t.Fatalf("state changed despite audit failure: operation=%+v resource=%+v", storedOperation, storedResource)
	}
}

func TestClaimOperationEnforcesTargetConcurrencyAndRetriesRecoveredOperations(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	firstOperation, _ := reserveResourceForTest(t, store)
	start := time.Now().UTC()
	if _, _, err := store.ClaimOperation(context.Background(), firstOperation.ID, start, time.Minute, 1, audit.Event{Subject: firstOperation.Subject}); err != nil {
		t.Fatalf("ClaimOperation(first) error = %v", err)
	}

	secondOperation := domain.Operation{
		IdempotencyKey: "request-abcdefghijkl",
		Subject:        "caller-subject",
		Action:         domain.ActionCreateResource,
		RequestHash:    "second-request-hash",
	}
	secondResource := domain.Resource{
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        domain.Scope{Application: "billing", Environment: "production"},
		LogicalName:  "billing__production",
		TargetID:     "postgres-primary",
	}
	secondOperation, _, _, err := store.ReserveCreate(context.Background(), secondOperation, secondResource, 5, audit.Event{Subject: secondOperation.Subject})
	if err != nil {
		t.Fatalf("ReserveCreate(second) error = %v", err)
	}
	if _, _, err := store.ClaimOperation(context.Background(), secondOperation.ID, start, time.Minute, 1, audit.Event{Subject: secondOperation.Subject}); !errors.Is(err, domain.ErrOperationCapacityReached) {
		t.Fatalf("ClaimOperation(over capacity) error = %v, want ErrOperationCapacityReached", err)
	}
	if err := store.FailCreate(context.Background(), firstOperation.ID, "TARGET_UNAVAILABLE", false, audit.Event{Subject: firstOperation.Subject}); err != nil {
		t.Fatalf("FailCreate() error = %v", err)
	}
	if _, _, err := store.ClaimOperation(context.Background(), firstOperation.ID, start.Add(2*time.Minute), time.Minute, 1, audit.Event{Subject: firstOperation.Subject}); err != nil {
		t.Fatalf("ClaimOperation(retry failed) error = %v", err)
	}
	resource, err := store.GetResource(context.Background(), firstOperation.ResourceID)
	if err != nil {
		t.Fatalf("GetResource() error = %v", err)
	}
	if resource.Status != domain.ResourceProvisioning || resource.ErrorCode != "" {
		t.Fatalf("retried resource state = %+v", resource)
	}
}

func TestResourceRevocationIsIdempotentAndClearsSecretReference(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	createOperation, resource := reserveResourceForTest(t, store)
	if _, _, err := store.ClaimOperation(context.Background(), createOperation.ID, time.Now().UTC(), time.Minute, 5, audit.Event{Subject: createOperation.Subject}); err != nil {
		t.Fatalf("ClaimOperation(create) error = %v", err)
	}
	resource, err := store.CompleteCreate(context.Background(), createOperation.ID, "ciphera://project/test-project/environments/production/secrets/DATABASE_URL", "v1", audit.Event{Subject: createOperation.Subject})
	if err != nil {
		t.Fatalf("CompleteCreate() error = %v", err)
	}

	operation := domain.Operation{
		IdempotencyKey: "revoke-request-123",
		Subject:        createOperation.Subject,
		Action:         domain.ActionRevokeResource,
		RequestHash:    "revoke-request-hash",
	}
	event := audit.Event{Subject: operation.Subject}
	operation, pending, wasExisting, err := store.ReserveRevoke(context.Background(), operation, resource.ID, event)
	if err != nil {
		t.Fatalf("ReserveRevoke() error = %v", err)
	}
	if wasExisting || operation.Status != domain.OperationAccepted || pending.Status != domain.ResourceRevocationPending {
		t.Fatalf("revoke reservation = %+v, %+v, existing=%t", operation, pending, wasExisting)
	}
	claimed, pending, err := store.ClaimOperation(context.Background(), operation.ID, time.Now().UTC(), time.Minute, 5, event)
	if err != nil {
		t.Fatalf("ClaimOperation(revoke) error = %v", err)
	}
	if claimed.Action != domain.ActionRevokeResource || pending.Status != domain.ResourceRevocationPending {
		t.Fatalf("claimed revoke = %+v, %+v", claimed, pending)
	}
	revoked, err := store.CompleteRevoke(context.Background(), operation.ID, event)
	if err != nil {
		t.Fatalf("CompleteRevoke() error = %v", err)
	}
	if revoked.Status != domain.ResourceRevoked || revoked.SecretURI != "" || revoked.SecretVersion != "" {
		t.Fatalf("revoked resource retained active metadata: %+v", revoked)
	}
	repeatedOperation, repeatedResource, wasExisting, err := store.ReserveRevoke(context.Background(), operation, resource.ID, event)
	if err != nil {
		t.Fatalf("ReserveRevoke(replay) error = %v", err)
	}
	if !wasExisting || repeatedOperation.ID != operation.ID || repeatedResource.Status != domain.ResourceRevoked {
		t.Fatalf("revoke replay = %+v, %+v, existing=%t", repeatedOperation, repeatedResource, wasExisting)
	}
}

func TestFailedRevocationCanRetryThroughReconciliation(t *testing.T) {
	t.Parallel()

	store := mustOpen(t, filepath.Join(t.TempDir(), "control.db"))
	createOperation, resource := reserveResourceForTest(t, store)
	if _, _, err := store.ClaimOperation(context.Background(), createOperation.ID, time.Now().UTC(), time.Minute, 5, audit.Event{Subject: createOperation.Subject}); err != nil {
		t.Fatalf("ClaimOperation(create) error = %v", err)
	}
	resource, err := store.CompleteCreate(context.Background(), createOperation.ID, "ciphera://project/test-project/environments/production/secrets/DATABASE_URL", "v1", audit.Event{Subject: createOperation.Subject})
	if err != nil {
		t.Fatalf("CompleteCreate() error = %v", err)
	}
	operation := domain.Operation{
		IdempotencyKey: "revoke-retry-123",
		Subject:        createOperation.Subject,
		Action:         domain.ActionRevokeResource,
		RequestHash:    "revoke-retry-hash",
	}
	event := audit.Event{Subject: operation.Subject}
	operation, _, _, err = store.ReserveRevoke(context.Background(), operation, resource.ID, event)
	if err != nil {
		t.Fatalf("ReserveRevoke() error = %v", err)
	}
	if _, _, err := store.ClaimOperation(context.Background(), operation.ID, time.Now().UTC(), time.Minute, 5, event); err != nil {
		t.Fatalf("ClaimOperation(revoke) error = %v", err)
	}
	if err := store.FailRevoke(context.Background(), operation.ID, "DRIVER_FAILURE", event); err != nil {
		t.Fatalf("FailRevoke() error = %v", err)
	}
	failed, err := store.GetResource(context.Background(), resource.ID)
	if err != nil || failed.Status != domain.ResourceReconciliation || failed.SecretURI == "" {
		t.Fatalf("reconciliation resource = %+v, %v", failed, err)
	}
	operation, failed, _, err = store.ReserveRevoke(context.Background(), operation, resource.ID, event)
	if err != nil {
		t.Fatalf("ReserveRevoke(retry) error = %v", err)
	}
	if _, _, err := store.ClaimOperation(context.Background(), operation.ID, time.Now().UTC(), time.Minute, 5, event); err != nil {
		t.Fatalf("ClaimOperation(retry) error = %v", err)
	}
	if _, err := store.CompleteRevoke(context.Background(), operation.ID, event); err != nil {
		t.Fatalf("CompleteRevoke(retry) error = %v", err)
	}
}

func reserveResourceForTest(t *testing.T, store *Store) (domain.Operation, domain.Resource) {
	t.Helper()

	operation := domain.Operation{
		IdempotencyKey: "request-1234567890",
		Subject:        "caller-subject",
		Action:         domain.ActionCreateResource,
		RequestHash:    "request-hash",
	}
	resource := domain.Resource{
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        domain.Scope{Application: "orders", Environment: "production"},
		LogicalName:  "orders__production",
		TargetID:     "postgres-primary",
	}
	reservedOperation, reservedResource, _, err := store.ReserveCreate(context.Background(), operation, resource, 5, audit.Event{
		Subject: operation.Subject,
		Outcome: audit.OutcomeAllowed,
	})
	if err != nil {
		t.Fatalf("ReserveCreate() error = %v", err)
	}
	return reservedOperation, reservedResource
}
