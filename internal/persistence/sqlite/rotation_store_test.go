package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

func TestRotationPersistsPendingReferenceAndRequiresExactAuditedAcknowledgement(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	databaseDirectory := t.TempDir()
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatalf("Chmod(database directory) error = %v", err)
	}
	databasePath := filepath.Join(databaseDirectory, "control.db")
	store, err := Open(databasePath)
	if err != nil {
		t.Fatalf("Open(initial store) error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close(store) error = %v", err)
		}
	})
	createOperation, resource := reserveResourceForTest(t, store)
	if _, _, err := store.ClaimOperation(ctx, createOperation.ID, time.Now().UTC(), time.Minute, 5, audit.Event{Subject: createOperation.Subject}); err != nil {
		t.Fatalf("ClaimOperation(create) error = %v", err)
	}
	resource, err = store.CompleteCreate(ctx, createOperation.ID, "ciphera://project/test-project/environments/production/secrets/DATABASE_URL", "", audit.Event{Subject: createOperation.Subject})
	if err != nil {
		t.Fatalf("CompleteCreate() error = %v", err)
	}

	operation := domain.Operation{
		IdempotencyKey: "rotate-request-001",
		Subject:        "caller-subject",
		Action:         domain.ActionRotateResource,
		RequestHash:    "rotation-request-hash",
	}
	event := audit.Event{Subject: operation.Subject, Outcome: audit.OutcomeAllowed}
	operation, stagingResource, rotation, wasExisting, err := store.ReserveRotation(
		ctx,
		operation,
		resource.ID,
		2,
		"DATABASE_URL",
		"ciphera://project/test-project/environments/production/secrets/ROT_PG_0000000000002",
		"generation-2",
		event,
	)
	if err != nil {
		t.Fatalf("ReserveRotation() error = %v", err)
	}
	if wasExisting || rotation.Status != domain.RotationStaging || stagingResource.Status != domain.ResourceActive || stagingResource.RotationStatus != domain.RotationStaging {
		t.Fatalf("rotation reservation = %+v, resource=%+v, existing=%t", rotation, stagingResource, wasExisting)
	}
	replayedOperation, _, replayedRotation, wasExisting, err := store.ReserveRotation(
		ctx,
		operation,
		resource.ID,
		2,
		"DATABASE_URL",
		"ciphera://project/test-project/environments/production/secrets/ROT_PG_0000000000002",
		"generation-2",
		event,
	)
	if err != nil {
		t.Fatalf("ReserveRotation(replay) error = %v", err)
	}
	if !wasExisting || replayedOperation.ID != operation.ID || replayedRotation.OperationID != rotation.OperationID {
		t.Fatalf("idempotent rotation reservation = %+v, %+v, existing=%t", replayedOperation, replayedRotation, wasExisting)
	}

	if _, _, err := store.ClaimOperation(ctx, operation.ID, time.Now().UTC(), time.Minute, 5, event); err != nil {
		t.Fatalf("ClaimOperation(rotate) error = %v", err)
	}
	rotation, err = store.CompleteRotationStage(ctx, operation.ID, event)
	if err != nil {
		t.Fatalf("CompleteRotationStage() error = %v", err)
	}
	if rotation.Status != domain.RotationPending {
		t.Fatalf("rotation status = %q, want pending", rotation.Status)
	}
	storedResource, err := store.GetResource(ctx, resource.ID)
	if err != nil || storedResource.RotationStatus != domain.RotationPending || storedResource.SecretURI != resource.SecretURI || storedResource.CredentialGeneration != 1 {
		t.Fatalf("resource during pending rotation = %+v, %v", storedResource, err)
	}
	pending, err := store.GetPendingRotation(ctx, resource.ID)
	if err != nil || pending.OperationID != operation.ID || pending.SecretURI != rotation.SecretURI {
		t.Fatalf("GetPendingRotation() = %+v, %v", pending, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(store before restart) error = %v", err)
	}
	store, err = Open(databasePath)
	if err != nil {
		t.Fatalf("Open(store after restart) error = %v", err)
	}
	pendingAfterRestart, err := store.GetPendingRotation(ctx, resource.ID)
	if err != nil || pendingAfterRestart.OperationID != operation.ID || pendingAfterRestart.SecretURI != rotation.SecretURI || pendingAfterRestart.Status != domain.RotationPending {
		t.Fatalf("pending rotation after store restart = %+v, %v", pendingAfterRestart, err)
	}
	if _, _, _, err := store.ReserveRevoke(ctx, domain.Operation{
		IdempotencyKey: "revoke-before-ack-001",
		Subject:        "caller-subject",
		Action:         domain.ActionRevokeResource,
		RequestHash:    "revoke-before-ack-hash",
	}, resource.ID, event); !errors.Is(err, domain.ErrRotationInProgress) {
		t.Fatalf("ReserveRevoke(pending rotation) error = %v, want ErrRotationInProgress", err)
	}

	acknowledgement := domain.RotationAcknowledgement{
		ResourceID:      resource.ID,
		OperationID:     operation.ID,
		SecretReference: rotation.SecretURI,
		SecretVersion:   rotation.SecretVersion,
		Generation:      rotation.NewGeneration,
	}
	wrongReference := acknowledgement
	wrongReference.SecretReference = "ciphera://project/test-project/environments/production/secrets/OTHER"
	if _, _, err := store.ClaimRotationFinalization(ctx, wrongReference, time.Now().UTC(), time.Minute, audit.Event{Subject: "runtime-subject"}); !errors.Is(err, domain.ErrRotationMismatch) {
		t.Fatalf("ClaimRotationFinalization(wrong reference) error = %v, want mismatch", err)
	}

	start := time.Now().UTC()
	claimedRotation, finalizingResource, err := store.ClaimRotationFinalization(ctx, acknowledgement, start, time.Minute, audit.Event{Subject: "runtime-subject"})
	if err != nil {
		t.Fatalf("ClaimRotationFinalization() error = %v", err)
	}
	if claimedRotation.Status != domain.RotationFinalizing || claimedRotation.AcknowledgedAt.IsZero() || finalizingResource.RotationStatus != domain.RotationFinalizing {
		t.Fatalf("claimed finalization = %+v, resource=%+v", claimedRotation, finalizingResource)
	}
	if _, _, err := store.ClaimRotationFinalization(ctx, acknowledgement, start.Add(time.Second), time.Minute, audit.Event{Subject: "runtime-subject"}); !errors.Is(err, domain.ErrOperationInProgress) {
		t.Fatalf("duplicate active finalization claim error = %v, want ErrOperationInProgress", err)
	}
	if err := store.FailRotationFinalization(ctx, operation.ID, "TARGET_FINALIZATION_FAILED", audit.Event{Subject: "runtime-subject"}); err != nil {
		t.Fatalf("FailRotationFinalization() error = %v", err)
	}
	claimedRotation, _, err = store.ClaimRotationFinalization(ctx, acknowledgement, start.Add(2*time.Minute), time.Minute, audit.Event{Subject: "runtime-subject"})
	if err != nil || claimedRotation.Status != domain.RotationFinalizing {
		t.Fatalf("ClaimRotationFinalization(retry) = %+v, %v", claimedRotation, err)
	}

	completedResource, err := store.CompleteRotationFinalization(ctx, operation.ID, audit.Event{Subject: "runtime-subject"})
	if err != nil {
		t.Fatalf("CompleteRotationFinalization() error = %v", err)
	}
	if completedResource.CredentialGeneration != 2 || completedResource.SecretURI != rotation.SecretURI || completedResource.RotationStatus != "" {
		t.Fatalf("completed resource = %+v", completedResource)
	}
	completedRotation, err := store.GetRotation(ctx, resource.ID, operation.ID)
	if err != nil || completedRotation.Status != domain.RotationCompleted {
		t.Fatalf("GetRotation(completed) = %+v, %v", completedRotation, err)
	}
	generations, err := store.ListCredentialGenerations(ctx, resource.ID)
	if err != nil || len(generations) != 2 || generations[0] != 1 || generations[1] != 2 {
		t.Fatalf("ListCredentialGenerations() = %v, %v", generations, err)
	}
	history, err := store.ListRotationHistory(ctx, resource.ID)
	if err != nil || len(history) != 1 || history[0].OldSecretURI != resource.SecretURI || history[0].SecretURI != rotation.SecretURI {
		t.Fatalf("ListRotationHistory() = %+v, %v", history, err)
	}

	failedOperation := domain.Operation{
		IdempotencyKey: "rotate-request-002",
		Subject:        "caller-subject",
		Action:         domain.ActionRotateResource,
		RequestHash:    "rotation-request-hash-002",
	}
	failedOperation, _, failedRotation, _, err := store.ReserveRotation(
		ctx,
		failedOperation,
		resource.ID,
		3,
		"DATABASE_URL",
		"ciphera://project/test-project/environments/production/secrets/ROT_PG_0000000000003",
		"generation-3",
		event,
	)
	if err != nil {
		t.Fatalf("ReserveRotation(failed candidate) error = %v", err)
	}
	if _, _, err := store.ClaimOperation(ctx, failedOperation.ID, time.Now().UTC(), time.Minute, 5, event); err != nil {
		t.Fatalf("ClaimOperation(failed candidate) error = %v", err)
	}
	if err := store.FailRotationStage(ctx, failedOperation.ID, "DRIVER_FAILURE", true, event); err != nil {
		t.Fatalf("FailRotationStage(reconciliation required) error = %v", err)
	}
	if _, err := store.GetPendingRotation(ctx, resource.ID); !errors.Is(err, domain.ErrRotationNotFound) {
		t.Fatalf("GetPendingRotation(unacknowledged reconciliation) error = %v, want not found", err)
	}
	failedAcknowledgement := domain.RotationAcknowledgement{
		ResourceID:      resource.ID,
		OperationID:     failedOperation.ID,
		SecretReference: failedRotation.SecretURI,
		SecretVersion:   failedRotation.SecretVersion,
		Generation:      failedRotation.NewGeneration,
	}
	if _, _, err := store.ClaimRotationFinalization(ctx, failedAcknowledgement, time.Now().UTC(), time.Minute, audit.Event{Subject: "runtime-subject"}); !errors.Is(err, domain.ErrRotationReconciliation) {
		t.Fatalf("ClaimRotationFinalization(unacknowledged reconciliation) error = %v, want reconciliation", err)
	}
}
