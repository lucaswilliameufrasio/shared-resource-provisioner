package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/persistence/sqlite"
)

func TestBackupCommandRestoresControlPlaneStateAtNewPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	sourcePath := filepath.Join(root, "source", "control.db")
	source, err := sqlite.Open(sourcePath)
	if err != nil {
		t.Fatalf("sqlite.Open(source) error = %v", err)
	}

	scope := domain.Scope{Application: "orders", Environment: "staging"}
	grant, err := source.CreateGrant(context.Background(), authorization.GrantRecord{
		Subject:     "runtime-subject",
		Application: scope.Application,
		Environment: scope.Environment,
		Action:      authorization.ActionCreateResource,
	}, audit.Event{Subject: "admin-subject", Action: "grant.create", Outcome: audit.OutcomeAllowed})
	if err != nil {
		_ = source.Close()
		t.Fatalf("CreateGrant() error = %v", err)
	}

	operation := domain.Operation{
		IdempotencyKey: "restore-drill-create-001",
		Subject:        "runtime-subject",
		Action:         domain.ActionCreateResource,
		RequestHash:    "restore-drill-request-hash",
	}
	resource := domain.Resource{
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        scope,
		LogicalName:  "orders__staging",
		TargetID:     "postgres-primary",
	}
	operation, resource, _, err = source.ReserveCreate(
		context.Background(), operation, resource, 10,
		audit.Event{Subject: operation.Subject, Outcome: audit.OutcomeAllowed},
	)
	if err != nil {
		_ = source.Close()
		t.Fatalf("ReserveCreate() error = %v", err)
	}
	if _, _, err := source.ClaimOperation(
		context.Background(), operation.ID, time.Now().UTC(), time.Minute, 2,
		audit.Event{Subject: operation.Subject, Outcome: audit.OutcomeAllowed},
	); err != nil {
		_ = source.Close()
		t.Fatalf("ClaimOperation() error = %v", err)
	}
	const safeReference = "ciphera://project/project-123/environments/staging/secrets/DATABASE_URL"
	if _, err := source.CompleteCreate(
		context.Background(), operation.ID, safeReference, "", audit.Event{Subject: operation.Subject},
	); err != nil {
		_ = source.Close()
		t.Fatalf("CompleteCreate() error = %v", err)
	}
	rotationOperation := domain.Operation{
		IdempotencyKey: "restore-drill-rotation-001",
		Subject:        operation.Subject,
		Action:         domain.ActionRotateResource,
		RequestHash:    "restore-drill-rotation-hash",
	}
	rotationEvent := audit.Event{Subject: rotationOperation.Subject, Outcome: audit.OutcomeAllowed}
	rotationOperation, _, pendingRotation, _, err := source.ReserveRotation(
		context.Background(),
		rotationOperation,
		resource.ID,
		2,
		"DATABASE_URL",
		"ciphera://project/project-123/environments/staging/secrets/ROT_PG_0000000000002",
		"generation-2",
		rotationEvent,
	)
	if err != nil {
		_ = source.Close()
		t.Fatalf("ReserveRotation() error = %v", err)
	}
	if _, _, err := source.ClaimOperation(
		context.Background(), rotationOperation.ID, time.Now().UTC(), time.Minute, 2, rotationEvent,
	); err != nil {
		_ = source.Close()
		t.Fatalf("ClaimOperation(rotation) error = %v", err)
	}
	pendingRotation, err = source.CompleteRotationStage(context.Background(), rotationOperation.ID, rotationEvent)
	if err != nil {
		_ = source.Close()
		t.Fatalf("CompleteRotationStage() error = %v", err)
	}
	if pendingRotation.Status != domain.RotationPending {
		_ = source.Close()
		t.Fatalf("rotation status before backup = %q, want pending", pendingRotation.Status)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close(source) error = %v", err)
	}

	backupPath := filepath.Join(root, "backup", "control.db")
	getenv := func(name string) string {
		if name == "SRP_SQLITE_PATH" {
			return sourcePath
		}
		return ""
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run([]string{"backup", backupPath}, getenv, logger); err != nil {
		t.Fatalf("run(backup) error = %v", err)
	}

	backupInfo, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("Stat(backup) error = %v", err)
	}
	if backupInfo.Mode().Perm() != 0o600 {
		t.Fatalf("backup permissions = %04o, want 0600", backupInfo.Mode().Perm())
	}

	recoveryPath := filepath.Join(root, "recovered-host", "control.db")
	if err := os.MkdirAll(filepath.Dir(recoveryPath), 0o700); err != nil {
		t.Fatalf("MkdirAll(recovery directory) error = %v", err)
	}
	if err := copyProtectedFile(backupPath, recoveryPath); err != nil {
		t.Fatalf("copyProtectedFile() error = %v", err)
	}

	recovered, err := sqlite.Open(recoveryPath)
	if err != nil {
		t.Fatalf("sqlite.Open(recovered host) error = %v", err)
	}
	t.Cleanup(func() {
		if err := recovered.Close(); err != nil {
			t.Errorf("Close(recovered) error = %v", err)
		}
	})

	allowed, err := recovered.HasGrant(context.Background(), grant.Subject, grant.Action, scope)
	if err != nil || !allowed {
		t.Fatalf("HasGrant(recovered) = %t, %v; want true", allowed, err)
	}
	recoveredResource, err := recovered.GetResource(context.Background(), resource.ID)
	if err != nil {
		t.Fatalf("GetResource(recovered) error = %v", err)
	}
	if recoveredResource.Status != domain.ResourceActive || recoveredResource.SecretURI != safeReference || recoveredResource.CredentialGeneration != 1 || recoveredResource.RotationStatus != domain.RotationPending {
		t.Fatalf("recovered resource = %+v, want active generation 1 with a pending rotation and safe reference", recoveredResource)
	}
	recoveredOperation, err := recovered.GetOperationByIdempotencyKey(context.Background(), operation.Subject, operation.IdempotencyKey)
	if err != nil {
		t.Fatalf("GetOperationByIdempotencyKey(recovered) error = %v", err)
	}
	if recoveredOperation.Status != domain.OperationSucceeded || recoveredOperation.ResourceID != resource.ID {
		t.Fatalf("recovered operation = %+v, want successful operation for restored resource", recoveredOperation)
	}
	recoveredRotation, err := recovered.GetPendingRotation(context.Background(), resource.ID)
	if err != nil {
		t.Fatalf("GetPendingRotation(recovered) error = %v", err)
	}
	if recoveredRotation.OperationID != rotationOperation.ID || recoveredRotation.SecretURI != pendingRotation.SecretURI || recoveredRotation.SecretVersion != pendingRotation.SecretVersion || recoveredRotation.NewGeneration != 2 || recoveredRotation.Status != domain.RotationPending {
		t.Fatalf("recovered pending rotation = %+v, want the exact staged reference, version, operation, and generation", recoveredRotation)
	}
	recoveredRotationOperation, err := recovered.GetOperationByIdempotencyKey(
		context.Background(), rotationOperation.Subject, rotationOperation.IdempotencyKey,
	)
	if err != nil {
		t.Fatalf("GetOperationByIdempotencyKey(recovered rotation) error = %v", err)
	}
	if recoveredRotationOperation.ID != rotationOperation.ID || recoveredRotationOperation.Status != domain.OperationSucceeded || recoveredRotationOperation.ResourceID != resource.ID {
		t.Fatalf("recovered rotation operation = %+v, want succeeded operation for the restored resource", recoveredRotationOperation)
	}
}

func TestBackupCommandRejectsMissingDatabase(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	missingDatabase := filepath.Join(root, "missing", "control.db")
	backupPath := filepath.Join(root, "backup", "control.db")
	getenv := func(name string) string {
		if name == "SRP_SQLITE_PATH" {
			return missingDatabase
		}
		return ""
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run([]string{"backup", backupPath}, getenv, logger); err == nil {
		t.Fatal("run(backup) succeeded without an existing database")
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("Stat(backup after missing source) error = %v, want not found", err)
	}
}

func copyProtectedFile(sourcePath string, destinationPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer func() {
		_ = source.Close()
	}()

	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		_ = os.Remove(destinationPath)
		return err
	}
	if err := destination.Sync(); err != nil {
		_ = destination.Close()
		_ = os.Remove(destinationPath)
		return err
	}
	if err := destination.Close(); err != nil {
		_ = os.Remove(destinationPath)
		return err
	}
	return nil
}
