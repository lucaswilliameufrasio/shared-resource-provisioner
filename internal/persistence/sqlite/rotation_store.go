package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
)

func (store *Store) ReserveRotation(
	ctx context.Context,
	operation domain.Operation,
	resourceID string,
	newGeneration int64,
	credentialName string,
	secretURI string,
	secretVersion string,
	event audit.Event,
) (domain.Operation, domain.Resource, domain.Rotation, bool, error) {
	if operation.Subject == "" || !identity.ValidSubject(operation.Subject) || operation.Subject != event.Subject ||
		operation.Action != domain.ActionRotateResource || !domain.ValidIdempotencyKey(operation.IdempotencyKey) ||
		operation.RequestHash == "" || resourceID == "" || newGeneration < 2 || credentialName == "" || secretURI == "" || len(secretURI) > 2048 {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, errors.New("invalid resource rotation reservation")
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, errors.New("unable to begin resource rotation reservation")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	existingOperation, err := scanOperation(tx.QueryRowContext(ctx, `
		SELECT id, idempotency_key, subject, action, request_hash, status, resource_id,
		       error_code, created_at_ns, updated_at_ns, lease_expires_ns
		FROM operations WHERE subject = ? AND idempotency_key = ?
	`, operation.Subject, operation.IdempotencyKey))
	if err == nil {
		if existingOperation.Action != operation.Action || existingOperation.RequestHash != operation.RequestHash || existingOperation.ResourceID != resourceID {
			return domain.Operation{}, domain.Resource{}, domain.Rotation{}, true, domain.ErrIdempotencyConflict
		}
		resource, resourceErr := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", resourceID))
		if resourceErr != nil {
			return domain.Operation{}, domain.Resource{}, domain.Rotation{}, true, errors.New("unable to read idempotent rotation resource")
		}
		rotation, rotationErr := scanRotation(tx.QueryRowContext(ctx, rotationSelect+" WHERE operation_id = ?", existingOperation.ID))
		if rotationErr != nil {
			return domain.Operation{}, domain.Resource{}, domain.Rotation{}, true, errors.New("unable to read idempotent rotation")
		}
		if err := tx.Commit(); err != nil {
			return domain.Operation{}, domain.Resource{}, domain.Rotation{}, true, errors.New("unable to finish idempotent rotation lookup")
		}
		return existingOperation, resource, rotation, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, errors.New("unable to read rotation idempotency state")
	}

	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", resourceID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, domain.ErrResourceNotFound
	}
	if err != nil {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, errors.New("unable to read resource for rotation")
	}
	if resource.Status != domain.ResourceActive {
		return domain.Operation{}, resource, domain.Rotation{}, false, domain.ErrResourceNotActive
	}
	switch resource.RotationStatus {
	case "":
	case domain.RotationReconciliationRequired:
		return domain.Operation{}, resource, domain.Rotation{}, false, domain.ErrRotationReconciliation
	default:
		return domain.Operation{}, resource, domain.Rotation{}, false, domain.ErrRotationInProgress
	}
	if newGeneration <= resource.CredentialGeneration {
		return domain.Operation{}, resource, domain.Rotation{}, false, domain.ErrInvalidResourceTransition
	}

	now := event.At.UTC()
	if event.At.IsZero() {
		now = time.Now().UTC()
	}
	operation.ID, err = newID()
	if err != nil {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, errors.New("unable to create rotation operation identity")
	}
	operation.Status = domain.OperationAccepted
	operation.ResourceID = resource.ID
	operation.CreatedAt = now
	operation.UpdatedAt = now
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operations (
			id, idempotency_key, subject, action, request_hash, status, resource_id,
			error_code, lease_expires_ns, created_at_ns, updated_at_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, '', 0, ?, ?)
	`, operation.ID, operation.IdempotencyKey, operation.Subject, operation.Action, operation.RequestHash,
		string(operation.Status), resource.ID, now.UnixNano(), now.UnixNano()); err != nil {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, errors.New("unable to persist rotation operation")
	}
	rotation := domain.Rotation{
		OperationID:      operation.ID,
		ResourceID:       resource.ID,
		OldGeneration:    resource.CredentialGeneration,
		NewGeneration:    newGeneration,
		OldSecretURI:     resource.SecretURI,
		OldSecretVersion: resource.SecretVersion,
		CredentialName:   credentialName,
		SecretURI:        secretURI,
		SecretVersion:    secretVersion,
		Status:           domain.RotationStaging,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO resource_rotations (
			operation_id, resource_id, old_generation, new_generation, old_secret_uri,
			old_secret_version, credential_name, secret_uri, secret_version, status,
			acknowledged_at_ns, lease_expires_ns, created_at_ns, updated_at_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
	`, rotation.OperationID, rotation.ResourceID, rotation.OldGeneration, rotation.NewGeneration,
		rotation.OldSecretURI, rotation.OldSecretVersion, rotation.CredentialName, rotation.SecretURI,
		rotation.SecretVersion, string(rotation.Status), now.UnixNano(), now.UnixNano()); err != nil {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, errors.New("unable to persist resource rotation")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE resources SET rotation_status = ?, updated_at_ns = ? WHERE id = ? AND rotation_status = ''
	`, string(domain.RotationStaging), now.UnixNano(), resource.ID); err != nil {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, errors.New("unable to mark resource rotation as staging")
	}
	event.At = now
	event.Action = "resource.rotate.accepted"
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	event.Outcome = audit.OutcomeAllowed
	if err := recordEvent(ctx, tx, event); err != nil {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, errors.New("unable to audit resource rotation reservation")
	}
	if err := tx.Commit(); err != nil {
		return domain.Operation{}, domain.Resource{}, domain.Rotation{}, false, errors.New("unable to commit resource rotation reservation")
	}
	resource.RotationStatus = domain.RotationStaging
	resource.UpdatedAt = now
	return operation, resource, rotation, false, nil
}

func (store *Store) CompleteRotationStage(ctx context.Context, operationID string, event audit.Event) (domain.Rotation, error) {
	if operationID == "" || !identity.ValidSubject(event.Subject) {
		return domain.Rotation{}, errors.New("invalid resource rotation staging completion")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Rotation{}, errors.New("unable to begin rotation staging completion")
	}
	defer func() {
		_ = tx.Rollback()
	}()
	operation, err := scanOperation(tx.QueryRowContext(ctx, operationSelect+" WHERE id = ?", operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Rotation{}, domain.ErrRotationNotFound
	}
	if err != nil {
		return domain.Rotation{}, errors.New("unable to read rotation operation")
	}
	rotation, err := scanRotation(tx.QueryRowContext(ctx, rotationSelect+" WHERE operation_id = ?", operationID))
	if err != nil {
		return domain.Rotation{}, errors.New("unable to read rotation staging state")
	}
	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", rotation.ResourceID))
	if err != nil {
		return domain.Rotation{}, errors.New("unable to read resource for rotation staging completion")
	}
	if operation.Action != domain.ActionRotateResource || rotation.Status != domain.RotationStaging || operation.Subject != event.Subject || operation.Status != domain.OperationRunning {
		if rotation.Status == domain.RotationPending && operation.Status == domain.OperationSucceeded {
			if err := tx.Commit(); err != nil {
				return domain.Rotation{}, errors.New("unable to finish completed rotation stage lookup")
			}
			return rotation, nil
		}
		return domain.Rotation{}, domain.ErrInvalidResourceTransition
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE resource_rotations SET status = ?, lease_expires_ns = 0, updated_at_ns = ?
		WHERE operation_id = ? AND status = ?
	`, string(domain.RotationPending), now.UnixNano(), operationID, string(domain.RotationStaging)); err != nil {
		return domain.Rotation{}, errors.New("unable to persist pending rotation")
	}
	resourceResult, err := tx.ExecContext(ctx, `
		UPDATE resources SET rotation_status = ?, updated_at_ns = ? WHERE id = ? AND rotation_status = ?
	`, string(domain.RotationPending), now.UnixNano(), rotation.ResourceID, string(domain.RotationStaging))
	if err != nil {
		return domain.Rotation{}, errors.New("unable to update resource rotation status")
	}
	resourceRows, err := resourceResult.RowsAffected()
	if err != nil || resourceRows != 1 {
		return domain.Rotation{}, domain.ErrInvalidResourceTransition
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET status = ?, error_code = '', lease_expires_ns = 0, updated_at_ns = ?
		WHERE id = ? AND status = ?
	`, string(domain.OperationSucceeded), now.UnixNano(), operationID, string(domain.OperationRunning)); err != nil {
		return domain.Rotation{}, errors.New("unable to complete rotation staging operation")
	}
	event.At = now
	event.Action = "resource.rotate.pending"
	event.EntityID = rotation.ResourceID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	event.Outcome = audit.OutcomeAllowed
	if err := recordEvent(ctx, tx, event); err != nil {
		return domain.Rotation{}, errors.New("unable to audit pending rotation")
	}
	if err := tx.Commit(); err != nil {
		return domain.Rotation{}, errors.New("unable to commit pending rotation")
	}
	rotation.Status = domain.RotationPending
	rotation.UpdatedAt = now
	rotation.LeaseExpiresAt = time.Time{}
	return rotation, nil
}

func (store *Store) FailRotationStage(ctx context.Context, operationID string, errorCode string, cleanupFailed bool, event audit.Event) error {
	if operationID == "" || !errorCodePattern.MatchString(errorCode) || !identity.ValidSubject(event.Subject) {
		return errors.New("invalid resource rotation staging failure")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("unable to begin rotation staging failure")
	}
	defer func() {
		_ = tx.Rollback()
	}()
	operation, err := scanOperation(tx.QueryRowContext(ctx, operationSelect+" WHERE id = ?", operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrRotationNotFound
	}
	if err != nil {
		return errors.New("unable to read failed rotation operation")
	}
	rotation, err := scanRotation(tx.QueryRowContext(ctx, rotationSelect+" WHERE operation_id = ?", operationID))
	if err != nil {
		return errors.New("unable to read failed rotation")
	}
	if operation.Action != domain.ActionRotateResource || operation.Subject != event.Subject || operation.Status != domain.OperationRunning || rotation.Status != domain.RotationStaging {
		return domain.ErrInvalidResourceTransition
	}
	now := time.Now().UTC()
	rotationStatus := domain.RotationFailed
	resourceRotationStatus := ""
	operationStatus := domain.OperationFailed
	action := "resource.rotate.failed"
	if cleanupFailed {
		rotationStatus = domain.RotationReconciliationRequired
		resourceRotationStatus = string(domain.RotationReconciliationRequired)
		operationStatus = domain.OperationReconciliationRequired
		action = "resource.rotate.reconciliation_required"
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE resource_rotations SET status = ?, lease_expires_ns = 0, updated_at_ns = ? WHERE operation_id = ?
	`, string(rotationStatus), now.UnixNano(), operationID); err != nil {
		return errors.New("unable to persist rotation staging failure")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE resources SET rotation_status = ?, updated_at_ns = ? WHERE id = ?
	`, resourceRotationStatus, now.UnixNano(), rotation.ResourceID); err != nil {
		return errors.New("unable to persist resource rotation failure")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET status = ?, error_code = ?, lease_expires_ns = 0, updated_at_ns = ? WHERE id = ?
	`, string(operationStatus), errorCode, now.UnixNano(), operationID); err != nil {
		return errors.New("unable to persist rotation operation failure")
	}
	event.At = now
	event.Action = action
	event.EntityID = rotation.ResourceID
	event.ErrorCode = errorCode
	event.Outcome = audit.OutcomeDenied
	if err := recordEvent(ctx, tx, event); err != nil {
		return errors.New("unable to audit rotation staging failure")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("unable to commit rotation staging failure")
	}
	return nil
}

func (store *Store) GetRotation(ctx context.Context, resourceID string, operationID string) (domain.Rotation, error) {
	rotation, err := scanRotation(store.db.QueryRowContext(ctx, rotationSelect+" WHERE resource_id = ? AND operation_id = ?", resourceID, operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Rotation{}, domain.ErrRotationNotFound
	}
	if err != nil {
		return domain.Rotation{}, errors.New("unable to read resource rotation")
	}
	return rotation, nil
}

func (store *Store) GetPendingRotation(ctx context.Context, resourceID string) (domain.Rotation, error) {
	rotation, err := scanRotation(store.db.QueryRowContext(ctx, rotationSelect+`
		WHERE resource_id = ? AND (
			status IN (?, ?) OR (status = ? AND acknowledged_at_ns > 0)
		)
		ORDER BY new_generation DESC LIMIT 1
	`, resourceID, string(domain.RotationPending), string(domain.RotationFinalizing), string(domain.RotationReconciliationRequired)))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Rotation{}, domain.ErrRotationNotFound
	}
	if err != nil {
		return domain.Rotation{}, errors.New("unable to read pending resource rotation")
	}
	return rotation, nil
}

func (store *Store) ClaimRotationFinalization(
	ctx context.Context,
	acknowledgement domain.RotationAcknowledgement,
	now time.Time,
	lease time.Duration,
	event audit.Event,
) (domain.Rotation, domain.Resource, error) {
	if acknowledgement.ResourceID == "" || acknowledgement.OperationID == "" || acknowledgement.SecretReference == "" || acknowledgement.Generation < 2 || lease <= 0 || !identity.ValidSubject(event.Subject) {
		return domain.Rotation{}, domain.Resource{}, domain.ErrRotationMismatch
	}
	now = now.UTC()
	leaseExpiresAt := now.Add(lease)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Rotation{}, domain.Resource{}, errors.New("unable to begin rotation finalization claim")
	}
	defer func() {
		_ = tx.Rollback()
	}()
	rotation, err := scanRotation(tx.QueryRowContext(ctx, rotationSelect+" WHERE resource_id = ? AND operation_id = ?", acknowledgement.ResourceID, acknowledgement.OperationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Rotation{}, domain.Resource{}, domain.ErrRotationNotFound
	}
	if err != nil {
		return domain.Rotation{}, domain.Resource{}, errors.New("unable to read rotation for acknowledgement")
	}
	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", acknowledgement.ResourceID))
	if err != nil {
		return domain.Rotation{}, domain.Resource{}, errors.New("unable to read resource for rotation acknowledgement")
	}
	if rotation.SecretURI != acknowledgement.SecretReference || rotation.SecretVersion != acknowledgement.SecretVersion || rotation.NewGeneration != acknowledgement.Generation {
		return domain.Rotation{}, domain.Resource{}, domain.ErrRotationMismatch
	}
	if rotation.Status == domain.RotationCompleted {
		if err := tx.Commit(); err != nil {
			return domain.Rotation{}, domain.Resource{}, errors.New("unable to finish completed acknowledgement lookup")
		}
		return rotation, resource, nil
	}
	if rotation.Status == domain.RotationReconciliationRequired && rotation.AcknowledgedAt.IsZero() {
		return domain.Rotation{}, domain.Resource{}, domain.ErrRotationReconciliation
	}
	if rotation.Status == domain.RotationFinalizing && rotation.LeaseExpiresAt.After(now) {
		return domain.Rotation{}, domain.Resource{}, domain.ErrOperationInProgress
	}
	if rotation.Status != domain.RotationPending && rotation.Status != domain.RotationFinalizing && rotation.Status != domain.RotationReconciliationRequired {
		return domain.Rotation{}, domain.Resource{}, domain.ErrInvalidResourceTransition
	}
	firstAcknowledgement := rotation.AcknowledgedAt.IsZero()
	if _, err := tx.ExecContext(ctx, `
		UPDATE resource_rotations SET status = ?, acknowledged_at_ns = CASE WHEN acknowledged_at_ns = 0 THEN ? ELSE acknowledged_at_ns END,
			lease_expires_ns = ?, updated_at_ns = ? WHERE operation_id = ?
	`, string(domain.RotationFinalizing), now.UnixNano(), leaseExpiresAt.UnixNano(), now.UnixNano(), rotation.OperationID); err != nil {
		return domain.Rotation{}, domain.Resource{}, errors.New("unable to claim rotation finalization")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE resources SET rotation_status = ?, updated_at_ns = ? WHERE id = ?
	`, string(domain.RotationFinalizing), now.UnixNano(), resource.ID); err != nil {
		return domain.Rotation{}, domain.Resource{}, errors.New("unable to update resource finalization state")
	}
	event.At = now
	event.Action = "resource.rotate.finalization_retry"
	if firstAcknowledgement {
		event.Action = "resource.rotate.acknowledged"
	}
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	event.TargetSubject = ""
	event.Outcome = audit.OutcomeAllowed
	if err := recordEvent(ctx, tx, event); err != nil {
		return domain.Rotation{}, domain.Resource{}, errors.New("unable to audit rotation acknowledgement")
	}
	if err := tx.Commit(); err != nil {
		return domain.Rotation{}, domain.Resource{}, errors.New("unable to commit rotation acknowledgement")
	}
	rotation.Status = domain.RotationFinalizing
	if firstAcknowledgement {
		rotation.AcknowledgedAt = now
	}
	rotation.LeaseExpiresAt = leaseExpiresAt
	rotation.UpdatedAt = now
	resource.RotationStatus = domain.RotationFinalizing
	resource.UpdatedAt = now
	return rotation, resource, nil
}

func (store *Store) CompleteRotationFinalization(ctx context.Context, operationID string, event audit.Event) (domain.Resource, error) {
	if operationID == "" || !identity.ValidSubject(event.Subject) {
		return domain.Resource{}, errors.New("invalid rotation finalization completion")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Resource{}, errors.New("unable to begin rotation finalization completion")
	}
	defer func() {
		_ = tx.Rollback()
	}()
	rotation, err := scanRotation(tx.QueryRowContext(ctx, rotationSelect+" WHERE operation_id = ?", operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Resource{}, domain.ErrRotationNotFound
	}
	if err != nil {
		return domain.Resource{}, errors.New("unable to read rotation finalization")
	}
	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", rotation.ResourceID))
	if err != nil {
		return domain.Resource{}, errors.New("unable to read resource for rotation completion")
	}
	if rotation.Status == domain.RotationCompleted && resource.CredentialGeneration == rotation.NewGeneration {
		if err := tx.Commit(); err != nil {
			return domain.Resource{}, errors.New("unable to finish completed rotation lookup")
		}
		return resource, nil
	}
	if rotation.Status != domain.RotationFinalizing || resource.RotationStatus != domain.RotationFinalizing {
		return domain.Resource{}, domain.ErrInvalidResourceTransition
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `
		UPDATE resources SET secret_uri = ?, secret_version = ?, credential_generation = ?,
			rotation_status = '', updated_at_ns = ? WHERE id = ? AND rotation_status = ?
	`, rotation.SecretURI, rotation.SecretVersion, rotation.NewGeneration, now.UnixNano(), resource.ID, string(domain.RotationFinalizing))
	if err != nil {
		return domain.Resource{}, errors.New("unable to promote rotated credential")
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return domain.Resource{}, domain.ErrInvalidResourceTransition
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE resource_rotations SET status = ?, lease_expires_ns = 0, updated_at_ns = ? WHERE operation_id = ?
	`, string(domain.RotationCompleted), now.UnixNano(), operationID); err != nil {
		return domain.Resource{}, errors.New("unable to complete rotation record")
	}
	event.At = now
	event.Action = "resource.rotate.completed"
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	event.Outcome = audit.OutcomeAllowed
	if err := recordEvent(ctx, tx, event); err != nil {
		return domain.Resource{}, errors.New("unable to audit rotation completion")
	}
	if err := tx.Commit(); err != nil {
		return domain.Resource{}, errors.New("unable to commit rotation completion")
	}
	resource.SecretURI = rotation.SecretURI
	resource.SecretVersion = rotation.SecretVersion
	resource.CredentialGeneration = rotation.NewGeneration
	resource.RotationStatus = ""
	resource.UpdatedAt = now
	return resource, nil
}

func (store *Store) FailRotationFinalization(ctx context.Context, operationID string, errorCode string, event audit.Event) error {
	if operationID == "" || !errorCodePattern.MatchString(errorCode) || !identity.ValidSubject(event.Subject) {
		return errors.New("invalid rotation finalization failure")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("unable to begin rotation finalization failure")
	}
	defer func() {
		_ = tx.Rollback()
	}()
	rotation, err := scanRotation(tx.QueryRowContext(ctx, rotationSelect+" WHERE operation_id = ?", operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrRotationNotFound
	}
	if err != nil {
		return errors.New("unable to read failed rotation finalization")
	}
	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", rotation.ResourceID))
	if err != nil {
		return errors.New("unable to read resource for failed rotation finalization")
	}
	if rotation.Status == domain.RotationCompleted {
		return tx.Commit()
	}
	if rotation.Status != domain.RotationFinalizing {
		return domain.ErrInvalidResourceTransition
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE resource_rotations SET status = ?, lease_expires_ns = 0, updated_at_ns = ? WHERE operation_id = ?
	`, string(domain.RotationReconciliationRequired), now.UnixNano(), operationID); err != nil {
		return errors.New("unable to persist rotation reconciliation state")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE resources SET rotation_status = ?, updated_at_ns = ? WHERE id = ?
	`, string(domain.RotationReconciliationRequired), now.UnixNano(), resource.ID); err != nil {
		return errors.New("unable to persist resource rotation reconciliation state")
	}
	event.At = now
	event.Action = "resource.rotate.reconciliation_required"
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	event.ErrorCode = errorCode
	event.Outcome = audit.OutcomeDenied
	if err := recordEvent(ctx, tx, event); err != nil {
		return errors.New("unable to audit rotation finalization failure")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("unable to commit rotation reconciliation state")
	}
	return nil
}

func (store *Store) ListRotationHistory(ctx context.Context, resourceID string) ([]domain.Rotation, error) {
	rows, err := store.db.QueryContext(ctx, rotationSelect+" WHERE resource_id = ? ORDER BY new_generation", resourceID)
	if err != nil {
		return nil, errors.New("unable to list resource rotation history")
	}
	defer func() {
		_ = rows.Close()
	}()
	rotations := make([]domain.Rotation, 0)
	for rows.Next() {
		rotation, err := scanRotation(rows)
		if err != nil {
			return nil, errors.New("unable to read resource rotation history")
		}
		rotations = append(rotations, rotation)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("unable to finish reading resource rotation history")
	}
	return rotations, nil
}

func (store *Store) ListCredentialGenerations(ctx context.Context, resourceID string) ([]int64, error) {
	resource, err := scanResource(store.db.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", resourceID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrResourceNotFound
	}
	if err != nil {
		return nil, errors.New("unable to read resource credential generation")
	}
	rotations, err := store.ListRotationHistory(ctx, resourceID)
	if err != nil {
		return nil, err
	}
	seen := map[int64]struct{}{resource.CredentialGeneration: {}}
	for _, rotation := range rotations {
		seen[rotation.OldGeneration] = struct{}{}
		seen[rotation.NewGeneration] = struct{}{}
	}
	generations := make([]int64, 0, len(seen))
	for generation := range seen {
		generations = append(generations, generation)
	}
	for left := 0; left < len(generations); left++ {
		for right := left + 1; right < len(generations); right++ {
			if generations[right] < generations[left] {
				generations[left], generations[right] = generations[right], generations[left]
			}
		}
	}
	return generations, nil
}

const operationSelect = `
	SELECT id, idempotency_key, subject, action, request_hash, status, resource_id,
	       error_code, created_at_ns, updated_at_ns, lease_expires_ns
	FROM operations
`

const rotationSelect = `
	SELECT operation_id, resource_id, old_generation, new_generation, old_secret_uri,
	       old_secret_version, credential_name, secret_uri, secret_version, status,
	       acknowledged_at_ns, lease_expires_ns, created_at_ns, updated_at_ns
	FROM resource_rotations
`

func scanRotation(scanner rowScanner) (domain.Rotation, error) {
	var rotation domain.Rotation
	var status string
	var acknowledgedAt int64
	var leaseExpiresAt int64
	var createdAt int64
	var updatedAt int64
	if err := scanner.Scan(
		&rotation.OperationID,
		&rotation.ResourceID,
		&rotation.OldGeneration,
		&rotation.NewGeneration,
		&rotation.OldSecretURI,
		&rotation.OldSecretVersion,
		&rotation.CredentialName,
		&rotation.SecretURI,
		&rotation.SecretVersion,
		&status,
		&acknowledgedAt,
		&leaseExpiresAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.Rotation{}, err
	}
	rotation.Status = domain.RotationStatus(status)
	if acknowledgedAt > 0 {
		rotation.AcknowledgedAt = time.Unix(0, acknowledgedAt).UTC()
	}
	if leaseExpiresAt > 0 {
		rotation.LeaseExpiresAt = time.Unix(0, leaseExpiresAt).UTC()
	}
	rotation.CreatedAt = time.Unix(0, createdAt).UTC()
	rotation.UpdatedAt = time.Unix(0, updatedAt).UTC()
	return rotation, nil
}
