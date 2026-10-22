package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
)

var errorCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

func (store *Store) ReserveCreate(
	ctx context.Context,
	operation domain.Operation,
	resource domain.Resource,
	maxResources int,
	event audit.Event,
) (domain.Operation, domain.Resource, bool, error) {
	command := domain.CreateResourceCommand{
		ResourceType:   resource.ResourceType,
		Scope:          resource.Scope,
		IdempotencyKey: operation.IdempotencyKey,
	}
	if err := domain.ValidateCreateResourceCommand(command); err != nil {
		return domain.Operation{}, domain.Resource{}, false, err
	}
	if maxResources < 1 {
		return domain.Operation{}, domain.Resource{}, false, errors.New("target resource limit must be positive")
	}
	if operation.Subject == "" || !identity.ValidSubject(operation.Subject) || operation.Subject != event.Subject || operation.Action != domain.ActionCreateResource || operation.RequestHash == "" || resource.TargetID == "" || resource.LogicalName == "" {
		return domain.Operation{}, domain.Resource{}, false, errors.New("invalid resource create reservation")
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to begin resource create reservation")
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
		if existingOperation.Action != operation.Action || existingOperation.RequestHash != operation.RequestHash {
			return domain.Operation{}, domain.Resource{}, true, domain.ErrIdempotencyConflict
		}
		existingResource, resourceErr := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", existingOperation.ResourceID))
		if resourceErr != nil {
			return domain.Operation{}, domain.Resource{}, true, errors.New("unable to read idempotent resource")
		}
		if err := tx.Commit(); err != nil {
			return domain.Operation{}, domain.Resource{}, true, errors.New("unable to finish idempotent resource lookup")
		}
		return existingOperation, existingResource, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to read idempotency state")
	}

	existingResource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+`
		WHERE resource_type = ? AND application = ? AND environment = ?
	`, string(resource.ResourceType), resource.Scope.Application, resource.Scope.Environment))
	if err == nil {
		return domain.Operation{}, existingResource, false, domain.ErrResourceAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to check existing resource")
	}
	var resourceCount int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM resources
		WHERE target_id = ? AND status IN (?, ?, ?, ?)
	`, resource.TargetID,
		string(domain.ResourceProvisioning),
		string(domain.ResourceActive),
		string(domain.ResourceReconciliation),
		string(domain.ResourceRevocationPending)).Scan(&resourceCount); err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to read target capacity")
	}
	if resourceCount >= maxResources {
		return domain.Operation{}, domain.Resource{}, false, domain.ErrTargetCapacityReached
	}

	now := event.At.UTC()
	if event.At.IsZero() {
		now = time.Now().UTC()
	}
	operation.ID, err = newID()
	if err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to create operation identity")
	}
	resource.ID, err = newID()
	if err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to create resource identity")
	}
	operation.Status = domain.OperationAccepted
	operation.ResourceID = resource.ID
	operation.CreatedAt = now
	operation.UpdatedAt = now
	resource.Status = domain.ResourceProvisioning
	resource.CreatedAt = now
	resource.UpdatedAt = now
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO resources (
			id, resource_type, application, environment, logical_name, target_id, status,
			secret_uri, secret_version, error_code, created_at_ns, updated_at_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, '', '', '', ?, ?)
	`, resource.ID, string(resource.ResourceType), resource.Scope.Application, resource.Scope.Environment,
		resource.LogicalName, resource.TargetID, string(resource.Status), now.UnixNano(), now.UnixNano()); err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to persist resource reservation")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operations (
			id, idempotency_key, subject, action, request_hash, status, resource_id,
			error_code, lease_expires_ns, created_at_ns, updated_at_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, '', 0, ?, ?)
	`, operation.ID, operation.IdempotencyKey, operation.Subject, operation.Action,
		operation.RequestHash, string(operation.Status), resource.ID, now.UnixNano(), now.UnixNano()); err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to persist resource operation")
	}
	event.At = now
	event.Action = "resource.create.accepted"
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	if event.Outcome == "" {
		event.Outcome = audit.OutcomeAllowed
	}
	if err := recordEvent(ctx, tx, event); err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to audit resource reservation")
	}
	if err := tx.Commit(); err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to commit resource reservation")
	}
	return operation, resource, false, nil
}

func (store *Store) ReserveRevoke(
	ctx context.Context,
	operation domain.Operation,
	resourceID string,
	event audit.Event,
) (domain.Operation, domain.Resource, bool, error) {
	if operation.Subject == "" || !identity.ValidSubject(operation.Subject) || operation.Subject != event.Subject || operation.Action != domain.ActionRevokeResource || operation.RequestHash == "" || operation.IdempotencyKey == "" || resourceID == "" {
		return domain.Operation{}, domain.Resource{}, false, errors.New("invalid resource revoke reservation")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to begin resource revoke reservation")
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
			return domain.Operation{}, domain.Resource{}, true, domain.ErrIdempotencyConflict
		}
		existingResource, resourceErr := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", resourceID))
		if resourceErr != nil {
			return domain.Operation{}, domain.Resource{}, true, errors.New("unable to read idempotent resource revoke")
		}
		if err := tx.Commit(); err != nil {
			return domain.Operation{}, domain.Resource{}, true, errors.New("unable to finish idempotent resource revoke lookup")
		}
		return existingOperation, existingResource, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to read resource revoke idempotency state")
	}

	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", resourceID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.Resource{}, false, domain.ErrResourceNotFound
	}
	if err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to read resource for revocation")
	}
	if resource.Status == domain.ResourceRevoked {
		return domain.Operation{}, resource, false, domain.ErrResourceAlreadyRevoked
	}
	if resource.RotationStatus != "" && resource.RotationStatus != domain.RotationReconciliationRequired {
		return domain.Operation{}, resource, false, domain.ErrRotationInProgress
	}
	if resource.Status == domain.ResourceRevocationPending {
		return domain.Operation{}, resource, false, domain.ErrOperationInProgress
	}
	if resource.Status != domain.ResourceActive && resource.Status != domain.ResourceFailed && resource.Status != domain.ResourceReconciliation {
		return domain.Operation{}, resource, false, domain.ErrResourceNotActive
	}

	now := event.At.UTC()
	if event.At.IsZero() {
		now = time.Now().UTC()
	}
	operation.ID, err = newID()
	if err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to create resource revoke operation identity")
	}
	operation.Status = domain.OperationAccepted
	operation.ResourceID = resource.ID
	operation.CreatedAt = now
	operation.UpdatedAt = now
	result, err := tx.ExecContext(ctx, `
		UPDATE resources SET status = ?, error_code = '', updated_at_ns = ?
		WHERE id = ? AND status IN (?, ?, ?)
	`, string(domain.ResourceRevocationPending), now.UnixNano(), resource.ID,
		string(domain.ResourceActive), string(domain.ResourceFailed), string(domain.ResourceReconciliation))
	if err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to mark resource revocation pending")
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return domain.Operation{}, domain.Resource{}, false, domain.ErrOperationInProgress
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operations (
			id, idempotency_key, subject, action, request_hash, status, resource_id,
			error_code, lease_expires_ns, created_at_ns, updated_at_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, '', 0, ?, ?)
	`, operation.ID, operation.IdempotencyKey, operation.Subject, operation.Action,
		operation.RequestHash, string(operation.Status), resource.ID, now.UnixNano(), now.UnixNano()); err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to persist resource revoke operation")
	}
	event.At = now
	event.Action = "resource.revoke.accepted"
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	if event.Outcome == "" {
		event.Outcome = audit.OutcomeAllowed
	}
	if err := recordEvent(ctx, tx, event); err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to audit resource revoke reservation")
	}
	if err := tx.Commit(); err != nil {
		return domain.Operation{}, domain.Resource{}, false, errors.New("unable to commit resource revoke reservation")
	}
	resource.Status = domain.ResourceRevocationPending
	resource.ErrorCode = ""
	resource.UpdatedAt = now
	return operation, resource, false, nil
}

func (store *Store) ClaimOperation(
	ctx context.Context,
	operationID string,
	now time.Time,
	lease time.Duration,
	maxConcurrentOperations int,
	event audit.Event,
) (domain.Operation, domain.Resource, error) {
	if operationID == "" || lease <= 0 || maxConcurrentOperations < 1 || !identity.ValidSubject(event.Subject) {
		return domain.Operation{}, domain.Resource{}, errors.New("invalid resource operation claim")
	}
	now = now.UTC()
	leaseExpiresAt := now.Add(lease)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Operation{}, domain.Resource{}, errors.New("unable to begin resource operation claim")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	result, err := tx.ExecContext(ctx, `
		UPDATE operations
		SET status = ?, lease_expires_ns = ?, updated_at_ns = ?
		WHERE id = ? AND (
			status = ? OR (status = ? AND lease_expires_ns <= ?) OR
			(status IN (?, ?) AND action IN (?, ?))
		)
	`, string(domain.OperationRunning), leaseExpiresAt.UnixNano(), now.UnixNano(), operationID,
		string(domain.OperationAccepted), string(domain.OperationRunning), now.UnixNano(),
		string(domain.OperationFailed), string(domain.OperationReconciliationRequired), domain.ActionCreateResource, domain.ActionRevokeResource)
	if err != nil {
		return domain.Operation{}, domain.Resource{}, errors.New("unable to claim resource operation")
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return domain.Operation{}, domain.Resource{}, errors.New("unable to inspect resource operation claim")
	}
	operation, err := scanOperation(tx.QueryRowContext(ctx, `
		SELECT id, idempotency_key, subject, action, request_hash, status, resource_id,
		       error_code, created_at_ns, updated_at_ns, lease_expires_ns
		FROM operations WHERE id = ?
	`, operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.Resource{}, domain.ErrResourceNotFound
	}
	if err != nil {
		return domain.Operation{}, domain.Resource{}, errors.New("unable to read resource operation")
	}
	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", operation.ResourceID))
	if err != nil {
		return domain.Operation{}, domain.Resource{}, errors.New("unable to read reserved resource")
	}
	if rows == 0 {
		if operation.Status == domain.OperationRunning {
			return operation, resource, domain.ErrOperationInProgress
		}
		if operation.Status == domain.OperationSucceeded {
			if err := tx.Commit(); err != nil {
				return domain.Operation{}, domain.Resource{}, errors.New("unable to finish completed operation lookup")
			}
			return operation, resource, nil
		}
		return operation, resource, domain.ErrOperationTerminal
	}

	resourceStatus := domain.ResourceProvisioning
	resourceStatusValue := string(resourceStatus)
	resourceStatusQuery := `
		UPDATE resources SET status = ?, error_code = '', updated_at_ns = ?
		WHERE id = ? AND status IN (?, ?, ?)
	`
	resourceStatusArgs := []any{
		resourceStatusValue, now.UnixNano(), resource.ID,
		string(domain.ResourceProvisioning), string(domain.ResourceFailed), string(domain.ResourceReconciliation),
	}
	switch operation.Action {
	case domain.ActionRotateResource:
		resourceStatus = domain.ResourceActive
		resourceStatusValue = string(domain.RotationStaging)
		resourceStatusQuery = `
			UPDATE resources SET rotation_status = ?, error_code = '', updated_at_ns = ?
			WHERE id = ? AND status = ? AND rotation_status = ?
		`
		resourceStatusArgs = []any{
			resourceStatusValue, now.UnixNano(), resource.ID,
			string(domain.ResourceActive), string(domain.RotationStaging),
		}
	case domain.ActionRevokeResource:
		resourceStatus = domain.ResourceRevocationPending
		resourceStatusValue = string(resourceStatus)
		resourceStatusArgs = []any{
			resourceStatusValue, now.UnixNano(), resource.ID,
			string(domain.ResourceRevocationPending), string(domain.ResourceFailed), string(domain.ResourceReconciliation),
		}
	case domain.ActionCreateResource:
	default:
		return domain.Operation{}, domain.Resource{}, domain.ErrInvalidResourceTransition
	}
	resourceResult, err := tx.ExecContext(ctx, resourceStatusQuery, resourceStatusArgs...)
	if err != nil {
		return domain.Operation{}, domain.Resource{}, errors.New("unable to mark resource operation in progress")
	}
	resourceRows, err := resourceResult.RowsAffected()
	if err != nil || resourceRows != 1 {
		return domain.Operation{}, domain.Resource{}, domain.ErrInvalidResourceTransition
	}
	var activeOperations int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM operations AS operation
		JOIN resources AS resource ON resource.id = operation.resource_id
		WHERE resource.target_id = ? AND operation.status = ? AND operation.lease_expires_ns > ?
	`, resource.TargetID, string(domain.OperationRunning), now.UnixNano()).Scan(&activeOperations); err != nil {
		return domain.Operation{}, domain.Resource{}, errors.New("unable to read target operation capacity")
	}
	if activeOperations > maxConcurrentOperations {
		return domain.Operation{}, domain.Resource{}, domain.ErrOperationCapacityReached
	}
	event.At = now
	switch operation.Action {
	case domain.ActionRevokeResource:
		event.Action = "resource.revoke.started"
	case domain.ActionRotateResource:
		event.Action = "resource.rotate.started"
	case domain.ActionCreateResource:
		event.Action = "resource.create.started"
	}
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	if event.Outcome == "" {
		event.Outcome = audit.OutcomeAllowed
	}
	if err := recordEvent(ctx, tx, event); err != nil {
		return domain.Operation{}, domain.Resource{}, errors.New("unable to audit resource operation claim")
	}
	if err := tx.Commit(); err != nil {
		return domain.Operation{}, domain.Resource{}, errors.New("unable to commit resource operation claim")
	}
	operation.Status = domain.OperationRunning
	operation.UpdatedAt = now
	operation.LeaseExpiresAt = leaseExpiresAt
	resource.Status = resourceStatus
	switch operation.Action {
	case domain.ActionRotateResource:
		resource.RotationStatus = domain.RotationStaging
	case domain.ActionRevokeResource:
		resource.Status = domain.ResourceRevocationPending
		resource.ErrorCode = ""
	}
	resource.ErrorCode = ""
	resource.UpdatedAt = now
	return operation, resource, nil
}

func (store *Store) CompleteCreate(
	ctx context.Context,
	operationID string,
	secretURI string,
	secretVersion string,
	event audit.Event,
) (domain.Resource, error) {
	if operationID == "" || secretURI == "" || len(secretURI) > 2048 || !identity.ValidSubject(event.Subject) {
		return domain.Resource{}, errors.New("invalid resource completion")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Resource{}, errors.New("unable to begin resource completion")
	}
	defer func() {
		_ = tx.Rollback()
	}()
	operation, err := scanOperation(tx.QueryRowContext(ctx, `
		SELECT id, idempotency_key, subject, action, request_hash, status, resource_id,
		       error_code, created_at_ns, updated_at_ns, lease_expires_ns
		FROM operations WHERE id = ?
	`, operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Resource{}, domain.ErrResourceNotFound
	}
	if err != nil {
		return domain.Resource{}, errors.New("unable to read resource operation")
	}
	if operation.Action != domain.ActionCreateResource || operation.Subject != event.Subject {
		return domain.Resource{}, domain.ErrInvalidResourceTransition
	}
	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", operation.ResourceID))
	if err != nil {
		return domain.Resource{}, errors.New("unable to read reserved resource")
	}
	if operation.Status == domain.OperationSucceeded && resource.Status == domain.ResourceActive {
		if err := tx.Commit(); err != nil {
			return domain.Resource{}, errors.New("unable to finish completed resource lookup")
		}
		return resource, nil
	}
	if operation.Status != domain.OperationRunning || resource.Status != domain.ResourceProvisioning {
		return domain.Resource{}, domain.ErrInvalidResourceTransition
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE resources
		SET status = ?, secret_uri = ?, secret_version = ?, error_code = '', updated_at_ns = ?
		WHERE id = ? AND status = ?
	`, string(domain.ResourceActive), secretURI, secretVersion, now.UnixNano(), resource.ID, string(domain.ResourceProvisioning)); err != nil {
		return domain.Resource{}, errors.New("unable to activate resource")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations
		SET status = ?, error_code = '', lease_expires_ns = 0, updated_at_ns = ?
		WHERE id = ? AND status = ?
	`, string(domain.OperationSucceeded), now.UnixNano(), operation.ID, string(domain.OperationRunning)); err != nil {
		return domain.Resource{}, errors.New("unable to complete resource operation")
	}
	event.At = now
	event.Action = "resource.create.succeeded"
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	event.Outcome = audit.OutcomeAllowed
	if err := recordEvent(ctx, tx, event); err != nil {
		return domain.Resource{}, errors.New("unable to audit resource completion")
	}
	if err := tx.Commit(); err != nil {
		return domain.Resource{}, errors.New("unable to commit resource completion")
	}
	resource.Status = domain.ResourceActive
	resource.SecretURI = secretURI
	resource.SecretVersion = secretVersion
	resource.ErrorCode = ""
	resource.UpdatedAt = now
	return resource, nil
}

func (store *Store) FailCreate(
	ctx context.Context,
	operationID string,
	errorCode string,
	reconciliationRequired bool,
	event audit.Event,
) error {
	if operationID == "" || !errorCodePattern.MatchString(errorCode) || !identity.ValidSubject(event.Subject) {
		return errors.New("invalid resource failure transition")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("unable to begin resource failure transition")
	}
	defer func() {
		_ = tx.Rollback()
	}()
	operation, err := scanOperation(tx.QueryRowContext(ctx, `
		SELECT id, idempotency_key, subject, action, request_hash, status, resource_id,
		       error_code, created_at_ns, updated_at_ns, lease_expires_ns
		FROM operations WHERE id = ?
	`, operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrResourceNotFound
	}
	if err != nil {
		return errors.New("unable to read resource operation")
	}
	if operation.Action != domain.ActionCreateResource || operation.Subject != event.Subject || operation.Status != domain.OperationRunning {
		return domain.ErrInvalidResourceTransition
	}
	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", operation.ResourceID))
	if err != nil {
		return errors.New("unable to read reserved resource")
	}
	now := time.Now().UTC()
	operationStatus := domain.OperationFailed
	action := "resource.create.failed"
	if reconciliationRequired {
		operationStatus = domain.OperationReconciliationRequired
		action = "resource.create.reconciliation_required"
	}
	resourceStatus := domain.ResourceFailed
	if reconciliationRequired {
		resourceStatus = domain.ResourceReconciliation
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE resources SET status = ?, error_code = ?, updated_at_ns = ?
		WHERE id = ? AND status = ?
	`, string(resourceStatus), errorCode, now.UnixNano(), resource.ID, string(domain.ResourceProvisioning)); err != nil {
		return errors.New("unable to persist resource failure")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET status = ?, error_code = ?, lease_expires_ns = 0, updated_at_ns = ?
		WHERE id = ? AND status = ?
	`, string(operationStatus), errorCode, now.UnixNano(), operation.ID, string(domain.OperationRunning)); err != nil {
		return errors.New("unable to persist operation failure")
	}
	event.At = now
	event.Action = action
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	event.Outcome = audit.OutcomeDenied
	event.ErrorCode = errorCode
	if err := recordEvent(ctx, tx, event); err != nil {
		return errors.New("unable to audit resource failure")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("unable to commit resource failure")
	}
	return nil
}

func (store *Store) CompleteRevoke(ctx context.Context, operationID string, event audit.Event) (domain.Resource, error) {
	if operationID == "" || !identity.ValidSubject(event.Subject) {
		return domain.Resource{}, errors.New("invalid resource revocation completion")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Resource{}, errors.New("unable to begin resource revocation completion")
	}
	defer func() {
		_ = tx.Rollback()
	}()
	operation, err := scanOperation(tx.QueryRowContext(ctx, `
		SELECT id, idempotency_key, subject, action, request_hash, status, resource_id,
		       error_code, created_at_ns, updated_at_ns, lease_expires_ns
		FROM operations WHERE id = ?
	`, operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Resource{}, domain.ErrResourceNotFound
	}
	if err != nil {
		return domain.Resource{}, errors.New("unable to read resource revoke operation")
	}
	if operation.Action != domain.ActionRevokeResource || operation.Subject != event.Subject {
		return domain.Resource{}, domain.ErrInvalidResourceTransition
	}
	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", operation.ResourceID))
	if err != nil {
		return domain.Resource{}, errors.New("unable to read resource for revocation completion")
	}
	if operation.Status == domain.OperationSucceeded && resource.Status == domain.ResourceRevoked {
		if err := tx.Commit(); err != nil {
			return domain.Resource{}, errors.New("unable to finish completed resource revoke lookup")
		}
		return resource, nil
	}
	if operation.Status != domain.OperationRunning || resource.Status != domain.ResourceRevocationPending {
		return domain.Resource{}, domain.ErrInvalidResourceTransition
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `
		UPDATE resources
		SET status = ?, secret_uri = '', secret_version = '', rotation_status = '', error_code = '', updated_at_ns = ?
		WHERE id = ? AND status = ?
	`, string(domain.ResourceRevoked), now.UnixNano(), resource.ID, string(domain.ResourceRevocationPending))
	if err != nil {
		return domain.Resource{}, errors.New("unable to persist resource revocation")
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return domain.Resource{}, domain.ErrInvalidResourceTransition
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations
		SET status = ?, error_code = '', lease_expires_ns = 0, updated_at_ns = ?
		WHERE id = ? AND status = ?
	`, string(domain.OperationSucceeded), now.UnixNano(), operation.ID, string(domain.OperationRunning)); err != nil {
		return domain.Resource{}, errors.New("unable to complete resource revocation operation")
	}
	event.At = now
	event.Action = "resource.revoke.succeeded"
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	event.Outcome = audit.OutcomeAllowed
	if err := recordEvent(ctx, tx, event); err != nil {
		return domain.Resource{}, errors.New("unable to audit resource revocation completion")
	}
	if err := tx.Commit(); err != nil {
		return domain.Resource{}, errors.New("unable to commit resource revocation")
	}
	resource.Status = domain.ResourceRevoked
	resource.SecretURI = ""
	resource.SecretVersion = ""
	resource.RotationStatus = ""
	resource.ErrorCode = ""
	resource.UpdatedAt = now
	return resource, nil
}

func (store *Store) FailRevoke(ctx context.Context, operationID string, errorCode string, event audit.Event) error {
	if operationID == "" || !errorCodePattern.MatchString(errorCode) || !identity.ValidSubject(event.Subject) {
		return errors.New("invalid resource revocation failure transition")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("unable to begin resource revocation failure transition")
	}
	defer func() {
		_ = tx.Rollback()
	}()
	operation, err := scanOperation(tx.QueryRowContext(ctx, `
		SELECT id, idempotency_key, subject, action, request_hash, status, resource_id,
		       error_code, created_at_ns, updated_at_ns, lease_expires_ns
		FROM operations WHERE id = ?
	`, operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrResourceNotFound
	}
	if err != nil {
		return errors.New("unable to read resource revoke operation")
	}
	if operation.Action != domain.ActionRevokeResource || operation.Subject != event.Subject || operation.Status != domain.OperationRunning {
		return domain.ErrInvalidResourceTransition
	}
	resource, err := scanResource(tx.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", operation.ResourceID))
	if err != nil {
		return errors.New("unable to read resource for revocation failure")
	}
	if resource.Status != domain.ResourceRevocationPending {
		return domain.ErrInvalidResourceTransition
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE resources SET status = ?, error_code = ?, updated_at_ns = ?
		WHERE id = ? AND status = ?
	`, string(domain.ResourceReconciliation), errorCode, now.UnixNano(), resource.ID, string(domain.ResourceRevocationPending)); err != nil {
		return errors.New("unable to persist resource revocation failure")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET status = ?, error_code = ?, lease_expires_ns = 0, updated_at_ns = ?
		WHERE id = ? AND status = ?
	`, string(domain.OperationReconciliationRequired), errorCode, now.UnixNano(), operation.ID, string(domain.OperationRunning)); err != nil {
		return errors.New("unable to persist resource revocation operation failure")
	}
	event.At = now
	event.Action = "resource.revoke.reconciliation_required"
	event.EntityID = resource.ID
	event.Application = resource.Scope.Application
	event.Environment = resource.Scope.Environment
	event.Resource = resource.ResourceType
	event.Outcome = audit.OutcomeDenied
	event.ErrorCode = errorCode
	if err := recordEvent(ctx, tx, event); err != nil {
		return errors.New("unable to audit resource revocation failure")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("unable to commit resource revocation failure")
	}
	return nil
}

func (store *Store) GetResource(ctx context.Context, id string) (domain.Resource, error) {
	resource, err := scanResource(store.db.QueryRowContext(ctx, resourceSelect+" WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Resource{}, domain.ErrResourceNotFound
	}
	if err != nil {
		return domain.Resource{}, errors.New("unable to read resource")
	}
	return resource, nil
}

func (store *Store) GetOperation(ctx context.Context, id string) (domain.Operation, error) {
	operation, err := scanOperation(store.db.QueryRowContext(ctx, `
		SELECT id, idempotency_key, subject, action, request_hash, status, resource_id,
		       error_code, created_at_ns, updated_at_ns, lease_expires_ns
		FROM operations WHERE id = ?
	`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.ErrResourceNotFound
	}
	if err != nil {
		return domain.Operation{}, errors.New("unable to read resource operation")
	}
	return operation, nil
}

func (store *Store) GetOperationByIdempotencyKey(ctx context.Context, subject string, idempotencyKey string) (domain.Operation, error) {
	if !identity.ValidSubject(subject) || !domain.ValidIdempotencyKey(idempotencyKey) {
		return domain.Operation{}, domain.ErrResourceNotFound
	}
	operation, err := scanOperation(store.db.QueryRowContext(ctx, `
		SELECT id, idempotency_key, subject, action, request_hash, status, resource_id,
		       error_code, created_at_ns, updated_at_ns, lease_expires_ns
		FROM operations WHERE subject = ? AND idempotency_key = ?
	`, subject, idempotencyKey))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.ErrResourceNotFound
	}
	if err != nil {
		return domain.Operation{}, errors.New("unable to read idempotent resource operation")
	}
	return operation, nil
}

const resourceSelect = `
	SELECT id, resource_type, application, environment, logical_name, target_id,
	       status, secret_uri, secret_version, credential_generation, rotation_status,
	       error_code, created_at_ns, updated_at_ns
	FROM resources
`

func scanResource(scanner rowScanner) (domain.Resource, error) {
	var resource domain.Resource
	var resourceType string
	var status string
	var rotationStatus string
	var createdAt int64
	var updatedAt int64
	if err := scanner.Scan(
		&resource.ID,
		&resourceType,
		&resource.Scope.Application,
		&resource.Scope.Environment,
		&resource.LogicalName,
		&resource.TargetID,
		&status,
		&resource.SecretURI,
		&resource.SecretVersion,
		&resource.CredentialGeneration,
		&rotationStatus,
		&resource.ErrorCode,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.Resource{}, err
	}
	resource.ResourceType = domain.ResourceType(resourceType)
	resource.Status = domain.ResourceStatus(status)
	resource.RotationStatus = domain.RotationStatus(rotationStatus)
	resource.CreatedAt = time.Unix(0, createdAt).UTC()
	resource.UpdatedAt = time.Unix(0, updatedAt).UTC()
	return resource, nil
}

func scanOperation(scanner rowScanner) (domain.Operation, error) {
	var operation domain.Operation
	var status string
	var createdAt int64
	var updatedAt int64
	var leaseExpiresAt int64
	if err := scanner.Scan(
		&operation.ID,
		&operation.IdempotencyKey,
		&operation.Subject,
		&operation.Action,
		&operation.RequestHash,
		&status,
		&operation.ResourceID,
		&operation.ErrorCode,
		&createdAt,
		&updatedAt,
		&leaseExpiresAt,
	); err != nil {
		return domain.Operation{}, err
	}
	operation.Status = domain.OperationStatus(status)
	operation.CreatedAt = time.Unix(0, createdAt).UTC()
	operation.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if leaseExpiresAt > 0 {
		operation.LeaseExpiresAt = time.Unix(0, leaseExpiresAt).UTC()
	}
	return operation, nil
}
