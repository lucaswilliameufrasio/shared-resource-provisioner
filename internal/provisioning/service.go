package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/secrets"
)

const (
	defaultOperationTimeout = 45 * time.Second
	defaultOperationLease   = 60 * time.Second
	cleanupTimeout          = 10 * time.Second
)

var (
	ErrUnauthenticated          = errors.New("UNAUTHENTICATED")
	ErrAuditUnavailable         = errors.New("AUDIT_UNAVAILABLE")
	ErrPersistenceUnavailable   = errors.New("PERSISTENCE_UNAVAILABLE")
	ErrTargetUnavailable        = errors.New("TARGET_UNAVAILABLE")
	ErrSecretStoreUnavailable   = errors.New("SECRET_STORE_UNAVAILABLE")
	ErrProvisioningFailed       = errors.New("PROVISIONING_FAILED")
	ErrReconciliationRequired   = errors.New("RECONCILIATION_REQUIRED")
	ErrRevocationFailed         = errors.New("REVOCATION_REQUIRES_RECONCILIATION")
	ErrInvalidResourceReference = errors.New("INVALID_RESOURCE_REFERENCE")
)

type ResourceStore interface {
	ReserveCreate(context.Context, domain.Operation, domain.Resource, int, audit.Event) (domain.Operation, domain.Resource, bool, error)
	ReserveRevoke(context.Context, domain.Operation, string, audit.Event) (domain.Operation, domain.Resource, bool, error)
	ClaimOperation(context.Context, string, time.Time, time.Duration, int, audit.Event) (domain.Operation, domain.Resource, error)
	CompleteCreate(context.Context, string, string, string, audit.Event) (domain.Resource, error)
	FailCreate(context.Context, string, string, bool, audit.Event) error
	CompleteRevoke(context.Context, string, audit.Event) (domain.Resource, error)
	FailRevoke(context.Context, string, string, audit.Event) error
	GetResource(context.Context, string) (domain.Resource, error)
	GetOperationByIdempotencyKey(context.Context, string, string) (domain.Operation, error)
	Record(context.Context, audit.Event) error
}

type Target struct {
	ID                      string
	ResourceType            domain.ResourceType
	MaxResources            int
	MaxConcurrentOperations int
	Driver                  Driver
}

type Service struct {
	store            ResourceStore
	authorizer       authorization.Authorizer
	auditor          audit.Recorder
	secretStore      secrets.SecretStore
	targetsByType    map[domain.ResourceType]Target
	targetsByID      map[string]Target
	operationTimeout time.Duration
	operationLease   time.Duration
	now              func() time.Time
}

func NewService(
	store ResourceStore,
	authorizer authorization.Authorizer,
	auditor audit.Recorder,
	secretStore secrets.SecretStore,
	targets []Target,
) (*Service, error) {
	if store == nil || authorizer == nil || auditor == nil || secretStore == nil {
		return nil, errors.New("resource store, authorizer, auditor, and secret store are required")
	}
	if len(targets) == 0 {
		return nil, errors.New("at least one provisionable service target is required")
	}
	service := &Service{
		store:            store,
		authorizer:       authorizer,
		auditor:          auditor,
		secretStore:      secretStore,
		targetsByType:    make(map[domain.ResourceType]Target, len(targets)),
		targetsByID:      make(map[string]Target, len(targets)),
		operationTimeout: defaultOperationTimeout,
		operationLease:   defaultOperationLease,
		now:              time.Now,
	}
	for _, target := range targets {
		if target.ID == "" || !target.ResourceType.Valid() || target.MaxResources < 1 || target.MaxConcurrentOperations < 1 || target.Driver == nil {
			return nil, errors.New("service target identity, limits, and driver are required")
		}
		if _, exists := service.targetsByID[target.ID]; exists {
			return nil, errors.New("service target IDs must be unique")
		}
		if _, exists := service.targetsByType[target.ResourceType]; exists {
			return nil, errors.New("only one target per resource type is supported")
		}
		service.targetsByID[target.ID] = target
		service.targetsByType[target.ResourceType] = target
	}
	if service.operationLease <= service.operationTimeout {
		return nil, errors.New("operation lease must exceed operation timeout")
	}
	return service, nil
}

func (service *Service) Create(ctx context.Context, request domain.CreateResourceCommand) (domain.ResourceView, error) {
	if err := domain.ValidateCreateResourceCommand(request); err != nil {
		return domain.ResourceView{}, err
	}
	principal, ok := identity.FromContext(ctx)
	if !ok {
		return domain.ResourceView{}, ErrUnauthenticated
	}
	plan, err := domain.BuildPlan(domain.PlanRequest{ResourceType: request.ResourceType, Scope: request.Scope})
	if err != nil {
		return domain.ResourceView{}, err
	}
	target, exists := service.targetsByType[request.ResourceType]
	if !exists {
		return domain.ResourceView{}, ErrTargetUnavailable
	}
	event := service.event(principal, authorization.ActionCreateResource, request.Scope, request.ResourceType)
	if err := service.authorize(ctx, principal, authorization.ActionCreateResource, request.Scope, event); err != nil {
		return domain.ResourceView{}, err
	}
	requestHash := hashRequest(string(request.ResourceType), request.Scope.Application, request.Scope.Environment, target.ID)
	operation := domain.Operation{
		IdempotencyKey: request.IdempotencyKey,
		Subject:        principal.Subject,
		Action:         domain.ActionCreateResource,
		RequestHash:    requestHash,
	}
	resource := domain.Resource{
		ResourceType: request.ResourceType,
		Scope:        request.Scope,
		LogicalName:  plan.LogicalName,
		TargetID:     target.ID,
	}
	operation, resource, _, err = service.store.ReserveCreate(ctx, operation, resource, target.MaxResources, event)
	if err != nil {
		return domain.ResourceView{}, service.recordMappedFailure(ctx, principal, event, err)
	}
	if operation.Status == domain.OperationSucceeded {
		return resource.View(), nil
	}
	operation, resource, err = service.store.ClaimOperation(ctx, operation.ID, service.now().UTC(), service.operationLease, target.MaxConcurrentOperations, event)
	if err != nil {
		return domain.ResourceView{}, service.recordMappedFailure(ctx, principal, event, err)
	}
	if operation.Status == domain.OperationSucceeded {
		return resource.View(), nil
	}

	secretName := credentialName(request.ResourceType)
	expectedReference, err := service.secretStore.ReferenceFor(request.Scope, secretName)
	if err != nil {
		return domain.ResourceView{}, service.failCreate(ctx, operation, event, "SECRET_STORE_UNAVAILABLE", false)
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.operationTimeout)
	defer cancel()
	credential, driverErr := target.Driver.Create(operationCtx, resource)
	defer clear(credential.Value)
	if driverErr != nil {
		code, mayHaveMutated := failureDetails(driverErr)
		if mayHaveMutated {
			if cleanupErr := service.cleanupResource(ctx, target, resource, nil); cleanupErr != nil {
				return domain.ResourceView{}, service.failCreate(ctx, operation, event, "COMPENSATION_FAILED", true)
			}
		}
		return domain.ResourceView{}, service.failCreate(ctx, operation, event, code, false)
	}
	if !secrets.ValidName(credential.Name) || credential.Name != secretName || len(credential.Value) == 0 {
		if cleanupErr := service.cleanupResource(ctx, target, resource, nil); cleanupErr != nil {
			return domain.ResourceView{}, service.failCreate(ctx, operation, event, "COMPENSATION_FAILED", true)
		}
		return domain.ResourceView{}, service.failCreate(ctx, operation, event, "DRIVER_FAILURE", false)
	}

	storedReference, err := service.secretStore.Put(operationCtx, request.Scope, secretName, credential.Value)
	if err != nil {
		if cleanupErr := service.cleanupResource(ctx, target, resource, &expectedReference); cleanupErr != nil {
			return domain.ResourceView{}, service.failCreate(ctx, operation, event, "COMPENSATION_FAILED", true)
		}
		return domain.ResourceView{}, service.failCreate(ctx, operation, event, "SECRET_STORE_UNAVAILABLE", false)
	}
	if err := secrets.ValidateReference(storedReference); err != nil || storedReference.URI != expectedReference.URI {
		if secrets.ValidateReference(storedReference) == nil {
			if cleanupErr := service.cleanupResource(ctx, target, resource, &storedReference); cleanupErr != nil {
				return domain.ResourceView{}, service.failCreate(ctx, operation, event, "COMPENSATION_FAILED", true)
			}
		} else if cleanupErr := service.cleanupResource(ctx, target, resource, &expectedReference); cleanupErr != nil {
			return domain.ResourceView{}, service.failCreate(ctx, operation, event, "COMPENSATION_FAILED", true)
		}
		return domain.ResourceView{}, service.failCreate(ctx, operation, event, "INVALID_SECRET_REFERENCE", false)
	}

	completed, err := service.store.CompleteCreate(ctx, operation.ID, storedReference.URI, storedReference.Version, event)
	if err != nil {
		stateCtx, stateCancel := service.backgroundContext(ctx)
		defer stateCancel()
		current, readErr := service.store.GetResource(stateCtx, resource.ID)
		if readErr == nil && current.Status == domain.ResourceActive {
			return current.View(), nil
		}
		return domain.ResourceView{}, service.failCreate(ctx, operation, event, "PERSISTENCE_UNAVAILABLE", true)
	}
	return completed.View(), nil
}

func (service *Service) Inspect(ctx context.Context, resourceID string) (domain.ResourceView, error) {
	if resourceID == "" || len(resourceID) > 128 || strings.TrimSpace(resourceID) != resourceID {
		return domain.ResourceView{}, domain.ErrResourceNotFound
	}
	principal, ok := identity.FromContext(ctx)
	if !ok {
		return domain.ResourceView{}, ErrUnauthenticated
	}
	resource, err := service.store.GetResource(ctx, resourceID)
	if err != nil {
		event := service.event(principal, authorization.ActionInspectResource, domain.Scope{}, "")
		event.EntityID = resourceID
		return domain.ResourceView{}, service.recordMappedFailure(ctx, principal, event, err)
	}
	event := service.event(principal, authorization.ActionInspectResource, resource.Scope, resource.ResourceType)
	event.EntityID = resource.ID
	if err := service.authorize(ctx, principal, authorization.ActionInspectResource, resource.Scope, event); err != nil {
		return domain.ResourceView{}, err
	}
	if err := service.record(ctx, event, audit.OutcomeAllowed, ""); err != nil {
		return domain.ResourceView{}, err
	}
	return resource.View(), nil
}

func (service *Service) Revoke(ctx context.Context, command domain.RevokeResourceCommand, idempotencyKey string) (domain.ResourceView, error) {
	if err := domain.ValidateRevokeResourceCommand(command); err != nil || !domain.ValidIdempotencyKey(idempotencyKey) {
		return domain.ResourceView{}, domain.ErrInvalidResourceTransition
	}
	principal, ok := identity.FromContext(ctx)
	if !ok {
		return domain.ResourceView{}, ErrUnauthenticated
	}
	resource, err := service.store.GetResource(ctx, command.ResourceID)
	if err != nil {
		event := service.event(principal, authorization.ActionRevokeResource, domain.Scope{}, "")
		event.EntityID = command.ResourceID
		return domain.ResourceView{}, service.recordMappedFailure(ctx, principal, event, err)
	}
	event := service.event(principal, authorization.ActionRevokeResource, resource.Scope, resource.ResourceType)
	event.EntityID = resource.ID
	if err := service.authorize(ctx, principal, authorization.ActionRevokeResource, resource.Scope, event); err != nil {
		return domain.ResourceView{}, err
	}
	target, exists := service.targetsByID[resource.TargetID]
	if !exists || target.ResourceType != resource.ResourceType {
		return domain.ResourceView{}, ErrTargetUnavailable
	}
	requestHash := hashRequest(resource.ID, resource.TargetID, "revoke")
	operation := domain.Operation{
		IdempotencyKey: idempotencyKey,
		Subject:        principal.Subject,
		Action:         domain.ActionRevokeResource,
		RequestHash:    requestHash,
	}
	operation, resource, _, err = service.store.ReserveRevoke(ctx, operation, command.ResourceID, event)
	if err != nil {
		if errors.Is(err, domain.ErrResourceAlreadyRevoked) {
			return resource.View(), nil
		}
		return domain.ResourceView{}, service.recordMappedFailure(ctx, principal, event, err)
	}
	if operation.Status == domain.OperationSucceeded {
		return resource.View(), nil
	}
	operation, resource, err = service.store.ClaimOperation(ctx, operation.ID, service.now().UTC(), service.operationLease, target.MaxConcurrentOperations, event)
	if err != nil {
		return domain.ResourceView{}, service.recordMappedFailure(ctx, principal, event, err)
	}
	if operation.Status == domain.OperationSucceeded {
		return resource.View(), nil
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.operationTimeout)
	defer cancel()
	driverErr := target.Driver.Revoke(operationCtx, resource)
	if driverErr != nil {
		return domain.ResourceView{}, service.failRevoke(ctx, operation, event, "DRIVER_FAILURE")
	}
	if resource.SecretURI != "" {
		reference := secrets.Reference{URI: resource.SecretURI, Version: resource.SecretVersion}
		if err := secrets.ValidateReference(reference); err != nil || service.secretStore.Delete(operationCtx, reference) != nil {
			return domain.ResourceView{}, service.failRevoke(ctx, operation, event, "SECRET_CLEANUP_FAILED")
		}
	}
	completed, err := service.store.CompleteRevoke(ctx, operation.ID, event)
	if err != nil {
		stateCtx, stateCancel := service.backgroundContext(ctx)
		defer stateCancel()
		current, readErr := service.store.GetResource(stateCtx, resource.ID)
		if readErr == nil && current.Status == domain.ResourceRevoked {
			return current.View(), nil
		}
		return domain.ResourceView{}, service.failRevoke(ctx, operation, event, "PERSISTENCE_UNAVAILABLE")
	}
	return completed.View(), nil
}

func (service *Service) authorize(ctx context.Context, principal identity.Principal, action authorization.Action, scope domain.Scope, event audit.Event) error {
	if err := service.authorizer.AuthorizeContext(ctx, principal, action, scope); err != nil {
		code := "PERMISSION_DENIED"
		if errors.Is(err, authorization.ErrAuthorizationUnavailable) {
			code = "AUTHORIZATION_UNAVAILABLE"
		}
		if recordErr := service.record(ctx, event, audit.OutcomeDenied, code); recordErr != nil {
			return ErrAuditUnavailable
		}
		if errors.Is(err, authorization.ErrPermissionDenied) {
			return authorization.ErrPermissionDenied
		}
		return authorization.ErrAuthorizationUnavailable
	}
	return nil
}

func (service *Service) failCreate(ctx context.Context, operation domain.Operation, event audit.Event, code string, reconciliationRequired bool) error {
	stateCtx, cancel := service.backgroundContext(ctx)
	defer cancel()
	if err := service.store.FailCreate(stateCtx, operation.ID, code, reconciliationRequired, event); err != nil {
		return ErrPersistenceUnavailable
	}
	if reconciliationRequired {
		return ErrReconciliationRequired
	}
	return ErrProvisioningFailed
}

func (service *Service) failRevoke(ctx context.Context, operation domain.Operation, event audit.Event, code string) error {
	stateCtx, cancel := service.backgroundContext(ctx)
	defer cancel()
	if err := service.store.FailRevoke(stateCtx, operation.ID, code, event); err != nil {
		return ErrPersistenceUnavailable
	}
	return ErrRevocationFailed
}

func (service *Service) cleanupResource(ctx context.Context, target Target, resource domain.Resource, reference *secrets.Reference) error {
	cleanupCtx, cancel := service.backgroundContext(ctx)
	defer cancel()
	var firstErr error
	if reference != nil {
		if err := service.secretStore.Delete(cleanupCtx, *reference); err != nil {
			firstErr = ErrSecretStoreUnavailable
		}
	}
	if err := target.Driver.Revoke(cleanupCtx, resource); err != nil && firstErr == nil {
		firstErr = ErrReconciliationRequired
	}
	return firstErr
}

func (service *Service) recordMappedFailure(ctx context.Context, _ identity.Principal, event audit.Event, err error) error {
	code := safeErrorCode(err)
	if err := service.record(ctx, event, audit.OutcomeDenied, code); err != nil {
		return ErrAuditUnavailable
	}
	switch {
	case errors.Is(err, authorization.ErrPermissionDenied):
		return authorization.ErrPermissionDenied
	case errors.Is(err, domain.ErrResourceNotFound):
		return domain.ErrResourceNotFound
	case errors.Is(err, domain.ErrIdempotencyConflict):
		return domain.ErrIdempotencyConflict
	case errors.Is(err, domain.ErrOperationInProgress):
		return domain.ErrOperationInProgress
	case errors.Is(err, domain.ErrOperationCapacityReached):
		return domain.ErrOperationCapacityReached
	case errors.Is(err, domain.ErrTargetCapacityReached):
		return domain.ErrTargetCapacityReached
	case errors.Is(err, domain.ErrResourceAlreadyExists):
		return domain.ErrResourceAlreadyExists
	case errors.Is(err, domain.ErrResourceAlreadyRevoked):
		return domain.ErrResourceAlreadyRevoked
	case errors.Is(err, domain.ErrResourceNotActive):
		return domain.ErrResourceNotActive
	case errors.Is(err, authorization.ErrAuthorizationUnavailable):
		return authorization.ErrAuthorizationUnavailable
	default:
		return ErrPersistenceUnavailable
	}
}

func (service *Service) record(ctx context.Context, event audit.Event, outcome audit.Outcome, errorCode string) error {
	event.At = service.now().UTC()
	event.Outcome = outcome
	event.ErrorCode = errorCode
	stateCtx, cancel := service.backgroundContext(ctx)
	defer cancel()
	if err := service.auditor.Record(stateCtx, event); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func (service *Service) event(principal identity.Principal, action authorization.Action, scope domain.Scope, resourceType domain.ResourceType) audit.Event {
	return audit.Event{
		At:          service.now().UTC(),
		Subject:     principal.Subject,
		Transport:   principal.Transport,
		Action:      string(action),
		Application: scope.Application,
		Environment: scope.Environment,
		Resource:    resourceType,
	}
}

func (service *Service) backgroundContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

func hashRequest(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func credentialName(resourceType domain.ResourceType) string {
	switch resourceType {
	case domain.ResourcePostgreSQL:
		return "DATABASE_URL"
	case domain.ResourceValkey:
		return "VALKEY_URL"
	case domain.ResourceNATS:
		return "NATS_CREDENTIALS"
	default:
		return ""
	}
}

func safeErrorCode(err error) string {
	if err == nil {
		return "UNEXPECTED_ERROR"
	}
	if errors.Is(err, domain.ErrResourceNotFound) {
		return "RESOURCE_NOT_FOUND"
	}
	if errors.Is(err, domain.ErrResourceAlreadyExists) {
		return "RESOURCE_ALREADY_EXISTS"
	}
	if errors.Is(err, domain.ErrResourceAlreadyRevoked) {
		return "RESOURCE_ALREADY_REVOKED"
	}
	if errors.Is(err, domain.ErrOperationInProgress) {
		return "OPERATION_IN_PROGRESS"
	}
	if errors.Is(err, domain.ErrOperationCapacityReached) {
		return "TARGET_OPERATION_CAPACITY_REACHED"
	}
	if errors.Is(err, domain.ErrTargetCapacityReached) {
		return "TARGET_CAPACITY_REACHED"
	}
	if errors.Is(err, domain.ErrIdempotencyConflict) {
		return "IDEMPOTENCY_CONFLICT"
	}
	if errors.Is(err, domain.ErrResourceNotActive) {
		return "RESOURCE_NOT_ACTIVE"
	}
	return "OPERATION_UNAVAILABLE"
}
