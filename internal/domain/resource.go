package domain

import (
	"errors"
	"regexp"
	"time"
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

var (
	ErrInvalidIdempotencyKey     = errors.New("INVALID_IDEMPOTENCY_KEY")
	ErrIdempotencyConflict       = errors.New("IDEMPOTENCY_CONFLICT")
	ErrOperationInProgress       = errors.New("OPERATION_IN_PROGRESS")
	ErrOperationTerminal         = errors.New("OPERATION_TERMINAL")
	ErrResourceAlreadyExists     = errors.New("RESOURCE_ALREADY_EXISTS")
	ErrResourceNotFound          = errors.New("RESOURCE_NOT_FOUND")
	ErrResourceNotActive         = errors.New("RESOURCE_NOT_ACTIVE")
	ErrResourceAlreadyRevoked    = errors.New("RESOURCE_ALREADY_REVOKED")
	ErrTargetCapacityReached     = errors.New("TARGET_CAPACITY_REACHED")
	ErrOperationCapacityReached  = errors.New("TARGET_OPERATION_CAPACITY_REACHED")
	ErrInvalidResourceTransition = errors.New("INVALID_RESOURCE_TRANSITION")
)

const (
	ActionCreateResource = "create_resource"
	ActionRevokeResource = "revoke_resource"
)

type ResourceStatus string

const (
	ResourceProvisioning      ResourceStatus = "provisioning"
	ResourceActive            ResourceStatus = "active"
	ResourceFailed            ResourceStatus = "failed"
	ResourceReconciliation    ResourceStatus = "reconciliation_required"
	ResourceRevocationPending ResourceStatus = "revocation_pending"
	ResourceRevoked           ResourceStatus = "revoked"
)

type OperationStatus string

const (
	OperationAccepted               OperationStatus = "accepted"
	OperationRunning                OperationStatus = "running"
	OperationSucceeded              OperationStatus = "succeeded"
	OperationFailed                 OperationStatus = "failed"
	OperationReconciliationRequired OperationStatus = "reconciliation_required"
)

type CreateResourceCommand struct {
	ResourceType   ResourceType
	Scope          Scope
	IdempotencyKey string
}

type RevokeResourceCommand struct {
	ResourceID   string
	Confirmation string
}

func ValidateRevokeResourceCommand(command RevokeResourceCommand) error {
	if command.ResourceID == "" || command.Confirmation != "revoke:"+command.ResourceID {
		return ErrInvalidResourceTransition
	}
	return nil
}

func ValidIdempotencyKey(value string) bool {
	return idempotencyKeyPattern.MatchString(value)
}

type Resource struct {
	ID            string
	ResourceType  ResourceType
	Scope         Scope
	LogicalName   string
	TargetID      string
	Status        ResourceStatus
	SecretURI     string
	SecretVersion string
	ErrorCode     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Operation struct {
	ID             string
	IdempotencyKey string
	Subject        string
	Action         string
	RequestHash    string
	Status         OperationStatus
	ResourceID     string
	ErrorCode      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LeaseExpiresAt time.Time
}

type ResourceView struct {
	ID              string         `json:"id"`
	ResourceType    ResourceType   `json:"resource_type"`
	Application     string         `json:"application"`
	Environment     string         `json:"environment"`
	LogicalName     string         `json:"logical_name"`
	Status          ResourceStatus `json:"status"`
	SecretReference string         `json:"secret_reference,omitempty"`
	SecretVersion   string         `json:"secret_version,omitempty"`
	ErrorCode       string         `json:"error_code,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func ValidateCreateResourceCommand(command CreateResourceCommand) error {
	if !command.ResourceType.Valid() {
		return ErrInvalidResourceType
	}
	if !validScopeName(command.Scope.Application) || !validScopeName(command.Scope.Environment) {
		return ErrInvalidScope
	}
	if !idempotencyKeyPattern.MatchString(command.IdempotencyKey) {
		return ErrInvalidIdempotencyKey
	}
	return nil
}

func (resource Resource) View() ResourceView {
	view := ResourceView{
		ID:           resource.ID,
		ResourceType: resource.ResourceType,
		Application:  resource.Scope.Application,
		Environment:  resource.Scope.Environment,
		LogicalName:  resource.LogicalName,
		Status:       resource.Status,
		ErrorCode:    resource.ErrorCode,
		CreatedAt:    resource.CreatedAt.UTC(),
		UpdatedAt:    resource.UpdatedAt.UTC(),
	}
	if resource.Status == ResourceActive {
		view.SecretReference = resource.SecretURI
		view.SecretVersion = resource.SecretVersion
	}
	return view
}
