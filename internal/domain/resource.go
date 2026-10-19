package domain

import (
	"errors"
	"regexp"
	"strings"
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
	ErrRotationNotFound          = errors.New("ROTATION_NOT_FOUND")
	ErrRotationMismatch          = errors.New("ROTATION_ACKNOWLEDGEMENT_MISMATCH")
	ErrRotationInProgress        = errors.New("ROTATION_IN_PROGRESS")
	ErrRotationReconciliation    = errors.New("ROTATION_RECONCILIATION_REQUIRED")
)

const (
	ActionCreateResource = "create_resource"
	ActionRevokeResource = "revoke_resource"
	ActionRotateResource = "rotate_resource"
	ActionAdoptRotation  = "adopt_rotation"
)

type RotationStatus string

const (
	RotationStaging                RotationStatus = "staging"
	RotationPending                RotationStatus = "pending"
	RotationFinalizing             RotationStatus = "finalizing"
	RotationReconciliationRequired RotationStatus = "reconciliation_required"
	RotationCompleted              RotationStatus = "completed"
	RotationFailed                 RotationStatus = "failed"
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

type RotateResourceCommand struct {
	ResourceID     string
	IdempotencyKey string
}

type RotationAcknowledgement struct {
	ResourceID      string
	OperationID     string
	SecretReference string
	SecretVersion   string
	Generation      int64
}

type Rotation struct {
	OperationID      string
	ResourceID       string
	OldGeneration    int64
	NewGeneration    int64
	OldSecretURI     string
	OldSecretVersion string
	CredentialName   string
	SecretURI        string
	SecretVersion    string
	Status           RotationStatus
	AcknowledgedAt   time.Time
	LeaseExpiresAt   time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type RotationReceipt struct {
	ResourceID  string         `json:"resource_id"`
	OperationID string         `json:"operation_id"`
	Generation  int64          `json:"generation"`
	Status      RotationStatus `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type PendingRotation struct {
	ResourceID      string         `json:"resource_id"`
	OperationID     string         `json:"operation_id"`
	CredentialName  string         `json:"credential_name"`
	SecretReference string         `json:"secret_reference"`
	SecretVersion   string         `json:"secret_version,omitempty"`
	Generation      int64          `json:"generation"`
	Status          RotationStatus `json:"status"`
}

func ValidateRevokeResourceCommand(command RevokeResourceCommand) error {
	if command.ResourceID == "" || command.Confirmation != "revoke:"+command.ResourceID {
		return ErrInvalidResourceTransition
	}
	return nil
}

func ValidateRotateResourceCommand(command RotateResourceCommand) error {
	if command.ResourceID == "" || len(command.ResourceID) > 128 || strings.TrimSpace(command.ResourceID) != command.ResourceID {
		return ErrInvalidResourceTransition
	}
	if !idempotencyKeyPattern.MatchString(command.IdempotencyKey) {
		return ErrInvalidIdempotencyKey
	}
	return nil
}

func ValidIdempotencyKey(value string) bool {
	return idempotencyKeyPattern.MatchString(value)
}

type Resource struct {
	ID                    string
	ResourceType          ResourceType
	Scope                 Scope
	LogicalName           string
	TargetID              string
	Status                ResourceStatus
	SecretURI             string
	SecretVersion         string
	CredentialGeneration  int64
	RotationStatus        RotationStatus
	CredentialGenerations []int64
	ErrorCode             string
	CreatedAt             time.Time
	UpdatedAt             time.Time
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
	RotationStatus  RotationStatus `json:"rotation_status,omitempty"`
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
		ID:             resource.ID,
		ResourceType:   resource.ResourceType,
		Application:    resource.Scope.Application,
		Environment:    resource.Scope.Environment,
		LogicalName:    resource.LogicalName,
		Status:         resource.Status,
		RotationStatus: resource.RotationStatus,
		ErrorCode:      resource.ErrorCode,
		CreatedAt:      resource.CreatedAt.UTC(),
		UpdatedAt:      resource.UpdatedAt.UTC(),
	}
	if resource.Status == ResourceActive {
		view.SecretReference = resource.SecretURI
		view.SecretVersion = resource.SecretVersion
	}
	return view
}
