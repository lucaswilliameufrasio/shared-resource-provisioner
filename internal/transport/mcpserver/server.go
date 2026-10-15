package mcpserver

import (
	"context"
	"errors"
	"log/slog"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/planning"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/provisioning"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Planner interface {
	Plan(ctx context.Context, request domain.PlanRequest) (domain.ResourcePlan, error)
}

type Lifecycle interface {
	Create(ctx context.Context, request domain.CreateResourceCommand) (domain.ResourceView, error)
	Inspect(ctx context.Context, resourceID string) (domain.ResourceView, error)
	Revoke(ctx context.Context, command domain.RevokeResourceCommand, idempotencyKey string) (domain.ResourceView, error)
}

type PlanResourceInput struct {
	ResourceType string `json:"resource_type" jsonschema:"Resource kind: postgresql, valkey, or nats"`
	Application  string `json:"application" jsonschema:"Authorized application scope in lowercase letters, digits, and hyphens"`
	Environment  string `json:"environment" jsonschema:"Authorized environment scope in lowercase letters, digits, and hyphens"`
}

type CreateResourceInput struct {
	ResourceType   string `json:"resource_type" jsonschema:"Resource kind: postgresql, valkey, or nats"`
	Application    string `json:"application" jsonschema:"Authorized application scope in lowercase letters, digits, and hyphens"`
	Environment    string `json:"environment" jsonschema:"Authorized environment scope in lowercase letters, digits, and hyphens"`
	IdempotencyKey string `json:"idempotency_key" jsonschema:"Stable request key for safe retries"`
}

type InspectResourceInput struct {
	ResourceID string `json:"resource_id" jsonschema:"Stable resource ID returned by create_resource"`
}

type RevokeResourceInput struct {
	ResourceID     string `json:"resource_id" jsonschema:"Stable resource ID returned by create_resource"`
	Confirmation   string `json:"confirmation" jsonschema:"Must exactly equal revoke:<resource_id>"`
	IdempotencyKey string `json:"idempotency_key" jsonschema:"Stable request key for safe retries"`
}

func New(planner Planner, logger *slog.Logger, lifecycle ...Lifecycle) (*mcp.Server, error) {
	if planner == nil {
		return nil, errors.New("resource planner is required")
	}
	if logger == nil {
		return nil, errors.New("MCP logger is required")
	}
	if len(lifecycle) > 1 {
		return nil, errors.New("at most one lifecycle service is allowed")
	}
	var resourceLifecycle Lifecycle
	if len(lifecycle) == 1 {
		resourceLifecycle = lifecycle[0]
	}
	instructions := "Plan isolated shared PostgreSQL, Valkey, and NATS resources. Planning does not mutate infrastructure. Credential values are never available through MCP."
	if resourceLifecycle != nil {
		instructions = "Plan and manage isolated shared PostgreSQL, Valkey, and NATS resources within authorized scopes. Create and revoke are explicit lifecycle actions. Credential values are never available through MCP; responses contain secret references only."
	}

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "shared-resource-provisioner",
			Version: "0.1.0",
		},
		&mcp.ServerOptions{
			Instructions: instructions,
			Logger:       logger,
		},
	)
	mcp.AddTool(
		server,
		&mcp.Tool{
			Name:        "plan_resource",
			Description: "Create a non-mutating isolation plan for one application and environment.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPointer(false)},
		},
		func(ctx context.Context, _ *mcp.CallToolRequest, input PlanResourceInput) (*mcp.CallToolResult, domain.ResourcePlan, error) {
			plan, err := planner.Plan(ctx, domain.PlanRequest{
				ResourceType: domain.ResourceType(input.ResourceType),
				Scope: domain.Scope{
					Application: input.Application,
					Environment: input.Environment,
				},
			})
			if err == nil {
				return nil, plan, nil
			}
			return nil, domain.ResourcePlan{}, safeToolError(err)
		},
	)
	if resourceLifecycle != nil {
		mcp.AddTool(
			server,
			&mcp.Tool{
				Name:        "create_resource",
				Description: "Provision one authorized PostgreSQL, Valkey, or NATS resource. Returns metadata and a secret reference, never credential values.",
				Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: boolPointer(false), OpenWorldHint: boolPointer(true)},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input CreateResourceInput) (*mcp.CallToolResult, domain.ResourceView, error) {
				resource, err := resourceLifecycle.Create(ctx, domain.CreateResourceCommand{
					ResourceType:   domain.ResourceType(input.ResourceType),
					Scope:          domain.Scope{Application: input.Application, Environment: input.Environment},
					IdempotencyKey: input.IdempotencyKey,
				})
				if err != nil {
					return nil, domain.ResourceView{}, safeToolError(err)
				}
				return nil, resource, nil
			},
		)
		mcp.AddTool(
			server,
			&mcp.Tool{
				Name:        "inspect_resource",
				Description: "Inspect an authorized resource's lifecycle metadata and safe secret reference.",
				Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPointer(true)},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input InspectResourceInput) (*mcp.CallToolResult, domain.ResourceView, error) {
				resource, err := resourceLifecycle.Inspect(ctx, input.ResourceID)
				if err != nil {
					return nil, domain.ResourceView{}, safeToolError(err)
				}
				return nil, resource, nil
			},
		)
		mcp.AddTool(
			server,
			&mcp.Tool{
				Name:        "revoke_resource",
				Description: "Revoke an authorized resource after explicit confirmation. This action is destructive and idempotent.",
				Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: boolPointer(true), OpenWorldHint: boolPointer(true)},
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, input RevokeResourceInput) (*mcp.CallToolResult, domain.ResourceView, error) {
				resource, err := resourceLifecycle.Revoke(ctx, domain.RevokeResourceCommand{
					ResourceID:   input.ResourceID,
					Confirmation: input.Confirmation,
				}, input.IdempotencyKey)
				if err != nil {
					return nil, domain.ResourceView{}, safeToolError(err)
				}
				return nil, resource, nil
			},
		)
	}
	return server, nil
}

func safeToolError(err error) error {
	switch {
	case errors.Is(err, domain.ErrInvalidResourceType):
		return errors.New("INVALID_RESOURCE_TYPE")
	case errors.Is(err, domain.ErrInvalidScope):
		return errors.New("INVALID_RESOURCE_SCOPE")
	case errors.Is(err, planning.ErrUnauthenticated):
		return errors.New("UNAUTHENTICATED")
	case errors.Is(err, authorization.ErrPermissionDenied):
		return errors.New("PERMISSION_DENIED")
	case errors.Is(err, authorization.ErrAuthorizationUnavailable):
		return errors.New("AUTHORIZATION_UNAVAILABLE")
	case errors.Is(err, planning.ErrAuditUnavailable):
		return errors.New("AUDIT_UNAVAILABLE")
	case errors.Is(err, provisioning.ErrAuditUnavailable):
		return errors.New("AUDIT_UNAVAILABLE")
	case errors.Is(err, provisioning.ErrPersistenceUnavailable):
		return errors.New("PERSISTENCE_UNAVAILABLE")
	case errors.Is(err, provisioning.ErrProvisioningFailed):
		return errors.New("PROVISIONING_FAILED")
	case errors.Is(err, provisioning.ErrReconciliationRequired):
		return errors.New("RECONCILIATION_REQUIRED")
	case errors.Is(err, provisioning.ErrRevocationFailed):
		return errors.New("REVOCATION_REQUIRES_RECONCILIATION")
	case errors.Is(err, provisioning.ErrTargetUnavailable):
		return errors.New("TARGET_UNAVAILABLE")
	case errors.Is(err, domain.ErrInvalidIdempotencyKey):
		return errors.New("INVALID_IDEMPOTENCY_KEY")
	case errors.Is(err, domain.ErrInvalidResourceTransition):
		return errors.New("INVALID_RESOURCE_TRANSITION")
	case errors.Is(err, domain.ErrIdempotencyConflict):
		return errors.New("IDEMPOTENCY_CONFLICT")
	case errors.Is(err, domain.ErrResourceNotFound):
		return errors.New("RESOURCE_NOT_FOUND")
	case errors.Is(err, domain.ErrResourceNotActive):
		return errors.New("RESOURCE_NOT_ACTIVE")
	case errors.Is(err, domain.ErrResourceAlreadyExists):
		return errors.New("RESOURCE_ALREADY_EXISTS")
	case errors.Is(err, domain.ErrResourceAlreadyRevoked):
		return errors.New("RESOURCE_ALREADY_REVOKED")
	case errors.Is(err, domain.ErrOperationInProgress):
		return errors.New("OPERATION_IN_PROGRESS")
	case errors.Is(err, domain.ErrOperationCapacityReached):
		return errors.New("TARGET_OPERATION_CAPACITY_REACHED")
	case errors.Is(err, domain.ErrTargetCapacityReached):
		return errors.New("TARGET_CAPACITY_REACHED")
	default:
		return errors.New("UNEXPECTED_ERROR")
	}
}

func boolPointer(value bool) *bool {
	return &value
}
