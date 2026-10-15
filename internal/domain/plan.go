package domain

import (
	"errors"
	"regexp"
)

type ResourceType string

const (
	ResourcePostgreSQL ResourceType = "postgresql"
	ResourceValkey     ResourceType = "valkey"
	ResourceNATS       ResourceType = "nats"
)

var (
	ErrInvalidResourceType = errors.New("INVALID_RESOURCE_TYPE")
	ErrInvalidScope        = errors.New("INVALID_RESOURCE_SCOPE")
	namePattern            = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,29}[a-z0-9])?$`)
)

type Scope struct {
	Application string
	Environment string
}

type PlanRequest struct {
	ResourceType ResourceType
	Scope        Scope
}

type ResourcePlan struct {
	ResourceType      ResourceType `json:"resource_type"`
	Application       string       `json:"application"`
	Environment       string       `json:"environment"`
	LogicalName       string       `json:"logical_name"`
	IsolationBoundary []string     `json:"isolation_boundary"`
	SecretDelivery    string       `json:"secret_delivery"`
	MutatesState      bool         `json:"mutates_state"`
}

func BuildPlan(request PlanRequest) (ResourcePlan, error) {
	if !request.ResourceType.Valid() {
		return ResourcePlan{}, ErrInvalidResourceType
	}
	if !validScopeName(request.Scope.Application) || !validScopeName(request.Scope.Environment) {
		return ResourcePlan{}, ErrInvalidScope
	}

	logicalName := request.Scope.Application + "__" + request.Scope.Environment
	if len(logicalName) > 63 {
		return ResourcePlan{}, ErrInvalidScope
	}
	plan := ResourcePlan{
		ResourceType:   request.ResourceType,
		Application:    request.Scope.Application,
		Environment:    request.Scope.Environment,
		LogicalName:    logicalName,
		SecretDelivery: "reference_only_when_provisioned",
		MutatesState:   false,
	}

	switch request.ResourceType {
	case ResourcePostgreSQL:
		plan.IsolationBoundary = []string{
			"one_database_per_application_environment",
			"least_privilege_role_per_application_environment",
		}
	case ResourceValkey:
		plan.LogicalName = request.Scope.Application + ":" + request.Scope.Environment
		plan.IsolationBoundary = []string{
			"dedicated_acl_identity_per_application_environment",
			"key_and_channel_prefix_restrictions",
			"command_allowlist",
		}
	case ResourceNATS:
		plan.LogicalName = logicalName
		plan.IsolationBoundary = []string{
			"dedicated_account_per_application_environment",
			"jetstream_limits_scoped_to_account_when_enabled",
		}
	}

	return plan, nil
}

func (resourceType ResourceType) Valid() bool {
	switch resourceType {
	case ResourcePostgreSQL, ResourceValkey, ResourceNATS:
		return true
	default:
		return false
	}
}

func validScopeName(value string) bool {
	return namePattern.MatchString(value)
}

func ValidScopeName(value string) bool {
	return validScopeName(value)
}
