package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
)

type Action string

const (
	ActionPlanResource    Action = "plan_resource"
	ActionCreateResource  Action = "create_resource"
	ActionInspectResource Action = "inspect_resource"
	ActionRevokeResource  Action = "revoke_resource"
	ActionRotateResource  Action = "rotate_resource"
	ActionAdoptRotation   Action = "adopt_rotation"
)

var ErrPermissionDenied = errors.New("PERMISSION_DENIED")

var (
	ErrAuthorizationUnavailable = errors.New("AUTHORIZATION_UNAVAILABLE")
	ErrGrantExists              = errors.New("GRANT_ALREADY_EXISTS")
	ErrGrantNotFound            = errors.New("GRANT_NOT_FOUND")
	ErrInvalidGrantCursor       = errors.New("INVALID_GRANT_CURSOR")
	ErrInvalidGrant             = errors.New("INVALID_GRANT")
)

type Grant struct {
	Subject      string   `json:"subject"`
	Applications []string `json:"applications"`
	Environments []string `json:"environments"`
	Actions      []Action `json:"actions"`
}

type Policy struct {
	grants []Grant
}

type Authorizer interface {
	AuthorizeContext(context.Context, identity.Principal, Action, domain.Scope) error
}

type GrantRecord struct {
	ID          string    `json:"id"`
	Subject     string    `json:"subject"`
	Application string    `json:"application"`
	Environment string    `json:"environment"`
	Action      Action    `json:"action"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

type GrantPage struct {
	Items      []GrantRecord
	NextCursor string
	HasMore    bool
}

type GrantReader interface {
	HasGrant(context.Context, string, Action, domain.Scope) (bool, error)
}

type GrantManager interface {
	GrantReader
	ListGrants(context.Context, string, int) (GrantPage, error)
	CreateGrant(context.Context, GrantRecord, audit.Event) (GrantRecord, error)
	DeleteGrant(context.Context, string, audit.Event) (GrantRecord, error)
}

type PersistentAuthorizer struct {
	grants GrantReader
}

type policyDocument struct {
	Grants []Grant `json:"grants"`
}

func NewPolicy(grants []Grant) (*Policy, error) {
	if len(grants) == 0 {
		return nil, errors.New("authorization policy must contain at least one grant")
	}

	validated := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		if !identity.ValidSubject(grant.Subject) || len(grant.Applications) == 0 || len(grant.Environments) == 0 || len(grant.Actions) == 0 {
			return nil, errors.New("authorization grants require subject, applications, environments, and actions")
		}
		if grant.Subject == "*" || containsWildcardValues(grant.Applications) || containsWildcardValues(grant.Environments) {
			return nil, errors.New("wildcard authorization grants are not supported")
		}
		if !validScopeList(grant.Applications) || !validScopeList(grant.Environments) {
			return nil, errors.New("authorization grants contain an invalid scope")
		}
		for _, action := range grant.Actions {
			if !ValidAction(action) {
				return nil, errors.New("authorization policy contains an unsupported action")
			}
		}
		validated = append(validated, cloneGrant(grant))
	}

	return &Policy{grants: validated}, nil
}

func (policy *Policy) Grants() []Grant {
	if policy == nil {
		return nil
	}
	grants := make([]Grant, 0, len(policy.grants))
	for _, grant := range policy.grants {
		grants = append(grants, cloneGrant(grant))
	}
	return grants
}

func ValidateGrantRecord(grant GrantRecord) error {
	if !identity.ValidSubject(grant.Subject) || grant.Subject == "*" || !domain.ValidScopeName(grant.Application) || !domain.ValidScopeName(grant.Environment) || !ValidAction(grant.Action) {
		return ErrInvalidGrant
	}
	return nil
}

func ValidAction(action Action) bool {
	switch action {
	case ActionPlanResource, ActionCreateResource, ActionInspectResource, ActionRevokeResource, ActionRotateResource, ActionAdoptRotation:
		return true
	default:
		return false
	}
}

func LoadPolicyFile(path string) (*Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("unable to open authorization policy")
	}
	defer func() {
		_ = file.Close()
	}()
	info, err := file.Stat()
	if err != nil || info.Size() > 1<<20 {
		return nil, errors.New("authorization policy file is invalid")
	}

	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var document policyDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("invalid authorization policy document")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid authorization policy document")
	}
	return NewPolicy(document.Grants)
}

func (policy *Policy) Authorize(principal identity.Principal, action Action, scope domain.Scope) error {
	for _, grant := range policy.grants {
		if grant.Subject != principal.Subject {
			continue
		}
		if !contains(grant.Applications, scope.Application) || !contains(grant.Environments, scope.Environment) {
			continue
		}
		if containsAction(grant.Actions, action) {
			return nil
		}
	}
	return ErrPermissionDenied
}

func (policy *Policy) AuthorizeContext(_ context.Context, principal identity.Principal, action Action, scope domain.Scope) error {
	return policy.Authorize(principal, action, scope)
}

func NewPersistentAuthorizer(grants GrantReader) (*PersistentAuthorizer, error) {
	if grants == nil {
		return nil, errors.New("persistent grant reader is required")
	}
	return &PersistentAuthorizer{grants: grants}, nil
}

func (authorizer *PersistentAuthorizer) AuthorizeContext(ctx context.Context, principal identity.Principal, action Action, scope domain.Scope) error {
	allowed, err := authorizer.grants.HasGrant(ctx, principal.Subject, action, scope)
	if err != nil {
		return ErrAuthorizationUnavailable
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

func cloneGrant(grant Grant) Grant {
	return Grant{
		Subject:      grant.Subject,
		Applications: append([]string(nil), grant.Applications...),
		Environments: append([]string(nil), grant.Environments...),
		Actions:      append([]Action(nil), grant.Actions...),
	}
}

func containsWildcardValues(values []string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}

func validScopeList(values []string) bool {
	for _, value := range values {
		if !domain.ValidScopeName(value) {
			return false
		}
	}
	return true
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsAction(values []Action, target Action) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
