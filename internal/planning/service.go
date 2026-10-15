package planning

import (
	"context"
	"errors"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
)

var (
	ErrUnauthenticated  = errors.New("UNAUTHENTICATED")
	ErrAuditUnavailable = errors.New("AUDIT_UNAVAILABLE")
)

type Service struct {
	authorizer authorization.Authorizer
	auditor    audit.Recorder
	now        func() time.Time
}

func NewService(authorizer authorization.Authorizer, auditor audit.Recorder) (*Service, error) {
	if authorizer == nil {
		return nil, errors.New("authorization service is required")
	}
	if auditor == nil {
		return nil, errors.New("audit recorder is required")
	}
	return &Service{authorizer: authorizer, auditor: auditor, now: time.Now}, nil
}

func (service *Service) Plan(ctx context.Context, request domain.PlanRequest) (domain.ResourcePlan, error) {
	plan, err := domain.BuildPlan(request)
	if err != nil {
		return domain.ResourcePlan{}, err
	}

	principal, ok := identity.FromContext(ctx)
	if !ok {
		return domain.ResourcePlan{}, ErrUnauthenticated
	}

	action := authorization.ActionPlanResource
	if err := service.authorizer.AuthorizeContext(ctx, principal, action, request.Scope); err != nil {
		event := service.auditEvent(principal, action, request, audit.OutcomeDenied, "PERMISSION_DENIED")
		if errors.Is(err, authorization.ErrAuthorizationUnavailable) {
			event.ErrorCode = "AUTHORIZATION_UNAVAILABLE"
		}
		if recordErr := service.auditor.Record(ctx, event); recordErr != nil {
			return domain.ResourcePlan{}, ErrAuditUnavailable
		}
		if errors.Is(err, authorization.ErrPermissionDenied) {
			return domain.ResourcePlan{}, authorization.ErrPermissionDenied
		}
		return domain.ResourcePlan{}, authorization.ErrAuthorizationUnavailable
	}

	event := service.auditEvent(principal, action, request, audit.OutcomeAllowed, "")
	if err := service.auditor.Record(ctx, event); err != nil {
		return domain.ResourcePlan{}, ErrAuditUnavailable
	}
	return plan, nil
}

func (service *Service) auditEvent(
	principal identity.Principal,
	action authorization.Action,
	request domain.PlanRequest,
	outcome audit.Outcome,
	errorCode string,
) audit.Event {
	return audit.Event{
		At:          service.now().UTC(),
		Subject:     principal.Subject,
		Transport:   principal.Transport,
		Action:      string(action),
		Application: request.Scope.Application,
		Environment: request.Scope.Environment,
		Resource:    request.ResourceType,
		Outcome:     outcome,
		ErrorCode:   errorCode,
	}
}
