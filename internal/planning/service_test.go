package planning

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
)

type recordingAuditor struct {
	events []audit.Event
	err    error
}

func (recorder *recordingAuditor) Record(_ context.Context, event audit.Event) error {
	if recorder.err != nil {
		return recorder.err
	}
	recorder.events = append(recorder.events, event)
	return nil
}

func TestPlanAuthorizesAuditsAndDoesNotMutate(t *testing.T) {
	t.Parallel()

	auditor := &recordingAuditor{}
	service := mustService(t, auditor)
	service.now = func() time.Time {
		return time.Date(2026, time.October, 13, 12, 0, 0, 0, time.UTC)
	}
	ctx := identity.WithPrincipal(context.Background(), identity.Principal{
		Subject:   "subject-123",
		Transport: identity.TransportStdio,
	})
	plan, err := service.Plan(ctx, domain.PlanRequest{
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        domain.Scope{Application: "orders", Environment: "production"},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if plan.MutatesState {
		t.Fatal("Plan() unexpectedly reports state mutation")
	}
	if len(auditor.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(auditor.events))
	}
	if auditor.events[0].Outcome != audit.OutcomeAllowed || auditor.events[0].ErrorCode != "" {
		t.Fatalf("audit event = %+v, want allowed", auditor.events[0])
	}
	if !auditor.events[0].At.Equal(service.now()) {
		t.Fatalf("audit timestamp = %s, want %s", auditor.events[0].At, service.now())
	}
}

func TestPlanDeniesOutOfScopeAndAuditsDenial(t *testing.T) {
	t.Parallel()

	auditor := &recordingAuditor{}
	service := mustService(t, auditor)
	ctx := identity.WithPrincipal(context.Background(), identity.Principal{
		Subject:   "subject-123",
		Transport: identity.TransportHTTP,
	})
	_, err := service.Plan(ctx, domain.PlanRequest{
		ResourceType: domain.ResourceValkey,
		Scope:        domain.Scope{Application: "payments", Environment: "production"},
	})
	if !errors.Is(err, authorization.ErrPermissionDenied) {
		t.Fatalf("Plan() error = %v, want permission denied", err)
	}
	if len(auditor.events) != 1 || auditor.events[0].Outcome != audit.OutcomeDenied {
		t.Fatalf("audit events = %+v, want one denied event", auditor.events)
	}
	if auditor.events[0].ErrorCode != "PERMISSION_DENIED" {
		t.Fatalf("audit error code = %q", auditor.events[0].ErrorCode)
	}
}

func TestPlanFailsClosedWhenAuditIsUnavailable(t *testing.T) {
	t.Parallel()

	service := mustService(t, &recordingAuditor{err: errors.New("internal audit failure")})
	ctx := identity.WithPrincipal(context.Background(), identity.Principal{
		Subject:   "subject-123",
		Transport: identity.TransportHTTP,
	})
	_, err := service.Plan(ctx, domain.PlanRequest{
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        domain.Scope{Application: "orders", Environment: "production"},
	})
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Plan() error = %v, want audit unavailable", err)
	}
	if err.Error() == "internal audit failure" {
		t.Fatal("internal audit error leaked through the service")
	}
}

func TestPlanRequiresPrincipal(t *testing.T) {
	t.Parallel()

	service := mustService(t, &recordingAuditor{})
	_, err := service.Plan(context.Background(), domain.PlanRequest{
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        domain.Scope{Application: "orders", Environment: "production"},
	})
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Plan() error = %v, want unauthenticated", err)
	}
}

func mustService(t *testing.T, auditor audit.Recorder) *Service {
	t.Helper()

	policy, err := authorization.NewPolicy([]authorization.Grant{{
		Subject:      "subject-123",
		Applications: []string{"orders"},
		Environments: []string{"production"},
		Actions:      []authorization.Action{authorization.ActionPlanResource},
	}})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	service, err := NewService(policy, auditor)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}
