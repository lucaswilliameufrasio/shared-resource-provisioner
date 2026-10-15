package domain

import (
	"errors"
	"testing"
)

func TestBuildPlanForEachResourceType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		resource    ResourceType
		logicalName string
	}{
		{name: "postgresql", resource: ResourcePostgreSQL, logicalName: "orders-api__production"},
		{name: "valkey", resource: ResourceValkey, logicalName: "orders-api:production"},
		{name: "nats", resource: ResourceNATS, logicalName: "orders-api__production"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan, err := BuildPlan(PlanRequest{
				ResourceType: test.resource,
				Scope:        Scope{Application: "orders-api", Environment: "production"},
			})
			if err != nil {
				t.Fatalf("BuildPlan() error = %v", err)
			}
			if plan.LogicalName != test.logicalName {
				t.Fatalf("LogicalName = %q, want %q", plan.LogicalName, test.logicalName)
			}
			if plan.MutatesState {
				t.Fatal("planning unexpectedly reported a mutation")
			}
			if plan.SecretDelivery != "reference_only_when_provisioned" {
				t.Fatalf("SecretDelivery = %q", plan.SecretDelivery)
			}
			if len(plan.IsolationBoundary) == 0 {
				t.Fatal("plan has no isolation boundary")
			}
		})
	}
}

func TestBuildPlanRejectsInvalidTypeAndScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request PlanRequest
		wantErr error
	}{
		{
			name: "unsupported type",
			request: PlanRequest{
				ResourceType: "mysql",
				Scope:        Scope{Application: "orders", Environment: "production"},
			},
			wantErr: ErrInvalidResourceType,
		},
		{
			name: "uppercase scope",
			request: PlanRequest{
				ResourceType: ResourcePostgreSQL,
				Scope:        Scope{Application: "Orders", Environment: "production"},
			},
			wantErr: ErrInvalidScope,
		},
		{
			name: "trailing separator",
			request: PlanRequest{
				ResourceType: ResourcePostgreSQL,
				Scope:        Scope{Application: "orders-", Environment: "production"},
			},
			wantErr: ErrInvalidScope,
		},
		{
			name: "postgres identifier too long",
			request: PlanRequest{
				ResourceType: ResourcePostgreSQL,
				Scope: Scope{
					Application: "abcdefghijklmnopqrstuvwxyzabcde",
					Environment: "abcdefghijklmnopqrstuvwxyzabcde",
				},
			},
			wantErr: ErrInvalidScope,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := BuildPlan(test.request)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("BuildPlan() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestLogicalNamesDoNotCollideAcrossScopes(t *testing.T) {
	t.Parallel()

	first, err := BuildPlan(PlanRequest{
		ResourceType: ResourcePostgreSQL,
		Scope:        Scope{Application: "foo-bar", Environment: "baz"},
	})
	if err != nil {
		t.Fatalf("first BuildPlan() error = %v", err)
	}
	second, err := BuildPlan(PlanRequest{
		ResourceType: ResourcePostgreSQL,
		Scope:        Scope{Application: "foo", Environment: "bar-baz"},
	})
	if err != nil {
		t.Fatalf("second BuildPlan() error = %v", err)
	}
	if first.LogicalName == second.LogicalName {
		t.Fatalf("scope names collided: %q", first.LogicalName)
	}
}
