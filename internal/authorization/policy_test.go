package authorization

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
)

func TestPolicyAuthorizesExactSubjectActionAndScope(t *testing.T) {
	t.Parallel()

	policy := mustPolicy(t, Grant{
		Subject:      "subject-123",
		Applications: []string{"orders"},
		Environments: []string{"production"},
		Actions:      []Action{ActionPlanResource},
	})
	principal := identity.Principal{Subject: "subject-123", Transport: identity.TransportHTTP}
	if err := policy.Authorize(principal, ActionPlanResource, domain.Scope{Application: "orders", Environment: "production"}); err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	denied := []struct {
		name      string
		principal identity.Principal
		action    Action
		scope     domain.Scope
	}{
		{name: "other subject", principal: identity.Principal{Subject: "other"}, action: ActionPlanResource, scope: domain.Scope{Application: "orders", Environment: "production"}},
		{name: "other application", principal: principal, action: ActionPlanResource, scope: domain.Scope{Application: "payments", Environment: "production"}},
		{name: "other environment", principal: principal, action: ActionPlanResource, scope: domain.Scope{Application: "orders", Environment: "staging"}},
		{name: "other action", principal: principal, action: "provision_resource", scope: domain.Scope{Application: "orders", Environment: "production"}},
	}
	for _, test := range denied {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := policy.Authorize(test.principal, test.action, test.scope); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("Authorize() error = %v, want permission denied", err)
			}
		})
	}
}

func TestNewPolicyRejectsWildcardsAndUnknownActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		grant Grant
	}{
		{
			name: "wildcard subject",
			grant: Grant{
				Subject:      "*",
				Applications: []string{"orders"},
				Environments: []string{"production"},
				Actions:      []Action{ActionPlanResource},
			},
		},
		{
			name: "unknown action",
			grant: Grant{
				Subject:      "subject-123",
				Applications: []string{"orders"},
				Environments: []string{"production"},
				Actions:      []Action{"execute_sql"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPolicy([]Grant{test.grant}); err == nil {
				t.Fatal("NewPolicy() succeeded for invalid grant")
			}
		})
	}
}

func TestLoadPolicyFileRejectsUnknownFieldsAndOversizedInput(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	validPath := filepath.Join(directory, "policy.json")
	valid := `{"grants":[{"subject":"subject-123","applications":["orders"],"environments":["production"],"actions":["plan_resource"]}]}`
	if err := os.WriteFile(validPath, []byte(valid), 0o600); err != nil {
		t.Fatalf("WriteFile(valid) error = %v", err)
	}
	if _, err := LoadPolicyFile(validPath); err != nil {
		t.Fatalf("LoadPolicyFile(valid) error = %v", err)
	}

	unknownPath := filepath.Join(directory, "unknown.json")
	if err := os.WriteFile(unknownPath, []byte(`{"grants":[],"unexpected":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile(unknown) error = %v", err)
	}
	if _, err := LoadPolicyFile(unknownPath); err == nil {
		t.Fatal("LoadPolicyFile() accepted an unknown field")
	}

	largePath := filepath.Join(directory, "large.json")
	if err := os.WriteFile(largePath, make([]byte, (1<<20)+1), 0o600); err != nil {
		t.Fatalf("WriteFile(large) error = %v", err)
	}
	if _, err := LoadPolicyFile(largePath); err == nil {
		t.Fatal("LoadPolicyFile() accepted an oversized policy")
	}
}

func mustPolicy(t *testing.T, grant Grant) *Policy {
	t.Helper()

	policy, err := NewPolicy([]Grant{grant})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}
