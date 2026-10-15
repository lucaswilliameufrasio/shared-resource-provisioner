package secrets

import (
	"errors"
	"testing"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

func TestReferenceContainsOnlyStableCipheraLocation(t *testing.T) {
	t.Parallel()

	reference, err := NewReference("project-123", domain.Scope{Application: "orders", Environment: "production"}, "DATABASE_URL")
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	if err := ValidateReference(reference); err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}
	if reference.URI != "ciphera://project/project-123/environments/production/secrets/DATABASE_URL" {
		t.Fatalf("reference URI = %q", reference.URI)
	}
}

func TestReferenceRejectsInvalidScopeProjectAndName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		project string
		scope   domain.Scope
		name    string
	}{
		{project: "project-123", scope: domain.Scope{Environment: "Production"}, name: "DATABASE_URL"},
		{project: "project/123", scope: domain.Scope{Environment: "production"}, name: "DATABASE_URL"},
		{project: "project-123", scope: domain.Scope{Environment: "production"}, name: "*"},
	}
	for _, test := range tests {
		if _, err := NewReference(test.project, test.scope, test.name); !errors.Is(err, ErrInvalidReference) {
			t.Fatalf("NewReference() error = %v, want ErrInvalidReference", err)
		}
	}
}
