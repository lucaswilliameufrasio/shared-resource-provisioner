package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestValidateCreateResourceCommandRequiresScopedIntentAndIdempotencyKey(t *testing.T) {
	t.Parallel()

	valid := CreateResourceCommand{
		ResourceType:   ResourcePostgreSQL,
		Scope:          Scope{Application: "orders", Environment: "production"},
		IdempotencyKey: "request-1234567890",
	}
	if err := ValidateCreateResourceCommand(valid); err != nil {
		t.Fatalf("ValidateCreateResourceCommand(valid) error = %v", err)
	}

	tests := []struct {
		name    string
		command CreateResourceCommand
		wantErr error
	}{
		{
			name: "missing idempotency key",
			command: CreateResourceCommand{
				ResourceType: ResourcePostgreSQL,
				Scope:        valid.Scope,
			},
			wantErr: ErrInvalidIdempotencyKey,
		},
		{
			name: "unsafe idempotency key",
			command: CreateResourceCommand{
				ResourceType:   ResourcePostgreSQL,
				Scope:          valid.Scope,
				IdempotencyKey: "request key",
			},
			wantErr: ErrInvalidIdempotencyKey,
		},
		{
			name: "invalid scope",
			command: CreateResourceCommand{
				ResourceType:   ResourcePostgreSQL,
				Scope:          Scope{Application: "Orders", Environment: "production"},
				IdempotencyKey: valid.IdempotencyKey,
			},
			wantErr: ErrInvalidScope,
		},
		{
			name: "unknown resource type",
			command: CreateResourceCommand{
				ResourceType:   "sql",
				Scope:          valid.Scope,
				IdempotencyKey: valid.IdempotencyKey,
			},
			wantErr: ErrInvalidResourceType,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateCreateResourceCommand(test.command); !errors.Is(err, test.wantErr) {
				t.Fatalf("ValidateCreateResourceCommand() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestResourceViewOmitsTargetAndSecretMaterial(t *testing.T) {
	t.Parallel()

	view := (Resource{
		ID:            "resource-id",
		ResourceType:  ResourcePostgreSQL,
		Scope:         Scope{Application: "orders", Environment: "production"},
		LogicalName:   "orders__production",
		TargetID:      "private-target",
		Status:        ResourceActive,
		SecretURI:     "ciphera://project/production/POSTGRESQL__DATABASE_URL",
		SecretVersion: "2",
	}).View()
	if view.SecretReference == "" || view.ID != "resource-id" {
		t.Fatalf("resource view = %+v", view)
	}
	if view.Application != "orders" || view.Environment != "production" {
		t.Fatalf("resource scope = %+v", view)
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("Marshal(resource view) error = %v", err)
	}
	if strings.Contains(string(encoded), "private-target") || strings.Contains(string(encoded), "secret_value") {
		t.Fatalf("resource response contains internal target or secret material: %s", encoded)
	}
}
