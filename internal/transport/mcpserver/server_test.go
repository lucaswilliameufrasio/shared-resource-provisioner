package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/planning"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/provisioning"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type testAuditor struct{}

func (testAuditor) Record(context.Context, audit.Event) error {
	return nil
}

func TestPlanResourceMCPToolReturnsOnlySafePlan(t *testing.T) {
	t.Parallel()

	policy, err := authorization.NewPolicy([]authorization.Grant{{
		Subject:      "subject-123",
		Applications: []string{"orders"},
		Environments: []string{"production"},
		Actions:      []authorization.Action{authorization.ActionPlanResource},
	}})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	planner, err := planning.NewService(policy, testAuditor{})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	server, err := New(planner, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverContext, cancelServer := context.WithCancel(identity.WithPrincipal(context.Background(), identity.Principal{
		Subject:   "subject-123",
		Transport: identity.TransportStdio,
	}))
	defer cancelServer()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Run(serverContext, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	clientContext, cancelClient := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClient()
	session, err := client.Connect(clientContext, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
	})

	tools, err := session.ListTools(clientContext, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "plan_resource" {
		t.Fatalf("tools = %+v, want only plan_resource", tools.Tools)
	}
	result, err := session.CallTool(clientContext, &mcp.CallToolParams{
		Name: "plan_resource",
		Arguments: map[string]any{
			"resource_type": "postgresql",
			"application":   "orders",
			"environment":   "production",
		},
	})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("CallTool() returned error content: %+v", result.Content)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("Marshal(StructuredContent) error = %v", err)
	}
	var plan domain.ResourcePlan
	if err := json.Unmarshal(encoded, &plan); err != nil {
		t.Fatalf("Unmarshal(StructuredContent) error = %v", err)
	}
	if plan.LogicalName != "orders__production" || plan.MutatesState {
		t.Fatalf("plan = %+v", plan)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "password") || strings.Contains(strings.ToLower(string(encoded)), "secret_value") {
		t.Fatalf("plan unexpectedly contains credential-like fields: %s", encoded)
	}

	_ = session.Close()
	cancelServer()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("MCP server did not stop after cancellation")
	}
}

func TestLifecycleToolsAreTypedAndReturnOnlySecretReferences(t *testing.T) {
	t.Parallel()

	policy, err := authorization.NewPolicy([]authorization.Grant{{
		Subject:      "subject-123",
		Applications: []string{"orders"},
		Environments: []string{"production"},
		Actions:      []authorization.Action{authorization.ActionPlanResource},
	}})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	planner, err := planning.NewService(policy, testAuditor{})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	lifecycle := &testLifecycle{resource: domain.ResourceView{
		ID:              "resource-123",
		ResourceType:    domain.ResourcePostgreSQL,
		Application:     "orders",
		Environment:     "production",
		Status:          domain.ResourceActive,
		SecretReference: "ciphera://project/test-project/environments/production/secrets/DATABASE_URL",
	}}
	server, err := New(planner, logger, lifecycle)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverContext, cancelServer := context.WithCancel(identity.WithPrincipal(context.Background(), identity.Principal{
		Subject:   "subject-123",
		Transport: identity.TransportStdio,
	}))
	defer cancelServer()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Run(serverContext, serverTransport)
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	clientContext, cancelClient := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClient()
	session, err := client.Connect(clientContext, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
	})
	tools, err := session.ListTools(clientContext, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools.Tools) != 5 {
		t.Fatalf("lifecycle-enabled tools = %+v, want plan and four typed lifecycle tools", tools.Tools)
	}
	toolNames := make(map[string]struct{}, len(tools.Tools))
	for _, tool := range tools.Tools {
		toolNames[tool.Name] = struct{}{}
	}
	for _, name := range []string{"plan_resource", "create_resource", "inspect_resource", "revoke_resource", "rotate_resource"} {
		if _, exists := toolNames[name]; !exists {
			t.Fatalf("tool %q is not registered", name)
		}
	}
	createTool, err := session.CallTool(clientContext, &mcp.CallToolParams{
		Name: "create_resource",
		Arguments: map[string]any{
			"resource_type":   "postgresql",
			"application":     "orders",
			"environment":     "production",
			"idempotency_key": "request-123",
		},
	})
	if err != nil {
		t.Fatalf("CallTool(create_resource) error = %v", err)
	}
	if createTool.IsError {
		t.Fatalf("create_resource returned error: %+v", createTool.Content)
	}
	encoded, err := json.Marshal(createTool.StructuredContent)
	if err != nil {
		t.Fatalf("Marshal(create result) error = %v", err)
	}
	if !strings.Contains(string(encoded), lifecycle.resource.SecretReference) || strings.Contains(string(encoded), "credential_value") || strings.Contains(string(encoded), "password") {
		t.Fatalf("create_resource output is unsafe: %s", encoded)
	}
	if lifecycle.createRequest.ResourceType != domain.ResourcePostgreSQL || lifecycle.createRequest.IdempotencyKey != "request-123" {
		t.Fatalf("create_resource received untyped arguments: %+v", lifecycle.createRequest)
	}
	inspectTool, err := session.CallTool(clientContext, &mcp.CallToolParams{
		Name:      "inspect_resource",
		Arguments: map[string]any{"resource_id": "resource-123"},
	})
	if err != nil || inspectTool.IsError || lifecycle.inspectResourceID != "resource-123" {
		t.Fatalf("inspect_resource result = %+v, err=%v, id=%q", inspectTool, err, lifecycle.inspectResourceID)
	}
	revokeTool, err := session.CallTool(clientContext, &mcp.CallToolParams{
		Name: "revoke_resource",
		Arguments: map[string]any{
			"resource_id":     "resource-123",
			"confirmation":    "revoke:resource-123",
			"idempotency_key": "revoke-123",
		},
	})
	if err != nil || revokeTool.IsError || lifecycle.revokeCommand.Confirmation != "revoke:resource-123" || lifecycle.revokeIdempotencyKey != "revoke-123" {
		t.Fatalf("revoke_resource result = %+v, err=%v, command=%+v, key=%q", revokeTool, err, lifecycle.revokeCommand, lifecycle.revokeIdempotencyKey)
	}
	rotateTool, err := session.CallTool(clientContext, &mcp.CallToolParams{
		Name: "rotate_resource",
		Arguments: map[string]any{
			"resource_id":     "resource-123",
			"idempotency_key": "rotate-123",
		},
	})
	if err != nil || rotateTool.IsError || lifecycle.rotateCommand.ResourceID != "resource-123" || lifecycle.rotateCommand.IdempotencyKey != "rotate-123" {
		t.Fatalf("rotate_resource result = %+v, err=%v, command=%+v", rotateTool, err, lifecycle.rotateCommand)
	}
	rotationJSON, err := json.Marshal(rotateTool.StructuredContent)
	if err != nil || strings.Contains(string(rotationJSON), "secret_reference") || strings.Contains(string(rotationJSON), "ciphera://") {
		t.Fatalf("rotate_resource returned a runtime-only secret reference: %s, %v", rotationJSON, err)
	}

	_ = session.Close()
	cancelServer()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("MCP server did not stop after cancellation")
	}
}

func TestLifecycleWithoutOIDCRuntimeDoesNotExposeRotationTool(t *testing.T) {
	t.Parallel()

	policy, err := authorization.NewPolicy([]authorization.Grant{{
		Subject:      "subject-123",
		Applications: []string{"orders"},
		Environments: []string{"production"},
		Actions:      []authorization.Action{authorization.ActionPlanResource},
	}})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	planner, err := planning.NewService(policy, testAuditor{})
	if err != nil {
		t.Fatalf("planning.NewService() error = %v", err)
	}
	server, err := New(planner, slog.New(slog.NewTextHandler(discardWriter{}, nil)), nonRotatingLifecycle{Lifecycle: &testLifecycle{}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverContext, cancelServer := context.WithCancel(identity.WithPrincipal(context.Background(), identity.Principal{
		Subject:   "subject-123",
		Transport: identity.TransportStdio,
	}))
	defer cancelServer()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Run(serverContext, serverTransport)
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	clientContext, cancelClient := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClient()
	session, err := client.Connect(clientContext, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	tools, err := session.ListTools(clientContext, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	for _, tool := range tools.Tools {
		if tool.Name == "rotate_resource" {
			t.Fatal("rotate_resource was exposed without the OIDC runtime acknowledgement service")
		}
	}
	_ = session.Close()
	cancelServer()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("MCP server did not stop after cancellation")
	}
}

func TestLifecycleToolErrorsDoNotExposeInternalDetails(t *testing.T) {
	t.Parallel()

	got := safeToolError(errors.New("generated credential value must never be shown"))
	if got.Error() != "UNEXPECTED_ERROR" || strings.Contains(got.Error(), "credential") {
		t.Fatalf("safeToolError() exposed a secret-like detail: %q", got)
	}
	if got := safeToolError(domain.ErrTargetCapacityReached); got.Error() != "TARGET_CAPACITY_REACHED" {
		t.Fatalf("safeToolError(target capacity) = %q", got)
	}
	if got := safeToolError(provisioning.ErrReconciliationRequired); got.Error() != "RECONCILIATION_REQUIRED" {
		t.Fatalf("safeToolError(reconciliation) = %q", got)
	}
}

func TestSafeToolErrorHidesInternalDetails(t *testing.T) {
	t.Parallel()

	got := safeToolError(errors.New("sensitive upstream failure detail"))
	if got.Error() != "UNEXPECTED_ERROR" {
		t.Fatalf("safeToolError() = %q", got)
	}
	if got := safeToolError(authorization.ErrAuthorizationUnavailable); got.Error() != "AUTHORIZATION_UNAVAILABLE" {
		t.Fatalf("safeToolError(authorization unavailable) = %q", got)
	}
}

type discardWriter struct{}

type testLifecycle struct {
	resource             domain.ResourceView
	createRequest        domain.CreateResourceCommand
	inspectResourceID    string
	revokeCommand        domain.RevokeResourceCommand
	revokeIdempotencyKey string
	rotateCommand        domain.RotateResourceCommand
}

type nonRotatingLifecycle struct {
	Lifecycle
}

func (lifecycle *testLifecycle) Create(_ context.Context, request domain.CreateResourceCommand) (domain.ResourceView, error) {
	lifecycle.createRequest = request
	return lifecycle.resource, nil
}

func (lifecycle *testLifecycle) Inspect(_ context.Context, resourceID string) (domain.ResourceView, error) {
	lifecycle.inspectResourceID = resourceID
	return lifecycle.resource, nil
}

func (lifecycle *testLifecycle) Revoke(_ context.Context, command domain.RevokeResourceCommand, idempotencyKey string) (domain.ResourceView, error) {
	lifecycle.revokeCommand = command
	lifecycle.revokeIdempotencyKey = idempotencyKey
	return lifecycle.resource, nil
}

func (lifecycle *testLifecycle) Rotate(_ context.Context, command domain.RotateResourceCommand) (domain.RotationReceipt, error) {
	lifecycle.rotateCommand = command
	return domain.RotationReceipt{ResourceID: command.ResourceID, OperationID: "operation-123", Generation: 2, Status: domain.RotationPending}, nil
}

func (discardWriter) Write(data []byte) (int, error) {
	return len(data), nil
}
