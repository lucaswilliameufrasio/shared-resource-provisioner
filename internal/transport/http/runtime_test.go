package httptransport

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/persistence/sqlite"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRuntimeRotationEndpointsRequireOIDCAndUseExactAcknowledgement(t *testing.T) {
	t.Parallel()

	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, &mcp.ServerOptions{})
	store, err := sqlite.Open(t.TempDir() + "/database/control.db")
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Store.Close() error = %v", err)
		}
	})
	if err := store.SeedPolicyOnce(context.Background(), nil); err != nil {
		t.Fatalf("SeedPolicyOnce() error = %v", err)
	}
	lifecycle := &runtimeRotationTestLifecycle{pending: domain.PendingRotation{
		ResourceID:      "resource-123",
		OperationID:     "operation-123",
		CredentialName:  "DATABASE_URL",
		SecretReference: "ciphera://project/project-123/environments/production/secrets/ROT_PG_0000000000002",
		SecretVersion:   "generation-2",
		Generation:      2,
		Status:          domain.RotationPending,
	}}
	issuer := newLocalOIDCIssuer(t)
	const audience = "shared-resource-provisioner-local-test"
	verifier, err := NewOIDCTokenVerifier(context.Background(), issuer.server.URL, audience)
	if err != nil {
		t.Fatalf("NewOIDCTokenVerifier() error = %v", err)
	}
	token := issuer.signedToken(t, "subject-123", audience, time.Now().Add(time.Minute))
	handler, err := NewHandler(
		server,
		verifier,
		"http://127.0.0.1:8080/mcp",
		issuer.server.URL,
		slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		store,
		[]string{"subject-123"},
		lifecycle,
	)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	pendingURL := "/v1/runtime/resources/resource-123/rotations/pending"
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, pendingURL, nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized pending status = %d, want 401", unauthorized.Code)
	}
	invalidTokenRequest := httptest.NewRequest(http.MethodGet, pendingURL, nil)
	invalidTokenRequest.Header.Set("Authorization", "Bearer "+issuer.signedToken(t, "subject-123", "wrong-audience", time.Now().Add(time.Minute)))
	invalidTokenResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidTokenResponse, invalidTokenRequest)
	if invalidTokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-audience pending status = %d, want 401", invalidTokenResponse.Code)
	}

	pendingRequest := httptest.NewRequest(http.MethodGet, pendingURL, nil)
	pendingRequest.Header.Set("Authorization", "Bearer "+token)
	pendingResponse := httptest.NewRecorder()
	handler.ServeHTTP(pendingResponse, pendingRequest)
	if pendingResponse.Code != http.StatusOK || pendingResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("pending response status=%d, cache-control=%q, body=%q", pendingResponse.Code, pendingResponse.Header().Get("Cache-Control"), pendingResponse.Body.String())
	}
	var pending domain.PendingRotation
	if err := json.Unmarshal(pendingResponse.Body.Bytes(), &pending); err != nil {
		t.Fatalf("Unmarshal(pending) error = %v", err)
	}
	if pending.SecretReference != lifecycle.pending.SecretReference || pending.Generation != 2 || lifecycle.pendingSubject != "subject-123" {
		t.Fatalf("pending result=%+v, caller subject=%q", pending, lifecycle.pendingSubject)
	}

	acknowledgementURL := "/v1/runtime/resources/resource-123/rotations/acknowledgements"
	malformed := httptest.NewRequest(http.MethodPost, acknowledgementURL, strings.NewReader(`{"operation_id":"operation-123","unexpected":true}`))
	malformed.Header.Set("Authorization", "Bearer "+token)
	malformed.Header.Set("Content-Type", "application/json")
	malformedResponse := httptest.NewRecorder()
	handler.ServeHTTP(malformedResponse, malformed)
	if malformedResponse.Code != http.StatusBadRequest || lifecycle.acknowledgements != 0 {
		t.Fatalf("malformed acknowledgement status=%d, calls=%d", malformedResponse.Code, lifecycle.acknowledgements)
	}
	missingVersion := httptest.NewRequest(http.MethodPost, acknowledgementURL, strings.NewReader(`{"operation_id":"operation-123","secret_reference":"ciphera://project/project-123/environments/production/secrets/ROT_PG_0000000000002","generation":2}`))
	missingVersion.Header.Set("Authorization", "Bearer "+token)
	missingVersion.Header.Set("Content-Type", "application/json")
	missingVersionResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingVersionResponse, missingVersion)
	if missingVersionResponse.Code != http.StatusUnprocessableEntity || lifecycle.acknowledgements != 0 {
		t.Fatalf("missing version acknowledgement status=%d, calls=%d", missingVersionResponse.Code, lifecycle.acknowledgements)
	}

	body := `{"operation_id":"operation-123","secret_reference":"` + lifecycle.pending.SecretReference + `","secret_version":"generation-2","generation":2}`
	acknowledgementRequest := httptest.NewRequest(http.MethodPost, acknowledgementURL, strings.NewReader(body))
	acknowledgementRequest.Header.Set("Authorization", "Bearer "+token)
	acknowledgementRequest.Header.Set("Content-Type", "application/json")
	acknowledgementResponse := httptest.NewRecorder()
	handler.ServeHTTP(acknowledgementResponse, acknowledgementRequest)
	if acknowledgementResponse.Code != http.StatusNoContent || lifecycle.acknowledgements != 1 {
		t.Fatalf("acknowledgement status=%d, calls=%d, body=%q", acknowledgementResponse.Code, lifecycle.acknowledgements, acknowledgementResponse.Body.String())
	}
	if lifecycle.acknowledgement.ResourceID != "resource-123" || lifecycle.acknowledgement.OperationID != "operation-123" || lifecycle.acknowledgement.SecretReference != lifecycle.pending.SecretReference || lifecycle.acknowledgement.Generation != 2 || lifecycle.acknowledgementSubject != "subject-123" {
		t.Fatalf("acknowledgement passed to lifecycle=%+v, subject=%q", lifecycle.acknowledgement, lifecycle.acknowledgementSubject)
	}
}

type runtimeRotationTestLifecycle struct {
	pending                domain.PendingRotation
	pendingSubject         string
	acknowledgement        domain.RotationAcknowledgement
	acknowledgementSubject string
	acknowledgements       int
}

func (lifecycle *runtimeRotationTestLifecycle) PendingRotation(ctx context.Context, resourceID string) (domain.PendingRotation, error) {
	principal, ok := identity.FromContext(ctx)
	if ok {
		lifecycle.pendingSubject = principal.Subject
	}
	if resourceID != lifecycle.pending.ResourceID {
		return domain.PendingRotation{}, domain.ErrResourceNotFound
	}
	return lifecycle.pending, nil
}

func (lifecycle *runtimeRotationTestLifecycle) AcknowledgeRotation(ctx context.Context, acknowledgement domain.RotationAcknowledgement) error {
	principal, ok := identity.FromContext(ctx)
	if ok {
		lifecycle.acknowledgementSubject = principal.Subject
	}
	lifecycle.acknowledgement = acknowledgement
	lifecycle.acknowledgements++
	return nil
}
