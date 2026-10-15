package httptransport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

func testTokenVerifier(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	if token != "test-token" {
		return nil, auth.ErrInvalidToken
	}
	return &auth.TokenInfo{UserID: "subject-123", Expiration: time.Now().Add(time.Minute)}, nil
}

func TestRequireBearerTokenSetsVerifiedPrincipal(t *testing.T) {
	t.Parallel()

	handler := RequireBearerToken(testTokenVerifier, "https://mcp.example.test/.well-known/oauth-protected-resource/mcp", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := identity.FromContext(request.Context())
		if !ok || principal.Subject != "subject-123" || principal.Transport != identity.TransportHTTP {
			t.Errorf("principal = %+v, ok = %t", principal, ok)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestRequireBearerTokenRejectsMissingMalformedAndInvalidTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		header   string
		verifier TokenVerifier
	}{
		{name: "missing", verifier: testTokenVerifier},
		{name: "wrong scheme", header: "Basic test-token", verifier: testTokenVerifier},
		{name: "extra token field", header: "Bearer test-token second", verifier: testTokenVerifier},
		{name: "invalid", header: "Bearer not-valid", verifier: testTokenVerifier},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := RequireBearerToken(test.verifier, "https://mcp.example.test/.well-known/oauth-protected-resource/mcp", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("unauthorized request reached the handler")
			}))
			request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if test.header != "" {
				request.Header.Set("Authorization", test.header)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
			if test.name == "missing" && !strings.Contains(response.Header().Get("WWW-Authenticate"), "resource_metadata=") {
				t.Fatalf("WWW-Authenticate = %q, want resource metadata discovery", response.Header().Get("WWW-Authenticate"))
			}
			if response.Body.String() == test.header {
				t.Fatal("authorization material was reflected in the response")
			}
		})
	}
}

func TestMCPResourceMetadataURLUsesResourcePath(t *testing.T) {
	t.Parallel()

	resourcePath, metadataURL, err := MCPResourceMetadataURL("https://mcp.example.test/provisioner/mcp")
	if err != nil {
		t.Fatalf("MCPResourceMetadataURL() error = %v", err)
	}
	if resourcePath != "/provisioner/mcp" {
		t.Fatalf("resource path = %q", resourcePath)
	}
	if metadataURL != "https://mcp.example.test/.well-known/oauth-protected-resource/provisioner/mcp" {
		t.Fatalf("metadata URL = %q", metadataURL)
	}
}
