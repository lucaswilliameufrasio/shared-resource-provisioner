package httptransport

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/persistence/sqlite"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNewHandlerKeepsHealthOpenAndMCPAuthenticated(t *testing.T) {
	t.Parallel()

	server := mcp.NewServer(
		&mcp.Implementation{Name: "test", Version: "test"},
		&mcp.ServerOptions{},
	)
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	if err := store.SeedPolicyOnce(context.Background(), nil); err != nil {
		t.Fatalf("SeedPolicyOnce() error = %v", err)
	}
	handler, err := NewHandler(server, testTokenVerifier, "http://127.0.0.1:8080/mcp", "https://issuer.example.test", slog.New(slog.NewTextHandler(discardWriter{}, nil)), store, []string{"subject-123"})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	healthRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, healthRequest)
	if healthResponse.Code != http.StatusOK || healthResponse.Body.String() != "ok\n" {
		t.Fatalf("health response = %d %q", healthResponse.Code, healthResponse.Body.String())
	}

	mcpRequest := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	mcpResponse := httptest.NewRecorder()
	handler.ServeHTTP(mcpResponse, mcpRequest)
	if mcpResponse.Code != http.StatusUnauthorized {
		t.Fatalf("MCP status = %d, want %d", mcpResponse.Code, http.StatusUnauthorized)
	}

	metadataRequest := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
	metadataResponse := httptest.NewRecorder()
	handler.ServeHTTP(metadataResponse, metadataRequest)
	if metadataResponse.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, want %d", metadataResponse.Code, http.StatusOK)
	}
	if !strings.Contains(metadataResponse.Body.String(), `"authorization_servers":["https://issuer.example.test"]`) {
		t.Fatalf("metadata did not advertise the configured issuer: %s", metadataResponse.Body.String())
	}
}

type discardWriter struct{}

func (discardWriter) Write(data []byte) (int, error) {
	return len(data), nil
}
