package httptransport

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const maxMCPRequestBodyBytes = 1 << 20

func NewHandler(
	server *mcp.Server,
	verifier TokenVerifier,
	resourceURL string,
	issuerURL string,
	logger *slog.Logger,
	grantManager authorization.GrantManager,
	adminSubjects []string,
	rotation ...RuntimeRotation,
) (http.Handler, error) {
	if server == nil || verifier == nil || issuerURL == "" || logger == nil || grantManager == nil {
		return nil, errors.New("MCP server, token verifier, issuer, logger, and grant manager are required")
	}
	if len(adminSubjects) == 0 {
		return nil, errors.New("at least one OIDC admin subject is required")
	}
	if len(rotation) > 1 {
		return nil, errors.New("at most one runtime rotation service is allowed")
	}
	seenAdminSubjects := make(map[string]struct{}, len(adminSubjects))
	for _, subject := range adminSubjects {
		if !identity.ValidSubject(subject) {
			return nil, errors.New("OIDC admin subject is invalid")
		}
		if _, exists := seenAdminSubjects[subject]; exists {
			return nil, errors.New("OIDC admin subjects must be unique")
		}
		seenAdminSubjects[subject] = struct{}{}
	}
	resourcePath, metadataURL, err := MCPResourceMetadataURL(resourceURL)
	if err != nil {
		return nil, err
	}
	metadata, err := url.Parse(metadataURL)
	if err != nil {
		return nil, errors.New("MCP resource metadata URL is invalid")
	}
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server {
			return server
		},
		&mcp.StreamableHTTPOptions{
			Logger:              logger,
			MaxRequestBodyBytes: maxMCPRequestBodyBytes,
		},
	)
	protectedMCP := http.NewCrossOriginProtection().Handler(RequireBearerToken(verifier, metadataURL, mcpHandler))
	adminHandler, err := NewAdminHandler(grantManager)
	if err != nil {
		return nil, err
	}
	protectedAdmin := http.NewCrossOriginProtection().Handler(RequireAdminBearerToken(verifier, metadataURL, adminSubjects, adminHandler))
	var protectedRuntime http.Handler
	if len(rotation) == 1 && rotation[0] != nil {
		runtimeHandler := newRuntimeRotationHandler(rotation[0])
		protectedRuntime = http.NewCrossOriginProtection().Handler(RequireBearerToken(verifier, metadataURL, runtimeHandler))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "ok\n")
	})
	mux.Handle(resourcePath, protectedMCP)
	mux.Handle("/v1/admin/", protectedAdmin)
	if protectedRuntime != nil {
		mux.Handle("/v1/runtime/", protectedRuntime)
	}
	mux.Handle(metadata.EscapedPath(), auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               resourceURL,
		AuthorizationServers:   []string{issuerURL},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Shared Resource Provisioner",
	}))

	return mux, nil
}
