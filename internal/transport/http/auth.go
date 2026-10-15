package httptransport

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

type TokenVerifier = auth.TokenVerifier

func NewOIDCTokenVerifier(ctx context.Context, issuer, audience string) (TokenVerifier, error) {
	if issuer == "" || audience == "" {
		return nil, errors.New("OIDC issuer and audience are required")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, errors.New("OIDC provider discovery failed")
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: audience})
	return func(ctx context.Context, rawToken string, _ *http.Request) (*auth.TokenInfo, error) {
		token, err := verifier.Verify(ctx, rawToken)
		if err != nil || !identity.ValidSubject(token.Subject) {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{
			UserID:     token.Subject,
			Expiration: token.Expiry,
		}, nil
	}, nil
}

func RequireBearerToken(verifier TokenVerifier, metadataURL string, next http.Handler) http.Handler {
	verifiedHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		tokenInfo := auth.TokenInfoFromContext(request.Context())
		if tokenInfo == nil || tokenInfo.UserID == "" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		principal := identity.Principal{Subject: tokenInfo.UserID, Transport: identity.TransportHTTP}
		next.ServeHTTP(writer, request.WithContext(identity.WithPrincipal(request.Context(), principal)))
	})
	return auth.RequireBearerToken(
		verifier,
		&auth.RequireBearerTokenOptions{ResourceMetadataURL: metadataURL},
	)(verifiedHandler)
}

func MCPResourceMetadataURL(resourceURL string) (string, string, error) {
	resource, err := url.Parse(resourceURL)
	if err != nil || resource.Host == "" || resource.User != nil || resource.RawQuery != "" || resource.Fragment != "" || resource.Path == "" || resource.Path == "/" {
		return "", "", errors.New("MCP resource URL is invalid")
	}
	resourcePath := resource.EscapedPath()
	if !strings.HasPrefix(resourcePath, "/") || strings.Contains(resourcePath, "%") || strings.Contains(resourcePath, "//") || strings.HasSuffix(resourcePath, "/") {
		return "", "", errors.New("MCP resource URL path is invalid")
	}
	metadataPath := "/.well-known/oauth-protected-resource" + resourcePath
	metadataURL := *resource
	metadataURL.Path = metadataPath
	metadataURL.RawPath = ""
	metadataURL.RawQuery = ""
	metadataURL.Fragment = ""
	return resourcePath, metadataURL.String(), nil
}
