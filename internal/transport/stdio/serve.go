package stdiotransport

import (
	"context"
	"errors"
	"io"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func Serve(ctx context.Context, subject string, server *mcp.Server) error {
	if subject == "" {
		return errors.New("stdio principal is required")
	}
	ctx = identity.WithPrincipal(ctx, identity.Principal{
		Subject:   subject,
		Transport: identity.TransportStdio,
	})
	err := server.Run(ctx, &mcp.StdioTransport{})
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("MCP stdio server stopped unexpectedly")
}
