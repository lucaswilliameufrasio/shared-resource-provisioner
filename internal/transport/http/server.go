package httptransport

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const httpShutdownGracePeriod = 60 * time.Second

func Serve(
	ctx context.Context,
	settings config.Settings,
	server *mcp.Server,
	grants authorization.GrantManager,
	logger *slog.Logger,
	rotation ...RuntimeRotation,
) error {
	if err := settings.ValidateHTTP(); err != nil {
		return err
	}
	verifier, err := NewOIDCTokenVerifier(ctx, settings.OIDCIssuerURL, settings.OIDCAudience)
	if err != nil {
		return err
	}
	handler, err := NewHandler(server, verifier, settings.MCPResourceURL, settings.OIDCIssuerURL, logger, grants, settings.AdminSubjects, rotation...)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", settings.HTTPAddress)
	if err != nil {
		return errors.New("unable to start HTTP listener")
	}

	httpServer := &http.Server{
		Addr:              settings.HTTPAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveResult := make(chan error, 1)
	go func() {
		var serveErr error
		if settings.TLSCertFile != "" {
			serveErr = httpServer.ServeTLS(listener, settings.TLSCertFile, settings.TLSKeyFile)
		} else {
			serveErr = httpServer.Serve(listener)
		}
		serveResult <- serveErr
	}()

	select {
	case err := <-serveResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTP server stopped unexpectedly")
	case <-ctx.Done():
		if err := shutdownHTTPServer(httpServer, httpShutdownGracePeriod); err != nil {
			_ = httpServer.Close()
			return errors.New("HTTP server shutdown failed")
		}
		err := <-serveResult
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTP server stopped unexpectedly")
	}
}

func shutdownHTTPServer(server *http.Server, timeout time.Duration) error {
	shutdownContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return server.Shutdown(shutdownContext)
}
