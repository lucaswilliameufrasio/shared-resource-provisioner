package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/drivers"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/persistence/sqlite"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/planning"
	httptransport "github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/transport/http"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/transport/mcpserver"
	stdiotransport "github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/transport/stdio"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(os.Args[1:], os.Getenv, logger); err != nil {
		logger.Error("provisioner stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, logger *slog.Logger) (runErr error) {
	if len(args) > 0 && args[0] == "backup" {
		if len(args) != 2 || args[1] == "" {
			return errors.New("usage: provisioner backup <destination>")
		}
		if err := backupDatabase(args[1], getenv); err != nil {
			return err
		}
		logger.Info("SQLite backup created")
		return nil
	}
	if len(args) != 1 {
		return errors.New("usage: provisioner <stdio|http>")
	}
	settings, err := config.LoadFromEnvironment(getenv)
	if err != nil {
		return err
	}
	var validateErr error
	switch args[0] {
	case "stdio":
		validateErr = settings.ValidateStdio()
	case "http":
		validateErr = settings.ValidateHTTP()
	default:
		return errors.New("transport must be stdio or http")
	}
	if validateErr != nil {
		return validateErr
	}

	var bootstrapGrants []authorization.Grant
	if settings.PolicyFile != "" {
		policy, err := authorization.LoadPolicyFile(settings.PolicyFile)
		if err != nil {
			return err
		}
		bootstrapGrants = policy.Grants()
	}
	store, err := sqlite.Open(settings.SQLitePath)
	if err != nil {
		return err
	}
	defer func() {
		if err := store.Close(); err != nil && runErr == nil {
			runErr = errors.New("unable to close control-plane database")
		}
	}()
	if err := store.SeedPolicyOnce(context.Background(), bootstrapGrants); err != nil {
		return err
	}
	authorizer, err := authorization.NewPersistentAuthorizer(store)
	if err != nil {
		return err
	}
	planner, err := planning.NewService(authorizer, store)
	if err != nil {
		return err
	}
	var lifecycle mcpserver.Lifecycle
	var runtimeRotation httptransport.RuntimeRotation
	if settings.MutationsEnabled {
		lifecycleService, resources, err := drivers.NewConfiguredService(settings, store, authorizer, store)
		if err != nil {
			return err
		}
		defer resources.Close()
		lifecycle = lifecycleService
		runtimeRotation = lifecycleService
	}
	mcpLifecycle := lifecycle
	if args[0] == "stdio" && lifecycle != nil {
		mcpLifecycle = stdioLifecycle{Lifecycle: lifecycle}
	}
	server, err := mcpserver.New(planner, logger, mcpLifecycle)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if args[0] == "stdio" {
		return stdiotransport.Serve(ctx, settings.StdioSubject, server)
	}
	return httptransport.Serve(ctx, settings, server, store, logger, runtimeRotation)
}

type stdioLifecycle struct {
	mcpserver.Lifecycle
}

func backupDatabase(destination string, getenv func(string) string) (runErr error) {
	settings, err := config.LoadFromEnvironment(getenv)
	if err != nil {
		return err
	}
	if settings.SQLitePath == "" {
		return errors.New("SQLite database path is required")
	}
	info, err := os.Lstat(settings.SQLitePath)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("SQLite database file is unavailable")
	}

	store, err := sqlite.Open(settings.SQLitePath)
	if err != nil {
		return err
	}
	defer func() {
		if err := store.Close(); err != nil && runErr == nil {
			runErr = err
		}
	}()

	return store.Backup(context.Background(), destination)
}
