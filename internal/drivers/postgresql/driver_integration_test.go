//go:build integration

package postgresql

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

func TestDriverCreatesIsolatedDatabaseEnforcesRoleLimitAndRevokesLocally(t *testing.T) {
	adminDSN := os.Getenv("SRP_TEST_POSTGRES_DSN")
	if adminDSN == "" {
		t.Skip("SRP_TEST_POSTGRES_DSN is not set")
	}
	adminConfig, err := parseConnectionConfig([]byte(adminDSN))
	if err != nil || !isLoopback(adminConfig.Host) {
		t.Fatal("PostgreSQL integration tests require a loopback target")
	}
	waitForPostgres(t, adminConfig)

	driver, err := New(config.Target{
		ID:                        "postgres-integration",
		ResourceType:              domain.ResourcePostgreSQL,
		MaxResources:              10,
		MaxConcurrentOperations:   2,
		MaxConnectionsPerResource: 1,
	}, []byte(adminDSN))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer driver.Close()

	firstResource := domain.Resource{
		ID:           "local-postgres-resource-one",
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        domain.Scope{Application: "orders", Environment: "test"},
	}
	firstCredential, err := driver.Create(context.Background(), firstResource)
	if err != nil {
		t.Fatalf("Create(first resource) error = %v", err)
	}
	defer clear(firstCredential.Value)
	defer func() {
		if err := driver.Revoke(context.Background(), firstResource); err != nil {
			t.Errorf("Revoke(first resource) error = %v", err)
		}
	}()
	firstConfig, err := pgx.ParseConfig(string(firstCredential.Value))
	if err != nil {
		t.Fatalf("ParseConfig(first credential) error = %v", err)
	}
	expectedFirstRole, _, err := objectNames(firstResource)
	if err != nil || firstConfig.User != expectedFirstRole {
		t.Fatalf("generated PostgreSQL connection string role = %q, expected resource role %q", firstConfig.User, expectedFirstRole)
	}
	defer func() {
		firstConfig.Password = ""
	}()
	firstConnection, err := pgx.ConnectConfig(context.Background(), firstConfig)
	if err != nil {
		t.Fatal("application role could not connect to its provisioned database")
	}
	defer firstConnection.Close(context.Background())
	if _, err := firstConnection.Exec(context.Background(), "CREATE TABLE isolation_check (id integer PRIMARY KEY)"); err != nil {
		t.Fatalf("application role could not create an object in its database: %v", err)
	}
	if _, err := firstConnection.Exec(context.Background(), "INSERT INTO isolation_check (id) VALUES (1)"); err != nil {
		t.Fatalf("application role could not write its database: %v", err)
	}

	secondResource := domain.Resource{
		ID:           "local-postgres-resource-two",
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        domain.Scope{Application: "billing", Environment: "test"},
	}
	secondCredential, err := driver.Create(context.Background(), secondResource)
	if err != nil {
		t.Fatalf("Create(second resource) error = %v", err)
	}
	defer clear(secondCredential.Value)
	defer func() {
		if err := driver.Revoke(context.Background(), secondResource); err != nil {
			t.Errorf("Revoke(second resource) error = %v", err)
		}
	}()
	_, secondDatabase, err := objectNames(secondResource)
	if err != nil {
		t.Fatalf("objectNames(second resource) error = %v", err)
	}
	crossDatabaseConfig := firstConfig.Copy()
	crossDatabaseConfig.Database = secondDatabase
	if crossConnection, err := pgx.ConnectConfig(context.Background(), crossDatabaseConfig); err == nil {
		var connectedUser string
		var connectedDatabase string
		_ = crossConnection.QueryRow(context.Background(), "SELECT current_user, current_database()").Scan(&connectedUser, &connectedDatabase)
		_ = crossConnection.Close(context.Background())
		t.Fatalf("resource role %q connected to database %q as %q", firstConfig.User, secondDatabase, connectedUser)
	}

	secondConnection, err := pgx.ConnectConfig(context.Background(), firstConfig.Copy())
	if err == nil {
		_ = secondConnection.Close(context.Background())
		t.Fatal("PostgreSQL accepted a connection above the configured per-role limit")
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "53300" {
		t.Fatal("PostgreSQL rejected the extra application connection for an unexpected reason")
	}
	if err := driver.Revoke(context.Background(), firstResource); err != nil {
		t.Fatalf("Revoke(first resource) error = %v", err)
	}
	if _, err := pgx.ConnectConfig(context.Background(), firstConfig.Copy()); err == nil {
		t.Fatal("PostgreSQL accepted the application role after resource revocation")
	}
}

func waitForPostgres(t *testing.T, configuration *pgx.ConnConfig) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		connection, err := pgx.ConnectConfig(ctx, configuration.Copy())
		cancel()
		if err == nil {
			_ = connection.Close(context.Background())
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("local PostgreSQL test service did not become ready")
}
