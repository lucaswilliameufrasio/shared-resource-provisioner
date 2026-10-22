package postgresql

import (
	"crypto/rand"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

func TestObjectNamesAreStableAndDistinctFromCallerScope(t *testing.T) {
	t.Parallel()

	resource := domain.Resource{
		ID:           "resource-id-001",
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        domain.Scope{Application: "orders", Environment: "production"},
	}
	roleOne, databaseOne, err := objectNames(resource)
	if err != nil {
		t.Fatalf("objectNames() error = %v", err)
	}
	roleTwo, databaseTwo, err := objectNames(resource)
	if err != nil {
		t.Fatalf("objectNames(repeated) error = %v", err)
	}
	if roleOne != roleTwo || databaseOne != databaseTwo || roleOne == databaseOne {
		t.Fatalf("resource names = %q, %q and %q, %q", roleOne, databaseOne, roleTwo, databaseTwo)
	}
	if len(roleOne) > 63 || len(databaseOne) > 63 || strings.Contains(roleOne, "orders") || strings.Contains(databaseOne, "production") {
		t.Fatalf("resource names disclose scope or exceed PostgreSQL identifier limits: %q, %q", roleOne, databaseOne)
	}
}

func TestRoleNamesAreGenerationSpecificAndKeepDatabaseStable(t *testing.T) {
	t.Parallel()

	resource := domain.Resource{
		ID:           "rotation-resource-id",
		ResourceType: domain.ResourcePostgreSQL,
		Scope:        domain.Scope{Application: "orders", Environment: "production"},
	}
	baseRole, database, err := objectNames(resource)
	if err != nil {
		t.Fatalf("objectNames() error = %v", err)
	}
	firstRole, firstDatabase, err := roleNameForGeneration(resource, 1)
	if err != nil {
		t.Fatalf("roleNameForGeneration(1) error = %v", err)
	}
	secondRole, secondDatabase, err := roleNameForGeneration(resource, 2)
	if err != nil {
		t.Fatalf("roleNameForGeneration(2) error = %v", err)
	}
	if firstRole != baseRole || secondRole == firstRole || firstDatabase != database || secondDatabase != database || len(secondRole) > 63 {
		t.Fatalf("generation names = (%q,%q), database=(%q,%q), base=(%q,%q)", firstRole, secondRole, firstDatabase, secondDatabase, baseRole, database)
	}
	if _, _, err := roleNameForGeneration(resource, 10_000_000_000_000); err == nil {
		t.Fatal("roleNameForGeneration() accepted an out-of-range generation")
	}
}

func TestIdentifierAndLiteralQuotingDoNotAllowSQLStructure(t *testing.T) {
	t.Parallel()

	identifier := quoteIdentifier(`name"; DROP DATABASE unrelated;--`)
	if !strings.HasPrefix(identifier, `"`) || !strings.HasSuffix(identifier, `"`) || !strings.Contains(identifier, `""`) {
		t.Fatalf("quoted identifier = %q", identifier)
	}
	literal := quoteLiteral("marker'; DROP DATABASE unrelated;--")
	if !strings.HasPrefix(literal, "'") || !strings.HasSuffix(literal, "'") || !strings.Contains(literal, "''") {
		t.Fatalf("quoted literal = %q", literal)
	}
}

func TestObjectNamesRejectNonPostgreSQLResources(t *testing.T) {
	t.Parallel()

	_, _, err := objectNames(domain.Resource{ID: "resource-id", ResourceType: domain.ResourceValkey, Scope: domain.Scope{Application: "orders", Environment: "production"}})
	if err == nil {
		t.Fatal("objectNames() accepted a non-PostgreSQL resource")
	}
}

func TestParseConnectionConfigRequiresVerifiedTLSForRemoteTargets(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{
		"postgres://admin@postgres.example.test/postgres?sslmode=disable",
		"postgres://admin@postgres.example.test/postgres?sslmode=prefer",
		"postgres://admin@postgres.example.test/postgres?sslmode=require",
	} {
		if _, err := parseConnectionConfig([]byte(endpoint)); err == nil {
			t.Fatalf("parseConnectionConfig() accepted an insecure remote endpoint")
		}
	}
	if _, err := parseConnectionConfig([]byte("postgres://admin@postgres.example.test/postgres?sslmode=verify-full")); err != nil {
		t.Fatalf("parseConnectionConfig(verified TLS) error = %v", err)
	}
	if _, err := parseConnectionConfig([]byte("postgres://admin@127.0.0.1:5432/postgres?sslmode=disable")); err != nil {
		t.Fatalf("parseConnectionConfig(loopback) error = %v", err)
	}
}

func TestNewCopiesAndClosesOwnerEndpointBytes(t *testing.T) {
	t.Parallel()

	endpoint := []byte("postgres://admin@127.0.0.1:5432/postgres?sslmode=disable\n")
	driver, err := New(config.Target{
		ResourceType:              domain.ResourcePostgreSQL,
		MaxResources:              10,
		MaxConcurrentOperations:   2,
		MaxConnectionsPerResource: 4,
	}, endpoint)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	clear(endpoint)
	if _, err := driver.connectionConfig(); err != nil {
		t.Fatalf("connectionConfig() after caller cleared input error = %v", err)
	}
	driver.Close()
	if _, err := driver.connectionConfig(); err == nil {
		t.Fatal("connectionConfig() succeeded after Close()")
	}
}

func TestApplicationConnectionStringReplacesAdminCredentialsAndDatabase(t *testing.T) {
	t.Parallel()

	adminPassword := randomPostgresCredential(t)
	applicationPassword := randomPostgresCredential(t)
	endpoint := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("postgres-admin", adminPassword),
		Host:     "postgres.example.test:5432",
		Path:     "/admin",
		RawQuery: "sslmode=verify-full&application_name=shared-resource-provisioner",
	}
	connectionString, err := applicationConnectionString(endpoint.String(), "srp_role_resource", applicationPassword, "srp_db_resource")
	if err != nil {
		t.Fatalf("applicationConnectionString() error = %v", err)
	}
	if strings.Contains(string(connectionString), adminPassword) {
		t.Fatal("application connection string retained the target administrator password")
	}
	configuration, err := pgx.ParseConfig(string(connectionString))
	if err != nil {
		t.Fatal("application connection string could not be parsed")
	}
	if configuration.User != "srp_role_resource" || configuration.Password != applicationPassword || configuration.Database != "srp_db_resource" || configuration.RuntimeParams["application_name"] != "shared-resource-provisioner" {
		t.Fatal("application connection string did not retain only the resource identity and safe target options")
	}
	if configuration.TLSConfig == nil || configuration.TLSConfig.ServerName != "postgres.example.test" {
		t.Fatal("application connection string did not preserve verified TLS")
	}
}

func TestParseConnectionConfigRejectsCredentialBearingOrAmbiguousQueryOptions(t *testing.T) {
	t.Parallel()

	adminPassword := randomPostgresCredential(t)
	endpoint := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("postgres-admin", adminPassword),
		Host:     "postgres.example.test:5432",
		Path:     "/admin",
		RawQuery: "sslmode=verify-full&sslpassword=" + url.QueryEscape(randomPostgresCredential(t)),
	}
	if _, err := parseConnectionConfig([]byte(endpoint.String())); err == nil {
		t.Fatal("parseConnectionConfig() accepted a credential-bearing TLS option")
	}
}

func randomPostgresCredential(t *testing.T) string {
	t.Helper()

	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(value)
	clear(value)
	return encoded
}
