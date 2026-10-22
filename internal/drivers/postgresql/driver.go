package postgresql

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/provisioning"
)

const ownerCommentPrefix = "shared-resource-provisioner:"

type Driver struct {
	target   config.Target
	endpoint []byte
	mu       sync.Mutex
	closed   bool
}

func New(target config.Target, endpoint []byte) (*Driver, error) {
	endpoint = bytes.TrimSpace(endpoint)
	if target.ResourceType != domain.ResourcePostgreSQL || target.MaxResources < 1 || target.MaxConcurrentOperations < 1 || target.MaxConnectionsPerResource < 1 || len(endpoint) == 0 {
		return nil, errors.New("PostgreSQL target and connection limit are required")
	}
	if _, err := parseConnectionConfig(endpoint); err != nil {
		return nil, errors.New("PostgreSQL target connection configuration is invalid")
	}
	return &Driver{target: target, endpoint: append([]byte(nil), endpoint...)}, nil
}

func (driver *Driver) Close() {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	clear(driver.endpoint)
	driver.endpoint = nil
	driver.closed = true
}

func (driver *Driver) Create(ctx context.Context, resource domain.Resource) (provisioning.Credential, error) {
	roleName, databaseName, err := objectNames(resource)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		clear(passwordBytes)
		return provisioning.Credential{}, provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)
	clear(passwordBytes)
	defer func() {
		password = ""
	}()

	adminConfig, err := driver.connectionConfig()
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	adminConn, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_UNAVAILABLE", false)
	}
	defer func() {
		_ = adminConn.Close(context.Background())
	}()

	ownerComment := ownerCommentPrefix + resource.ID
	roleExists, roleComment, err := readRoleOwner(ctx, adminConn, roleName)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if roleExists && roleComment != ownerComment {
		return provisioning.Credential{}, provisioning.NewDriverFailure("RESOURCE_NAME_CONFLICT", false)
	}
	databaseExists, databaseComment, err := readDatabaseOwner(ctx, adminConn, databaseName)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if databaseExists && databaseComment != ownerComment {
		return provisioning.Credential{}, provisioning.NewDriverFailure("RESOURCE_NAME_CONFLICT", false)
	}

	roleSQL := "ALTER ROLE " + quoteIdentifier(roleName) + " LOGIN CONNECTION LIMIT " + strconv.Itoa(driver.target.MaxConnectionsPerResource) + " PASSWORD " + quoteLiteral(password)
	if !roleExists {
		roleSQL = "CREATE ROLE " + quoteIdentifier(roleName) + " LOGIN CONNECTION LIMIT " + strconv.Itoa(driver.target.MaxConnectionsPerResource) + " PASSWORD " + quoteLiteral(password)
	}
	if _, err := adminConn.Exec(ctx, roleSQL); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	if !roleExists {
		if _, err := adminConn.Exec(ctx, "COMMENT ON ROLE "+quoteIdentifier(roleName)+" IS "+quoteLiteral(ownerComment)); err != nil {
			return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
	}
	if !databaseExists {
		createDatabase := "CREATE DATABASE " + quoteIdentifier(databaseName) + " OWNER " + quoteIdentifier(roleName) + " CONNECTION LIMIT " + strconv.Itoa(driver.target.MaxConnectionsPerResource)
		if _, err := adminConn.Exec(ctx, createDatabase); err != nil {
			return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
		if _, err := adminConn.Exec(ctx, "COMMENT ON DATABASE "+quoteIdentifier(databaseName)+" IS "+quoteLiteral(ownerComment)); err != nil {
			return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
	} else {
		if _, err := adminConn.Exec(ctx, "ALTER DATABASE "+quoteIdentifier(databaseName)+" OWNER TO "+quoteIdentifier(roleName)); err != nil {
			return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
		if _, err := adminConn.Exec(ctx, "ALTER DATABASE "+quoteIdentifier(databaseName)+" CONNECTION LIMIT "+strconv.Itoa(driver.target.MaxConnectionsPerResource)); err != nil {
			return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
	}
	if _, err := adminConn.Exec(ctx, "REVOKE CONNECT, TEMPORARY ON DATABASE "+quoteIdentifier(databaseName)+" FROM PUBLIC"); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	if _, err := adminConn.Exec(ctx, "GRANT CONNECT, TEMPORARY ON DATABASE "+quoteIdentifier(databaseName)+" TO "+quoteIdentifier(roleName)); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}

	databaseConfig := adminConfig.Copy()
	databaseConfig.Database = databaseName
	databaseConn, err := pgx.ConnectConfig(ctx, databaseConfig)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	if _, err := databaseConn.Exec(ctx, "REVOKE ALL ON SCHEMA public FROM PUBLIC"); err != nil {
		_ = databaseConn.Close(context.Background())
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	if _, err := databaseConn.Exec(ctx, "ALTER SCHEMA public OWNER TO "+quoteIdentifier(roleName)); err != nil {
		_ = databaseConn.Close(context.Background())
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	if _, err := databaseConn.Exec(ctx, "GRANT USAGE, CREATE ON SCHEMA public TO "+quoteIdentifier(roleName)); err != nil {
		_ = databaseConn.Close(context.Background())
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	if err := databaseConn.Close(context.Background()); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}

	credential, err := applicationConnectionString(adminConfig.ConnString(), roleName, password, databaseName)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	return provisioning.Credential{Name: "DATABASE_URL", Value: credential}, nil
}

func (driver *Driver) Revoke(ctx context.Context, resource domain.Resource) error {
	_, databaseName, err := objectNames(resource)
	if err != nil {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	generations := credentialGenerations(resource)
	roles := make([]string, 0, len(generations))
	for _, generation := range generations {
		roleName, _, err := roleNameForGeneration(resource, generation)
		if err != nil {
			return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
		}
		roles = append(roles, roleName)
	}
	adminConfig, err := driver.connectionConfig()
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	adminConn, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	defer func() {
		_ = adminConn.Close(context.Background())
	}()
	ownerComment := ownerCommentPrefix + resource.ID
	databaseExists, databaseComment, err := readDatabaseOwner(ctx, adminConn, databaseName)
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if databaseExists && databaseComment != ownerComment {
		return provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
	}
	if databaseExists {
		databaseOwner, err := readDatabaseOwnerName(ctx, adminConn, databaseName)
		if err != nil {
			return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
		}
		ownedByManagedRole := false
		for _, roleName := range roles {
			if databaseOwner == roleName {
				ownedByManagedRole = true
				break
			}
		}
		if !ownedByManagedRole {
			return provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
		}
	}
	roleExists := make([]bool, len(roles))
	for index, roleName := range roles {
		var roleComment string
		roleExists[index], roleComment, err = readRoleOwner(ctx, adminConn, roleName)
		if err != nil {
			return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
		}
		if roleExists[index] && roleComment != ownerComment {
			return provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
		}
	}
	anyRoleExists := false
	for _, exists := range roleExists {
		if exists {
			anyRoleExists = true
			break
		}
	}
	if !anyRoleExists && !databaseExists {
		return nil
	}
	for index, roleName := range roles {
		if !roleExists[index] {
			continue
		}
		if _, err := adminConn.Exec(ctx, "ALTER ROLE "+quoteIdentifier(roleName)+" NOLOGIN"); err != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
	}
	for memberIndex, memberRole := range roles {
		if !roleExists[memberIndex] {
			continue
		}
		for inheritedIndex := 0; inheritedIndex < memberIndex; inheritedIndex++ {
			if !roleExists[inheritedIndex] {
				continue
			}
			if _, err := adminConn.Exec(ctx, "REVOKE "+quoteIdentifier(roles[inheritedIndex])+" FROM "+quoteIdentifier(memberRole)); err != nil {
				return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
			}
		}
	}
	for _, roleName := range roles {
		if _, err := adminConn.Exec(ctx, "SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE usename = $1 AND pid <> pg_catalog.pg_backend_pid()", roleName); err != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
	}
	if databaseExists {
		if _, err := adminConn.Exec(ctx, "DROP DATABASE "+quoteIdentifier(databaseName)+" WITH (FORCE)"); err != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
	}
	for index := len(roles) - 1; index >= 0; index-- {
		if !roleExists[index] {
			continue
		}
		if _, err := adminConn.Exec(ctx, "DROP ROLE "+quoteIdentifier(roles[index])); err != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
	}
	return nil
}

func (driver *Driver) connectionConfig() (*pgx.ConnConfig, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.closed || len(driver.endpoint) == 0 {
		return nil, errors.New("PostgreSQL driver is closed")
	}
	configuration, err := parseConnectionConfig(driver.endpoint)
	if err != nil {
		return nil, errors.New("PostgreSQL endpoint is invalid")
	}
	return configuration, nil
}

func parseConnectionConfig(endpoint []byte) (*pgx.ConnConfig, error) {
	parsed, err := url.Parse(string(endpoint))
	if err != nil || parsed.Host == "" || parsed.User == nil || strings.TrimSpace(parsed.User.Username()) == "" || parsed.Fragment != "" {
		return nil, errors.New("PostgreSQL endpoint must be a credentialed URI")
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return nil, errors.New("PostgreSQL endpoint scheme is invalid")
	}
	if err := validateEndpointQuery(parsed.Query()); err != nil {
		return nil, err
	}
	configuration, err := pgx.ParseConfig(string(endpoint))
	if err != nil || configuration.Host == "" {
		return nil, errors.New("invalid PostgreSQL endpoint")
	}
	if isLoopback(configuration.Host) || filepath.IsAbs(configuration.Host) {
		return configuration, nil
	}
	if configuration.TLSConfig == nil || configuration.TLSConfig.InsecureSkipVerify || configuration.TLSConfig.ServerName == "" || len(configuration.Fallbacks) > 0 {
		return nil, errors.New("remote PostgreSQL endpoints require verified TLS without plaintext fallback")
	}
	return configuration, nil
}

func applicationConnectionString(endpoint string, username string, password string, database string) ([]byte, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User == nil || parsed.Fragment != "" || database == "" {
		return nil, errors.New("PostgreSQL endpoint cannot form an application URI")
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return nil, errors.New("PostgreSQL endpoint scheme is invalid")
	}
	if err := validateEndpointQuery(parsed.Query()); err != nil {
		return nil, err
	}
	parsed.User = url.UserPassword(username, password)
	parsed.Path = "/" + database
	parsed.RawPath = ""
	return []byte(parsed.String()), nil
}

func validateEndpointQuery(query url.Values) error {
	allowed := map[string]struct{}{
		"sslmode": {}, "sslrootcert": {}, "connect_timeout": {},
		"application_name": {}, "target_session_attrs": {},
	}
	for key := range query {
		if _, exists := allowed[strings.ToLower(key)]; !exists {
			return errors.New("PostgreSQL endpoint contains an unsupported query option")
		}
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func objectNames(resource domain.Resource) (string, string, error) {
	if resource.ID == "" || resource.ResourceType != domain.ResourcePostgreSQL || !domain.ValidScopeName(resource.Scope.Application) || !domain.ValidScopeName(resource.Scope.Environment) {
		return "", "", errors.New("invalid PostgreSQL resource identity")
	}
	sum := sha256.Sum256([]byte(resource.ID))
	suffix := hex.EncodeToString(sum[:12])
	return "srp_role_" + suffix, "srp_db_" + suffix, nil
}

func readRoleOwner(ctx context.Context, connection *pgx.Conn, roleName string) (bool, string, error) {
	var comment string
	var exists bool
	err := connection.QueryRow(ctx, `
		SELECT
			pg_catalog.to_regrole($1) IS NOT NULL,
			COALESCE(pg_catalog.shobj_description(pg_catalog.to_regrole($1), 'pg_authid'), '')
	`, roleName).Scan(&exists, &comment)
	return exists, comment, err
}

func readDatabaseOwner(ctx context.Context, connection *pgx.Conn, databaseName string) (bool, string, error) {
	var comment string
	err := connection.QueryRow(ctx, `
		SELECT COALESCE(pg_catalog.shobj_description(oid, 'pg_database'), '')
		FROM pg_catalog.pg_database WHERE datname = $1
	`, databaseName).Scan(&comment)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	return err == nil, comment, err
}

func quoteIdentifier(value string) string {
	return pgx.Identifier{value}.Sanitize()
}

func quoteLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
