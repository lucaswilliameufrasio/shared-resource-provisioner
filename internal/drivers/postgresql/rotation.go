package postgresql

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/provisioning"
)

func (driver *Driver) StageRotation(ctx context.Context, resource domain.Resource, newGeneration int64) (provisioning.Credential, error) {
	if newGeneration <= resource.CredentialGeneration {
		return provisioning.Credential{}, provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	oldRole, _, err := roleNameForGeneration(resource, resource.CredentialGeneration)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	newRole, databaseName, err := roleNameForGeneration(resource, newGeneration)
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
	oldExists, oldComment, err := readRoleOwner(ctx, adminConn, oldRole)
	if err != nil || !oldExists || oldComment != ownerComment {
		return provisioning.Credential{}, provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
	}
	databaseExists, databaseComment, err := readDatabaseOwner(ctx, adminConn, databaseName)
	if err != nil || !databaseExists || databaseComment != ownerComment {
		return provisioning.Credential{}, provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
	}
	databaseOwner, err := readDatabaseOwnerName(ctx, adminConn, databaseName)
	if err != nil || databaseOwner != oldRole {
		return provisioning.Credential{}, provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
	}
	newExists, newComment, err := readRoleOwner(ctx, adminConn, newRole)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if newExists && newComment != ownerComment {
		return provisioning.Credential{}, provisioning.NewDriverFailure("RESOURCE_NAME_CONFLICT", false)
	}
	roleSQL := "ALTER ROLE " + quoteIdentifier(newRole) + " LOGIN CONNECTION LIMIT " + strconv.Itoa(driver.target.MaxConnectionsPerResource) + " PASSWORD " + quoteLiteral(password)
	if !newExists {
		roleSQL = "CREATE ROLE " + quoteIdentifier(newRole) + " LOGIN CONNECTION LIMIT " + strconv.Itoa(driver.target.MaxConnectionsPerResource) + " PASSWORD " + quoteLiteral(password)
	}
	if _, err := adminConn.Exec(ctx, roleSQL); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	if !newExists {
		if _, err := adminConn.Exec(ctx, "COMMENT ON ROLE "+quoteIdentifier(newRole)+" IS "+quoteLiteral(ownerComment)); err != nil {
			return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
	}
	if _, err := adminConn.Exec(ctx, "GRANT "+quoteIdentifier(oldRole)+" TO "+quoteIdentifier(newRole)); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}

	credential, err := applicationConnectionString(adminConfig.ConnString(), newRole, password, databaseName)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	return provisioning.Credential{Name: "DATABASE_URL", Value: credential}, nil
}

func (driver *Driver) FinalizeRotation(ctx context.Context, resource domain.Resource, oldGeneration int64, newGeneration int64, _ []int64) error {
	oldRole, databaseName, err := roleNameForGeneration(resource, oldGeneration)
	if err != nil {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	newRole, _, err := roleNameForGeneration(resource, newGeneration)
	if err != nil || newGeneration <= oldGeneration {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
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
	newExists, newComment, err := readRoleOwner(ctx, adminConn, newRole)
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if !newExists || newComment != ownerComment {
		return provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
	}
	oldExists, oldComment, err := readRoleOwner(ctx, adminConn, oldRole)
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if oldExists && oldComment != ownerComment {
		return provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
	}
	databaseExists, databaseComment, err := readDatabaseOwner(ctx, adminConn, databaseName)
	if err != nil || !databaseExists || databaseComment != ownerComment {
		return provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
	}
	databaseOwner, err := readDatabaseOwnerName(ctx, adminConn, databaseName)
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if databaseOwner != oldRole && databaseOwner != newRole {
		return provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
	}
	if databaseOwner == oldRole {
		if _, err := adminConn.Exec(ctx, "ALTER DATABASE "+quoteIdentifier(databaseName)+" OWNER TO "+quoteIdentifier(newRole)); err != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
	}

	if oldExists {
		databaseConfig := adminConfig.Copy()
		databaseConfig.Database = databaseName
		databaseConn, err := pgx.ConnectConfig(ctx, databaseConfig)
		if err != nil {
			return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
		}
		_, reassignErr := databaseConn.Exec(ctx, "REASSIGN OWNED BY "+quoteIdentifier(oldRole)+" TO "+quoteIdentifier(newRole))
		closeErr := databaseConn.Close(context.Background())
		if reassignErr != nil || closeErr != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
		if _, err := adminConn.Exec(ctx, "GRANT CONNECT, TEMPORARY ON DATABASE "+quoteIdentifier(databaseName)+" TO "+quoteIdentifier(newRole)); err != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
		if _, err := adminConn.Exec(ctx, "ALTER ROLE "+quoteIdentifier(oldRole)+" NOLOGIN"); err != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
		if _, err := adminConn.Exec(ctx, "SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE usename = $1 AND pid <> pg_catalog.pg_backend_pid()", oldRole); err != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
		if _, err := adminConn.Exec(ctx, "REVOKE "+quoteIdentifier(oldRole)+" FROM "+quoteIdentifier(newRole)); err != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
		if _, err := adminConn.Exec(ctx, "DROP ROLE "+quoteIdentifier(oldRole)); err != nil {
			return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
		}
	}
	return nil
}

func (driver *Driver) AbortRotation(ctx context.Context, resource domain.Resource, generation int64) error {
	roleName, databaseName, err := roleNameForGeneration(resource, generation)
	if err != nil || generation <= resource.CredentialGeneration {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
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
	roleExists, roleComment, err := readRoleOwner(ctx, adminConn, roleName)
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if !roleExists {
		return nil
	}
	if roleComment != ownerCommentPrefix+resource.ID {
		return provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
	}
	databaseOwner, err := readDatabaseOwnerName(ctx, adminConn, databaseName)
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if databaseOwner == roleName {
		return provisioning.NewDriverFailure("RESOURCE_OWNERSHIP_MISMATCH", false)
	}
	if _, err := adminConn.Exec(ctx, "ALTER ROLE "+quoteIdentifier(roleName)+" NOLOGIN"); err != nil {
		return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	if _, err := adminConn.Exec(ctx, "SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE usename = $1 AND pid <> pg_catalog.pg_backend_pid()", roleName); err != nil {
		return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	previousRole, _, err := roleNameForGeneration(resource, resource.CredentialGeneration)
	if err != nil {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	if _, err := adminConn.Exec(ctx, "REVOKE "+quoteIdentifier(previousRole)+" FROM "+quoteIdentifier(roleName)); err != nil {
		return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	if _, err := adminConn.Exec(ctx, "DROP ROLE "+quoteIdentifier(roleName)); err != nil {
		return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	return nil
}

func roleNameForGeneration(resource domain.Resource, generation int64) (string, string, error) {
	baseRole, databaseName, err := objectNames(resource)
	if err != nil || generation < 1 || generation > 9_999_999_999_999 {
		return "", "", errors.New("invalid PostgreSQL credential generation")
	}
	if generation == 1 {
		return baseRole, databaseName, nil
	}
	return baseRole + "_g" + strconv.FormatInt(generation, 10), databaseName, nil
}

func credentialGenerations(resource domain.Resource) []int64 {
	if len(resource.CredentialGenerations) == 0 {
		generation := resource.CredentialGeneration
		if generation < 1 {
			generation = 1
		}
		return []int64{generation}
	}
	result := make([]int64, 0, len(resource.CredentialGenerations))
	seen := make(map[int64]struct{}, len(resource.CredentialGenerations))
	for _, generation := range resource.CredentialGenerations {
		if generation < 1 || generation > 9_999_999_999_999 {
			continue
		}
		if _, exists := seen[generation]; exists {
			continue
		}
		seen[generation] = struct{}{}
		result = append(result, generation)
	}
	if len(result) == 0 {
		return []int64{1}
	}
	for left := 0; left < len(result); left++ {
		for right := left + 1; right < len(result); right++ {
			if result[right] < result[left] {
				result[left], result[right] = result[right], result[left]
			}
		}
	}
	return result
}

func readDatabaseOwnerName(ctx context.Context, connection *pgx.Conn, databaseName string) (string, error) {
	var owner string
	err := connection.QueryRow(ctx, `
		SELECT pg_catalog.pg_get_userbyid(datdba)
		FROM pg_catalog.pg_database WHERE datname = $1
	`, databaseName).Scan(&owner)
	if err != nil {
		return "", err
	}
	return owner, nil
}
