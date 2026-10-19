package natsdriver

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/provisioning"
	"github.com/nats-io/nkeys"
)

func (driver *Driver) StageRotation(ctx context.Context, resource domain.Resource, newGeneration int64) (provisioning.Credential, error) {
	if newGeneration <= resource.CredentialGeneration {
		return provisioning.Credential{}, provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	operatorSeed, err := driver.copyOperatorSeed()
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer clear(operatorSeed)
	operatorKey, err := nkeys.FromSeed(operatorSeed)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer operatorKey.Wipe()
	accountKey, userKey, err := deriveResourceKeysForGeneration(operatorSeed, resource, newGeneration)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	defer accountKey.Wipe()
	defer userKey.Wipe()
	accountPublic, err := accountKey.PublicKey()
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	credential, err := makeUserCredential(driver.target, resource, accountKey, userKey, accountPublic)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	accountJWT, err := driver.encodeGenerationClaims(operatorKey, accountKey, resource, resource.CredentialGenerations, resource.CredentialGeneration, newGeneration)
	if err != nil {
		clear(credential.Value)
		return provisioning.Credential{}, provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	if err := driver.publishAccountClaims(ctx, accountJWT); err != nil {
		clear(credential.Value)
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	return credential, nil
}

func (driver *Driver) FinalizeRotation(ctx context.Context, resource domain.Resource, oldGeneration int64, newGeneration int64, allGenerations []int64) error {
	if oldGeneration < 1 || newGeneration <= oldGeneration {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	operatorKey, accountKey, err := driver.rotationSigningKeys(resource)
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer operatorKey.Wipe()
	defer accountKey.Wipe()
	generations := normalizedGenerations(allGenerations, oldGeneration, newGeneration)
	accountJWT, err := driver.encodeGenerationClaims(operatorKey, accountKey, resource, generations, newGeneration)
	if err != nil {
		return provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	if err := driver.publishAccountClaims(ctx, accountJWT); err != nil {
		return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	return nil
}

func (driver *Driver) AbortRotation(ctx context.Context, resource domain.Resource, generation int64) error {
	if generation <= resource.CredentialGeneration || generation < 2 {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	operatorKey, accountKey, err := driver.rotationSigningKeys(resource)
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer operatorKey.Wipe()
	defer accountKey.Wipe()
	accountJWT, err := driver.encodeGenerationClaims(operatorKey, accountKey, resource, resource.CredentialGenerations, resource.CredentialGeneration)
	if err != nil {
		return provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	if err := driver.publishAccountClaims(ctx, accountJWT); err != nil {
		return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	return nil
}

func (driver *Driver) rotationSigningKeys(resource domain.Resource) (nkeys.KeyPair, nkeys.KeyPair, error) {
	operatorSeed, err := driver.copyOperatorSeed()
	if err != nil {
		return nil, nil, err
	}
	defer clear(operatorSeed)
	operatorKey, err := nkeys.FromSeed(operatorSeed)
	if err != nil {
		return nil, nil, err
	}
	accountKey, _, err := deriveResourceKeys(operatorSeed, resource)
	if err != nil {
		operatorKey.Wipe()
		return nil, nil, err
	}
	return operatorKey, accountKey, nil
}

func (driver *Driver) encodeGenerationClaims(operatorKey nkeys.KeyPair, accountKey nkeys.KeyPair, resource domain.Resource, generations []int64, retainedGenerations ...int64) (string, error) {
	accountPublic, err := accountKey.PublicKey()
	if err != nil {
		return "", err
	}
	operatorSeed, err := driver.copyOperatorSeed()
	if err != nil {
		return "", err
	}
	defer clear(operatorSeed)
	retained := make(map[int64]struct{}, len(retainedGenerations))
	for _, generation := range retainedGenerations {
		retained[generation] = struct{}{}
	}
	revokedUsers := make([]string, 0, len(generations))
	seen := make(map[int64]struct{}, len(generations))
	for _, generation := range generations {
		if generation < 1 {
			continue
		}
		if _, keep := retained[generation]; keep {
			continue
		}
		if _, exists := seen[generation]; exists {
			continue
		}
		seen[generation] = struct{}{}
		_, userKey, err := deriveResourceKeysForGeneration(operatorSeed, resource, generation)
		if err != nil {
			return "", err
		}
		userPublic, err := userKey.PublicKey()
		userKey.Wipe()
		if err != nil {
			return "", err
		}
		revokedUsers = append(revokedUsers, userPublic)
	}
	claims := buildAccountClaimsWithRevocations(driver.target, resource, accountPublic, revokedUsers, time.Now().UTC())
	return claims.Encode(operatorKey)
}

func deriveResourceKeysForGeneration(operatorSeed []byte, resource domain.Resource, generation int64) (nkeys.KeyPair, nkeys.KeyPair, error) {
	if resource.ID == "" || resource.ResourceType != domain.ResourceNATS || !domain.ValidScopeName(resource.Scope.Application) || !domain.ValidScopeName(resource.Scope.Environment) || generation < 1 || generation > 9_999_999_999_999 {
		return nil, nil, errors.New("invalid NATS resource credential generation")
	}
	accountSeed := deriveSeed(operatorSeed, accountKeyPurpose, resource.ID)
	userSeedIdentity := resource.ID
	if generation > 1 {
		userSeedIdentity += "\x00generation:" + strconv.FormatInt(generation, 10)
	}
	userSeed := deriveSeed(operatorSeed, userKeyPurpose, userSeedIdentity)
	defer clear(accountSeed)
	defer clear(userSeed)
	accountKey, err := nkeys.FromRawSeed(nkeys.PrefixByteAccount, accountSeed)
	if err != nil {
		return nil, nil, err
	}
	userKey, err := nkeys.FromRawSeed(nkeys.PrefixByteUser, userSeed)
	if err != nil {
		accountKey.Wipe()
		return nil, nil, err
	}
	return accountKey, userKey, nil
}

func makeUserCredential(target config.Target, resource domain.Resource, accountKey nkeys.KeyPair, userKey nkeys.KeyPair, accountPublic string) (provisioning.Credential, error) {
	userPublic, err := userKey.PublicKey()
	if err != nil {
		return provisioning.Credential{}, err
	}
	userClaims := buildUserClaims(resource, accountPublic, userPublic, target)
	userJWT, err := userClaims.Encode(accountKey)
	if err != nil {
		return provisioning.Credential{}, err
	}
	userSeed, err := userKey.Seed()
	if err != nil {
		return provisioning.Credential{}, err
	}
	defer clear(userSeed)
	return provisioning.Credential{Name: "NATS_CREDENTIALS", Value: encodeCredentials(userJWT, userSeed)}, nil
}

func normalizedGenerations(values []int64, oldGeneration int64, newGeneration int64) []int64 {
	seen := make(map[int64]struct{}, len(values)+2)
	result := make([]int64, 0, len(values)+2)
	for _, generation := range values {
		if generation < 1 {
			continue
		}
		if _, exists := seen[generation]; exists {
			continue
		}
		seen[generation] = struct{}{}
		result = append(result, generation)
	}
	for _, generation := range []int64{oldGeneration, newGeneration} {
		if _, exists := seen[generation]; exists {
			continue
		}
		seen[generation] = struct{}{}
		result = append(result, generation)
	}
	return result
}

func credentialGenerations(resource domain.Resource) []int64 {
	if len(resource.CredentialGenerations) == 0 {
		generation := resource.CredentialGeneration
		if generation < 1 {
			generation = 1
		}
		return []int64{generation}
	}
	return normalizedGenerations(resource.CredentialGenerations, resource.CredentialGeneration, resource.CredentialGeneration)
}
