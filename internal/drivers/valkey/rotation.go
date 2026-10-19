package valkey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/provisioning"
)

func (driver *Driver) StageRotation(ctx context.Context, resource domain.Resource, newGeneration int64) (provisioning.Credential, error) {
	if newGeneration <= resource.CredentialGeneration {
		return provisioning.Credential{}, provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	username, keyPattern, channelPattern, err := resourceNamesForGeneration(resource, newGeneration)
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
	client, endpointURL, err := driver.adminClient()
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer func() {
		_ = client.Close()
	}()
	if err := client.Ping(ctx).Err(); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_UNAVAILABLE", false)
	}
	arguments := aclSetUserArguments(driver.target.AllowedValkeyCommands, username, password, keyPattern, channelPattern)
	if err := client.Do(ctx, arguments...).Err(); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	endpointURL.User = url.UserPassword(username, password)
	return provisioning.Credential{Name: "VALKEY_URL", Value: []byte(endpointURL.String())}, nil
}

func (driver *Driver) FinalizeRotation(ctx context.Context, resource domain.Resource, oldGeneration int64, newGeneration int64, _ []int64) error {
	if oldGeneration < 1 || newGeneration <= oldGeneration {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	oldUsername, _, _, err := resourceNamesForGeneration(resource, oldGeneration)
	if err != nil {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	client, _, err := driver.adminClient()
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer func() {
		_ = client.Close()
	}()
	if err := client.Ping(ctx).Err(); err != nil {
		return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if err := client.Do(ctx, "ACL", "DELUSER", oldUsername).Err(); err != nil {
		return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	return nil
}

func (driver *Driver) AbortRotation(ctx context.Context, resource domain.Resource, generation int64) error {
	if generation <= resource.CredentialGeneration || generation < 2 {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	username, _, _, err := resourceNamesForGeneration(resource, generation)
	if err != nil {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	client, _, err := driver.adminClient()
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer func() {
		_ = client.Close()
	}()
	if err := client.Ping(ctx).Err(); err != nil {
		return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if err := client.Do(ctx, "ACL", "DELUSER", username).Err(); err != nil {
		return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	return nil
}

func resourceNamesForGeneration(resource domain.Resource, generation int64) (string, string, string, error) {
	username, keyPattern, channelPattern, err := resourceNames(resource)
	if err != nil || generation < 1 || generation > 9_999_999_999_999 {
		return "", "", "", errors.New("invalid Valkey credential generation")
	}
	if generation == 1 {
		return username, keyPattern, channelPattern, nil
	}
	return username + "_g" + strconv.FormatInt(generation, 10), keyPattern, channelPattern, nil
}

func credentialGenerations(resource domain.Resource) []int64 {
	if len(resource.CredentialGenerations) == 0 {
		generation := resource.CredentialGeneration
		if generation < 1 {
			generation = 1
		}
		return []int64{generation}
	}
	seen := make(map[int64]struct{}, len(resource.CredentialGenerations))
	result := make([]int64, 0, len(resource.CredentialGenerations))
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
