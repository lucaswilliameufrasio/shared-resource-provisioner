//go:build integration

package valkey

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/redis/go-redis/v9"
)

func TestDriverScopesACLKeysCommandsAndRevokesLocally(t *testing.T) {
	endpoint := os.Getenv("SRP_TEST_VALKEY_URL")
	if endpoint == "" {
		t.Skip("SRP_TEST_VALKEY_URL is not set")
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil || parsedEndpoint.Host == "" || !isLoopback(parsedEndpoint.Hostname()) {
		t.Fatal("Valkey integration tests require a loopback target")
	}
	if err := waitForValkey(endpoint); err != nil {
		t.Fatal("local Valkey test service did not become ready")
	}
	driver, err := New(integrationTarget(), []byte(endpoint))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer driver.Close()

	firstResource := domain.Resource{
		ID:           "local-valkey-resource-one",
		ResourceType: domain.ResourceValkey,
		Scope:        domain.Scope{Application: "orders", Environment: "test"},
	}
	firstCredential, err := driver.Create(context.Background(), firstResource)
	if err != nil {
		t.Fatalf("Create(first resource) error = %v", err)
	}
	defer clear(firstCredential.Value)
	firstClient := newResourceClient(t, firstCredential.Value)
	defer firstClient.Close()
	_, keyPattern, _, err := resourceNames(firstResource)
	if err != nil {
		t.Fatalf("resourceNames(first) error = %v", err)
	}
	firstKey := strings.TrimSuffix(strings.TrimPrefix(keyPattern, "~"), "*") + "probe"
	if err := firstClient.Set(context.Background(), firstKey, "isolated-test", time.Minute).Err(); err != nil {
		t.Fatal("application ACL could not write a key within its scope")
	}
	if value, err := firstClient.Get(context.Background(), firstKey).Result(); err != nil || value != "isolated-test" {
		t.Fatal("application ACL could not read its scoped key")
	}
	if err := firstClient.Do(context.Background(), "ACL", "WHOAMI").Err(); err == nil {
		t.Fatal("application ACL unexpectedly allowed an administrative command")
	}

	secondResource := domain.Resource{
		ID:           "local-valkey-resource-two",
		ResourceType: domain.ResourceValkey,
		Scope:        domain.Scope{Application: "billing", Environment: "test"},
	}
	secondCredential, err := driver.Create(context.Background(), secondResource)
	if err != nil {
		t.Fatalf("Create(second resource) error = %v", err)
	}
	secondClient := newResourceClient(t, secondCredential.Value)
	defer secondClient.Close()
	clear(secondCredential.Value)
	if err := secondClient.Get(context.Background(), firstKey).Err(); err == nil {
		t.Fatal("a distinct application scope could read another scope's key")
	}

	if err := firstClient.Close(); err != nil {
		t.Fatal("application Valkey connection could not be closed")
	}
	if err := driver.Revoke(context.Background(), firstResource); err != nil {
		t.Fatalf("Revoke(first resource) error = %v", err)
	}
	revokedClient := newResourceClient(t, firstCredential.Value)
	defer revokedClient.Close()
	if err := revokedClient.Get(context.Background(), firstKey).Err(); err == nil {
		t.Fatal("Valkey accepted the resource credential after ACL revocation")
	}
	if err := driver.Revoke(context.Background(), firstResource); err != nil {
		t.Fatalf("Revoke(retry) error = %v", err)
	}
}

func newResourceClient(t *testing.T, credential []byte) *redis.Client {
	t.Helper()
	options, err := redis.ParseURL(string(credential))
	if err != nil {
		t.Fatal("generated Valkey credential could not be parsed")
	}
	client := redis.NewClient(options)
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}

func waitForValkey(endpoint string) error {
	options, err := redis.ParseURL(endpoint)
	if err != nil {
		return err
	}
	options.MaxRetries = -1
	options.DialTimeout = 500 * time.Millisecond
	options.ReadTimeout = time.Second
	options.WriteTimeout = time.Second
	options.PoolSize = 1
	options.MaxActiveConns = 1
	client := redis.NewClient(options)
	defer func() {
		_ = client.Close()
	}()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := client.Ping(ctx).Err()
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return context.DeadlineExceeded
}

func integrationTarget() config.Target {
	return config.Target{
		ID:                      "valkey-integration",
		ResourceType:            domain.ResourceValkey,
		MaxResources:            10,
		MaxConcurrentOperations: 2,
		AllowedValkeyCommands:   []string{"get", "set", "del"},
	}
}
