package valkey

import (
	"crypto/rand"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

func TestResourceNamesUseDistinctUserAndScopedKeyChannelPrefixes(t *testing.T) {
	t.Parallel()

	resource := domain.Resource{
		ID:           "resource-id-001",
		ResourceType: domain.ResourceValkey,
		Scope:        domain.Scope{Application: "orders", Environment: "production"},
	}
	username, keyPattern, channelPattern, err := resourceNames(resource)
	if err != nil {
		t.Fatalf("resourceNames() error = %v", err)
	}
	if !strings.HasPrefix(username, "srp_") || !strings.HasPrefix(keyPattern, "~srp:") || !strings.HasPrefix(channelPattern, "&srp:") {
		t.Fatal("resource ACL names and patterns do not use their expected namespaces")
	}
	if strings.TrimPrefix(keyPattern, "~") != strings.TrimPrefix(channelPattern, "&") {
		t.Fatal("Valkey key and channel ACLs do not share the same scope prefix")
	}
}

func TestACLArgumentsContainOnlyScopedRulesAndAllowedCommands(t *testing.T) {
	t.Parallel()

	password := randomCredential(t)
	arguments := aclSetUserArguments([]string{"get", "set"}, "srp_user", password, "~srp:scope:*", "&srp:scope:*")
	if len(arguments) != 10 {
		t.Fatalf("ACL argument count = %d, want 10", len(arguments))
	}
	if arguments[0] != "ACL" || arguments[1] != "SETUSER" || arguments[2] != "srp_user" || arguments[3] != "reset" || arguments[4] != "on" || arguments[6] != "~srp:scope:*" || arguments[7] != "&srp:scope:*" || arguments[8] != "+get" || arguments[9] != "+set" {
		t.Fatal("ACL command contains unexpected identity, scope, or command rules")
	}
	if arguments[5] != ">"+password {
		t.Fatal("ACL command did not receive the generated credential")
	}
}

func TestNewRequiresTLSForRemoteTargetAndRejectsQueryCredentials(t *testing.T) {
	t.Parallel()

	endpoint := []byte("redis://admin@valkey.example.test:6379/0")
	if _, err := New(validTarget(), endpoint); err == nil {
		t.Fatal("New() accepted a non-TLS remote Valkey target")
	}

	password := randomCredential(t)
	endpointURL := url.URL{
		Scheme:   "rediss",
		Host:     "valkey.example.test:6379",
		User:     url.UserPassword("admin", password),
		RawQuery: "token=" + url.QueryEscape(password),
	}
	encoded := []byte(endpointURL.String())
	if _, err := New(validTarget(), encoded); err == nil {
		t.Fatal("New() accepted a target URL with a credential in its query")
	}
	clear(encoded)
}

func TestNewAcceptsLoopbackPlaintextForIsolatedTests(t *testing.T) {
	t.Parallel()

	password := randomCredential(t)
	endpointURL := url.URL{
		Scheme: "redis",
		Host:   "127.0.0.1:6379",
		User:   url.UserPassword("admin", password),
		Path:   "/0",
	}
	endpoint := []byte(endpointURL.String())
	driver, err := New(validTarget(), endpoint)
	if err != nil {
		t.Fatalf("New(loopback) error = %v", err)
	}
	driver.Close()
	clear(endpoint)
}

func validTarget() config.Target {
	return config.Target{
		ResourceType:            domain.ResourceValkey,
		MaxResources:            10,
		MaxConcurrentOperations: 2,
		AllowedValkeyCommands:   []string{"get", "set"},
	}
}

func randomCredential(t *testing.T) string {
	t.Helper()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	return value
}
