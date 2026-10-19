//go:build integration

package provisioning

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/secrets/ciphera"
)

func TestCipheraBackedProvisioningUsesSafeReferencesAndCompensatesFailures(t *testing.T) {
	t.Run("create and revoke through the production Ciphera client", func(t *testing.T) {
		t.Parallel()

		serviceKey := randomCipheraIntegrationSecret(t)
		accessToken := randomCipheraIntegrationSecret(t)
		generatedCredential := randomCipheraIntegrationSecret(t)
		cipheraAPI := &cipheraProtocolFake{
			serviceKey:   serviceKey,
			accessToken:  accessToken,
			writeStatus:  http.StatusCreated,
			deleteStatus: http.StatusNoContent,
		}
		server := httptest.NewServer(cipheraAPI)
		defer server.Close()

		driver := &cipheraIntegrationDriver{credential: generatedCredential}
		service, store := newCipheraBackedIntegrationService(t, server.URL, serviceKey, driver)
		ctx := identity.WithPrincipal(context.Background(), identity.Principal{
			Subject:   "caller-subject",
			Transport: identity.TransportStdio,
		})
		command := domain.CreateResourceCommand{
			ResourceType:   domain.ResourcePostgreSQL,
			Scope:          domain.Scope{Application: "orders", Environment: "production"},
			IdempotencyKey: "ciphera-create-001",
		}

		created, err := service.Create(ctx, command)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if created.Status != domain.ResourceActive || !strings.HasPrefix(created.SecretReference, "ciphera://") {
			t.Fatalf("created view = %+v, want active resource with a safe reference", created)
		}
		encoded, err := json.Marshal(created)
		if err != nil {
			t.Fatalf("Marshal(created) error = %v", err)
		}
		if strings.Contains(string(encoded), driver.credential) {
			t.Fatal("resource view exposed the generated credential")
		}
		writes, deletes, storedCredential, storedKey := cipheraAPI.snapshot()
		if writes != 1 || deletes != 0 || storedCredential != driver.credential || !strings.HasSuffix(storedKey, "__DATABASE_URL") {
			t.Fatal("Ciphera protocol did not receive the expected scoped secret write")
		}

		revoked, err := service.Revoke(ctx, domain.RevokeResourceCommand{
			ResourceID:   created.ID,
			Confirmation: "revoke:" + created.ID,
		}, "ciphera-revoke-001")
		if err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
		if revoked.Status != domain.ResourceRevoked || revoked.SecretReference != "" || driver.revokeCalls != 1 {
			t.Fatalf("revoke result = %+v; driver revoke calls = %d", revoked, driver.revokeCalls)
		}
		writes, deletes, _, _ = cipheraAPI.snapshot()
		if writes != 1 || deletes != 1 {
			t.Fatalf("Ciphera request counts = writes:%d deletes:%d, want one each", writes, deletes)
		}
		stored, err := store.GetResource(context.Background(), created.ID)
		if err != nil || stored.Status != domain.ResourceRevoked || stored.SecretURI != "" {
			t.Fatalf("stored resource after revoke = %+v, %v", stored, err)
		}
	})

	t.Run("failed Ciphera write compensates target and records safe failure", func(t *testing.T) {
		t.Parallel()

		serviceKey := randomCipheraIntegrationSecret(t)
		accessToken := randomCipheraIntegrationSecret(t)
		generatedCredential := randomCipheraIntegrationSecret(t)
		cipheraAPI := &cipheraProtocolFake{
			serviceKey:   serviceKey,
			accessToken:  accessToken,
			writeStatus:  http.StatusServiceUnavailable,
			deleteStatus: http.StatusNotFound,
		}
		server := httptest.NewServer(cipheraAPI)
		defer server.Close()

		driver := &cipheraIntegrationDriver{credential: generatedCredential}
		service, store := newCipheraBackedIntegrationService(t, server.URL, serviceKey, driver)
		ctx := identity.WithPrincipal(context.Background(), identity.Principal{
			Subject:   "caller-subject",
			Transport: identity.TransportStdio,
		})
		command := domain.CreateResourceCommand{
			ResourceType:   domain.ResourcePostgreSQL,
			Scope:          domain.Scope{Application: "orders", Environment: "production"},
			IdempotencyKey: "ciphera-failure-001",
		}

		_, err := service.Create(ctx, command)
		if !errors.Is(err, ErrProvisioningFailed) || strings.Contains(err.Error(), driver.credential) {
			t.Fatalf("Create() error = %v, want safe ErrProvisioningFailed", err)
		}
		if driver.createCalls != 1 || driver.revokeCalls != 1 {
			t.Fatalf("driver calls = create:%d revoke:%d, want one each", driver.createCalls, driver.revokeCalls)
		}
		writes, deletes, _, _ := cipheraAPI.snapshot()
		if writes != 1 || deletes != 1 {
			t.Fatalf("Ciphera request counts = writes:%d deletes:%d, want one each", writes, deletes)
		}
		operation, err := store.GetOperationByIdempotencyKey(context.Background(), "caller-subject", command.IdempotencyKey)
		if err != nil {
			t.Fatalf("GetOperationByIdempotencyKey() error = %v", err)
		}
		resource, err := store.GetResource(context.Background(), operation.ResourceID)
		if err != nil || resource.Status != domain.ResourceFailed || resource.ErrorCode != "SECRET_STORE_UNAVAILABLE" {
			t.Fatalf("resource after compensated failure = %+v, %v", resource, err)
		}
	})

	t.Run("failed secret cleanup and target cleanup require reconciliation", func(t *testing.T) {
		t.Parallel()

		serviceKey := randomCipheraIntegrationSecret(t)
		accessToken := randomCipheraIntegrationSecret(t)
		generatedCredential := randomCipheraIntegrationSecret(t)
		cipheraAPI := &cipheraProtocolFake{
			serviceKey:   serviceKey,
			accessToken:  accessToken,
			writeStatus:  http.StatusServiceUnavailable,
			deleteStatus: http.StatusServiceUnavailable,
		}
		server := httptest.NewServer(cipheraAPI)
		defer server.Close()

		driver := &cipheraIntegrationDriver{
			credential: generatedCredential,
			revokeErr:  errors.New("test-only target cleanup failure"),
		}
		service, store := newCipheraBackedIntegrationService(t, server.URL, serviceKey, driver)
		ctx := identity.WithPrincipal(context.Background(), identity.Principal{
			Subject:   "caller-subject",
			Transport: identity.TransportStdio,
		})
		command := domain.CreateResourceCommand{
			ResourceType:   domain.ResourcePostgreSQL,
			Scope:          domain.Scope{Application: "orders", Environment: "production"},
			IdempotencyKey: "ciphera-reconcile-001",
		}

		_, err := service.Create(ctx, command)
		if !errors.Is(err, ErrReconciliationRequired) || strings.Contains(err.Error(), driver.credential) {
			t.Fatalf("Create() error = %v, want safe ErrReconciliationRequired", err)
		}
		operation, err := store.GetOperationByIdempotencyKey(context.Background(), "caller-subject", command.IdempotencyKey)
		if err != nil {
			t.Fatalf("GetOperationByIdempotencyKey() error = %v", err)
		}
		resource, err := store.GetResource(context.Background(), operation.ResourceID)
		if err != nil || resource.Status != domain.ResourceReconciliation || resource.ErrorCode != "COMPENSATION_FAILED" {
			t.Fatalf("resource after failed compensation = %+v, %v", resource, err)
		}
	})
}

func newCipheraBackedIntegrationService(
	t *testing.T,
	apiURL string,
	serviceKey string,
	driver *cipheraIntegrationDriver,
) (*Service, interface {
	GetOperationByIdempotencyKey(context.Context, string, string) (domain.Operation, error)
	GetResource(context.Context, string) (domain.Resource, error)
}) {
	t.Helper()

	store := openTestStore(t)
	grantTestActions(t, store, authorization.ActionCreateResource, authorization.ActionRevokeResource)
	authorizer, err := authorization.NewPersistentAuthorizer(store)
	if err != nil {
		t.Fatalf("NewPersistentAuthorizer() error = %v", err)
	}
	secretStore, err := ciphera.NewStore(config.CipheraFile{
		APIURL:          apiURL,
		ProjectIDsByEnv: map[string]string{"production": "project-test"},
	}, []byte(serviceKey), nil)
	if err != nil {
		t.Fatalf("ciphera.NewStore() error = %v", err)
	}
	t.Cleanup(secretStore.Close)
	service, err := NewService(store, authorizer, store, secretStore, []Target{{
		ID:                      "postgres-test",
		ResourceType:            domain.ResourcePostgreSQL,
		MaxResources:            10,
		MaxConcurrentOperations: 2,
		Driver:                  driver,
	}})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service, store
}

type cipheraIntegrationDriver struct {
	credential  string
	createCalls int
	revokeCalls int
	revokeErr   error
}

func (driver *cipheraIntegrationDriver) Create(_ context.Context, resource domain.Resource) (Credential, error) {
	driver.createCalls++
	return Credential{Name: credentialName(resource.ResourceType), Value: []byte(driver.credential)}, nil
}

func (driver *cipheraIntegrationDriver) Revoke(context.Context, domain.Resource) error {
	driver.revokeCalls++
	return driver.revokeErr
}

func (driver *cipheraIntegrationDriver) StageRotation(_ context.Context, resource domain.Resource, _ int64) (Credential, error) {
	return Credential{Name: credentialName(resource.ResourceType), Value: []byte(driver.credential)}, nil
}

func (driver *cipheraIntegrationDriver) FinalizeRotation(context.Context, domain.Resource, int64, int64, []int64) error {
	return driver.revokeErr
}

func (driver *cipheraIntegrationDriver) AbortRotation(context.Context, domain.Resource, int64) error {
	return nil
}

type cipheraProtocolFake struct {
	mu            sync.Mutex
	serviceKey    string
	accessToken   string
	writeStatus   int
	deleteStatus  int
	secretWrites  int
	secretDeletes int
	secretValue   string
	secretKey     string
}

func (fake *cipheraProtocolFake) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/auth/service-account/token":
		if request.Header.Get("Authorization") != "Bearer "+fake.serviceKey {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"access_token": fake.accessToken,
			"token_type":   "Bearer",
			"expires_in":   60,
		})
	case request.Method == http.MethodPost && request.URL.Path == "/v1/projects/project-test/secrets/batch":
		if request.Header.Get("Authorization") != "Bearer "+fake.accessToken {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, maxCipheraIntegrationBodyBytes))
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var payload struct {
			Environment string `json:"environment"`
			Secrets     []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"secrets"`
		}
		if json.Unmarshal(body, &payload) != nil || payload.Environment != "production" || len(payload.Secrets) != 1 {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		fake.mu.Lock()
		fake.secretWrites++
		fake.secretKey = payload.Secrets[0].Key
		fake.secretValue = payload.Secrets[0].Value
		fake.mu.Unlock()
		writer.WriteHeader(fake.writeStatus)
	case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/v1/projects/project-test/secrets/production/"):
		if request.Header.Get("Authorization") != "Bearer "+fake.accessToken {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		fake.mu.Lock()
		fake.secretDeletes++
		fake.mu.Unlock()
		writer.WriteHeader(fake.deleteStatus)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (fake *cipheraProtocolFake) snapshot() (int, int, string, string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.secretWrites, fake.secretDeletes, fake.secretValue, fake.secretKey
}

const maxCipheraIntegrationBodyBytes = 64 << 10

func randomCipheraIntegrationSecret(t *testing.T) string {
	t.Helper()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
