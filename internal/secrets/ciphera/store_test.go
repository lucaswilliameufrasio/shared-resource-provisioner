package ciphera

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
	"testing"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/secrets"
)

func TestStoreWritesOnlyToMappedCipheraProjectAndDeletesByReference(t *testing.T) {
	t.Parallel()

	serviceKey := randomCredential(t, 32)
	accessToken := randomCredential(t, 32)
	credential := randomCredential(t, 48)
	serviceKeyString := string(serviceKey)
	accessTokenString := string(accessToken)
	credentialString := string(credential)
	defer clear(serviceKey)
	defer clear(accessToken)
	defer clear(credential)

	var tokenExchanges int
	var secretWrites int
	var secretDeletes int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/auth/service-account/token":
			tokenExchanges++
			if request.Header.Get("Authorization") != "Bearer "+serviceKeyString {
				t.Errorf("token exchange authorization header was incorrect")
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"access_token":       accessTokenString,
				"token_type":         "Bearer",
				"expires_in":         600,
				"tenant_id":          "tenant-test",
				"service_account_id": "account-test",
			})
		case request.Method == http.MethodPost && request.URL.Path == "/v1/projects/project-123/secrets/batch":
			secretWrites++
			if request.Header.Get("Authorization") != "Bearer "+accessTokenString {
				t.Errorf("batch write authorization header was incorrect")
			}
			body, err := io.ReadAll(io.LimitReader(request.Body, maxCipheraBodyBytes))
			if err != nil {
				t.Errorf("read batch body failed")
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
			if err := json.Unmarshal(body, &payload); err != nil || payload.Environment != "production" || len(payload.Secrets) != 1 {
				t.Errorf("batch write request shape was incorrect")
			} else {
				secret := payload.Secrets[0]
				if !strings.HasPrefix(secret.Key, "SRP_") || !strings.HasSuffix(secret.Key, "__DATABASE_URL") || secret.Value != credentialString {
					t.Errorf("batch write did not preserve the scoped key and value")
				}
				payload.Secrets[0].Value = ""
			}
			clear(body)
			writer.WriteHeader(http.StatusCreated)
		case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/v1/projects/project-123/secrets/production/"):
			secretDeletes++
			if request.Header.Get("Authorization") != "Bearer "+accessTokenString {
				t.Errorf("delete authorization header was incorrect")
			}
			writer.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected Ciphera request method or path")
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	store, err := NewStore(config.CipheraFile{
		APIURL:          server.URL,
		ProjectIDsByEnv: map[string]string{"production": "project-123"},
	}, serviceKey, server.Client())
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer store.Close()

	scope := domain.Scope{Application: "orders", Environment: "production"}
	plannedReference, err := store.ReferenceFor(scope, "DATABASE_URL")
	if err != nil {
		t.Fatalf("ReferenceFor() error = %v", err)
	}
	if _, _, _, err := parseReference(plannedReference); err != nil {
		t.Fatalf("parseReference() error = %v", err)
	}
	reference, err := store.Put(context.Background(), scope, "DATABASE_URL", credential)
	if err != nil {
		t.Fatalf("Put() error = %v (token exchanges: %d, writes: %d)", err, tokenExchanges, secretWrites)
	}
	if err := secrets.ValidateReference(reference); err != nil {
		t.Fatalf("Put() returned invalid reference: %v", err)
	}
	if strings.Contains(reference.URI, credentialString) {
		t.Fatal("secret reference contains credential material")
	}
	if err := store.Delete(context.Background(), reference); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if tokenExchanges != 2 || secretWrites != 1 || secretDeletes != 1 {
		t.Fatalf("Ciphera request counts = exchanges:%d writes:%d deletes:%d", tokenExchanges, secretWrites, secretDeletes)
	}
}

func TestStoreFailsClosedWithoutEchoingServiceErrors(t *testing.T) {
	t.Parallel()

	serviceKey := randomCredential(t, 32)
	serviceKeyString := string(serviceKey)
	defer clear(serviceKey)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+serviceKeyString {
			t.Errorf("service-key header was not sent to the token endpoint")
		}
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, serviceKeyString)
	}))
	defer server.Close()
	store, err := NewStore(config.CipheraFile{
		APIURL:          server.URL,
		ProjectIDsByEnv: map[string]string{"production": "project-123"},
	}, serviceKey, server.Client())
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer store.Close()

	value := randomCredential(t, 32)
	defer clear(value)
	_, err = store.Put(context.Background(), domain.Scope{Application: "orders", Environment: "production"}, "DATABASE_URL", value)
	if !errors.Is(err, ErrCipheraUnavailable) {
		t.Fatalf("Put() error = %v, want ErrCipheraUnavailable", err)
	}
	if strings.Contains(err.Error(), serviceKeyString) {
		t.Fatal("Ciphera error reflected the service key")
	}
}

func TestStoreRejectsInvalidSecretBytesAndUnmappedEnvironment(t *testing.T) {
	t.Parallel()

	serviceKey := randomCredential(t, 32)
	defer clear(serviceKey)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("invalid request unexpectedly reached Ciphera")
	}))
	defer server.Close()
	store, err := NewStore(config.CipheraFile{
		APIURL:          server.URL,
		ProjectIDsByEnv: map[string]string{"production": "project-123"},
	}, serviceKey, server.Client())
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer store.Close()

	_, err = store.Put(context.Background(), domain.Scope{Application: "orders", Environment: "production"}, "DATABASE_URL", []byte{0xff})
	if !errors.Is(err, ErrInvalidSecretValue) {
		t.Fatalf("Put(invalid bytes) error = %v, want ErrInvalidSecretValue", err)
	}
	_, err = store.ReferenceFor(domain.Scope{Application: "orders", Environment: "staging"}, "DATABASE_URL")
	if !errors.Is(err, secrets.ErrInvalidReference) {
		t.Fatalf("ReferenceFor(unmapped environment) error = %v, want invalid reference", err)
	}
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()

	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	return value
}

func randomCredential(t *testing.T, size int) []byte {
	t.Helper()

	raw := randomBytes(t, size)
	encoded := []byte(base64.RawURLEncoding.EncodeToString(raw))
	clear(raw)
	return encoded
}
