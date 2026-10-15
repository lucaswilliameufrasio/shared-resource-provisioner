package ciphera

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/secrets"
)

const (
	maxSecretValueBytes = 16 << 10
	maxCipheraBodyBytes = 64 << 10
)

var (
	ErrCipheraUnavailable = errors.New("CIPHERA_UNAVAILABLE")
	ErrInvalidSecretValue = errors.New("INVALID_SECRET_VALUE")
)

type Store struct {
	baseURL  *url.URL
	key      []byte
	projects map[string]string
	client   *http.Client
	closeMu  sync.Mutex
	closed   bool
}

func NewStore(settings config.CipheraFile, serviceKey []byte, client *http.Client) (*Store, error) {
	serviceKey = bytes.TrimSpace(serviceKey)
	if len(serviceKey) == 0 || len(settings.ProjectIDsByEnv) == 0 {
		return nil, errors.New("secret-store settings and service key are required")
	}
	baseURL, err := url.Parse(settings.APIURL)
	if err != nil || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("secret-store API URL is invalid")
	}
	switch baseURL.Scheme {
	case "https":
	case "http":
		if !isLoopback(baseURL.Hostname()) {
			return nil, errors.New("secret-store API URL must use HTTPS except on loopback")
		}
	default:
		return nil, errors.New("secret-store API URL must use HTTPS except on loopback")
	}
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if clientCopy.Timeout <= 0 {
		clientCopy.Timeout = 10 * time.Second
	}
	client = &clientCopy
	projects := make(map[string]string, len(settings.ProjectIDsByEnv))
	for environment, projectID := range settings.ProjectIDsByEnv {
		if !domain.ValidScopeName(environment) || !validProjectID(projectID) {
			return nil, errors.New("secret-store project mapping is invalid")
		}
		projects[environment] = projectID
	}
	return &Store{
		baseURL:  baseURL,
		key:      bytes.Clone(serviceKey),
		projects: projects,
		client:   client,
	}, nil
}

func (store *Store) Close() {
	store.closeMu.Lock()
	defer store.closeMu.Unlock()
	clear(store.key)
	store.key = nil
	store.closed = true
}

func (store *Store) ReferenceFor(scope domain.Scope, name string) (secrets.Reference, error) {
	projectID, ok := store.projects[scope.Environment]
	if !ok {
		return secrets.Reference{}, secrets.ErrInvalidReference
	}
	key, err := keyName(scope, name)
	if err != nil {
		return secrets.Reference{}, err
	}
	return secrets.NewReference(projectID, scope, key)
}

func (store *Store) Put(ctx context.Context, scope domain.Scope, name string, value []byte) (secrets.Reference, error) {
	if len(value) == 0 || len(value) > maxSecretValueBytes || !utf8.Valid(value) {
		return secrets.Reference{}, ErrInvalidSecretValue
	}
	reference, err := store.ReferenceFor(scope, name)
	if err != nil {
		return secrets.Reference{}, err
	}
	projectID, environment, key, err := parseReference(reference)
	if err != nil {
		return secrets.Reference{}, secrets.ErrInvalidReference
	}
	accessToken, err := store.exchangeServiceKey(ctx)
	if err != nil {
		return secrets.Reference{}, err
	}
	defer clear(accessToken)

	payload := struct {
		Environment string `json:"environment"`
		Secrets     []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"secrets"`
	}{Environment: environment}
	payload.Secrets = append(payload.Secrets, struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}{Key: key, Value: string(value)})
	body, err := json.Marshal(payload)
	if err != nil {
		return secrets.Reference{}, ErrCipheraUnavailable
	}
	defer clear(body)
	payload.Secrets[0].Value = ""

	endpoint := store.endpoint("/v1/projects/" + url.PathEscape(projectID) + "/secrets/batch")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return secrets.Reference{}, ErrCipheraUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+string(accessToken))
	request.Header.Set("Content-Type", "application/json")
	response, err := store.client.Do(request)
	if err != nil {
		return secrets.Reference{}, ErrCipheraUnavailable
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxCipheraBodyBytes))
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusCreated {
		return secrets.Reference{}, ErrCipheraUnavailable
	}
	return reference, nil
}

func (store *Store) Delete(ctx context.Context, reference secrets.Reference) error {
	projectID, environment, key, err := parseReference(reference)
	if err != nil {
		return secrets.ErrInvalidReference
	}
	if store.projects[environment] != projectID {
		return secrets.ErrInvalidReference
	}
	accessToken, err := store.exchangeServiceKey(ctx)
	if err != nil {
		return err
	}
	defer clear(accessToken)

	endpoint := store.endpoint("/v1/projects/" + url.PathEscape(projectID) + "/secrets/" + url.PathEscape(environment) + "/" + url.PathEscape(key))
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return ErrCipheraUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+string(accessToken))
	response, err := store.client.Do(request)
	if err != nil {
		return ErrCipheraUnavailable
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxCipheraBodyBytes))
		_ = response.Body.Close()
	}()
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusOK {
		return nil
	}
	return ErrCipheraUnavailable
}

func (store *Store) exchangeServiceKey(ctx context.Context) ([]byte, error) {
	store.closeMu.Lock()
	if store.closed || len(store.key) == 0 {
		store.closeMu.Unlock()
		return nil, ErrCipheraUnavailable
	}
	key := append([]byte(nil), store.key...)
	store.closeMu.Unlock()
	defer clear(key)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, store.endpoint("/v1/auth/service-account/token"), nil)
	if err != nil {
		return nil, ErrCipheraUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+string(key))
	response, err := store.client.Do(request)
	if err != nil {
		return nil, ErrCipheraUnavailable
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxCipheraBodyBytes))
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return nil, ErrCipheraUnavailable
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxCipheraBodyBytes))
	if err := decoder.Decode(&token); err != nil || token.AccessToken == "" || len(token.AccessToken) > 8192 || !strings.EqualFold(token.TokenType, "bearer") || token.ExpiresIn <= 0 {
		token.AccessToken = ""
		return nil, ErrCipheraUnavailable
	}
	accessToken := []byte(token.AccessToken)
	token.AccessToken = ""
	return accessToken, nil
}

func (store *Store) endpoint(path string) string {
	base := *store.baseURL
	base.Path = strings.TrimRight(base.Path, "/") + path
	base.RawPath = ""
	return base.String()
}

func keyName(scope domain.Scope, name string) (string, error) {
	if !domain.ValidScopeName(scope.Application) || !domain.ValidScopeName(scope.Environment) || !secrets.ValidName(name) {
		return "", secrets.ErrInvalidReference
	}
	scopeHash := sha256.Sum256([]byte(scope.Application + "\x00" + scope.Environment))
	key := "SRP_" + strings.ToUpper(hex.EncodeToString(scopeHash[:16])) + "__" + name
	if len(key) > 64 {
		return "", secrets.ErrInvalidReference
	}
	return key, nil
}

func parseReference(reference secrets.Reference) (string, string, string, error) {
	if err := secrets.ValidateReference(reference); err != nil {
		return "", "", "", err
	}
	parsed, err := url.Parse(reference.URI)
	if err != nil {
		return "", "", "", err
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) != 5 {
		return "", "", "", secrets.ErrInvalidReference
	}
	return parts[0], parts[2], parts[4], nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validProjectID(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 128 {
		return false
	}
	for _, character := range value {
		isLower := character >= 'a' && character <= 'z'
		isUpper := character >= 'A' && character <= 'Z'
		isDigit := character >= '0' && character <= '9'
		if !isLower && !isUpper && !isDigit && character != '-' && character != '_' {
			return false
		}
	}
	return true
}
