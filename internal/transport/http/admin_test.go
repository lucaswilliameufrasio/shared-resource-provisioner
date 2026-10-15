package httptransport

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/persistence/sqlite"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAdminGrantAPIRequiresAdminAndManagesDurableGrants(t *testing.T) {
	t.Parallel()

	store := newAdminTestStore(t)
	handler := newAdminTestHandler(t, store)

	unauthorized := performAdminRequest(handler, http.MethodGet, adminGrantCollection, "", "")
	if unauthorized.Code != http.StatusUnauthorized || !strings.Contains(unauthorized.Body.String(), `"error_code":"UNAUTHORIZED"`) {
		t.Fatalf("unauthorized response = %d %q", unauthorized.Code, unauthorized.Body.String())
	}
	if strings.Contains(unauthorized.Body.String(), "admin-token") {
		t.Fatal("unauthorized response reflected the bearer token")
	}

	forbidden := performAdminRequest(handler, http.MethodGet, adminGrantCollection, "caller-token", "")
	if forbidden.Code != http.StatusForbidden || !strings.Contains(forbidden.Body.String(), `"error_code":"PERMISSION_DENIED"`) {
		t.Fatalf("forbidden response = %d %q", forbidden.Code, forbidden.Body.String())
	}

	requestBody := `{"subject":"service-subject","application":"orders","environment":"production","action":"plan_resource"}`
	created := performAdminRequest(handler, http.MethodPost, adminGrantCollection, "admin-token", requestBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create response = %d %q", created.Code, created.Body.String())
	}
	var grant authorization.GrantRecord
	if err := json.Unmarshal(created.Body.Bytes(), &grant); err != nil {
		t.Fatalf("decode created grant error = %v", err)
	}
	if grant.ID == "" || grant.CreatedBy != "admin-subject" || grant.Subject != "service-subject" {
		t.Fatalf("created grant = %+v", grant)
	}

	duplicate := performAdminRequest(handler, http.MethodPost, adminGrantCollection, "admin-token", requestBody)
	if duplicate.Code != http.StatusConflict || !strings.Contains(duplicate.Body.String(), `"error_code":"GRANT_ALREADY_EXISTS"`) {
		t.Fatalf("duplicate response = %d %q", duplicate.Code, duplicate.Body.String())
	}

	listed := performAdminRequest(handler, http.MethodGet, adminGrantCollection+"?limit=5", "admin-token", "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list response = %d %q", listed.Code, listed.Body.String())
	}
	var page struct {
		Data       []authorization.GrantRecord `json:"data"`
		NextCursor string                      `json:"next_cursor"`
		HasMore    bool                        `json:"has_more"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode grant page error = %v", err)
	}
	if len(page.Data) != 1 || page.Data[0].ID != grant.ID || page.HasMore || page.NextCursor != "" {
		t.Fatalf("grant page = %+v", page)
	}

	allowed, err := store.HasGrant(context.Background(), "service-subject", authorization.ActionPlanResource, domain.Scope{
		Application: "orders",
		Environment: "production",
	})
	if err != nil || !allowed {
		t.Fatalf("HasGrant() = %t, %v; want true", allowed, err)
	}

	deleted := performAdminRequest(handler, http.MethodDelete, adminGrantCollection+"/"+grant.ID, "admin-token", "")
	if deleted.Code != http.StatusNoContent || deleted.Body.Len() != 0 {
		t.Fatalf("delete response = %d %q", deleted.Code, deleted.Body.String())
	}
	allowed, err = store.HasGrant(context.Background(), "service-subject", authorization.ActionPlanResource, domain.Scope{
		Application: "orders",
		Environment: "production",
	})
	if err != nil || allowed {
		t.Fatalf("HasGrant() after delete = %t, %v; want false", allowed, err)
	}

}

func TestAdminGrantAPIValidatesInputAndDoesNotReflectIt(t *testing.T) {
	t.Parallel()

	store := newAdminTestStore(t)
	handler := newAdminTestHandler(t, store)
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "unknown field",
			body:       `{"subject":"service","application":"orders","environment":"production","action":"plan_resource","secret":"do-not-echo"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "MALFORMED_REQUEST",
		},
		{
			name:       "wildcard grant",
			body:       `{"subject":"*","application":"orders","environment":"production","action":"plan_resource"}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "INVALID_PARAMS",
		},
		{
			name:       "unsupported action",
			body:       `{"subject":"service","application":"orders","environment":"production","action":"execute_sql"}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "INVALID_PARAMS",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := performAdminRequest(handler, http.MethodPost, adminGrantCollection, "admin-token", test.body)
			if response.Code != test.wantStatus || !strings.Contains(response.Body.String(), `"error_code":"`+test.wantCode+`"`) {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "do-not-echo") {
				t.Fatal("error response reflected request data")
			}
			if test.wantStatus == http.StatusUnprocessableEntity && !strings.Contains(response.Body.String(), `"validation_errors":[`) {
				t.Fatalf("validation response missing details: %q", response.Body.String())
			}
		})
	}

	oversizedBody := strings.Repeat("x", adminRequestMaxBytes+1)
	tooLarge := performAdminRequest(handler, http.MethodPost, adminGrantCollection, "admin-token", oversizedBody)
	if tooLarge.Code != http.StatusRequestEntityTooLarge || !strings.Contains(tooLarge.Body.String(), `"error_code":"PAYLOAD_TOO_LARGE"`) {
		t.Fatalf("oversized response = %d %q", tooLarge.Code, tooLarge.Body.String())
	}
}

func TestAdminBearerTokenRejectsExpiredAndUnknownSubjects(t *testing.T) {
	t.Parallel()

	verifier := func(_ context.Context, rawToken string, _ *http.Request) (*auth.TokenInfo, error) {
		switch rawToken {
		case "expired-token":
			return &auth.TokenInfo{UserID: "admin-subject", Expiration: time.Now().Add(-time.Minute)}, nil
		case "invalid-token":
			return nil, auth.ErrInvalidToken
		default:
			return &auth.TokenInfo{UserID: "admin-subject", Expiration: time.Now().Add(time.Minute)}, nil
		}
	}
	handler := RequireAdminBearerToken(verifier, "https://issuer.example.test/prm", []string{"admin-subject"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("invalid token reached the admin handler")
	}))
	for _, token := range []string{"expired-token", "invalid-token"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, adminGrantCollection, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("token %q status = %d, want unauthorized", token, response.Code)
		}
	}
}

func newAdminTestStore(t *testing.T) *sqlite.Store {
	t.Helper()

	store, err := sqlite.Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := store.SeedPolicyOnce(context.Background(), nil); err != nil {
		_ = store.Close()
		t.Fatalf("SeedPolicyOnce() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store
}

func newAdminTestHandler(t *testing.T, store *sqlite.Store) http.Handler {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, &mcp.ServerOptions{})
	handler, err := NewHandler(
		server,
		testAdminTokenVerifier,
		"http://127.0.0.1:8080/mcp",
		"https://issuer.example.test",
		slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		store,
		[]string{"admin-subject"},
	)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func testAdminTokenVerifier(_ context.Context, rawToken string, _ *http.Request) (*auth.TokenInfo, error) {
	subject := ""
	switch rawToken {
	case "admin-token":
		subject = "admin-subject"
	case "caller-token":
		subject = "caller-subject"
	default:
		return nil, errors.New("invalid token")
	}
	return &auth.TokenInfo{UserID: subject, Expiration: time.Now().Add(time.Minute)}, nil
}

func performAdminRequest(handler http.Handler, method string, path string, token string, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
