package httptransport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
)

const (
	adminGrantCollection = "/v1/admin/grants"
	adminRequestMaxBytes = 16 << 10
	defaultGrantPageSize = 50
	maximumGrantPageSize = 100
)

type adminAPI struct {
	grants authorization.GrantManager
}

type createGrantRequest struct {
	Subject     string               `json:"subject"`
	Application string               `json:"application"`
	Environment string               `json:"environment"`
	Action      authorization.Action `json:"action"`
}

type grantPageResponse struct {
	Data       []authorization.GrantRecord `json:"data"`
	NextCursor string                      `json:"next_cursor,omitempty"`
	HasMore    bool                        `json:"has_more"`
}

type validationIssue struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type adminErrorExtra struct {
	ValidationErrors []validationIssue `json:"validation_errors,omitempty"`
}

type adminErrorResponse struct {
	Message   string           `json:"message"`
	ErrorCode string           `json:"error_code"`
	Extra     *adminErrorExtra `json:"extra,omitempty"`
}

func NewAdminHandler(grants authorization.GrantManager) (http.Handler, error) {
	if grants == nil {
		return nil, errors.New("authorization grant manager is required")
	}
	return &adminAPI{grants: grants}, nil
}

func (api *adminAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")

	if request.URL.Path == adminGrantCollection {
		switch request.Method {
		case http.MethodGet:
			api.listGrants(writer, request)
		case http.MethodPost:
			api.createGrant(writer, request)
		default:
			writer.Header().Set("Allow", "GET, POST")
			writeAdminError(writer, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Método não permitido.", nil)
		}
		return
	}

	if strings.HasPrefix(request.URL.Path, adminGrantCollection+"/") {
		if request.Method != http.MethodDelete {
			writer.Header().Set("Allow", "DELETE")
			writeAdminError(writer, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Método não permitido.", nil)
			return
		}
		api.deleteGrant(writer, request)
		return
	}

	writeAdminError(writer, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Recurso não encontrado.", nil)
}

func (api *adminAPI) listGrants(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	for key, values := range query {
		if key != "cursor" && key != "limit" {
			writeAdminError(writer, http.StatusBadRequest, "MALFORMED_REQUEST", "Parâmetro de consulta desconhecido.", nil)
			return
		}
		if len(values) != 1 {
			writeAdminError(writer, http.StatusBadRequest, "MALFORMED_REQUEST", "Parâmetro de consulta repetido.", nil)
			return
		}
	}
	limit := defaultGrantPageSize
	if rawLimit, exists := query["limit"]; exists {
		parsedLimit, err := strconv.Atoi(rawLimit[0])
		if err != nil || parsedLimit < 1 || parsedLimit > maximumGrantPageSize {
			writeAdminValidationError(writer, "limit", "Informe um limite entre 1 e 100.")
			return
		}
		limit = parsedLimit
	}
	cursor := ""
	if cursorValues, exists := query["cursor"]; exists {
		cursor = cursorValues[0]
	}
	if len(cursor) > 512 {
		writeAdminValidationError(writer, "cursor", "O cursor é inválido.")
		return
	}
	page, err := api.grants.ListGrants(request.Context(), cursor, limit)
	if errors.Is(err, authorization.ErrInvalidGrantCursor) {
		writeAdminValidationError(writer, "cursor", "O cursor é inválido.")
		return
	}
	if err != nil {
		writeAdminError(writer, http.StatusInternalServerError, "UNEXPECTED_ERROR", "Não foi possível listar as permissões.", nil)
		return
	}
	if page.Items == nil {
		page.Items = []authorization.GrantRecord{}
	}
	writeAdminJSON(writer, http.StatusOK, grantPageResponse{
		Data:       page.Items,
		NextCursor: page.NextCursor,
		HasMore:    page.HasMore,
	})
}

func (api *adminAPI) createGrant(writer http.ResponseWriter, request *http.Request) {
	body, err := readAdminBody(request)
	if errors.Is(err, errAdminBodyTooLarge) {
		writeAdminError(writer, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "O corpo da solicitação excede o limite permitido.", nil)
		return
	}
	if err != nil {
		writeAdminError(writer, http.StatusBadRequest, "MALFORMED_REQUEST", "O corpo da solicitação é inválido.", nil)
		return
	}
	var input createGrantRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeAdminError(writer, http.StatusBadRequest, "MALFORMED_REQUEST", "O corpo da solicitação é inválido.", nil)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeAdminError(writer, http.StatusBadRequest, "MALFORMED_REQUEST", "O corpo da solicitação deve conter um único objeto JSON.", nil)
		return
	}
	grant := authorization.GrantRecord{
		Subject:     input.Subject,
		Application: input.Application,
		Environment: input.Environment,
		Action:      input.Action,
	}
	if err := authorization.ValidateGrantRecord(grant); err != nil {
		writeAdminValidationError(writer, "grant", "Informe sujeito, aplicação, ambiente e ação válidos; curingas não são permitidos.")
		return
	}
	principal, ok := identity.FromContext(request.Context())
	if !ok {
		writeAdminError(writer, http.StatusUnauthorized, "UNAUTHORIZED", "Autenticação necessária.", nil)
		return
	}
	created, err := api.grants.CreateGrant(request.Context(), grant, audit.Event{
		Subject:   principal.Subject,
		Transport: identity.TransportHTTP,
		Action:    "grant.create",
		Outcome:   audit.OutcomeAllowed,
	})
	if errors.Is(err, authorization.ErrGrantExists) {
		writeAdminError(writer, http.StatusConflict, "GRANT_ALREADY_EXISTS", "A permissão já existe.", nil)
		return
	}
	if err != nil {
		writeAdminError(writer, http.StatusInternalServerError, "UNEXPECTED_ERROR", "Não foi possível criar a permissão.", nil)
		return
	}
	writer.Header().Set("Location", adminGrantCollection+"/"+created.ID)
	writeAdminJSON(writer, http.StatusCreated, created)
}

func (api *adminAPI) deleteGrant(writer http.ResponseWriter, request *http.Request) {
	id := strings.TrimPrefix(request.URL.Path, adminGrantCollection+"/")
	if id == "" || strings.Contains(id, "/") || len(id) > 64 {
		writeAdminError(writer, http.StatusNotFound, "GRANT_NOT_FOUND", "Permissão não encontrada.", nil)
		return
	}
	principal, ok := identity.FromContext(request.Context())
	if !ok {
		writeAdminError(writer, http.StatusUnauthorized, "UNAUTHORIZED", "Autenticação necessária.", nil)
		return
	}
	_, err := api.grants.DeleteGrant(request.Context(), id, audit.Event{
		Subject:   principal.Subject,
		Transport: identity.TransportHTTP,
		Action:    "grant.delete",
		Outcome:   audit.OutcomeAllowed,
	})
	if errors.Is(err, authorization.ErrGrantNotFound) {
		writeAdminError(writer, http.StatusNotFound, "GRANT_NOT_FOUND", "Permissão não encontrada.", nil)
		return
	}
	if err != nil {
		writeAdminError(writer, http.StatusInternalServerError, "UNEXPECTED_ERROR", "Não foi possível excluir a permissão.", nil)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

var errAdminBodyTooLarge = errors.New("admin request body too large")

func readAdminBody(request *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(request.Body, adminRequestMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > adminRequestMaxBytes {
		return nil, errAdminBodyTooLarge
	}
	return body, nil
}

func writeAdminValidationError(writer http.ResponseWriter, field string, message string) {
	extra := &adminErrorExtra{
		ValidationErrors: []validationIssue{{Field: field, Message: message}},
	}
	writeAdminError(writer, http.StatusUnprocessableEntity, "INVALID_PARAMS", "A solicitação contém dados inválidos.", extra)
}

func writeAdminError(writer http.ResponseWriter, status int, code string, message string, extra *adminErrorExtra) {
	writeAdminJSON(writer, status, adminErrorResponse{
		Message:   message,
		ErrorCode: code,
		Extra:     extra,
	})
}

func writeAdminJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func RequireAdminBearerToken(verifier TokenVerifier, metadataURL string, adminSubjects []string, next http.Handler) http.Handler {
	allowedSubjects := make(map[string]struct{}, len(adminSubjects))
	for _, subject := range adminSubjects {
		if identity.ValidSubject(subject) {
			allowedSubjects[subject] = struct{}{}
		}
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		parts := strings.Fields(request.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 8192 {
			writeAdminUnauthorized(writer, metadataURL)
			return
		}
		tokenInfo, err := verifier(request.Context(), parts[1], request)
		if err != nil || tokenInfo == nil || !identity.ValidSubject(tokenInfo.UserID) || tokenInfo.Expiration.IsZero() || !tokenInfo.Expiration.After(time.Now()) {
			writeAdminUnauthorized(writer, metadataURL)
			return
		}
		if _, allowed := allowedSubjects[tokenInfo.UserID]; !allowed {
			writeAdminError(writer, http.StatusForbidden, "PERMISSION_DENIED", "Acesso administrativo não autorizado.", nil)
			return
		}
		principal := identity.Principal{Subject: tokenInfo.UserID, Transport: identity.TransportHTTP}
		contextWithPrincipal := identity.WithPrincipal(request.Context(), principal)
		next.ServeHTTP(writer, request.WithContext(contextWithPrincipal))
	})
}

func writeAdminUnauthorized(writer http.ResponseWriter, metadataURL string) {
	writer.Header().Set("WWW-Authenticate", "Bearer resource_metadata="+strconv.Quote(metadataURL))
	writeAdminError(writer, http.StatusUnauthorized, "UNAUTHORIZED", "Autenticação necessária.", nil)
}
