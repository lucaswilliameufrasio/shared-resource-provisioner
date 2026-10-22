package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/provisioning"
)

const runtimeRequestMaxBytes = 8 << 10

type RuntimeRotation interface {
	PendingRotation(context.Context, string) (domain.PendingRotation, error)
	AcknowledgeRotation(context.Context, domain.RotationAcknowledgement) error
}

type runtimeRotationAPI struct {
	lifecycle RuntimeRotation
}

type rotationAcknowledgementRequest struct {
	OperationID     string `json:"operation_id"`
	SecretReference string `json:"secret_reference"`
	SecretVersion   string `json:"secret_version"`
	Generation      int64  `json:"generation"`
}

func newRuntimeRotationHandler(lifecycle RuntimeRotation) http.Handler {
	mux := http.NewServeMux()
	api := &runtimeRotationAPI{lifecycle: lifecycle}
	mux.HandleFunc("GET /v1/runtime/resources/{resourceID}/rotations/pending", api.pending)
	mux.HandleFunc("POST /v1/runtime/resources/{resourceID}/rotations/acknowledgements", api.acknowledge)
	return mux
}

func (api *runtimeRotationAPI) pending(writer http.ResponseWriter, request *http.Request) {
	rotation, err := api.lifecycle.PendingRotation(request.Context(), request.PathValue("resourceID"))
	if err != nil {
		writeRuntimeError(writer, err)
		return
	}
	writeAdminJSON(writer, http.StatusOK, rotation)
}

func (api *runtimeRotationAPI) acknowledge(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		writeAdminError(writer, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "O tipo de conteúdo deve ser application/json.", nil)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, runtimeRequestMaxBytes+1))
	if err != nil {
		writeAdminError(writer, http.StatusBadRequest, "MALFORMED_REQUEST", "O corpo da solicitação é inválido.", nil)
		return
	}
	if len(body) > runtimeRequestMaxBytes {
		writeAdminError(writer, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "O corpo da solicitação excede o limite permitido.", nil)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var input rotationAcknowledgementRequest
	if err := decoder.Decode(&input); err != nil {
		writeAdminError(writer, http.StatusBadRequest, "MALFORMED_REQUEST", "O corpo da solicitação é inválido.", nil)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeAdminError(writer, http.StatusBadRequest, "MALFORMED_REQUEST", "O corpo da solicitação deve conter um único objeto JSON.", nil)
		return
	}
	if input.OperationID == "" || input.SecretReference == "" || input.SecretVersion == "" || input.Generation < 2 || strings.TrimSpace(input.OperationID) != input.OperationID || strings.TrimSpace(input.SecretReference) != input.SecretReference || strings.TrimSpace(input.SecretVersion) != input.SecretVersion {
		writeAdminValidationError(writer, "acknowledgement", "Informe a operação, referência e geração exatas recebidas no polling.")
		return
	}
	err = api.lifecycle.AcknowledgeRotation(request.Context(), domain.RotationAcknowledgement{
		ResourceID:      request.PathValue("resourceID"),
		OperationID:     input.OperationID,
		SecretReference: input.SecretReference,
		SecretVersion:   input.SecretVersion,
		Generation:      input.Generation,
	})
	if err != nil {
		writeRuntimeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func writeRuntimeError(writer http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "UNEXPECTED_ERROR"
	message := "Não foi possível concluir a operação de rotação."
	switch {
	case errors.Is(err, authorization.ErrPermissionDenied):
		status = http.StatusForbidden
		code = "PERMISSION_DENIED"
		message = "A operação não está autorizada."
	case errors.Is(err, domain.ErrResourceNotFound), errors.Is(err, domain.ErrRotationNotFound):
		status = http.StatusNotFound
		code = "RESOURCE_NOT_FOUND"
		message = "O recurso não foi encontrado."
	case errors.Is(err, domain.ErrRotationMismatch):
		status = http.StatusConflict
		code = "ROTATION_ACKNOWLEDGEMENT_MISMATCH"
		message = "A confirmação não corresponde à rotação pendente."
	case errors.Is(err, domain.ErrOperationInProgress), errors.Is(err, domain.ErrRotationInProgress):
		status = http.StatusConflict
		code = "ROTATION_IN_PROGRESS"
		message = "A rotação já está sendo processada."
	case errors.Is(err, provisioning.ErrRotationReconciliation), errors.Is(err, domain.ErrRotationReconciliation):
		status = http.StatusConflict
		code = "ROTATION_RECONCILIATION_REQUIRED"
		message = "A rotação requer reconciliação operacional."
	case errors.Is(err, provisioning.ErrAuditUnavailable), errors.Is(err, provisioning.ErrPersistenceUnavailable), errors.Is(err, authorization.ErrAuthorizationUnavailable):
		status = http.StatusServiceUnavailable
		code = "SERVICE_UNAVAILABLE"
		message = "O serviço está temporariamente indisponível."
	case errors.Is(err, provisioning.ErrRotationFailed), errors.Is(err, provisioning.ErrTargetUnavailable), errors.Is(err, provisioning.ErrSecretStoreUnavailable):
		status = http.StatusServiceUnavailable
		code = "ROTATION_FAILED"
		message = "A rotação não pôde ser concluída."
	}
	writeAdminError(writer, status, code, message, nil)
}
