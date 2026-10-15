package audit

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
)

type Outcome string

const (
	OutcomeAllowed Outcome = "allowed"
	OutcomeDenied  Outcome = "denied"
)

type Event struct {
	At            time.Time
	Subject       string
	TargetSubject string
	Transport     identity.Transport
	Action        string
	EntityID      string
	Application   string
	Environment   string
	Resource      domain.ResourceType
	Outcome       Outcome
	ErrorCode     string
}

type Recorder interface {
	Record(ctx context.Context, event Event) error
}

type Logger struct {
	logger *slog.Logger
}

func NewLogger(logger *slog.Logger) (*Logger, error) {
	if logger == nil {
		return nil, errors.New("audit logger is required")
	}
	return &Logger{logger: logger}, nil
}

func (recorder *Logger) Record(_ context.Context, event Event) error {
	recorder.logger.Info(
		"audit event",
		"timestamp", event.At.UTC().Format(time.RFC3339Nano),
		"subject", event.Subject,
		"target_subject", event.TargetSubject,
		"transport", event.Transport,
		"action", event.Action,
		"entity_id", event.EntityID,
		"application", event.Application,
		"environment", event.Environment,
		"resource_type", event.Resource,
		"outcome", event.Outcome,
		"error_code", event.ErrorCode,
	)
	return nil
}
