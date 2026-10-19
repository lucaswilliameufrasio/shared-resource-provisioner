package provisioning

import (
	"context"
	"errors"
	"regexp"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

var safeFailureCode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

type Credential struct {
	Name    string
	Value   []byte
	Version string
}

type Driver interface {
	Create(ctx context.Context, resource domain.Resource) (Credential, error)
	Revoke(ctx context.Context, resource domain.Resource) error
}

type RotationDriver interface {
	StageRotation(ctx context.Context, resource domain.Resource, newGeneration int64) (Credential, error)
	FinalizeRotation(ctx context.Context, resource domain.Resource, oldGeneration int64, newGeneration int64, allGenerations []int64) error
	AbortRotation(ctx context.Context, resource domain.Resource, generation int64) error
}

type DriverFailure struct {
	Code                   string
	ReconciliationRequired bool
}

func (failure DriverFailure) Error() string {
	if !safeFailureCode.MatchString(failure.Code) {
		return "DRIVER_FAILURE"
	}
	return failure.Code
}

func NewDriverFailure(code string, reconciliationRequired bool) error {
	if !safeFailureCode.MatchString(code) {
		return errors.New("DRIVER_FAILURE")
	}
	return DriverFailure{Code: code, ReconciliationRequired: reconciliationRequired}
}

func failureDetails(err error) (string, bool) {
	var failure DriverFailure
	if errors.As(err, &failure) && safeFailureCode.MatchString(failure.Code) {
		return failure.Code, failure.ReconciliationRequired
	}
	return "DRIVER_FAILURE", true
}
