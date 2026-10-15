package secrets

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

var secretNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

var ErrInvalidReference = errors.New("INVALID_SECRET_REFERENCE")

func ValidName(name string) bool {
	return secretNamePattern.MatchString(name)
}

// Reference is safe to return to callers. It identifies secret material held
// by a SecretStore without containing the material itself.
type Reference struct {
	URI     string `json:"uri"`
	Version string `json:"version,omitempty"`
}

// SecretStore is an internal write-only port. It deliberately has no method
// for returning secret values to MCP handlers.
type SecretStore interface {
	ReferenceFor(scope domain.Scope, name string) (Reference, error)
	Put(ctx context.Context, scope domain.Scope, name string, value []byte) (Reference, error)
	Delete(ctx context.Context, reference Reference) error
}

func NewReference(projectID string, scope domain.Scope, name string) (Reference, error) {
	if projectID == "" || strings.TrimSpace(projectID) != projectID || !domain.ValidScopeName(scope.Environment) || !secretNamePattern.MatchString(name) {
		return Reference{}, ErrInvalidReference
	}
	for _, character := range projectID {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-', character == '_':
		default:
			return Reference{}, ErrInvalidReference
		}
	}
	uri := url.URL{
		Scheme: "ciphera",
		Host:   "project",
		Path:   "/" + projectID + "/environments/" + scope.Environment + "/secrets/" + name,
	}
	return Reference{URI: uri.String()}, nil
}

func ValidateReference(reference Reference) error {
	parsed, err := url.Parse(reference.URI)
	if err != nil || parsed.Scheme != "ciphera" || parsed.Host != "project" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrInvalidReference
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) != 5 || parts[1] != "environments" || parts[3] != "secrets" {
		return ErrInvalidReference
	}
	_, err = NewReference(parts[0], domain.Scope{Environment: parts[2]}, parts[4])
	if err != nil {
		return ErrInvalidReference
	}
	return nil
}
