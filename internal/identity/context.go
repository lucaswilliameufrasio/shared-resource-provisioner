package identity

import (
	"context"
	"strings"
	"unicode"
)

type Transport string

const (
	TransportHTTP  Transport = "http"
	TransportStdio Transport = "stdio"
)

type Principal struct {
	Subject   string
	Transport Transport
}

type contextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, principal)
}

func FromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(contextKey{}).(Principal)
	if !ok || !ValidSubject(principal.Subject) {
		return Principal{}, false
	}
	return principal, true
}

func ValidSubject(subject string) bool {
	if subject == "" || len(subject) > 256 || strings.TrimSpace(subject) != subject {
		return false
	}
	for _, character := range subject {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
