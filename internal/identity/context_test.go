package identity

import (
	"context"
	"testing"
)

func TestFromContextRequiresValidPrincipalSubject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subject string
		wantOK  bool
	}{
		{name: "valid", subject: "subject-123", wantOK: true},
		{name: "empty"},
		{name: "leading whitespace", subject: " subject-123"},
		{name: "control character", subject: "subject\n123"},
		{name: "too long", subject: string(make([]byte, 257))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := WithPrincipal(context.Background(), Principal{Subject: test.subject})
			_, ok := FromContext(ctx)
			if ok != test.wantOK {
				t.Fatalf("FromContext() ok = %t, want %t", ok, test.wantOK)
			}
		})
	}
}
