package httptransport

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const localOIDCKeyID = "local-test-signing-key"

type localOIDCIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newLocalOIDCIssuer(t *testing.T) *localOIDCIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	issuer := &localOIDCIssuer{key: key}
	mux := http.NewServeMux()
	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(map[string]string{
			"issuer":   issuer.server.URL,
			"jwks_uri": issuer.server.URL + "/jwks",
		}); err != nil {
			t.Errorf("encode OIDC discovery response: %v", err)
		}
	})
	mux.HandleFunc("/jwks", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"kid": localOIDCKeyID,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		}); err != nil {
			t.Errorf("encode OIDC JWKS response: %v", err)
		}
	})

	return issuer
}

func (issuer *localOIDCIssuer) signedToken(t *testing.T, subject, audience string, expiresAt time.Time) string {
	t.Helper()

	header, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"kid": localOIDCKeyID,
		"typ": "JWT",
	})
	if err != nil {
		t.Fatalf("Marshal(JWT header) error = %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": issuer.server.URL,
		"sub": subject,
		"aud": audience,
		"iat": time.Now().Unix(),
		"exp": expiresAt.Unix(),
	})
	if err != nil {
		t.Fatalf("Marshal(JWT claims) error = %v", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claims)
	signingInput := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, issuer.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15() error = %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
