package natsdriver

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestParseCredentialsRequiresMatchingUserJWTAndSeed(t *testing.T) {
	t.Parallel()

	credentials := makeCredentials(t)
	userJWT, userSeed, err := parseCredentials(credentials)
	if err != nil {
		t.Fatalf("parseCredentials(valid) error = %v", err)
	}
	clear(userJWT)
	clear(userSeed)

	accountKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	defer accountKey.Wipe()
	userKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	defer userKey.Wipe()
	otherUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	defer otherUser.Wipe()
	otherSeed, err := otherUser.Seed()
	if err != nil {
		t.Fatalf("Seed() error = %v", err)
	}
	defer clear(otherSeed)
	userPublic, err := userKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}
	accountPublic, err := accountKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(account) error = %v", err)
	}
	claims := jwt.NewUserClaims(userPublic)
	claims.IssuerAccount = accountPublic
	claims.Permissions = jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{"orders.>"}},
		Sub: jwt.Permission{Allow: jwt.StringList{"orders.>"}},
	}
	token, err := claims.Encode(accountKey)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	mismatched := encodeCredentials(token, otherSeed)
	defer clear(mismatched)
	if _, _, err := parseCredentials(mismatched); err == nil {
		t.Fatal("parseCredentials() accepted a JWT and seed for different users")
	}
	clear(credentials)
}

func TestBuildAccountAndUserClaimsContainBoundedIsolation(t *testing.T) {
	t.Parallel()

	operator, operatorSeed, accountKey, userKey, resource := makeResourceKeys(t)
	defer operator.Wipe()
	defer clear(operatorSeed)
	defer accountKey.Wipe()
	defer userKey.Wipe()
	target := validTarget()
	accountPublic, err := accountKey.PublicKey()
	if err != nil {
		t.Fatalf("account PublicKey() error = %v", err)
	}
	userPublic, err := userKey.PublicKey()
	if err != nil {
		t.Fatalf("user PublicKey() error = %v", err)
	}

	accountJWT, err := buildAccountClaims(target, resource, accountPublic, userPublic, false, time.Now().UTC()).Encode(operator)
	if err != nil {
		t.Fatalf("Encode(account claims) error = %v", err)
	}
	accountClaims, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil {
		t.Fatalf("DecodeAccountClaims() error = %v", err)
	}
	if accountClaims.Limits.Conn != int64(target.NATSMaxConnections) || accountClaims.Limits.Subs != int64(target.NATSMaxSubscriptions) || accountClaims.Limits.Payload != target.NATSMaxPayloadBytes {
		t.Fatalf("NATS account limits = %+v", accountClaims.Limits)
	}
	if accountClaims.Limits.MemoryStorage != target.NATSJetStreamMemoryBytes || accountClaims.Limits.DiskStorage != target.NATSJetStreamDiskBytes || accountClaims.Limits.Streams != int64(target.NATSJetStreamMaxStreams) || accountClaims.Limits.Consumer != int64(target.NATSJetStreamMaxConsumers) {
		t.Fatalf("JetStream limits = %+v", accountClaims.Limits)
	}

	userJWT, err := buildUserClaims(resource, accountPublic, userPublic, target).Encode(accountKey)
	if err != nil {
		t.Fatalf("Encode(user claims) error = %v", err)
	}
	userClaims, err := jwt.DecodeUserClaims(userJWT)
	if err != nil {
		t.Fatalf("DecodeUserClaims() error = %v", err)
	}
	if len(userClaims.Pub.Allow) != 1 || userClaims.Pub.Allow[0] != ">" || len(userClaims.Sub.Allow) != 1 || userClaims.Sub.Allow[0] != ">" {
		t.Fatalf("NATS user permissions = %+v", userClaims.Permissions)
	}
}

func TestRevocationClaimsRevokeOnlyTheResourceUser(t *testing.T) {
	t.Parallel()

	operator, operatorSeed, accountKey, userKey, resource := makeResourceKeys(t)
	defer operator.Wipe()
	defer clear(operatorSeed)
	defer accountKey.Wipe()
	defer userKey.Wipe()
	accountPublic, err := accountKey.PublicKey()
	if err != nil {
		t.Fatalf("account PublicKey() error = %v", err)
	}
	userPublic, err := userKey.PublicKey()
	if err != nil {
		t.Fatalf("user PublicKey() error = %v", err)
	}
	userClaims := jwt.NewUserClaims(userPublic)
	userClaims.IssuerAccount = accountPublic
	userJWT, err := userClaims.Encode(accountKey)
	if err != nil {
		t.Fatalf("Encode(user claims) error = %v", err)
	}
	decodedUser, err := jwt.DecodeUserClaims(userJWT)
	if err != nil {
		t.Fatalf("DecodeUserClaims() error = %v", err)
	}
	revokedAt := time.Now().UTC()
	revocationClaims := buildAccountClaims(validTarget(), resource, accountPublic, userPublic, true, revokedAt)
	if !revocationClaims.IsClaimRevoked(decodedUser) {
		t.Fatal("account claims did not revoke the resource's user identity")
	}
}

func TestNATSUpdateAcknowledgementRejectsSkippedAndErrorResponses(t *testing.T) {
	t.Parallel()

	for _, response := range []string{
		"jwt update skipped",
		"jwt update error",
		"jwt update resulted in error",
		`{"data":{"code":200,"message":"jwt update skipped"}}`,
		`{"error":{"code":500,"description":"jwt update error"}}`,
		"",
	} {
		if validClaimsUpdateResponse(response) {
			t.Fatalf("validClaimsUpdateResponse(%q) = true", response)
		}
	}
	for _, response := range []string{
		"jwt updated",
		"OK",
		"+OK",
		`{"data":{"code":200,"message":"jwt updated"}}`,
	} {
		if !validClaimsUpdateResponse(response) {
			t.Fatalf("validClaimsUpdateResponse(%q) = false", response)
		}
	}
}

func TestNormalizedEndpointRequiresTLSOffLoopbackAndNoCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
		wantTLS  bool
		wantErr  bool
	}{
		{name: "loopback plaintext", endpoint: "nats://127.0.0.1:4222"},
		{name: "remote TLS", endpoint: "tls://nats.example.test:4222", wantTLS: true},
		{name: "remote plaintext", endpoint: "nats://nats.example.test:4222", wantErr: true},
		{name: "credentials", endpoint: "tls://user:password@nats.example.test:4222", wantErr: true},
		{name: "query", endpoint: "tls://nats.example.test:4222?token=unsafe", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, useTLS, err := normalizedEndpoint([]byte(test.endpoint))
			if (err != nil) != test.wantErr || useTLS != test.wantTLS {
				t.Fatalf("normalizedEndpoint() = TLS %t, error %v", useTLS, err)
			}
		})
	}
}

func TestValidateJetStreamLimitsRequiresEveryHardBound(t *testing.T) {
	t.Parallel()

	target := validTarget()
	if err := validateJetStreamLimits(target); err != nil {
		t.Fatalf("validateJetStreamLimits(valid) error = %v", err)
	}
	target.NATSJetStreamMaxConsumers = 0
	if err := validateJetStreamLimits(target); err == nil {
		t.Fatal("validateJetStreamLimits() accepted incomplete JetStream limits")
	}
}

func TestCredentialEncodingContainsOnlyNATSCredentialBlocks(t *testing.T) {
	t.Parallel()

	credentials := makeCredentials(t)
	defer clear(credentials)
	if bytes.Count(credentials, []byte("BEGIN NATS USER JWT")) != 1 || bytes.Count(credentials, []byte("BEGIN USER NKEY SEED")) != 1 {
		t.Fatal("NATS credentials have missing or duplicate blocks")
	}
	if strings.Contains(string(credentials), "shared-resource-provisioner") {
		t.Fatal("NATS credentials contain provisioner metadata")
	}
}

func TestDeriveResourceKeysAreStableAndResourceSpecific(t *testing.T) {
	t.Parallel()

	operator, operatorSeed, _, _, resource := makeResourceKeys(t)
	defer operator.Wipe()
	defer clear(operatorSeed)
	firstAccount, firstUser, err := deriveResourceKeys(operatorSeed, resource)
	if err != nil {
		t.Fatalf("deriveResourceKeys(first) error = %v", err)
	}
	defer firstAccount.Wipe()
	defer firstUser.Wipe()
	secondAccount, secondUser, err := deriveResourceKeys(operatorSeed, resource)
	if err != nil {
		t.Fatalf("deriveResourceKeys(second) error = %v", err)
	}
	defer secondAccount.Wipe()
	defer secondUser.Wipe()
	firstAccountPublic, err := firstAccount.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(first account) error = %v", err)
	}
	secondAccountPublic, err := secondAccount.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(second account) error = %v", err)
	}
	firstUserPublic, err := firstUser.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(first user) error = %v", err)
	}
	secondUserPublic, err := secondUser.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(second user) error = %v", err)
	}
	if firstAccountPublic != secondAccountPublic || firstUserPublic != secondUserPublic || firstAccountPublic == firstUserPublic {
		t.Fatal("NATS resource key derivation is unstable or reused the account identity as the user")
	}
	resource.ID = "a-different-resource-id"
	otherAccount, otherUser, err := deriveResourceKeys(operatorSeed, resource)
	if err != nil {
		t.Fatalf("deriveResourceKeys(other) error = %v", err)
	}
	defer otherAccount.Wipe()
	defer otherUser.Wipe()
	otherAccountPublic, err := otherAccount.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(other account) error = %v", err)
	}
	if otherAccountPublic == firstAccountPublic {
		t.Fatal("distinct resources share a NATS account key")
	}
}

func TestCredentialGenerationsKeepAccountStableAndPreservePriorRevocations(t *testing.T) {
	t.Parallel()

	operator, operatorSeed, accountKey, firstUserKey, resource := makeResourceKeys(t)
	defer operator.Wipe()
	defer clear(operatorSeed)
	defer accountKey.Wipe()
	defer firstUserKey.Wipe()
	firstAccountPublic, err := accountKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(account) error = %v", err)
	}
	firstUserPublic, err := firstUserKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(generation one) error = %v", err)
	}

	secondAccount, secondUser, err := deriveResourceKeysForGeneration(operatorSeed, resource, 2)
	if err != nil {
		t.Fatalf("deriveResourceKeysForGeneration(2) error = %v", err)
	}
	defer secondAccount.Wipe()
	defer secondUser.Wipe()
	secondAccountPublic, err := secondAccount.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(second account) error = %v", err)
	}
	secondUserPublic, err := secondUser.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(generation two) error = %v", err)
	}
	if firstAccountPublic != secondAccountPublic || firstUserPublic == secondUserPublic {
		t.Fatal("rotation did not preserve the account identity and change the user identity")
	}

	thirdAccount, thirdUser, err := deriveResourceKeysForGeneration(operatorSeed, resource, 3)
	if err != nil {
		t.Fatalf("deriveResourceKeysForGeneration(3) error = %v", err)
	}
	defer thirdAccount.Wipe()
	defer thirdUser.Wipe()
	thirdUserPublic, err := thirdUser.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(generation three) error = %v", err)
	}
	firstJWT, err := buildUserClaims(resource, firstAccountPublic, firstUserPublic, validTarget()).Encode(accountKey)
	if err != nil {
		t.Fatalf("Encode(generation one claims) error = %v", err)
	}
	firstClaims, err := jwt.DecodeUserClaims(firstJWT)
	if err != nil {
		t.Fatalf("DecodeUserClaims(generation one) error = %v", err)
	}
	secondJWT, err := buildUserClaims(resource, firstAccountPublic, secondUserPublic, validTarget()).Encode(accountKey)
	if err != nil {
		t.Fatalf("Encode(generation two claims) error = %v", err)
	}
	secondClaims, err := jwt.DecodeUserClaims(secondJWT)
	if err != nil {
		t.Fatalf("DecodeUserClaims(generation two) error = %v", err)
	}
	thirdJWT, err := buildUserClaims(resource, firstAccountPublic, thirdUserPublic, validTarget()).Encode(accountKey)
	if err != nil {
		t.Fatalf("Encode(generation three claims) error = %v", err)
	}
	thirdClaims, err := jwt.DecodeUserClaims(thirdJWT)
	if err != nil {
		t.Fatalf("DecodeUserClaims(generation three) error = %v", err)
	}
	staged := buildAccountClaimsWithRevocations(validTarget(), resource, firstAccountPublic, []string{firstUserPublic}, time.Now().UTC())
	if !staged.IsClaimRevoked(firstClaims) || staged.IsClaimRevoked(secondClaims) || staged.IsClaimRevoked(thirdClaims) {
		t.Fatal("staging generation three did not preserve generation two while retaining the prior revocation")
	}
	finalized := buildAccountClaimsWithRevocations(validTarget(), resource, firstAccountPublic, []string{firstUserPublic, secondUserPublic}, time.Now().UTC())
	if !finalized.IsClaimRevoked(firstClaims) || !finalized.IsClaimRevoked(secondClaims) || finalized.IsClaimRevoked(thirdClaims) {
		t.Fatal("finalizing generation three did not revoke every superseded user identity")
	}
}

func validTarget() config.Target {
	return config.Target{
		ID:                        "nats-primary",
		ResourceType:              domain.ResourceNATS,
		MaxResources:              20,
		MaxConcurrentOperations:   2,
		NATSMaxConnections:        10,
		NATSMaxSubscriptions:      50,
		NATSMaxPayloadBytes:       1 << 20,
		NATSJetStreamMemoryBytes:  1 << 20,
		NATSJetStreamDiskBytes:    2 << 20,
		NATSJetStreamMaxStreams:   5,
		NATSJetStreamMaxConsumers: 10,
	}
}

func makeCredentials(t *testing.T) []byte {
	t.Helper()

	accountKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	defer accountKey.Wipe()
	userKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	defer userKey.Wipe()
	accountPublic, err := accountKey.PublicKey()
	if err != nil {
		t.Fatalf("account PublicKey() error = %v", err)
	}
	userPublic, err := userKey.PublicKey()
	if err != nil {
		t.Fatalf("user PublicKey() error = %v", err)
	}
	claims := jwt.NewUserClaims(userPublic)
	claims.IssuerAccount = accountPublic
	claims.Permissions = jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{">"}},
		Sub: jwt.Permission{Allow: jwt.StringList{">"}},
	}
	token, err := claims.Encode(accountKey)
	if err != nil {
		t.Fatalf("Encode(system user JWT) error = %v", err)
	}
	seed, err := userKey.Seed()
	if err != nil {
		t.Fatalf("Seed(system user) error = %v", err)
	}
	credentials := encodeCredentials(token, seed)
	clear(seed)
	return credentials
}

func makeResourceKeys(t *testing.T) (nkeys.KeyPair, []byte, nkeys.KeyPair, nkeys.KeyPair, domain.Resource) {
	t.Helper()

	operator, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatalf("CreateOperator() error = %v", err)
	}
	operatorSeed, err := operator.Seed()
	if err != nil {
		t.Fatalf("Seed(operator) error = %v", err)
	}
	resource := domain.Resource{
		ID:           "resource-id-001",
		ResourceType: domain.ResourceNATS,
		Scope:        domain.Scope{Application: "orders", Environment: "production"},
	}
	accountKey, userKey, err := deriveResourceKeys(operatorSeed, resource)
	if err != nil {
		t.Fatalf("deriveResourceKeys() error = %v", err)
	}
	return operator, operatorSeed, accountKey, userKey, resource
}
