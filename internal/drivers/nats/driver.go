package natsdriver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/provisioning"
	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

const (
	accountKeyPurpose = "shared-resource-provisioner/nats/account/v1"
	userKeyPurpose    = "shared-resource-provisioner/nats/user/v1"
	claimsUpdateSubj  = "$SYS.REQ.CLAIMS.UPDATE"
)

type Driver struct {
	target       config.Target
	endpoint     []byte
	operatorSeed []byte
	systemCreds  []byte
	mu           sync.Mutex
	closed       bool
}

func New(target config.Target, endpoint []byte, operatorSeed []byte, systemCredentials []byte) (*Driver, error) {
	endpoint = bytes.TrimSpace(endpoint)
	operatorSeed = bytes.TrimSpace(operatorSeed)
	if target.ResourceType != domain.ResourceNATS || target.MaxResources < 1 || target.MaxConcurrentOperations < 1 || len(endpoint) == 0 || len(operatorSeed) == 0 || len(systemCredentials) == 0 || target.NATSMaxConnections < 1 || target.NATSMaxSubscriptions < 1 || target.NATSMaxPayloadBytes < 1 {
		return nil, errors.New("NATS target, operator seed, system credentials, and hard limits are required")
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, errors.New("NATS target endpoint is invalid")
	}
	operatorKey, err := nkeys.FromSeed(operatorSeed)
	if err != nil {
		return nil, errors.New("NATS operator seed is invalid")
	}
	operatorPublic, err := operatorKey.PublicKey()
	operatorKey.Wipe()
	if err != nil || nkeys.Prefix(operatorPublic) != nkeys.PrefixByteOperator {
		return nil, errors.New("NATS operator seed must be an operator key")
	}
	systemJWT, systemSeed, err := parseCredentials(systemCredentials)
	if err != nil {
		return nil, errors.New("NATS system credentials file is invalid")
	}
	clear(systemJWT)
	systemKey, err := nkeys.FromSeed(systemSeed)
	clear(systemSeed)
	if err != nil {
		return nil, errors.New("NATS system credentials file is invalid")
	}
	systemKey.Wipe()
	if err := validateJetStreamLimits(target); err != nil {
		return nil, err
	}
	return &Driver{
		target:       target,
		endpoint:     append([]byte(nil), endpoint...),
		operatorSeed: append([]byte(nil), operatorSeed...),
		systemCreds:  append([]byte(nil), systemCredentials...),
	}, nil
}

func (driver *Driver) Close() {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	clear(driver.endpoint)
	clear(driver.operatorSeed)
	clear(driver.systemCreds)
	driver.endpoint = nil
	driver.operatorSeed = nil
	driver.systemCreds = nil
	driver.closed = true
}

func (driver *Driver) Create(ctx context.Context, resource domain.Resource) (provisioning.Credential, error) {
	operatorSeed, err := driver.copyOperatorSeed()
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer clear(operatorSeed)
	operatorKey, err := nkeys.FromSeed(operatorSeed)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer operatorKey.Wipe()
	accountKey, userKey, err := deriveResourceKeys(operatorSeed, resource)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	defer accountKey.Wipe()
	defer userKey.Wipe()
	accountPublic, err := accountKey.PublicKey()
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	userPublic, err := userKey.PublicKey()
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	accountClaims := buildAccountClaims(driver.target, resource, accountPublic, userPublic, false, time.Now().UTC())
	accountJWT, err := accountClaims.Encode(operatorKey)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	userClaims := buildUserClaims(resource, accountPublic, userPublic, driver.target)
	userJWT, err := userClaims.Encode(accountKey)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	userSeed, err := userKey.Seed()
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	defer clear(userSeed)

	if err := driver.publishAccountClaims(ctx, accountJWT); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	credential := encodeCredentials(userJWT, userSeed)
	return provisioning.Credential{Name: "NATS_CREDENTIALS", Value: credential}, nil
}

func (driver *Driver) Revoke(ctx context.Context, resource domain.Resource) error {
	operatorSeed, err := driver.copyOperatorSeed()
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer clear(operatorSeed)
	operatorKey, err := nkeys.FromSeed(operatorSeed)
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer operatorKey.Wipe()
	accountKey, userKey, err := deriveResourceKeys(operatorSeed, resource)
	if err != nil {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	defer accountKey.Wipe()
	defer userKey.Wipe()
	accountPublic, err := accountKey.PublicKey()
	if err != nil {
		return provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	userPublic, err := userKey.PublicKey()
	if err != nil {
		return provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	claims := buildAccountClaims(driver.target, resource, accountPublic, userPublic, true, time.Now().UTC())
	accountJWT, err := claims.Encode(operatorKey)
	if err != nil {
		return provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	if err := driver.publishAccountClaims(ctx, accountJWT); err != nil {
		return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	return nil
}

func (driver *Driver) publishAccountClaims(ctx context.Context, accountJWT string) error {
	endpoint, systemCredentials, err := driver.copyConnectionSettings()
	if err != nil {
		return err
	}
	defer clear(endpoint)
	defer clear(systemCredentials)
	userJWT, userSeed, err := parseCredentials(systemCredentials)
	if err != nil {
		return errors.New("NATS system credentials are invalid")
	}
	defer clear(userJWT)
	defer clear(userSeed)

	connectionURL, useTLS, err := normalizedEndpoint(endpoint)
	if err != nil {
		return errors.New("NATS endpoint is invalid")
	}
	options := []nats.Option{
		nats.UserJWTAndSeed(string(userJWT), string(userSeed)),
		nats.Timeout(5 * time.Second),
		nats.MaxReconnects(0),
		nats.Name("shared-resource-provisioner"),
	}
	if useTLS {
		options = append(options, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12}))
	}
	connection, err := nats.Connect(connectionURL, options...)
	if err != nil {
		return errors.New("NATS system connection failed")
	}
	defer connection.Close()
	reply, err := connection.RequestWithContext(ctx, claimsUpdateSubj, []byte(accountJWT))
	if err != nil {
		return errors.New("NATS account claim update failed")
	}
	if !validClaimsUpdateResponse(string(reply.Data)) {
		return errors.New("NATS account claim update was rejected")
	}
	return nil
}

func deriveResourceKeys(operatorSeed []byte, resource domain.Resource) (nkeys.KeyPair, nkeys.KeyPair, error) {
	if resource.ID == "" || resource.ResourceType != domain.ResourceNATS || !domain.ValidScopeName(resource.Scope.Application) || !domain.ValidScopeName(resource.Scope.Environment) {
		return nil, nil, errors.New("invalid NATS resource identity")
	}
	accountSeed := deriveSeed(operatorSeed, accountKeyPurpose, resource.ID)
	userSeed := deriveSeed(operatorSeed, userKeyPurpose, resource.ID)
	defer clear(accountSeed)
	defer clear(userSeed)
	accountKey, err := nkeys.FromRawSeed(nkeys.PrefixByteAccount, accountSeed)
	if err != nil {
		return nil, nil, err
	}
	userKey, err := nkeys.FromRawSeed(nkeys.PrefixByteUser, userSeed)
	if err != nil {
		accountKey.Wipe()
		return nil, nil, err
	}
	return accountKey, userKey, nil
}

func deriveSeed(root []byte, purpose string, resourceID string) []byte {
	mac := hmac.New(sha256.New, root)
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(resourceID))
	return mac.Sum(nil)
}

func buildAccountClaims(target config.Target, resource domain.Resource, accountPublic string, userPublic string, revoke bool, now time.Time) *jwt.AccountClaims {
	claims := jwt.NewAccountClaims(accountPublic)
	claims.Name = "srp-" + shortResourceHash(resource.ID)
	claims.Limits.Conn = int64(target.NATSMaxConnections)
	claims.Limits.Subs = int64(target.NATSMaxSubscriptions)
	claims.Limits.Payload = target.NATSMaxPayloadBytes
	if target.NATSJetStreamMemoryBytes > 0 {
		claims.Limits.JetStreamLimits = jwt.JetStreamLimits{
			MemoryStorage:    target.NATSJetStreamMemoryBytes,
			DiskStorage:      target.NATSJetStreamDiskBytes,
			Streams:          int64(target.NATSJetStreamMaxStreams),
			Consumer:         int64(target.NATSJetStreamMaxConsumers),
			MaxBytesRequired: true,
		}
	}
	if revoke {
		claims.RevokeAt(userPublic, now)
	}
	return claims
}

func buildUserClaims(resource domain.Resource, accountPublic string, userPublic string, target config.Target) *jwt.UserClaims {
	claims := jwt.NewUserClaims(userPublic)
	claims.Name = "srp-" + shortResourceHash(resource.ID)
	claims.IssuerAccount = accountPublic
	claims.Permissions = jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{">"}},
		Sub: jwt.Permission{Allow: jwt.StringList{">"}},
	}
	claims.Subs = int64(target.NATSMaxSubscriptions)
	claims.Limits.Payload = target.NATSMaxPayloadBytes
	return claims
}

func encodeCredentials(userJWT string, userSeed []byte) []byte {
	credential := make([]byte, 0, len(userJWT)+len(userSeed)+128)
	credential = append(credential, "-----BEGIN NATS USER JWT-----\n"...)
	credential = append(credential, userJWT...)
	credential = append(credential, "\n------END NATS USER JWT------\n\n"...)
	credential = append(credential, "-----BEGIN USER NKEY SEED-----\n"...)
	credential = append(credential, userSeed...)
	credential = append(credential, "\n------END USER NKEY SEED------\n"...)
	return credential
}

func parseCredentials(contents []byte) ([]byte, []byte, error) {
	userJWT, jwtErr := extractCredentialBlock(contents, "-----BEGIN NATS USER JWT-----", "------END NATS USER JWT------")
	userSeed, seedErr := extractCredentialBlock(contents, "-----BEGIN USER NKEY SEED-----", "------END USER NKEY SEED------")
	if jwtErr != nil || seedErr != nil || len(userJWT) == 0 || len(userSeed) == 0 {
		clear(userJWT)
		clear(userSeed)
		return nil, nil, errors.New("invalid NATS credentials")
	}
	claims, err := jwt.DecodeUserClaims(string(userJWT))
	if err != nil {
		clear(userJWT)
		clear(userSeed)
		return nil, nil, errors.New("invalid NATS user JWT")
	}
	key, err := nkeys.FromSeed(userSeed)
	if err != nil {
		clear(userJWT)
		clear(userSeed)
		return nil, nil, errors.New("invalid NATS user seed")
	}
	defer key.Wipe()
	publicKey, err := key.PublicKey()
	if err != nil || nkeys.Prefix(publicKey) != nkeys.PrefixByteUser || claims.Subject != publicKey || claims.IssuerAccount == "" || nkeys.Prefix(claims.IssuerAccount) != nkeys.PrefixByteAccount {
		clear(userJWT)
		clear(userSeed)
		return nil, nil, errors.New("NATS user JWT and seed do not match")
	}
	validation := jwt.CreateValidationResults()
	claims.Validate(validation)
	if validation.IsBlocking(true) {
		clear(userJWT)
		clear(userSeed)
		return nil, nil, errors.New("NATS user JWT is not valid")
	}
	return userJWT, userSeed, nil
}

func extractCredentialBlock(contents []byte, begin string, end string) ([]byte, error) {
	start := bytes.Index(contents, []byte(begin))
	if start < 0 {
		return nil, errors.New("missing NATS credential block")
	}
	start += len(begin)
	for start < len(contents) && (contents[start] == '\r' || contents[start] == '\n' || contents[start] == ' ' || contents[start] == '\t') {
		start++
	}
	endOffset := bytes.Index(contents[start:], []byte(end))
	if endOffset < 0 {
		return nil, errors.New("unterminated NATS credential block")
	}
	value := bytes.TrimSpace(contents[start : start+endOffset])
	if len(value) == 0 {
		return nil, errors.New("empty NATS credential block")
	}
	return bytes.Clone(value), nil
}

func shortResourceHash(resourceID string) string {
	sum := sha256.Sum256([]byte(resourceID))
	return hex.EncodeToString(sum[:8])
}

func validateEndpoint(endpoint []byte) error {
	_, _, err := normalizedEndpoint(endpoint)
	return err
}

func normalizedEndpoint(endpoint []byte) (string, bool, error) {
	parsed, err := url.Parse(strings.TrimSpace(string(endpoint)))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return "", false, errors.New("NATS endpoint must be an absolute URL without credentials or path")
	}
	useTLS := parsed.Scheme == "tls"
	if parsed.Scheme != "nats" && !useTLS {
		return "", false, errors.New("NATS endpoint scheme is invalid")
	}
	if !useTLS && !isLoopback(parsed.Hostname()) {
		return "", false, errors.New("NATS endpoint must use TLS except on loopback")
	}
	parsed.Scheme = "nats"
	return parsed.String(), useTLS, nil
}

func validateJetStreamLimits(target config.Target) error {
	values := []int64{
		target.NATSJetStreamMemoryBytes,
		target.NATSJetStreamDiskBytes,
		int64(target.NATSJetStreamMaxStreams),
		int64(target.NATSJetStreamMaxConsumers),
	}
	for _, value := range values {
		if value < 0 {
			return errors.New("NATS JetStream limits cannot be negative")
		}
	}
	enabled := false
	complete := true
	for _, value := range values {
		if value > 0 {
			enabled = true
		}
		if value == 0 {
			complete = false
		}
	}
	if enabled && !complete {
		return errors.New("NATS JetStream requires explicit memory, disk, stream, and consumer limits")
	}
	return nil
}

func validClaimsUpdateResponse(response string) bool {
	response = strings.ToLower(strings.TrimSpace(response))
	if response == "jwt updated" || response == "ok" || response == "+ok" {
		return true
	}
	var update struct {
		Data *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"data"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(response), &update); err != nil || update.Error != nil || update.Data == nil {
		return false
	}
	return update.Data.Code == 200 && strings.TrimSpace(update.Data.Message) == "jwt updated"
}

func (driver *Driver) copyOperatorSeed() ([]byte, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.closed || len(driver.operatorSeed) == 0 {
		return nil, errors.New("NATS driver is closed")
	}
	return append([]byte(nil), driver.operatorSeed...), nil
}

func (driver *Driver) copyConnectionSettings() ([]byte, []byte, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.closed || len(driver.endpoint) == 0 || len(driver.systemCreds) == 0 {
		return nil, nil, errors.New("NATS driver is closed")
	}
	return append([]byte(nil), driver.endpoint...), append([]byte(nil), driver.systemCreds...), nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
