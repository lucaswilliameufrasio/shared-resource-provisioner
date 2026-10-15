package valkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/provisioning"
	"github.com/redis/go-redis/v9"
)

type Driver struct {
	target   config.Target
	endpoint []byte
	mu       sync.Mutex
	closed   bool
}

func New(target config.Target, endpoint []byte) (*Driver, error) {
	endpoint = bytes.TrimSpace(endpoint)
	if target.ResourceType != domain.ResourceValkey || target.MaxResources < 1 || target.MaxConcurrentOperations < 1 || len(endpoint) == 0 || len(target.AllowedValkeyCommands) == 0 {
		return nil, errors.New("valkey target and command allowlist are required")
	}
	if err := validateCommands(target.AllowedValkeyCommands); err != nil {
		return nil, err
	}
	endpointURL, err := url.Parse(string(endpoint))
	if err != nil || endpointURL.Host == "" || endpointURL.User == nil || endpointURL.RawQuery != "" {
		return nil, errors.New("valkey target endpoint is invalid")
	}
	if endpointURL.Scheme != "redis" && endpointURL.Scheme != "rediss" {
		return nil, errors.New("valkey target must use redis or rediss URL scheme")
	}
	if endpointURL.Scheme != "rediss" && !isLoopback(endpointURL.Hostname()) {
		return nil, errors.New("valkey target must use TLS except on loopback")
	}
	if _, err := redis.ParseURL(endpointURL.String()); err != nil {
		return nil, errors.New("valkey target connection configuration is invalid")
	}
	return &Driver{target: target, endpoint: append([]byte(nil), endpoint...)}, nil
}

func (driver *Driver) Close() {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	clear(driver.endpoint)
	driver.endpoint = nil
	driver.closed = true
}

func (driver *Driver) Create(ctx context.Context, resource domain.Resource) (provisioning.Credential, error) {
	username, keyPattern, channelPattern, err := resourceNames(resource)
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		clear(passwordBytes)
		return provisioning.Credential{}, provisioning.NewDriverFailure("CREDENTIAL_GENERATION_FAILED", false)
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)
	clear(passwordBytes)
	defer func() {
		password = ""
	}()

	client, endpointURL, err := driver.adminClient()
	if err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer func() {
		_ = client.Close()
	}()
	if err := client.Ping(ctx).Err(); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("TARGET_UNAVAILABLE", false)
	}
	arguments := aclSetUserArguments(driver.target.AllowedValkeyCommands, username, password, keyPattern, channelPattern)
	if err := client.Do(ctx, arguments...).Err(); err != nil {
		return provisioning.Credential{}, provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	endpointURL.User = url.UserPassword(username, password)
	credential := []byte(endpointURL.String())
	return provisioning.Credential{Name: "VALKEY_URL", Value: credential}, nil
}

func (driver *Driver) Revoke(ctx context.Context, resource domain.Resource) error {
	username, _, _, err := resourceNames(resource)
	if err != nil {
		return provisioning.NewDriverFailure("INVALID_RESOURCE_METADATA", false)
	}
	client, _, err := driver.adminClient()
	if err != nil {
		return provisioning.NewDriverFailure("TARGET_CONFIGURATION_INVALID", false)
	}
	defer func() {
		_ = client.Close()
	}()
	if err := client.Ping(ctx).Err(); err != nil {
		return provisioning.NewDriverFailure("TARGET_UNAVAILABLE", true)
	}
	if err := client.Do(ctx, "ACL", "DELUSER", username).Err(); err != nil {
		return provisioning.NewDriverFailure("DRIVER_FAILURE", true)
	}
	return nil
}

func (driver *Driver) adminClient() (*redis.Client, *url.URL, error) {
	driver.mu.Lock()
	if driver.closed || len(driver.endpoint) == 0 {
		driver.mu.Unlock()
		return nil, nil, errors.New("valkey driver is closed")
	}
	endpoint := append([]byte(nil), driver.endpoint...)
	driver.mu.Unlock()
	defer clear(endpoint)

	endpointURL, err := url.Parse(string(endpoint))
	if err != nil {
		return nil, nil, err
	}
	options, err := redis.ParseURL(endpointURL.String())
	if err != nil {
		return nil, nil, err
	}
	options.MaxRetries = -1
	options.DialTimeout = 5 * time.Second
	options.ReadTimeout = 10 * time.Second
	options.WriteTimeout = 10 * time.Second
	options.PoolSize = 1
	options.MaxActiveConns = 1
	options.ContextTimeoutEnabled = true
	return redis.NewClient(options), endpointURL, nil
}

func resourceNames(resource domain.Resource) (string, string, string, error) {
	if resource.ID == "" || resource.ResourceType != domain.ResourceValkey || !domain.ValidScopeName(resource.Scope.Application) || !domain.ValidScopeName(resource.Scope.Environment) {
		return "", "", "", errors.New("invalid Valkey resource identity")
	}
	resourceSum := sha256.Sum256([]byte(resource.ID))
	scopeSum := sha256.Sum256([]byte(resource.Scope.Application + "\x00" + resource.Scope.Environment))
	name := "srp_" + hex.EncodeToString(resourceSum[:16])
	prefix := "srp:" + hex.EncodeToString(scopeSum[:16]) + ":*"
	return name, "~" + prefix, "&" + prefix, nil
}

func aclSetUserArguments(commands []string, username string, password string, keyPattern string, channelPattern string) []any {
	arguments := []any{"ACL", "SETUSER", username, "reset", "on", ">" + password, keyPattern, channelPattern}
	for _, command := range commands {
		arguments = append(arguments, "+"+strings.ToLower(command))
	}
	return arguments
}

func validateCommands(commands []string) error {
	allowed := map[string]struct{}{
		"ping": {}, "get": {}, "set": {}, "del": {}, "exists": {}, "expire": {}, "pexpire": {},
		"ttl": {}, "pttl": {}, "mget": {}, "mset": {}, "hget": {}, "hset": {}, "hdel": {},
		"hgetall": {}, "lpush": {}, "rpush": {}, "lrange": {}, "llen": {}, "sadd": {},
		"srem": {}, "smembers": {}, "zadd": {}, "zrange": {}, "zrem": {}, "publish": {},
		"subscribe": {}, "psubscribe": {}, "unsubscribe": {}, "punsubscribe": {}, "multi": {}, "exec": {},
		"discard": {}, "watch": {}, "unwatch": {},
	}
	seen := make(map[string]struct{}, len(commands))
	for _, command := range commands {
		lower := strings.ToLower(command)
		if _, exists := allowed[lower]; !exists {
			return errors.New("valkey command is outside the supported allowlist")
		}
		if _, exists := seen[lower]; exists {
			return errors.New("valkey command list contains duplicates")
		}
		seen[lower] = struct{}{}
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
