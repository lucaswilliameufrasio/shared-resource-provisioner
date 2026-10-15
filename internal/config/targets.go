package config

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

const maxOperatorConfigBytes = 1 << 20

type TargetFile struct {
	Targets []Target `json:"targets"`
}

type Target struct {
	ID                        string              `json:"id"`
	ResourceType              domain.ResourceType `json:"resource_type"`
	EndpointFile              string              `json:"endpoint_file"`
	MaxResources              int                 `json:"max_resources"`
	MaxConcurrentOperations   int                 `json:"max_concurrent_operations"`
	MaxConnectionsPerResource int                 `json:"max_connections_per_resource,omitempty"`
	AllowedValkeyCommands     []string            `json:"allowed_valkey_commands,omitempty"`
	NATSOperatorSeedFile      string              `json:"nats_operator_seed_file,omitempty"`
	NATSSystemCredentialsFile string              `json:"nats_system_credentials_file,omitempty"`
	NATSMaxConnections        int                 `json:"nats_max_connections,omitempty"`
	NATSMaxSubscriptions      int                 `json:"nats_max_subscriptions,omitempty"`
	NATSMaxPayloadBytes       int64               `json:"nats_max_payload_bytes,omitempty"`
	NATSJetStreamMemoryBytes  int64               `json:"nats_jetstream_memory_bytes,omitempty"`
	NATSJetStreamDiskBytes    int64               `json:"nats_jetstream_disk_bytes,omitempty"`
	NATSJetStreamMaxStreams   int                 `json:"nats_jetstream_max_streams,omitempty"`
	NATSJetStreamMaxConsumers int                 `json:"nats_jetstream_max_consumers,omitempty"`
}

type CipheraFile struct {
	APIURL          string            `json:"api_url"`
	ServiceKeyFile  string            `json:"service_key_file"`
	ProjectIDsByEnv map[string]string `json:"project_ids_by_environment"`
}

func LoadTargetFile(path string) (TargetFile, error) {
	var result TargetFile
	if strings.TrimSpace(path) == "" {
		return result, errors.New("target configuration file is required")
	}
	if err := decodeConfigFile(path, &result); err != nil {
		return TargetFile{}, errors.New("target configuration file is invalid")
	}
	if len(result.Targets) == 0 {
		return TargetFile{}, errors.New("at least one service target is required")
	}
	seenIDs := make(map[string]struct{}, len(result.Targets))
	seenTypes := make(map[domain.ResourceType]struct{}, len(result.Targets))
	for _, target := range result.Targets {
		if err := validateTarget(target); err != nil {
			return TargetFile{}, err
		}
		if _, exists := seenIDs[target.ID]; exists {
			return TargetFile{}, errors.New("service target IDs must be unique")
		}
		seenIDs[target.ID] = struct{}{}
		if _, exists := seenTypes[target.ResourceType]; exists {
			return TargetFile{}, errors.New("only one target per resource type is supported")
		}
		seenTypes[target.ResourceType] = struct{}{}
	}
	return result, nil
}

func LoadCipheraFile(path string) (CipheraFile, error) {
	var result CipheraFile
	if strings.TrimSpace(path) == "" {
		return result, errors.New("secret-store configuration file is required")
	}
	if err := decodeConfigFile(path, &result); err != nil {
		return CipheraFile{}, errors.New("secret-store configuration file is invalid")
	}
	if err := validateHTTPServiceURL(result.APIURL); err != nil {
		return CipheraFile{}, errors.New("secret-store API URL is invalid")
	}
	if strings.TrimSpace(result.ServiceKeyFile) == "" || len(result.ProjectIDsByEnv) == 0 {
		return CipheraFile{}, errors.New("secret-store service key file and environment project mapping are required")
	}
	for environment, projectID := range result.ProjectIDsByEnv {
		if !domain.ValidScopeName(environment) || !validIdentifier(projectID, 128) {
			return CipheraFile{}, errors.New("secret-store project mapping is invalid")
		}
	}
	return result, nil
}

func decodeConfigFile(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxOperatorConfigBytes {
		return errors.New("configuration file is not a bounded regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxOperatorConfigBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("configuration file contains trailing JSON")
	}
	return nil
}

func validateTarget(target Target) error {
	if !validIdentifier(target.ID, 64) || !target.ResourceType.Valid() || strings.TrimSpace(target.EndpointFile) == "" {
		return errors.New("service target identity, type, and endpoint file are required")
	}
	if target.MaxResources < 1 || target.MaxConcurrentOperations < 1 {
		return errors.New("each target needs positive resource and concurrent-operation limits")
	}
	switch target.ResourceType {
	case domain.ResourcePostgreSQL:
		if target.MaxConnectionsPerResource < 1 || len(target.AllowedValkeyCommands) > 0 || target.NATSOperatorSeedFile != "" || target.NATSSystemCredentialsFile != "" {
			return errors.New("PostgreSQL target limits or fields are invalid")
		}
	case domain.ResourceValkey:
		if len(target.AllowedValkeyCommands) == 0 || target.MaxConnectionsPerResource != 0 || target.NATSOperatorSeedFile != "" || target.NATSSystemCredentialsFile != "" {
			return errors.New("valkey target command policy or fields are invalid")
		}
		if err := validateValkeyCommands(target.AllowedValkeyCommands); err != nil {
			return err
		}
	case domain.ResourceNATS:
		if strings.TrimSpace(target.NATSOperatorSeedFile) == "" || strings.TrimSpace(target.NATSSystemCredentialsFile) == "" || target.NATSMaxConnections < 1 || target.NATSMaxSubscriptions < 1 || target.NATSMaxPayloadBytes < 1 {
			return errors.New("NATS target credentials and hard limits are required")
		}
		if target.MaxConnectionsPerResource != 0 || len(target.AllowedValkeyCommands) > 0 {
			return errors.New("NATS target fields are invalid")
		}
		jetStreamValues := []int64{
			target.NATSJetStreamMemoryBytes,
			target.NATSJetStreamDiskBytes,
			int64(target.NATSJetStreamMaxStreams),
			int64(target.NATSJetStreamMaxConsumers),
		}
		for _, value := range jetStreamValues {
			if value < 0 {
				return errors.New("NATS JetStream limits cannot be negative")
			}
		}
		jetStreamEnabled := target.NATSJetStreamMemoryBytes > 0 || target.NATSJetStreamDiskBytes > 0 || target.NATSJetStreamMaxStreams > 0 || target.NATSJetStreamMaxConsumers > 0
		if jetStreamEnabled && (target.NATSJetStreamMemoryBytes == 0 || target.NATSJetStreamDiskBytes == 0 || target.NATSJetStreamMaxStreams == 0 || target.NATSJetStreamMaxConsumers == 0) {
			return errors.New("NATS JetStream requires explicit positive memory, disk, stream, and consumer limits")
		}
	}
	return nil
}

func validIdentifier(value string, maxLength int) bool {
	if value == "" || len(value) > maxLength || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		isLower := character >= 'a' && character <= 'z'
		isUpper := character >= 'A' && character <= 'Z'
		isDigit := character >= '0' && character <= '9'
		if !isLower && !isUpper && !isDigit && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func validateValkeyCommands(commands []string) error {
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
			return errors.New("valkey target contains a command outside the supported allowlist")
		}
		if _, exists := seen[lower]; exists {
			return errors.New("valkey target commands must be unique")
		}
		seen[lower] = struct{}{}
	}
	return nil
}

func validateHTTPServiceURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("service URL must be an absolute HTTP URL")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	return errors.New("service URL must use HTTPS except on loopback")
}
