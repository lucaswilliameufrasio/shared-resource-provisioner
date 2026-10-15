package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
)

func TestLoadTargetFileRequiresPerTargetCapacityAndServiceLimits(t *testing.T) {
	t.Parallel()

	valid := TargetFile{Targets: []Target{
		{
			ID:                        "pg-primary",
			ResourceType:              domain.ResourcePostgreSQL,
			EndpointFile:              "/run/secrets/postgres-dsn",
			MaxResources:              20,
			MaxConcurrentOperations:   2,
			MaxConnectionsPerResource: 12,
		},
		{
			ID:                      "cache-primary",
			ResourceType:            domain.ResourceValkey,
			EndpointFile:            "/run/secrets/valkey-url",
			MaxResources:            20,
			MaxConcurrentOperations: 2,
			AllowedValkeyCommands:   []string{"ping", "get", "set", "del"},
		},
		{
			ID:                        "nats-primary",
			ResourceType:              domain.ResourceNATS,
			EndpointFile:              "/run/secrets/nats-url",
			MaxResources:              20,
			MaxConcurrentOperations:   2,
			NATSOperatorSeedFile:      "/run/secrets/operator-seed",
			NATSSystemCredentialsFile: "/run/secrets/system-creds",
			NATSMaxConnections:        25,
			NATSMaxSubscriptions:      100,
			NATSMaxPayloadBytes:       1 << 20,
		},
	}}
	path := writeConfig(t, valid)
	loaded, err := LoadTargetFile(path)
	if err != nil {
		t.Fatalf("LoadTargetFile() error = %v", err)
	}
	if len(loaded.Targets) != 3 || loaded.Targets[0].MaxConcurrentOperations != 2 {
		t.Fatalf("loaded target file = %+v", loaded)
	}
}

func TestOperatorExamplesRemainValidConfigurationWithoutCredentialValues(t *testing.T) {
	t.Parallel()

	if _, err := LoadTargetFile("../../config/targets.example.json"); err != nil {
		t.Fatalf("LoadTargetFile(example) error = %v", err)
	}
	if _, err := LoadCipheraFile("../../config/ciphera.example.json"); err != nil {
		t.Fatalf("LoadCipheraFile(example) error = %v", err)
	}
}

func TestLoadTargetFileRejectsUnsafeOrAmbiguousTargetSettings(t *testing.T) {
	t.Parallel()

	base := Target{
		ID:                      "cache-primary",
		ResourceType:            domain.ResourceValkey,
		EndpointFile:            "/run/secrets/valkey-url",
		MaxResources:            5,
		MaxConcurrentOperations: 1,
		AllowedValkeyCommands:   []string{"get", "set"},
	}
	tests := []struct {
		name    string
		targets []Target
	}{
		{
			name: "missing resource limit",
			targets: []Target{func() Target {
				target := base
				target.MaxResources = 0
				return target
			}()},
		},
		{
			name: "admin command not allowlisted",
			targets: []Target{func() Target {
				target := base
				target.AllowedValkeyCommands = []string{"get", "flushall"}
				return target
			}()},
		},
		{
			name: "duplicate type",
			targets: []Target{base, func() Target {
				target := base
				target.ID = "cache-secondary"
				return target
			}()},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := LoadTargetFile(writeConfig(t, TargetFile{Targets: test.targets})); err == nil {
				t.Fatal("LoadTargetFile() accepted unsafe target configuration")
			}
		})
	}
}

func TestLoadCipheraFileRequiresSafeEndpointAndEnvironmentMapping(t *testing.T) {
	t.Parallel()

	valid := CipheraFile{
		APIURL:          "https://ciphera.example.test",
		ServiceKeyFile:  "/run/secrets/ciphera-service-key",
		ProjectIDsByEnv: map[string]string{"production": "project-123"},
	}
	path := writeConfig(t, valid)
	loaded, err := LoadCipheraFile(path)
	if err != nil {
		t.Fatalf("LoadCipheraFile() error = %v", err)
	}
	if loaded.ProjectIDsByEnv["production"] != "project-123" {
		t.Fatalf("project mapping = %#v", loaded.ProjectIDsByEnv)
	}

	invalid := valid
	invalid.APIURL = "http://ciphera.example.test"
	if _, err := LoadCipheraFile(writeConfig(t, invalid)); err == nil {
		t.Fatal("LoadCipheraFile() accepted non-loopback HTTP")
	}
}

func writeConfig(t *testing.T, value any) string {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(config) error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	return path
}
