package config

import "testing"

func TestLoadFromEnvironmentDefaultsHTTPAddress(t *testing.T) {
	t.Parallel()

	settings, err := LoadFromEnvironment(func(string) string {
		return ""
	})
	if err != nil {
		t.Fatalf("LoadFromEnvironment() error = %v", err)
	}
	if settings.HTTPAddress != "127.0.0.1:8080" {
		t.Fatalf("HTTPAddress = %q", settings.HTTPAddress)
	}
	if settings.MutationsEnabled {
		t.Fatal("mutation gate is enabled by default")
	}
}

func TestLoadFromEnvironmentParsesMutationGateExplicitly(t *testing.T) {
	t.Parallel()

	settings, err := LoadFromEnvironment(func(key string) string {
		if key == "SRP_MUTATIONS_ENABLED" {
			return "true"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("LoadFromEnvironment() error = %v", err)
	}
	if !settings.MutationsEnabled {
		t.Fatal("mutation gate did not honor explicit true setting")
	}
	if _, err := LoadFromEnvironment(func(key string) string {
		if key == "SRP_MUTATIONS_ENABLED" {
			return "sometimes"
		}
		return ""
	}); err == nil {
		t.Fatal("LoadFromEnvironment() accepted an invalid mutation gate")
	}
}

func TestLoadFromEnvironmentParsesExactAdminSubjects(t *testing.T) {
	t.Parallel()

	values := map[string]string{"SRP_ADMIN_SUBJECTS": `["admin-a","admin-b"]`}
	settings, err := LoadFromEnvironment(func(key string) string {
		return values[key]
	})
	if err != nil {
		t.Fatalf("LoadFromEnvironment() error = %v", err)
	}
	if len(settings.AdminSubjects) != 2 || settings.AdminSubjects[0] != "admin-a" || settings.AdminSubjects[1] != "admin-b" {
		t.Fatalf("AdminSubjects = %#v", settings.AdminSubjects)
	}
}

func TestLoadFromEnvironmentRejectsInvalidAdminSubjects(t *testing.T) {
	t.Parallel()

	values := []string{`{}`, `null`, `["admin","admin"]`, `[" admin"]`, `["admin"] []`}
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			_, err := LoadFromEnvironment(func(key string) string {
				if key == "SRP_ADMIN_SUBJECTS" {
					return value
				}
				return ""
			})
			if err == nil {
				t.Fatal("LoadFromEnvironment() accepted invalid admin subjects")
			}
		})
	}
}

func TestValidateHTTPRequiresSQLiteAdminOIDCAndTLS(t *testing.T) {
	t.Parallel()

	base := Settings{
		SQLitePath:     "data/control.db",
		HTTPAddress:    "127.0.0.1:8080",
		MCPResourceURL: "http://127.0.0.1:8080/mcp",
		OIDCIssuerURL:  "https://issuer.example.test",
		OIDCAudience:   "provisioner",
		AdminSubjects:  []string{"admin-subject"},
	}
	tests := []struct {
		name     string
		settings Settings
		wantErr  bool
	}{
		{name: "valid loopback", settings: base},
		{
			name: "database required",
			settings: func() Settings {
				settings := base
				settings.SQLitePath = ""
				return settings
			}(),
			wantErr: true,
		},
		{
			name: "admin required",
			settings: func() Settings {
				settings := base
				settings.AdminSubjects = nil
				return settings
			}(),
			wantErr: true,
		},
		{
			name: "remote without TLS",
			settings: func() Settings {
				settings := base
				settings.HTTPAddress = "0.0.0.0:8080"
				settings.MCPResourceURL = "https://provisioner.example.test/mcp"
				return settings
			}(),
			wantErr: true,
		},
		{
			name: "remote with TLS",
			settings: func() Settings {
				settings := base
				settings.HTTPAddress = "0.0.0.0:8443"
				settings.TLSCertFile = "cert.pem"
				settings.TLSKeyFile = "key.pem"
				settings.MCPResourceURL = "https://provisioner.example.test/mcp"
				return settings
			}(),
		},
		{
			name: "remote loopback OIDC issuer",
			settings: func() Settings {
				settings := base
				settings.OIDCIssuerURL = "http://issuer.example.test"
				return settings
			}(),
			wantErr: true,
		},
		{
			name: "duplicate admin subject",
			settings: func() Settings {
				settings := base
				settings.AdminSubjects = []string{"admin-subject", "admin-subject"}
				return settings
			}(),
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := test.settings.ValidateHTTP()
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateHTTP() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestValidateStdioRequiresExplicitIdentityPolicyAndDatabase(t *testing.T) {
	t.Parallel()

	if err := (Settings{PolicyFile: "policy.json", SQLitePath: "data/control.db"}).ValidateStdio(); err == nil {
		t.Fatal("ValidateStdio() accepted missing principal")
	}
	if err := (Settings{StdioSubject: "subject-123", SQLitePath: "data/control.db"}).ValidateStdio(); err == nil {
		t.Fatal("ValidateStdio() accepted missing policy file")
	}
	if err := (Settings{StdioSubject: "subject-123", PolicyFile: "policy.json"}).ValidateStdio(); err == nil {
		t.Fatal("ValidateStdio() accepted missing SQLite path")
	}
	if err := (Settings{StdioSubject: "subject-123", PolicyFile: "policy.json", SQLitePath: "data/control.db"}).ValidateStdio(); err != nil {
		t.Fatalf("ValidateStdio() error = %v", err)
	}
	if err := (Settings{StdioSubject: "subject-123", PolicyFile: "policy.json", SQLitePath: "data/control.db", MutationsEnabled: true}).ValidateStdio(); err == nil {
		t.Fatal("ValidateStdio() accepted enabled mutations without target and Ciphera configuration")
	}
}
