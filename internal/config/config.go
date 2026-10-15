package config

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
)

const defaultHTTPAddress = "127.0.0.1:8080"

type Settings struct {
	HTTPAddress      string
	SQLitePath       string
	TLSCertFile      string
	TLSKeyFile       string
	MCPResourceURL   string
	OIDCIssuerURL    string
	OIDCAudience     string
	PolicyFile       string
	AdminSubjects    []string
	StdioSubject     string
	TargetFile       string
	CipheraFile      string
	MutationsEnabled bool
}

func LoadFromEnvironment(getenv func(string) string) (Settings, error) {
	settings := Settings{
		HTTPAddress:    getenv("SRP_HTTP_ADDR"),
		SQLitePath:     getenv("SRP_SQLITE_PATH"),
		TLSCertFile:    getenv("SRP_TLS_CERT_FILE"),
		TLSKeyFile:     getenv("SRP_TLS_KEY_FILE"),
		MCPResourceURL: getenv("SRP_MCP_RESOURCE_URL"),
		OIDCIssuerURL:  getenv("SRP_OIDC_ISSUER_URL"),
		OIDCAudience:   getenv("SRP_OIDC_AUDIENCE"),
		PolicyFile:     getenv("SRP_AUTHZ_POLICY_FILE"),
		StdioSubject:   getenv("SRP_STDIO_SUBJECT"),
		TargetFile:     getenv("SRP_TARGETS_FILE"),
		CipheraFile:    getenv("SRP_CIPHERA_CONFIG_FILE"),
	}
	mutationsEnabled := strings.TrimSpace(getenv("SRP_MUTATIONS_ENABLED"))
	if mutationsEnabled != "" {
		enabled, err := strconv.ParseBool(mutationsEnabled)
		if err != nil {
			return Settings{}, errors.New("mutation gate must be a boolean")
		}
		settings.MutationsEnabled = enabled
	}
	adminSubjectsJSON := strings.TrimSpace(getenv("SRP_ADMIN_SUBJECTS"))
	if adminSubjectsJSON != "" {
		decoder := json.NewDecoder(strings.NewReader(adminSubjectsJSON))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&settings.AdminSubjects); err != nil {
			return Settings{}, errors.New("admin subjects must be a JSON array")
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return Settings{}, errors.New("admin subjects must be a single JSON array")
		}
		if settings.AdminSubjects == nil {
			return Settings{}, errors.New("admin subjects must be a JSON array")
		}
		seen := make(map[string]struct{}, len(settings.AdminSubjects))
		for _, subject := range settings.AdminSubjects {
			if !identity.ValidSubject(subject) {
				return Settings{}, errors.New("admin subject is invalid")
			}
			if _, exists := seen[subject]; exists {
				return Settings{}, errors.New("admin subjects must be unique")
			}
			seen[subject] = struct{}{}
		}
	}
	if settings.HTTPAddress == "" {
		settings.HTTPAddress = defaultHTTPAddress
	}
	return settings, nil
}

func (settings Settings) ValidateStdio() error {
	if !identity.ValidSubject(settings.StdioSubject) {
		return errors.New("stdio principal is required")
	}
	if strings.TrimSpace(settings.PolicyFile) == "" {
		return errors.New("authorization policy file is required")
	}
	if strings.TrimSpace(settings.SQLitePath) == "" {
		return errors.New("SQLite database path is required")
	}
	if err := validateProvisioningSettings(settings); err != nil {
		return err
	}
	return nil
}

func (settings Settings) ValidateHTTP() error {
	if strings.TrimSpace(settings.SQLitePath) == "" {
		return errors.New("SQLite database path is required")
	}
	if len(settings.AdminSubjects) == 0 {
		return errors.New("at least one OIDC admin subject is required")
	}
	if err := validateProvisioningSettings(settings); err != nil {
		return err
	}
	seenAdminSubjects := make(map[string]struct{}, len(settings.AdminSubjects))
	for _, subject := range settings.AdminSubjects {
		if !identity.ValidSubject(subject) {
			return errors.New("admin subject is invalid")
		}
		if _, exists := seenAdminSubjects[subject]; exists {
			return errors.New("admin subjects must be unique")
		}
		seenAdminSubjects[subject] = struct{}{}
	}
	if strings.TrimSpace(settings.OIDCIssuerURL) == "" || strings.TrimSpace(settings.OIDCAudience) == "" {
		return errors.New("OIDC issuer and audience are required")
	}
	if err := validateMCPResourceURL(settings.MCPResourceURL); err != nil {
		return err
	}
	resourceURL, _ := url.Parse(settings.MCPResourceURL)
	if !isLoopbackAddress(settings.HTTPAddress) && resourceURL.Scheme != "https" {
		return errors.New("non-loopback HTTP listeners require an HTTPS MCP resource URL")
	}
	if err := validateIssuerURL(settings.OIDCIssuerURL); err != nil {
		return err
	}
	if (settings.TLSCertFile == "") != (settings.TLSKeyFile == "") {
		return errors.New("TLS certificate and key must be configured together")
	}
	if settings.TLSCertFile == "" && !isLoopbackAddress(settings.HTTPAddress) {
		return errors.New("TLS is required for non-loopback HTTP listeners")
	}
	return nil
}

func validateProvisioningSettings(settings Settings) error {
	hasTargetFile := strings.TrimSpace(settings.TargetFile) != ""
	hasCipheraFile := strings.TrimSpace(settings.CipheraFile) != ""
	if hasTargetFile != hasCipheraFile {
		return errors.New("service targets and Ciphera configuration must be configured together")
	}
	if settings.MutationsEnabled && !hasTargetFile {
		return errors.New("mutation gate requires service target and Ciphera configuration files")
	}
	return nil
}

func validateMCPResourceURL(raw string) error {
	resource, err := url.Parse(raw)
	if err != nil || resource.Host == "" || resource.User != nil || resource.RawQuery != "" || resource.Fragment != "" {
		return errors.New("MCP resource URL is invalid")
	}
	if resource.Scheme != "https" && (resource.Scheme != "http" || !isLoopbackHost(resource.Hostname())) {
		return errors.New("MCP resource URL must use HTTPS except on loopback")
	}
	path := resource.EscapedPath()
	if path == "" || path == "/" || !strings.HasPrefix(path, "/") || strings.Contains(path, "%") || strings.Contains(path, "//") || strings.HasSuffix(path, "/") {
		return errors.New("MCP resource URL must have a simple non-root endpoint path")
	}
	return nil
}

func validateIssuerURL(raw string) error {
	issuer, err := url.Parse(raw)
	if err != nil || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return errors.New("OIDC issuer URL is invalid")
	}
	if issuer.Scheme == "https" {
		return nil
	}
	if issuer.Scheme != "http" || !isLoopbackHost(issuer.Hostname()) {
		return errors.New("OIDC issuer must use HTTPS except on loopback")
	}
	return nil
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	return isLoopbackHost(host)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
