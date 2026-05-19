package managedconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFileMissingReturnsErrNotManaged(t *testing.T) {
	_, err := LoadFile(filepath.Join(t.TempDir(), "missing.json"))
	if !errors.Is(err, ErrNotManaged) {
		t.Fatalf("LoadFile() error = %v, want ErrNotManaged", err)
	}
}

func TestParseValidConfigNormalizesStrings(t *testing.T) {
	cfg, err := Parse([]byte(`{
  "version": " managed-install-v1 ",
  "organization_id": " org_123 ",
  "cloud_url": " https://api.kontext.dev ",
  "mode": " observe ",
  "agent": " claude ",
  "credentials": {
    "install_token_ref": " keychain:kontext-managed-install-token "
  },
  "device": {
    "label": " Engineering Mac "
  }
}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Version != Version || cfg.OrganizationID != "org_123" || cfg.CloudURL != "https://api.kontext.dev" {
		t.Fatalf("config not normalized: %+v", cfg)
	}
	if got := cfg.Credentials.InstallTokenRef; got.Source != "keychain" || got.Name != "kontext-managed-install-token" {
		t.Fatalf("token ref = %+v", got)
	}
	if cfg.Device.Label != "Engineering Mac" {
		t.Fatalf("device label = %q", cfg.Device.Label)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte(`{
  "version": "managed-install-v1",
  "organization_id": "org_123",
  "cloud_url": "https://api.kontext.dev",
  "mode": "observe",
  "agent": "claude",
  "credentials": {"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"},
  "extra": true
}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Parse() error = %v, want unknown field", err)
	}
}

func TestParseRejectsTrailingJSON(t *testing.T) {
	_, err := Parse([]byte(validConfigJSON() + `{}`))
	if err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("Parse() error = %v, want trailing JSON", err)
	}
}

func TestParseRequiresFields(t *testing.T) {
	tests := map[string]string{
		"version":           `"version": ""`,
		"organization_id":   `"organization_id": ""`,
		"cloud_url":         `"cloud_url": ""`,
		"mode":              `"mode": ""`,
		"agent":             `"agent": ""`,
		"install_token_ref": `"install_token_ref": ""`,
	}
	for name, replacement := range tests {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(validConfigJSON(), replacementFor(name), replacement, 1)
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatalf("Parse() error = nil, want failure")
			}
		})
	}
}

func TestParseRejectsInvalidCloudURL(t *testing.T) {
	tests := map[string]string{
		"non_https":     "http://api.kontext.dev",
		"missing_host":  "https:///path",
		"invalid_port":  "https://api.kontext.dev:bad",
		"port_too_high": "https://api.kontext.dev:99999",
		"userinfo":      "https://user@api.kontext.dev",
		"path":          "https://api.kontext.dev/org-a",
		"query":         "https://api.kontext.dev?token=1",
		"fragment":      "https://api.kontext.dev#frag",
	}
	for name, cloudURL := range tests {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(validConfigJSON(), "https://api.kontext.dev", cloudURL, 1)
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatalf("Parse() error = nil, want failure")
			}
		})
	}
}

func TestParseTokenRefAcceptsValidRefs(t *testing.T) {
	tests := map[string]TokenRef{
		"keychain:kontext-managed-install-token": {Source: "keychain", Name: "kontext-managed-install-token"},
		"env:KONTEXT_INSTALL_TOKEN":              {Source: "env", Name: "KONTEXT_INSTALL_TOKEN"},
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			got, err := ParseTokenRef(input)
			if err != nil {
				t.Fatalf("ParseTokenRef() error = %v", err)
			}
			if got != want {
				t.Fatalf("ParseTokenRef() = %+v, want %+v", got, want)
			}
			if got.String() != input {
				t.Fatalf("String() = %q, want %q", got.String(), input)
			}
		})
	}
}

func TestParseTokenRefRejectsInvalidRefs(t *testing.T) {
	tests := []string{
		"raw-token-value",
		"keychain:",
		"file:token",
		"env:KONTEXT INSTALL TOKEN",
		"env:KONTEXT:INSTALL:TOKEN",
		"env:KONTEXT-INSTALL-TOKEN",
		"env:1TOKEN",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseTokenRef(input); err == nil {
				t.Fatalf("ParseTokenRef() error = nil, want failure")
			}
		})
	}
}

func TestPathFromEnvHonorsOverride(t *testing.T) {
	t.Setenv(EnvPath, " "+filepath.Join(t.TempDir(), "managed.json")+" ")
	if got := PathFromEnv(); got != strings.TrimSpace(os.Getenv(EnvPath)) {
		t.Fatalf("PathFromEnv() = %q", got)
	}
}

func TestLoadFileReturnsChecksumAndPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte(validConfigJSON()), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if loaded.Path != path {
		t.Fatalf("Path = %q, want %q", loaded.Path, path)
	}
	if len(loaded.Checksum) != 64 {
		t.Fatalf("Checksum = %q, want sha256 hex", loaded.Checksum)
	}
}

func validConfigJSON() string {
	return `{
  "version": "managed-install-v1",
  "organization_id": "org_123",
  "cloud_url": "https://api.kontext.dev",
  "mode": "observe",
  "agent": "claude",
  "credentials": {
    "install_token_ref": "env:KONTEXT_INSTALL_TOKEN"
  },
  "device": {
    "label": "Engineering Mac"
  }
}`
}

func replacementFor(field string) string {
	switch field {
	case "install_token_ref":
		return `"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"`
	default:
		return `"` + field + `": "` + map[string]string{
			"version":         "managed-install-v1",
			"organization_id": "org_123",
			"cloud_url":       "https://api.kontext.dev",
			"mode":            "observe",
			"agent":           "claude",
		}[field] + `"`
	}
}
