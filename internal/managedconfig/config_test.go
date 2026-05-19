package managedconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMissingConfigReturnsNotManaged(t *testing.T) {
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
		"credentials": {"install_token_ref": " env:KONTEXT_INSTALL_TOKEN "},
		"device": {"label": " MacBook Pro "}
	}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Version != Version || cfg.OrganizationID != "org_123" || cfg.CloudURL != "https://api.kontext.dev" {
		t.Fatalf("config not normalized: %+v", cfg)
	}
	if cfg.Credentials.InstallTokenRef.Source != "env" || cfg.Credentials.InstallTokenRef.Name != "KONTEXT_INSTALL_TOKEN" {
		t.Fatalf("token ref = %+v, want env/KONTEXT_INSTALL_TOKEN", cfg.Credentials.InstallTokenRef)
	}
	if cfg.Device.Label != "MacBook Pro" {
		t.Fatalf("device label = %q, want MacBook Pro", cfg.Device.Label)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte(`{
		"version": "managed-install-v1",
		"organization_id": "org_123",
		"cloud_url": "https://api.kontext.dev",
		"mode": "observe",
		"agent": "claude",
		"credentials": {"install_token_ref": "keychain:kontext"},
		"extra": true
	}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Parse() error = %v, want unknown field", err)
	}
}

func TestParseRejectsDeviceHostname(t *testing.T) {
	_, err := Parse([]byte(`{
		"version": "managed-install-v1",
		"organization_id": "org_123",
		"cloud_url": "https://api.kontext.dev",
		"mode": "observe",
		"agent": "claude",
		"credentials": {"install_token_ref": "keychain:kontext"},
		"device": {"hostname": "host.local"}
	}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Parse() error = %v, want unknown device field", err)
	}
}

func TestParseRejectsInvalidCloudURLs(t *testing.T) {
	tests := []string{
		"http://api.kontext.dev",
		"https:///missing-host",
		"https://user:pass@api.kontext.dev",
		"https://api.kontext.dev?x=1",
		"https://api.kontext.dev#fragment",
	}
	for _, cloudURL := range tests {
		t.Run(cloudURL, func(t *testing.T) {
			_, err := Parse([]byte(strings.ReplaceAll(validConfigJSON, "$CLOUD_URL", cloudURL)))
			if err == nil {
				t.Fatal("Parse() error = nil, want invalid cloud_url error")
			}
		})
	}
}

func TestParseTokenRefs(t *testing.T) {
	for _, ref := range []string{"keychain:kontext-install", "env:KONTEXT_INSTALL_TOKEN"} {
		t.Run(ref, func(t *testing.T) {
			parsed, err := ParseTokenRef(ref)
			if err != nil {
				t.Fatalf("ParseTokenRef() error = %v", err)
			}
			if parsed.String() != ref {
				t.Fatalf("String() = %q, want %q", parsed.String(), ref)
			}
		})
	}

	for _, ref := range []string{"", "file:/tmp/token", "env:", "keychain:", "env:FOO:BAR", "env:FOO BAR"} {
		t.Run(ref, func(t *testing.T) {
			if _, err := ParseTokenRef(ref); err == nil {
				t.Fatal("ParseTokenRef() error = nil, want invalid ref error")
			}
		})
	}
}

func TestLoadUsesEnvOverrideAndChecksum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(validConfigJSON, "$CLOUD_URL", "https://api.kontext.dev")), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv(EnvPath, path)

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.Path != path {
		t.Fatalf("Path = %q, want %q", loaded.Path, path)
	}
	if !strings.HasPrefix(loaded.Checksum, "sha256:") {
		t.Fatalf("Checksum = %q, want sha256 prefix", loaded.Checksum)
	}
}

const validConfigJSON = `{
	"version": "managed-install-v1",
	"organization_id": "org_123",
	"cloud_url": "$CLOUD_URL",
	"mode": "observe",
	"agent": "claude",
	"credentials": {"install_token_ref": "keychain:kontext-install"},
	"device": {"label": "workstation"}
}`
