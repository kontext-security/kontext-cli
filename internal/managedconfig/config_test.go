package managedconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMissingConfigReturnsUnmanaged(t *testing.T) {
	state := Load(context.Background(), Options{Path: filepath.Join(t.TempDir(), "missing.json")})
	if state.Kind != StateUnmanaged {
		t.Fatalf("Kind = %q, want %q", state.Kind, StateUnmanaged)
	}
}

func TestLoadValidConfigReturnsManagedActive(t *testing.T) {
	path := writeConfig(t, validConfigJSON())
	state := Load(context.Background(), Options{Path: path})
	if state.Kind != StateManagedActive {
		t.Fatalf("Kind = %q, want %q, errors = %#v", state.Kind, StateManagedActive, state.Errors)
	}
	if state.Config.OrganizationID != "org_example" {
		t.Fatalf("OrganizationID = %q, want org_example", state.Config.OrganizationID)
	}
	if !strings.HasPrefix(state.Checksum, "sha256:") {
		t.Fatalf("Checksum = %q, want sha256 prefix", state.Checksum)
	}
}

func TestLoadInvalidJSONReturnsManagedInvalid(t *testing.T) {
	path := writeConfig(t, `{"version":`)
	state := Load(context.Background(), Options{Path: path})
	if state.Kind != StateManagedInvalid {
		t.Fatalf("Kind = %q, want %q", state.Kind, StateManagedInvalid)
	}
	if got := state.Errors[0].Code; got != "invalid_json" {
		t.Fatalf("error code = %q, want invalid_json", got)
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	path := writeConfig(t, strings.Replace(validConfigJSON(), `"credentials":`, `"extra": true, "credentials":`, 1))
	state := Load(context.Background(), Options{Path: path})
	if state.Kind != StateManagedInvalid {
		t.Fatalf("Kind = %q, want %q", state.Kind, StateManagedInvalid)
	}
	if got := state.Errors[0].Code; got != "invalid_json" {
		t.Fatalf("error code = %q, want invalid_json", got)
	}
}

func TestValidateRejectsUnsupportedVersionModeAgentAndCloudURL(t *testing.T) {
	cfg := validConfig()
	cfg.Version = "v0"
	cfg.Mode = "ask"
	cfg.Agent = "other"
	cfg.CloudURL = "http://api.kontext.security?token=bad"
	errs := Validate(cfg)
	wantCodes := []string{"unsupported_version", "invalid_cloud_url", "unsupported_mode", "unsupported_agent"}
	for _, code := range wantCodes {
		if !hasCode(errs, code) {
			t.Fatalf("Validate() missing code %q in %#v", code, errs)
		}
	}
}

func TestValidateRejectsMissingRequiredFields(t *testing.T) {
	errs := Validate(Config{})
	for _, code := range []string{"unsupported_version", "required", "unsupported_mode", "unsupported_agent"} {
		if !hasCode(errs, code) {
			t.Fatalf("Validate() missing code %q in %#v", code, errs)
		}
	}
}

func TestValidateRejectsUnsafeCloudURLParts(t *testing.T) {
	tests := []string{
		"https://user:pass@api.kontext.security",
		"https://api.kontext.security?x=1",
		"https://api.kontext.security#frag",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			cfg := validConfig()
			cfg.CloudURL = raw
			if !hasCode(Validate(cfg), "invalid_cloud_url") {
				t.Fatalf("Validate(%q) did not reject cloud_url", raw)
			}
		})
	}
}

func TestCredentialRefs(t *testing.T) {
	for _, raw := range []string{"keychain:kontext-managed-install-token", "env:KONTEXT_INSTALL_TOKEN"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseCredentialRef(raw); err != nil {
				t.Fatalf("ParseCredentialRef() error = %v", err)
			}
		})
	}
}

func TestValidateRejectsRawTokenValues(t *testing.T) {
	for _, raw := range []string{
		"sk_live_123",
		"token:secret",
		"header.payload.signature",
		"abcdefghijklmnopqrstuvwxyz1234567890",
	} {
		t.Run(raw, func(t *testing.T) {
			cfg := validConfig()
			cfg.Credentials.InstallTokenRef = raw
			if !hasCode(Validate(cfg), "inline_secret_rejected") && !hasCode(Validate(cfg), "invalid_credential_ref") {
				t.Fatalf("Validate(%q) did not reject raw token", raw)
			}
		})
	}
}

func writeConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func validConfigJSON() string {
	return `{
  "version": "managed-install-v1",
  "organization_id": "org_example",
  "cloud_url": "https://api.kontext.security",
  "mode": "observe",
  "agent": "claude",
  "device": {
    "label": "optional-human-label"
  },
  "credentials": {
    "install_token_ref": "keychain:kontext-managed-install-token"
  }
}`
}

func validConfig() Config {
	label := "optional-human-label"
	return Config{
		Version:        SchemaVersion,
		OrganizationID: "org_example",
		CloudURL:       "https://api.kontext.security",
		Mode:           DefaultMode,
		Agent:          DefaultAgent,
		Device:         Device{Label: &label},
		Credentials:    Credentials{InstallTokenRef: "keychain:kontext-managed-install-token"},
	}
}

func hasCode(errs []ValidationError, code string) bool {
	for _, err := range errs {
		if err.Code == code {
			return true
		}
	}
	return false
}
