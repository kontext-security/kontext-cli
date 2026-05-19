package managedconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadMissingConfigReturnsUnmanaged(t *testing.T) {
	result := Load(filepath.Join(t.TempDir(), "managed.json"), time.Unix(1, 0))
	if result.State != StateUnmanaged {
		t.Fatalf("state = %q, want %q", result.State, StateUnmanaged)
	}
	if result.Config != nil {
		t.Fatal("config should be nil for unmanaged state")
	}
}

func TestLoadValidConfigReturnsManagedActive(t *testing.T) {
	path := writeConfig(t, validConfig(`"install_token_ref":"keychain:kontext-managed-install-token"`))

	result := Load(path, time.Unix(1, 0))
	if result.State != StateManagedActive {
		t.Fatalf("state = %q, want %q: %s", result.State, StateManagedActive, result.Error)
	}
	if result.Config.OrganizationID != "org_example" {
		t.Fatalf("organization_id = %q, want org_example", result.Config.OrganizationID)
	}
	if result.Source.Checksum == "" {
		t.Fatal("checksum should be set for loaded config")
	}
}

func TestLoadInvalidJSONReturnsManagedInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte(`{`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	result := Load(path, time.Unix(1, 0))
	if result.State != StateManagedInvalid {
		t.Fatalf("state = %q, want %q", result.State, StateManagedInvalid)
	}
	if result.Error == "" {
		t.Fatal("invalid config should include an error")
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	_, err := Decode([]byte(`{
		"version":"managed-install-v1",
		"organization_id":"org_example",
		"cloud_url":"https://api.kontext.security",
		"mode":"observe",
		"agent":"claude",
		"unexpected":true,
		"device":{},
		"credentials":{"install_token_ref":"env:KONTEXT_INSTALL_TOKEN"}
	}`))
	if err == nil {
		t.Fatal("Decode() error = nil, want unknown field rejection")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %q, want unknown field", err.Error())
	}
}

func TestDecodeRejectsBadVersionModeAndAgent(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "version", body: strings.Replace(validConfig(`"install_token_ref":"env:KONTEXT_INSTALL_TOKEN"`), Version, "v0", 1), want: "version"},
		{name: "mode", body: strings.Replace(validConfig(`"install_token_ref":"env:KONTEXT_INSTALL_TOKEN"`), `"mode":"observe"`, `"mode":"ask"`, 1), want: "mode"},
		{name: "agent", body: strings.Replace(validConfig(`"install_token_ref":"env:KONTEXT_INSTALL_TOKEN"`), `"agent":"claude"`, `"agent":"codex"`, 1), want: "agent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode([]byte(tt.body))
			if err == nil {
				t.Fatal("Decode() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.want)
			}
		})
	}
}

func TestDecodeRejectsUnsafeCloudURL(t *testing.T) {
	tests := []string{
		`"cloud_url":"http://api.kontext.security"`,
		`"cloud_url":"https://user:pass@api.kontext.security"`,
		`"cloud_url":"https://api.kontext.security?token=x"`,
	}

	for _, replacement := range tests {
		t.Run(replacement, func(t *testing.T) {
			body := strings.Replace(validConfig(`"install_token_ref":"env:KONTEXT_INSTALL_TOKEN"`), `"cloud_url":"https://api.kontext.security"`, replacement, 1)
			_, err := Decode([]byte(body))
			if err == nil {
				t.Fatal("Decode() error = nil, want cloud_url validation error")
			}
			if !strings.Contains(err.Error(), "cloud_url") {
				t.Fatalf("error = %q, want cloud_url", err.Error())
			}
		})
	}
}

func TestDecodeRejectsRawTokenAndAcceptsRefs(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{name: "keychain", ref: `"install_token_ref":"keychain:kontext-managed-install-token"`},
		{name: "env", ref: `"install_token_ref":"env:KONTEXT_INSTALL_TOKEN"`},
		{name: "raw", ref: `"install_token_ref":"secret-token-value"`, wantErr: true},
		{name: "empty keychain", ref: `"install_token_ref":"keychain:"`, wantErr: true},
		{name: "bad env", ref: `"install_token_ref":"env:token"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode([]byte(validConfig(tt.ref)))
			if tt.wantErr && err == nil {
				t.Fatal("Decode() error = nil, want validation error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
		})
	}
}

func TestPathFromEnv(t *testing.T) {
	t.Setenv(EnvPath, "/tmp/kontext-managed.json")
	if got := PathFromEnv(); got != "/tmp/kontext-managed.json" {
		t.Fatalf("PathFromEnv() = %q", got)
	}
}

func TestRedactTokenRef(t *testing.T) {
	for _, ref := range []string{"keychain:secret", "env:KONTEXT_INSTALL_TOKEN", "raw-secret"} {
		got := RedactTokenRef(ref)
		if strings.Contains(got, "secret") || strings.Contains(got, "KONTEXT_INSTALL_TOKEN") {
			t.Fatalf("RedactTokenRef(%q) = %q, leaked source detail", ref, got)
		}
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func validConfig(tokenRef string) string {
	return `{
		"version":"managed-install-v1",
		"organization_id":"org_example",
		"cloud_url":"https://api.kontext.security",
		"mode":"observe",
		"agent":"claude",
		"device":{"label":"test-device","hostname":"host-1"},
		"credentials":{` + tokenRef + `}
	}`
}
