package run

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/credential"
)

func TestBitwardenResolverFetchesDomainCredential(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args.txt")
	aacPath := filepath.Join(dir, "aac")
	script := "#!/bin/sh\n" +
		"printf '%s' \"$*\" > \"" + argsPath + "\"\n" +
		"printf '%s' '{\"success\":true,\"domain\":\"github.com\",\"credential\":{\"username\":\"octocat\",\"password\":\"ghp_test\"}}'\n"
	if err := os.WriteFile(aacPath, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(aac) error = %v", err)
	}

	t.Setenv("KONTEXT_BITWARDEN_AAC_BIN", aacPath)
	t.Setenv("KONTEXT_BITWARDEN_TOKEN", "pair-token")
	t.Setenv("KONTEXT_BITWARDEN_PROVIDER", "bitwarden")

	resolver := &bitwardenCredentialResolver{}
	value, err := resolver.Resolve(context.Background(), credential.Entry{
		Scheme:   bitwardenScheme,
		EnvVar:   "GITHUB_TOKEN",
		Provider: "domain:github.com",
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if value != "ghp_test" {
		t.Fatalf("Resolve() = %q, want %q", value, "ghp_test")
	}

	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("ReadFile(args) error = %v", err)
	}
	got := string(args)
	for _, want := range []string{
		"connect",
		"--output json",
		"--token pair-token",
		"--provider bitwarden",
		"--domain github.com",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("aac args = %q, want substring %q", got, want)
		}
	}
}

func TestBitwardenResolverSupportsIDAndFieldSelection(t *testing.T) {
	dir := t.TempDir()
	aacPath := filepath.Join(dir, "aac")
	script := "#!/bin/sh\n" +
		"printf '%s' '{\"success\":true,\"credential_id\":\"cred-123\",\"credential\":{\"username\":\"db-user\",\"password\":\"db-pass\",\"id\":\"cred-123\"}}'\n"
	if err := os.WriteFile(aacPath, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(aac) error = %v", err)
	}

	t.Setenv("KONTEXT_BITWARDEN_AAC_BIN", aacPath)

	resolver := &bitwardenCredentialResolver{}
	value, err := resolver.Resolve(context.Background(), credential.Entry{
		Scheme:   bitwardenScheme,
		EnvVar:   "DB_USER",
		Provider: "id:item-123",
		Resource: "username",
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if value != "db-user" {
		t.Fatalf("Resolve() = %q, want %q", value, "db-user")
	}
}

func TestBitwardenResolverRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	_, err := selectBitwardenField(
		credential.Entry{
			Scheme:   bitwardenScheme,
			EnvVar:   "BAD",
			Provider: "domain:github.com",
			Resource: "unsupported",
		},
		bitwardenConnectResponse{Success: true},
	)
	if err == nil {
		t.Fatal("selectBitwardenField() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "unsupported bitwarden field") {
		t.Fatalf("selectBitwardenField() error = %q, want unsupported-field message", err)
	}
}
