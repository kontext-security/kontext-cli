package installation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureGeneratesAndPreservesInstallationID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	now := time.Unix(10, 0)

	first, err := Ensure(path, now)
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if !strings.HasPrefix(first.InstallationID, "ins_") {
		t.Fatalf("installation_id = %q, want ins_ prefix", first.InstallationID)
	}

	second, err := Ensure(path, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Ensure() error = %v", err)
	}
	if second.InstallationID != first.InstallationID {
		t.Fatalf("installation_id changed from %q to %q", first.InstallationID, second.InstallationID)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("created_at changed from %s to %s", first.CreatedAt, second.CreatedAt)
	}
}

func TestLoadMissingReturnsExistsFalse(t *testing.T) {
	_, exists, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if exists {
		t.Fatal("exists = true, want false")
	}
}

func TestLoadMalformedInstallationSurfacesError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	if err := os.WriteFile(path, []byte(`{"installation_id":"bad"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, exists, err := Load(path)
	if !exists {
		t.Fatal("exists = false, want true for malformed file")
	}
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Fatalf("error = %q, want version validation", err.Error())
	}
}

func TestWriteUsesSafePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "installation.json")
	record := Record{
		Version:        Version,
		InstallationID: "ins_0123456789abcdefghijkl",
		CreatedAt:      time.Unix(10, 0).UTC(),
	}

	if err := Write(path, record); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 0600", got)
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	_, err := Decode([]byte(`{
		"version":"installation-v1",
		"installation_id":"ins_0123456789abcdefghijkl",
		"created_at":"2026-05-19T10:00:00Z",
		"secret":"nope"
	}`))
	if err == nil {
		t.Fatal("Decode() error = nil, want unknown field rejection")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %q, want unknown field", err.Error())
	}
}

func TestPathFromEnv(t *testing.T) {
	t.Setenv(EnvPath, "/tmp/kontext-installation.json")
	if got := PathFromEnv(); got != "/tmp/kontext-installation.json" {
		t.Fatalf("PathFromEnv() = %q", got)
	}
}
