package installation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureGeneratesInstallationWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	inst, err := Ensure(context.Background(), path, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if !strings.HasPrefix(inst.InstallationID, "ins_") {
		t.Fatalf("InstallationID = %q, want ins_ prefix", inst.InstallationID)
	}
	if !inst.CreatedAt.Equal(now) {
		t.Fatalf("CreatedAt = %v, want %v", inst.CreatedAt, now)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 0600", got)
	}
}

func TestEnsurePreservesExistingInstallation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	first, err := Ensure(context.Background(), path)
	if err != nil {
		t.Fatalf("first Ensure() error = %v", err)
	}
	second, err := Ensure(context.Background(), path)
	if err != nil {
		t.Fatalf("second Ensure() error = %v", err)
	}
	if second.InstallationID != first.InstallationID {
		t.Fatalf("InstallationID changed from %q to %q", first.InstallationID, second.InstallationID)
	}
}

func TestLoadRejectsMalformedInstallation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	if err := os.WriteFile(path, []byte(`{"version":"bad"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want error")
	}
}
