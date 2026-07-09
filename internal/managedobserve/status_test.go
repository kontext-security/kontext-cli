package managedobserve

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemonStatusRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	if err := WriteDaemonStatus(dbPath, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	got := LoadDaemonStatus(dbPath)
	if got == nil || got.Version != "1.2.3" || got.PID != os.Getpid() || got.StartedAt == "" {
		t.Fatalf("LoadDaemonStatus = %+v", got)
	}
	if _, err := time.Parse(time.RFC3339, got.StartedAt); err != nil {
		t.Fatalf("StartedAt = %q, want RFC3339: %v", got.StartedAt, err)
	}
}

func TestLoadDaemonStatusMissingFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	if got := LoadDaemonStatus(dbPath); got != nil {
		t.Fatalf("LoadDaemonStatus missing = %+v, want nil", got)
	}
}

func TestLoadDaemonStatusCorruptFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	if err := os.WriteFile(DaemonStatusPath(dbPath), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := LoadDaemonStatus(dbPath); got != nil {
		t.Fatalf("LoadDaemonStatus corrupt = %+v, want nil", got)
	}
}

func TestDaemonStatusFileMode(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	if err := WriteDaemonStatus(dbPath, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(DaemonStatusPath(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("daemon status mode = %v, want 0600", got)
	}
}
