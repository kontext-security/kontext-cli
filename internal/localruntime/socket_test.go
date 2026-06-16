package localruntime

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnsureSocketDirTightensPermissiveDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket directory permissions are not portable to windows")
	}
	dir := filepath.Join(t.TempDir(), "socket-dir")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	if err := EnsureSocketDir(filepath.Join(dir, "kontext.sock")); err != nil {
		t.Fatalf("EnsureSocketDir() error = %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("socket dir mode = %#o, want 0700", got)
	}
}

func TestEnsureSocketDirRejectsSymlinkParent(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	link := filepath.Join(t.TempDir(), "socket-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	if err := EnsureSocketDir(filepath.Join(link, "kontext.sock")); err == nil {
		t.Fatal("EnsureSocketDir() error = nil, want failure for symlink parent")
	}
}
