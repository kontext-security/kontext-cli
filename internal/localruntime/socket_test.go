package localruntime

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEnsureSocketDirCreatesPrivateDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	socketPath := filepath.Join(root, "guard", "kontext.sock")
	if err := EnsureSocketDir(socketPath); err != nil {
		t.Fatalf("EnsureSocketDir() error = %v", err)
	}

	info, err := os.Stat(filepath.Dir(socketPath))
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("socket dir mode = %o, want 700", got)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("socket dir stat missing uid")
	}
	if got := int(stat.Uid); got != os.Getuid() {
		t.Fatalf("socket dir owner uid = %d, want %d", got, os.Getuid())
	}
}

func TestEnsureSocketDirTightensExistingDirectoryPermissions(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	dir := filepath.Join(root, "guard")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("Chmod() setup error = %v", err)
	}

	socketPath := filepath.Join(dir, "kontext.sock")
	if err := EnsureSocketDir(socketPath); err != nil {
		t.Fatalf("EnsureSocketDir() error = %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("socket dir mode = %o, want 700", got)
	}
}

func TestEnsureSocketDirRejectsSymlinkDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	link := filepath.Join(root, "guard")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	err := EnsureSocketDir(filepath.Join(link, "kontext.sock"))
	if err == nil {
		t.Fatal("EnsureSocketDir() error = nil, want symlink rejection")
	}
	if !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("EnsureSocketDir() error = %v, want symlink rejection", err)
	}
}
