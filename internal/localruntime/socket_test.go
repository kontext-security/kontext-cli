package localruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureSocketDirHardensExistingDirectoryPermissions(t *testing.T) {
	t.Parallel()

	parent := filepath.Join(t.TempDir(), "guard")
	if err := os.Mkdir(parent, 0o777); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	socketPath := filepath.Join(parent, "kontext.sock")
	if err := EnsureSocketDir(socketPath); err != nil {
		t.Fatalf("EnsureSocketDir() error = %v", err)
	}

	info, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %o, want 700", got)
	}
}

func TestEnsureSocketDirRejectsSymlinkParent(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	err := EnsureSocketDir(filepath.Join(link, "kontext.sock"))
	if err == nil {
		t.Fatal("EnsureSocketDir() error = nil, want symlink rejection")
	}
	if !strings.Contains(err.Error(), "is a symlink") {
		t.Fatalf("EnsureSocketDir() error = %v, want symlink rejection", err)
	}
}
