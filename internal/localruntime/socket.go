package localruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func DefaultSocketPath() string {
	if path := os.Getenv("KONTEXT_GUARD_SOCKET"); path != "" {
		return path
	}
	return filepath.Join("/tmp", fmt.Sprintf("kontext-guard-%d", os.Getuid()), "kontext.sock")
}

func EnsureSocketDir(socketPath string) error {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("socket directory %q must not be a symlink", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("socket directory %q is not a directory", dir)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("socket directory %q owner could not be verified", dir)
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("socket directory %q must be owned by uid %d", dir, os.Getuid())
	}

	return os.Chmod(dir, 0o700)
}
