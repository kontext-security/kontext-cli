package localruntime

import (
	"errors"
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
		return fmt.Errorf("%s is a symlink", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("socket directory ownership is unavailable")
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("socket directory %s is owned by uid %d, want %d", dir, stat.Uid, os.Getuid())
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}
