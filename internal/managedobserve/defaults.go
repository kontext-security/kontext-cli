package managedobserve

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	DefaultLaunchdLabel = "security.kontext.managed-observe"

	// EnvExpectedConfigScope marks which managed-config scope a daemon was
	// installed for. The self-serve LaunchAgent sets it to "user"; the daemon
	// parks instead of running when the resolved scope differs, so an MDM
	// config appearing later is never served by the leftover self-serve agent.
	EnvExpectedConfigScope = "KONTEXT_EXPECTED_CONFIG_SCOPE"

	envSocketPath     = "KONTEXT_MANAGED_OBSERVE_SOCKET"
	envDBPath         = "KONTEXT_MANAGED_OBSERVE_DB"
	envIdleTimeout    = "KONTEXT_MANAGED_OBSERVE_IDLE_TIMEOUT"
	envLaunchdLabel   = "KONTEXT_MANAGED_OBSERVE_LAUNCHD_LABEL"
	defaultIdleWindow = 30 * time.Minute
)

func DefaultSocketPath() string {
	if path := strings.TrimSpace(os.Getenv(envSocketPath)); path != "" {
		return path
	}
	return filepath.Join("/tmp", fmt.Sprintf("kontext-managed-observe-%d", os.Getuid()), "kontext.sock")
}

func DefaultDBPath() string {
	if path := strings.TrimSpace(os.Getenv(envDBPath)); path != "" {
		return path
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "Kontext", "managed-observe", "guard.db")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "Library", "Application Support", "Kontext", "managed-observe", "guard.db")
	}
	return filepath.Join("managed-observe", "guard.db")
}

func DefaultIdleTimeout() time.Duration {
	if value := strings.TrimSpace(os.Getenv(envIdleTimeout)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultIdleWindow
}

func DefaultLabel() string {
	if label := strings.TrimSpace(os.Getenv(envLaunchdLabel)); label != "" {
		return label
	}
	return DefaultLaunchdLabel
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
