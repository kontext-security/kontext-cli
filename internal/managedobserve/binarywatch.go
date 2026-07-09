package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
)

const (
	envBinaryWatchInterval     = "KONTEXT_BINARY_WATCH_INTERVAL"
	defaultBinaryWatchInterval = 2 * time.Minute
)

// startBinaryWatchdog exits after launchd KeepAlive leaves an old deleted
// binary running across brew upgrades; a clean exit lets launchd respawn the
// new binary.
func startBinaryWatchdog(ctx context.Context, log diagnostic.Logger) <-chan struct{} {
	replaced := make(chan struct{}, 1)
	resolved, initialInfo, ok := binaryWatchdogConfig(log)
	if !ok {
		close(replaced)
		return replaced
	}
	// Capture the stat seam once so the goroutine never reads package state
	// concurrently with tests swapping the seams.
	stat := statPath
	go runBinaryWatchdog(ctx, resolved, initialInfo, binaryWatchInterval(), stat, log, replaced)
	return replaced
}

func binaryWatchdogConfig(log diagnostic.Logger) (string, os.FileInfo, bool) {
	if runtimeGOOS != "darwin" {
		return "", nil, false
	}
	exe, err := executablePath()
	if err != nil {
		logAlways(log, "binary watchdog eligibility: executable path: %v\n", err)
		return "", nil, false
	}
	resolved, err := evalSymlinksPath(exe)
	if err != nil {
		logAlways(log, "binary watchdog eligibility: resolve executable: %v\n", err)
		return "", nil, false
	}
	info, err := statPath(resolved)
	if err != nil {
		logAlways(log, "binary watchdog eligibility: stat %s: %v\n", resolved, err)
		return "", nil, false
	}
	return resolved, info, true
}

func runBinaryWatchdog(ctx context.Context, resolved string, initialInfo os.FileInfo, interval time.Duration, stat func(string) (os.FileInfo, error), log diagnostic.Logger, replaced chan<- struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	loggedStatErr := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentInfo, err := stat(resolved)
			if errors.Is(err, fs.ErrNotExist) {
				signalBinaryReplaced(resolved, log, replaced)
				return
			}
			if err != nil {
				if !loggedStatErr {
					logAlways(log, "binary watchdog: stat %s: %v\n", resolved, err)
					loggedStatErr = true
				}
				continue
			}
			if !os.SameFile(initialInfo, currentInfo) {
				signalBinaryReplaced(resolved, log, replaced)
				return
			}
		}
	}
}

func signalBinaryReplaced(resolved string, log diagnostic.Logger, replaced chan<- struct{}) {
	logAlways(log, "binary watchdog: %s was replaced on disk; exiting for launchd restart\n", resolved)
	select {
	case replaced <- struct{}{}:
	default:
	}
}

func binaryWatchInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv(envBinaryWatchInterval))
	if raw == "" {
		return defaultBinaryWatchInterval
	}
	interval, err := time.ParseDuration(raw)
	if err != nil || interval <= 0 {
		return defaultBinaryWatchInterval
	}
	return interval
}

func logAlways(log diagnostic.Logger, format string, args ...any) {
	if log.Enabled() {
		log.Printf(format, args...)
		return
	}
	fmt.Fprint(os.Stderr, diagnostic.Redact(fmt.Sprintf(format, args...)))
}
