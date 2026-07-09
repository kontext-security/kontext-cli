package managedobserve

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
)

func TestBinaryWatchdogFiresWhenFileDeleted(t *testing.T) {
	resetUpdaterSeams(t)
	t.Setenv(envBinaryWatchInterval, "10ms")
	runtimeGOOS = "darwin"
	path := writeWatchdogBinary(t)
	executablePath = func() (string, error) { return path, nil }
	evalSymlinksPath = filepath.EvalSymlinks

	replaced := startBinaryWatchdog(context.Background(), diagnostic.Logger{})
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	assertWatchdogFires(t, replaced)
}

func TestBinaryWatchdogFiresWhenFileReplaced(t *testing.T) {
	resetUpdaterSeams(t)
	t.Setenv(envBinaryWatchInterval, "10ms")
	runtimeGOOS = "darwin"
	path := writeWatchdogBinary(t)
	executablePath = func() (string, error) { return path, nil }
	evalSymlinksPath = filepath.EvalSymlinks

	replaced := startBinaryWatchdog(context.Background(), diagnostic.Logger{})
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if err := os.WriteFile(path, []byte("new"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	assertWatchdogFires(t, replaced)
}

func TestBinaryWatchdogDoesNotFireWhenFileUnchanged(t *testing.T) {
	resetUpdaterSeams(t)
	t.Setenv(envBinaryWatchInterval, "10ms")
	runtimeGOOS = "darwin"
	path := writeWatchdogBinary(t)
	executablePath = func() (string, error) { return path, nil }
	evalSymlinksPath = filepath.EvalSymlinks
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	replaced := startBinaryWatchdog(ctx, diagnostic.Logger{})
	assertWatchdogDoesNotFire(t, replaced)
}

func TestBinaryWatchdogSkipsNonDarwin(t *testing.T) {
	resetUpdaterSeams(t)
	runtimeGOOS = "linux"

	replaced := startBinaryWatchdog(context.Background(), diagnostic.Logger{})
	assertWatchdogClosed(t, replaced)
}

func TestBinaryWatchdogSkipsExecutablePathError(t *testing.T) {
	resetUpdaterSeams(t)
	runtimeGOOS = "darwin"
	executablePath = func() (string, error) { return "", errors.New("missing executable") }

	replaced := startBinaryWatchdog(context.Background(), diagnostic.Logger{})
	assertWatchdogClosed(t, replaced)
}

func TestBinaryWatchdogStopsWhenContextCancelled(t *testing.T) {
	resetUpdaterSeams(t)
	t.Setenv(envBinaryWatchInterval, "10ms")
	runtimeGOOS = "darwin"
	path := writeWatchdogBinary(t)
	executablePath = func() (string, error) { return path, nil }
	evalSymlinksPath = filepath.EvalSymlinks
	ctx, cancel := context.WithCancel(context.Background())

	replaced := startBinaryWatchdog(ctx, diagnostic.Logger{})
	cancel()
	time.Sleep(30 * time.Millisecond)
	select {
	case <-replaced:
		t.Fatal("watchdog fired after context cancellation")
	default:
	}
}

func writeWatchdogBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kontext")
	if err := os.WriteFile(path, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func assertWatchdogFires(t *testing.T, replaced <-chan struct{}) {
	t.Helper()
	select {
	case _, ok := <-replaced:
		if !ok {
			t.Fatal("watchdog channel closed without firing")
		}
	case <-time.After(time.Second):
		t.Fatal("watchdog did not fire")
	}
}

func assertWatchdogDoesNotFire(t *testing.T, replaced <-chan struct{}) {
	t.Helper()
	select {
	case <-replaced:
		t.Fatal("watchdog fired")
	case <-time.After(30 * time.Millisecond):
	}
}

func assertWatchdogClosed(t *testing.T, replaced <-chan struct{}) {
	t.Helper()
	select {
	case _, ok := <-replaced:
		if ok {
			t.Fatal("watchdog fired")
		}
	case <-time.After(time.Second):
		t.Fatal("watchdog channel did not close")
	}
}
