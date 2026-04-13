package sidecar

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/kontext-dev/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-dev/kontext-cli/internal/auth"
)

// fakeBackend records calls and returns a configurable error from each method.
type fakeBackend struct {
	heartbeatCalls atomic.Int32
	ingestCalls    atomic.Int32
	heartbeatErr   error
	ingestErr      error
}

func (f *fakeBackend) Heartbeat(_ context.Context, _ string) error {
	f.heartbeatCalls.Add(1)
	return f.heartbeatErr
}

func (f *fakeBackend) IngestEvent(_ context.Context, _ *agentv1.ProcessHookEventRequest) error {
	f.ingestCalls.Add(1)
	return f.ingestErr
}

// newTestServer builds a Server wired to a fake backend with a short
// heartbeat interval so tests don't wait 30s. The socket lives under t.TempDir.
func newTestServer(t *testing.T, backend backendClient) *Server {
	t.Helper()
	// Short session dir to stay under macOS's 104-byte sun_path limit.
	dir, err := os.MkdirTemp("", "kontext-sidecar-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return &Server{
		socketPath:        filepath.Join(dir, "k.sock"),
		sessionID:         "test-session",
		agentName:         "test-agent",
		client:            backend,
		heartbeatInterval: 5 * time.Millisecond,
	}
}

// captureStderr redirects os.Stderr to a pipe for the duration of fn and
// returns everything written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	_ = w.Close()
	os.Stderr = orig
	return <-done
}

func TestSidecar_HeartbeatStopsOnInvalidGrant(t *testing.T) {
	fb := &fakeBackend{
		heartbeatErr: fmt.Errorf("connect: %w", auth.ErrInvalidGrant),
	}
	s := newTestServer(t, fb)

	out := captureStderr(t, func() {
		if err := s.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}

		// Wait for the loop to exit after the first tick.
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if fb.heartbeatCalls.Load() >= 1 {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		// Give the handler a moment to print + cancel.
		time.Sleep(20 * time.Millisecond)
		s.Stop()
	})

	if got := fb.heartbeatCalls.Load(); got == 0 {
		t.Fatalf("heartbeatCalls = 0, want >= 1")
	}
	if !strings.Contains(out, "session has expired") {
		t.Errorf("stderr missing expected message; got: %q", out)
	}
	if !strings.Contains(out, "kontext login") {
		t.Errorf("stderr missing kontext login hint; got: %q", out)
	}

	// Heartbeat loop should have exited — record the current count, wait,
	// and confirm it did not increase.
	callsAfterShutdown := fb.heartbeatCalls.Load()
	time.Sleep(50 * time.Millisecond)
	if fb.heartbeatCalls.Load() != callsAfterShutdown {
		t.Errorf("heartbeat continued after invalid_grant: %d → %d",
			callsAfterShutdown, fb.heartbeatCalls.Load())
	}
}

func TestSidecar_TransientHeartbeatErrorKeepsLoopRunning(t *testing.T) {
	fb := &fakeBackend{
		heartbeatErr: fmt.Errorf("connect: dial tcp: no such host"),
	}
	s := newTestServer(t, fb)

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(s.Stop)

	// Wait for multiple ticks — loop should keep retrying transient errors.
	time.Sleep(50 * time.Millisecond)
	if got := fb.heartbeatCalls.Load(); got < 2 {
		t.Fatalf("heartbeatCalls = %d, want >= 2 (loop should keep retrying transient errors)", got)
	}
}

func TestSidecar_IngestAuthFailureMessagePrintsOnce(t *testing.T) {
	fb := &fakeBackend{
		ingestErr: fmt.Errorf("ProcessHookEvent: %w", auth.ErrInvalidGrant),
	}
	s := newTestServer(t, fb)
	// Stop the heartbeat loop from firing during this test so we isolate
	// the ingestion path.
	s.heartbeatInterval = time.Hour

	out := captureStderr(t, func() {
		if err := s.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(s.Stop)

		// Dial the sidecar and send two hook evaluate requests.
		sendHook := func() {
			conn, err := net.Dial("unix", s.socketPath)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			if err := WriteMessage(conn, EvaluateRequest{Type: "evaluate", HookEvent: "PreToolUse"}); err != nil {
				t.Fatalf("write: %v", err)
			}
			var res EvaluateResult
			if err := ReadMessage(conn, &res); err != nil {
				t.Fatalf("read: %v", err)
			}
		}
		sendHook()
		sendHook()

		// Let the async ingest goroutines run.
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if fb.ingestCalls.Load() >= 2 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond)
	})

	if got := fb.ingestCalls.Load(); got < 2 {
		t.Fatalf("ingestCalls = %d, want >= 2", got)
	}
	if n := strings.Count(out, "session has expired"); n != 1 {
		t.Errorf("stderr 'session has expired' count = %d, want 1; stderr: %q", n, out)
	}
}
