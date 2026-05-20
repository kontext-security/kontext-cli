package localruntime

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"
)

func TestServiceEvaluatesBlockingHook(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{
		evaluateResult: hook.Result{
			Decision: hook.DecisionDeny,
			Reason:   "blocked by runtime",
		},
	}
	service := newTestService(t, runtime, false)
	client := NewClient(service.SocketPath())

	result, err := client.Process(context.Background(), hook.Event{
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny || result.Reason != "blocked by runtime" {
		t.Fatalf("Process() = %+v, want runtime deny result", result)
	}
	if got := runtime.evaluateCalls.Load(); got != 1 {
		t.Fatalf("EvaluateHook calls = %d, want 1", got)
	}
}

func TestServiceCanAckTelemetryBeforeAsyncIngest(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{ingested: make(chan hook.Event, 1)}
	service := newTestService(t, runtime, true)
	client := NewClient(service.SocketPath())

	result, err := client.Process(context.Background(), hook.Event{
		SessionID: "agent-session",
		HookName:  hook.HookPostToolUse,
		ToolName:  "Bash",
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("Process().Decision = %q, want allow", result.Decision)
	}

	select {
	case event := <-runtime.ingested:
		if event.HookName != hook.HookPostToolUse {
			t.Fatalf("ingested hook = %q, want PostToolUse", event.HookName)
		}
		if event.SessionID != "agent-session" {
			t.Fatalf("ingested session = %q, want agent-session", event.SessionID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("async ingest did not run")
	}
}

func TestServiceShutdownDrainsAsyncIngest(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{
		ingestStarted: make(chan struct{}),
		releaseIngest: make(chan struct{}),
	}
	service := newTestService(t, runtime, true)
	client := NewClient(service.SocketPath())

	result, err := client.Process(context.Background(), hook.Event{
		SessionID: "agent-session",
		HookName:  hook.HookPostToolUse,
		ToolName:  "Bash",
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("Process().Decision = %q, want allow", result.Decision)
	}

	select {
	case <-runtime.ingestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("async ingest did not start")
	}

	done := make(chan error, 1)
	go func() {
		done <- service.Shutdown(context.Background())
	}()
	select {
	case err := <-done:
		t.Fatalf("Shutdown() returned before async ingest drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(runtime.releaseIngest)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown() did not return after async ingest completed")
	}
}

func TestServiceUsesCustomFailureResult(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{evaluateErr: context.DeadlineExceeded}
	core, err := runtimecore.New(runtime)
	if err != nil {
		t.Fatalf("runtimecore.New() error = %v", err)
	}
	result := newTestServiceWithOptions(t, Options{
		Core: core,
		OnFailure: func(event hook.Event, err error) hook.Result {
			if event.HookName != hook.HookPreToolUse || err == nil {
				t.Fatalf("failure callback event=%+v err=%v", event, err)
			}
			return hook.Result{
				Decision: hook.DecisionAllow,
				Reason:   "custom fail-open",
			}
		},
	})
	client := NewClient(result.SocketPath())

	got, err := client.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if got.Decision != hook.DecisionAllow || got.Reason != "custom fail-open" {
		t.Fatalf("Process() = %+v, want custom fail-open result", got)
	}
}

func TestServiceFailsClosedWhenBlockingHookPayloadCannotDecode(t *testing.T) {
	t.Parallel()

	service := newTestService(t, &stubRuntime{}, false)
	result := service.process(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolInput: []byte(`{`),
	})

	if result.Allowed {
		t.Fatal("result.Allowed = true, want false")
	}
	if result.Decision != string(hook.DecisionDeny) {
		t.Fatalf("result.Decision = %q, want deny", result.Decision)
	}
}

func TestServiceAllowsNonblockingHookPayloadDecodeFailure(t *testing.T) {
	t.Parallel()

	service := newTestService(t, &stubRuntime{}, true)
	result := service.process(context.Background(), &EvaluateRequest{
		HookEvent: "PostToolUse",
		ToolInput: []byte(`{`),
	})

	if !result.Allowed {
		t.Fatal("result.Allowed = false, want true")
	}
	if result.Decision != string(hook.DecisionAllow) {
		t.Fatalf("result.Decision = %q, want allow", result.Decision)
	}
}

func TestServiceStartRejectsExistingRegularSocketPath(t *testing.T) {
	t.Parallel()

	socketPath := tempSocketPath(t)
	contents := []byte("do not delete")
	if err := os.WriteFile(socketPath, contents, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	core, err := runtimecore.New(&stubRuntime{})
	if err != nil {
		t.Fatalf("runtimecore.New() error = %v", err)
	}
	service, err := NewService(Options{
		SocketPath: socketPath,
		Core:       core,
		AgentName:  "claude",
		Diagnostic: diagnostic.New(io.Discard, false),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	if err := service.Start(context.Background()); err == nil {
		t.Fatal("Start() error = nil, want existing regular file rejected")
	}
	got, err := os.ReadFile(socketPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(contents) {
		t.Fatalf("socket path contents = %q, want %q", got, contents)
	}
}

func TestServiceStartRemovesStaleUnixSocket(t *testing.T) {
	t.Parallel()

	socketPath := tempSocketPath(t)
	stale, err := net.Listen("unix", socketPath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("Unix sockets unavailable: %v", err)
		}
		t.Fatalf("Listen() stale socket error = %v", err)
	}
	if unixListener, ok := stale.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	if err := stale.Close(); err != nil {
		t.Fatalf("Close() stale socket error = %v", err)
	}
	if info, err := os.Lstat(socketPath); err != nil {
		t.Fatalf("Lstat() stale socket error = %v", err)
	} else if info.Mode().Type() != os.ModeSocket {
		t.Fatalf("stale socket mode = %v, want socket", info.Mode())
	}

	service := newTestServiceWithOptions(t, Options{
		SocketPath: socketPath,
		Core:       mustTestCore(t, &stubRuntime{}),
		AgentName:  "claude",
		Diagnostic: diagnostic.New(io.Discard, false),
	})
	if _, err := os.Lstat(service.SocketPath()); err != nil {
		t.Fatalf("Lstat() runtime socket error = %v", err)
	}
}

func newTestService(t *testing.T, runtime *stubRuntime, asyncIngest bool) *Service {
	t.Helper()

	return newTestServiceWithOptions(t, Options{
		Core:        mustTestCore(t, runtime),
		AgentName:   "claude",
		AsyncIngest: asyncIngest,
		Diagnostic:  diagnostic.New(io.Discard, false),
	})
}

func newTestServiceWithOptions(t *testing.T, opts Options) *Service {
	t.Helper()

	if opts.SocketPath == "" {
		opts.SocketPath = tempSocketPath(t)
	}
	if opts.AgentName == "" {
		opts.AgentName = "claude"
	}
	if !opts.Diagnostic.Enabled() {
		opts.Diagnostic = diagnostic.New(io.Discard, false)
	}
	service, err := NewService(Options{
		SocketPath:  opts.SocketPath,
		Core:        opts.Core,
		SessionID:   opts.SessionID,
		AgentName:   opts.AgentName,
		AsyncIngest: opts.AsyncIngest,
		OnFailure:   opts.OnFailure,
		Diagnostic:  opts.Diagnostic,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(service.Stop)
	return service
}

func tempSocketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "kontext-runtime-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "kontext.sock")
}

func mustTestCore(t *testing.T, runtime *stubRuntime) *runtimecore.Core {
	t.Helper()

	core, err := runtimecore.New(runtime)
	if err != nil {
		t.Fatalf("runtimecore.New() error = %v", err)
	}
	return core
}

type stubRuntime struct {
	evaluateResult hook.Result
	evaluateErr    error
	ingested       chan hook.Event
	ingestStarted  chan struct{}
	releaseIngest  chan struct{}
	evaluateCalls  atomic.Int32
	ingestCalls    atomic.Int32
	startedIngest  atomic.Bool
}

func (s *stubRuntime) EvaluateHook(_ context.Context, _ hook.Event) (hook.Result, error) {
	s.evaluateCalls.Add(1)
	return s.evaluateResult, s.evaluateErr
}

func (s *stubRuntime) IngestEvent(ctx context.Context, event hook.Event) (hook.Result, error) {
	s.ingestCalls.Add(1)
	if s.ingestStarted != nil && s.startedIngest.CompareAndSwap(false, true) {
		close(s.ingestStarted)
	}
	if s.releaseIngest != nil {
		select {
		case <-s.releaseIngest:
		case <-ctx.Done():
			return hook.Result{}, ctx.Err()
		}
	}
	if s.ingested != nil {
		s.ingested <- event
	}
	return hook.Result{Decision: hook.DecisionAllow}, nil
}
