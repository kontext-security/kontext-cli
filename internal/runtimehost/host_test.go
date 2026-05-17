package runtimehost

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

func TestStartLoadsEmbeddedModelOutsideRepoCWD(t *testing.T) {
	t.Setenv("KONTEXT_MODEL", "")
	t.Setenv("KONTEXT_THRESHOLD", "")
	t.Setenv("KONTEXT_HORIZON", "")
	t.Chdir(t.TempDir())

	host, err := Start(context.Background(), Options{
		AgentName: "claude",
		CWD:       t.TempDir(),
		DBPath:    filepath.Join(t.TempDir(), "guard.db"),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer host.Close(context.Background())

	if host.ActiveModelPath == "" {
		t.Fatal("ActiveModelPath is empty")
	}
	if _, err := os.Stat(host.ActiveModelPath); err != nil {
		t.Fatalf("active model stat error = %v", err)
	}
}

func TestStartUsesFullSessionIDForSessionDir(t *testing.T) {
	sessionID := "1234567890abcdef1234567890abcdef"
	host, err := Start(context.Background(), Options{
		AgentName: "claude",
		SessionID: sessionID,
		CWD:       t.TempDir(),
		DBPath:    filepath.Join(t.TempDir(), "guard.db"),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer host.Close(context.Background())

	if got, want := filepath.Base(host.SessionDir), sessionID; got != want {
		t.Fatalf("session dir base = %q, want %q", got, want)
	}
}

func TestStartRejectsUnsafeSessionID(t *testing.T) {
	for _, sessionID := range []string{"../escape", "nested/path", `nested\path`, ".", "..", "bad id"} {
		t.Run(sessionID, func(t *testing.T) {
			host, err := Start(context.Background(), Options{
				AgentName: "claude",
				SessionID: sessionID,
				CWD:       t.TempDir(),
				DBPath:    filepath.Join(t.TempDir(), "guard.db"),
			})
			if err == nil {
				if closeErr := host.Close(context.Background()); closeErr != nil {
					t.Fatalf("unexpected Start() success; Close() error = %v", closeErr)
				}
				t.Fatal("Start() error = nil, want unsafe session ID error")
			}
		})
	}
}

func TestStartDoesNotChmodCustomDBParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "project")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	host, err := Start(context.Background(), Options{
		AgentName: "claude",
		CWD:       t.TempDir(),
		DBPath:    filepath.Join(parent, "guard.db"),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer host.Close(context.Background())

	info, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("custom DB parent mode = %o, want 755", got)
	}
}

func TestStartPersistsLocalDecisions(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	host, err := Start(ctx, Options{
		AgentName:  "claude",
		CWD:        t.TempDir(),
		DBPath:     dbPath,
		Diagnostic: diagnostic.New(nil, false),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := localruntime.NewClient(host.SocketPath)
	result, err := client.Process(ctx, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
		ToolInput: map[string]any{
			"command": "rm -rf /tmp/kontext-test",
		},
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision == "" {
		t.Fatal("result decision is empty")
	}
	sessionID := host.SessionID
	if err := host.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	defer store.Close()
	events, err := store.Events(ctx, sessionID)
	if err != nil {
		t.Fatalf("Events() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if string(events[0].Decision) != string(result.Decision) {
		t.Fatalf("stored decision = %q, want %q", events[0].Decision, result.Decision)
	}
}

func TestCloseDrainsAsyncTelemetryBeforeClosingSession(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	host, err := Start(ctx, Options{
		AgentName:  "claude",
		CWD:        t.TempDir(),
		DBPath:     dbPath,
		Diagnostic: diagnostic.New(nil, false),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := localruntime.NewClient(host.SocketPath)
	result, err := client.Process(ctx, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPostToolUse,
		ToolName: "Bash",
		ToolInput: map[string]any{
			"command": "echo done",
		},
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("post-tool decision = %q, want allow ack", result.Decision)
	}
	sessionID := host.SessionID
	if err := host.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	defer store.Close()
	events, err := store.Events(ctx, sessionID)
	if err != nil {
		t.Fatalf("Events() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	session, err := store.Session(ctx, sessionID)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if session.Status != "closed" {
		t.Fatalf("session status = %q, want closed", session.Status)
	}
}

func TestDashboardAddrRejectsNonLoopback(t *testing.T) {
	tests := []string{
		"0.0.0.0:4765",
		"[::]:4765",
		":4765",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if _, err := DashboardAddr(tt, false); err == nil {
				t.Fatal("DashboardAddr() error = nil, want non-loopback error")
			}
		})
	}
}

func TestDashboardAddrAllowsLoopback(t *testing.T) {
	tests := []string{
		"127.0.0.1:0",
		"localhost:0",
		"[::1]:0",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if _, err := DashboardAddr(tt, false); err != nil {
				t.Fatalf("DashboardAddr() error = %v", err)
			}
		})
	}
}

func TestStartDashboardUsesLoopbackEphemeralPort(t *testing.T) {
	host, err := Start(context.Background(), Options{
		AgentName:      "claude",
		CWD:            t.TempDir(),
		DBPath:         filepath.Join(t.TempDir(), "guard.db"),
		DashboardAddr:  "127.0.0.1:0",
		StartDashboard: true,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer host.Close(context.Background())

	if host.DashboardURL == "" {
		t.Fatal("DashboardURL is empty")
	}
	resp, err := http.Get(host.DashboardURL + "/healthz")
	if err != nil {
		t.Fatalf("GET healthz error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
}
