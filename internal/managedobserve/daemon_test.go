package managedobserve

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

func TestDaemonPreservesHookSessionIDs(t *testing.T) {
	socketPath, dbPath, stop := startTestDaemon(t)

	client := localruntime.NewClient(socketPath)
	client.Timeout = time.Second
	for _, sessionID := range []string{"claude-session-one", "claude-session-two"} {
		result, err := client.Process(context.Background(), hook.Event{
			SessionID: sessionID,
			Agent:     "claude",
			HookName:  hook.HookPreToolUse,
			ToolName:  "Read",
			CWD:       "/tmp/project",
		})
		if err != nil {
			t.Fatalf("Process(%s) error = %v", sessionID, err)
		}
		if result.Decision != hook.DecisionAllow {
			t.Fatalf("Process(%s) decision = %q reason = %q, want allow", sessionID, result.Decision, result.Reason)
		}
	}
	stop()

	store := openTestStore(t, dbPath)
	defer store.Close()
	for _, sessionID := range []string{"claude-session-one", "claude-session-two"} {
		session := waitForSession(t, store, sessionID)
		if session.ID != sessionID || session.Source != "daemon_observed" || session.Status != "open" {
			t.Fatalf("session %s = %+v, want open daemon-observed session", sessionID, session)
		}
	}
}

func TestDaemonSessionEndClosesHookSessionID(t *testing.T) {
	socketPath, dbPath, stop := startTestDaemon(t)

	client := localruntime.NewClient(socketPath)
	client.Timeout = time.Second
	result, err := client.Process(context.Background(), hook.Event{
		SessionID: "claude-session-end",
		Agent:     "claude",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Read",
		CWD:       "/tmp/project",
	})
	if err != nil {
		t.Fatalf("PreToolUse error = %v", err)
	}
	if result.ReasonCode == "" {
		t.Fatalf("PreToolUse result = %+v, want recorded decision", result)
	}
	store := openTestStore(t, dbPath)
	defer store.Close()
	session := waitForSession(t, store, "claude-session-end")
	if session.Status != "open" {
		t.Fatalf("session after PreToolUse = %+v, want open", session)
	}

	if _, err := client.Process(context.Background(), hook.Event{
		SessionID: "claude-session-end",
		Agent:     "claude",
		HookName:  hook.HookSessionEnd,
		CWD:       "/tmp/project",
	}); err != nil {
		t.Fatalf("SessionEnd error = %v", err)
	}
	stop()

	session = waitForSession(t, store, "claude-session-end")
	if session.Status != "closed" || session.ClosedAt == nil {
		t.Fatalf("session = %+v, want actual hook session closed", session)
	}
}

func TestDaemonStreamsLedgerBatches(t *testing.T) {
	requests := make(chan map[string]any, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/authorization-ledger/batches" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-install-token" {
			t.Fatalf("Authorization = %q, want bearer install token", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		requests <- body
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	socketDir, err := os.MkdirTemp("/tmp", "kontext-managedobserve-stream-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "kontext.sock")
	dbPath := filepath.Join(dir, "guard.db")
	writeTestManagedConfigWithCloudURL(t, filepath.Join(dir, "managed.json"), server.URL)
	writeTestInstallation(t, filepath.Join(dir, "installation.json"))

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(ctx, DaemonOptions{
			SocketPath:       socketPath,
			DBPath:           dbPath,
			IdleTimeout:      time.Hour,
			StreamStatePath:  filepath.Join(dir, "stream-state.json"),
			StreamInterval:   20 * time.Millisecond,
			StreamHTTPClient: server.Client(),
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("RunDaemon() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("RunDaemon did not stop")
		}
	})
	waitForSocket(t, socketPath, errCh)

	client := localruntime.NewClient(socketPath)
	client.Timeout = time.Second
	if _, err := client.Process(context.Background(), hook.Event{
		SessionID: "claude-stream-session",
		Agent:     "claude",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Read",
		CWD:       "/tmp/project",
	}); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	select {
	case body := <-requests:
		if body["organization_id"] != "org_123" {
			t.Fatalf("organization_id = %v", body["organization_id"])
		}
		if body["installation_id"] != "ins_0123456789abcdefghijklmnopqrstuv" {
			t.Fatalf("installation_id = %v", body["installation_id"])
		}
		actions, ok := body["authorization_actions"].([]any)
		if !ok {
			t.Fatalf("authorization_actions = %#v", body["authorization_actions"])
		}
		found := false
		for _, raw := range actions {
			action, ok := raw.(map[string]any)
			if ok && action["session_id"] == "claude-stream-session" {
				found = true
			}
		}
		if !found {
			t.Fatalf("authorization_actions = %#v, want claude stream session action", body["authorization_actions"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for hosted ledger batch")
	}
}

func TestCleanupIntervalNeverReturnsZero(t *testing.T) {
	if got := cleanupInterval(time.Nanosecond); got != time.Nanosecond {
		t.Fatalf("cleanupInterval(1ns) = %s, want 1ns", got)
	}
	if got := cleanupInterval(time.Hour); got != 30*time.Minute {
		t.Fatalf("cleanupInterval(1h) = %s, want 30m", got)
	}
}

func TestEnsureSocketDirTightensOwnerWritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket directory permissions are not portable to windows")
	}
	dir := filepath.Join(t.TempDir(), "socket-dir")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	if err := EnsureSocketDir(filepath.Join(dir, "kontext.sock")); err != nil {
		t.Fatalf("EnsureSocketDir() error = %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("socket dir mode = %#o, want 0700", got)
	}
}

func TestEnsureSocketDirRestoresOwnerWritePermission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket directory permissions are not portable to windows")
	}
	dir := filepath.Join(t.TempDir(), "socket-dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	if err := EnsureSocketDir(filepath.Join(dir, "kontext.sock")); err != nil {
		t.Fatalf("EnsureSocketDir() error = %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("socket dir mode = %#o, want 0700", got)
	}
}

func TestEnsureSocketDirRejectsNonDirectoryParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "socket-parent")
	if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := EnsureSocketDir(filepath.Join(parent, "kontext.sock")); err == nil {
		t.Fatal("EnsureSocketDir() error = nil, want failure for non-directory parent")
	}
}

func TestEnsureSocketDirRejectsSymlinkParent(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	link := filepath.Join(t.TempDir(), "socket-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := EnsureSocketDir(filepath.Join(link, "kontext.sock")); err == nil {
		t.Fatal("EnsureSocketDir() error = nil, want failure for symlink parent")
	}
}

func startTestDaemon(t *testing.T) (string, string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	socketDir, err := os.MkdirTemp("/tmp", "kontext-managedobserve-daemon-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "kontext.sock")
	dbPath := filepath.Join(dir, "guard.db")
	writeTestManagedConfigWithCloudURL(t, filepath.Join(dir, "managed.json"), server.URL)
	writeTestInstallation(t, filepath.Join(dir, "installation.json"))

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(ctx, DaemonOptions{
			SocketPath:       socketPath,
			DBPath:           dbPath,
			IdleTimeout:      time.Hour,
			StreamHTTPClient: server.Client(),
		})
	}()
	waitForSocket(t, socketPath, errCh)
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("RunDaemon() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("RunDaemon did not stop")
		}
	}
	t.Cleanup(stop)
	return socketPath, dbPath, stop
}

func waitForSocket(t *testing.T, socketPath string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("RunDaemon exited early: %v", err)
		default:
		}
		conn, err := net.DialTimeout("unix", socketPath, 20*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("managed observe daemon socket %s did not become ready", socketPath)
}

func writeTestManagedConfig(t *testing.T, path string) {
	t.Helper()
	writeTestManagedConfigWithCloudURL(t, path, "https://app.kontext.dev")
}

func writeTestManagedConfigWithCloudURL(t *testing.T, path, cloudURL string) {
	t.Helper()
	t.Setenv("KONTEXT_INSTALL_TOKEN", "test-install-token")
	if err := os.WriteFile(path, []byte(`{
  "version": "managed-install-v1",
  "organization_id": "org_123",
  "cloud_url": "`+cloudURL+`",
  "mode": "observe",
  "agent": "claude",
  "device": {"label": "test-mac"},
  "credentials": {"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"}
}`), 0o600); err != nil {
		t.Fatalf("WriteFile(managed config) error = %v", err)
	}
	t.Setenv("KONTEXT_MANAGED_CONFIG", path)
}

func writeTestInstallation(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"installation_id":"ins_0123456789abcdefghijklmnopqrstuv"}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(installation) error = %v", err)
	}
	t.Setenv("KONTEXT_INSTALLATION_STATE", path)
}

func openTestStore(t *testing.T, dbPath string) *sqlite.Store {
	t.Helper()
	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	return store
}

func waitForSession(t *testing.T, store *sqlite.Store, sessionID string) sqlite.SessionRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		session, err := store.Session(context.Background(), sessionID)
		if err == nil {
			return session
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Session(%s) error = %v", sessionID, lastErr)
	return sqlite.SessionRecord{}
}
