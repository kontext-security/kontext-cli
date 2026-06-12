package coworkobserve

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

// fakeDaemon accepts localruntime evaluate requests on a unix socket and
// records them, mimicking the managed-observe daemon.
type fakeDaemon struct {
	listener net.Listener
	mu       sync.Mutex
	requests []localruntime.EvaluateRequest
	result   *localruntime.EvaluateResult
}

func (d *fakeDaemon) setResult(res localruntime.EvaluateResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.result = &res
}

func startFakeDaemon(t *testing.T) (*fakeDaemon, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "s.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d := &fakeDaemon{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var req localruntime.EvaluateRequest
				if err := localruntime.ReadMessage(conn, &req); err != nil {
					return
				}
				d.mu.Lock()
				d.requests = append(d.requests, req)
				res := localruntime.EvaluateResult{Type: "result", Decision: "allow", Allowed: true}
				if d.result != nil {
					res = *d.result
				}
				d.mu.Unlock()
				_ = localruntime.WriteMessage(conn, res)
			}(conn)
		}
	}()
	return d, socketPath
}

func (d *fakeDaemon) toolNames() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	names := make([]string, 0, len(d.requests))
	for _, req := range d.requests {
		names = append(names, req.ToolName)
	}
	return names
}

func testOptions(t *testing.T, socketPath string) Options {
	t.Helper()
	return Options{
		SocketPath:   socketPath,
		SessionsRoot: t.TempDir(),
		Diagnostic:   diagnostic.New(io.Discard, false),
	}
}

func writeSpool(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func eventLine(tool string) string {
	return `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"` + tool + `","tool_input":{"command":"x"},"tool_use_id":"tu-` + tool + `","cwd":"/w"}`
}

func TestMergeSettingsPreservesExistingContent(t *testing.T) {
	existing := []byte(`{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}],"Stop":[{"hooks":[{"type":"command","command":"echo bye"}]}]}}`)
	merged, needed := mergeSettings(existing, hookEntry(guardhookruntime.ModeObserve))
	if !needed {
		t.Fatal("mergeSettings reported no write needed for foreign settings")
	}
	var settings map[string]any
	if err := json.Unmarshal(merged, &settings); err != nil {
		t.Fatalf("merged settings are not valid JSON: %v", err)
	}
	if settings["model"] != "opus" {
		t.Fatalf("model dropped: %v", settings["model"])
	}
	hooks := settings["hooks"].(map[string]any)
	if _, ok := hooks["Stop"]; !ok {
		t.Fatal("Stop hooks dropped")
	}
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse entries = %d, want existing + ours", len(pre))
	}
	if !bytes.Contains(merged, []byte("echo hi")) || !bytes.Contains(merged, []byte(settingsMark)) {
		t.Fatal("merged settings missing existing hook or our spool hook")
	}

	// A second merge is a no-op.
	if _, needed := mergeSettings(merged, hookEntry(guardhookruntime.ModeObserve)); needed {
		t.Fatal("mergeSettings wants to rewrite settings that already carry the hook")
	}
}

func TestMergeSettingsFromEmptyAndInvalid(t *testing.T) {
	for _, existing := range [][]byte{nil, []byte("  "), []byte("{broken")} {
		merged, needed := mergeSettings(existing, hookEntry(guardhookruntime.ModeObserve))
		if !needed {
			t.Fatalf("mergeSettings(%q) reported no write needed", existing)
		}
		var settings map[string]any
		if err := json.Unmarshal(merged, &settings); err != nil {
			t.Fatalf("merged settings are not valid JSON: %v", err)
		}
		if !bytes.Contains(merged, []byte(settingsMark)) {
			t.Fatal("merged settings missing spool hook")
		}
	}
}

func TestMergeSettingsReplacesStaleVariantOnModeSwitch(t *testing.T) {
	observed, needed := mergeSettings(nil, hookEntry(guardhookruntime.ModeObserve))
	if !needed {
		t.Fatal("initial observe merge reported no write needed")
	}

	enforced, needed := mergeSettings(observed, hookEntry(guardhookruntime.ModeEnforce))
	if !needed {
		t.Fatal("mode switch reported no write needed")
	}
	var settings map[string]any
	if err := json.Unmarshal(enforced, &settings); err != nil {
		t.Fatalf("merged settings are not valid JSON: %v", err)
	}
	pre := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("PreToolUse entries = %d, want stale observe variant replaced", len(pre))
	}
	if !bytes.Contains(enforced, []byte(decisionsDirName)) {
		t.Fatal("enforce variant missing decision poll")
	}
	if _, needed := mergeSettings(enforced, hookEntry(guardhookruntime.ModeEnforce)); needed {
		t.Fatal("repeat enforce merge should be a no-op")
	}
}

func TestInjectAndHealthTracking(t *testing.T) {
	daemon, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	sessionDir := filepath.Join(opts.SessionsRoot, "acct", "ws", "local_abc")
	claudeDir := filepath.Join(sessionDir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	h := newHealth()
	inject(opts, h)
	if len(h.sessionsSeen) != 1 || len(h.hooked) != 1 {
		t.Fatalf("seen=%d hooked=%d, want 1/1", len(h.sessionsSeen), len(h.hooked))
	}
	settings, err := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	if err != nil {
		t.Fatalf("settings.json not written: %v", err)
	}
	if !bytes.Contains(settings, []byte(settingsMark)) {
		t.Fatalf("settings.json missing spool hook: %s", settings)
	}

	writeSpool(t, filepath.Join(sessionDir, spoolName), eventLine("Bash")+"\n")
	c := &collector{offsets: map[string]int64{}}
	c.collect(opts, h)
	if len(h.spooled) != 1 || h.eventsReplayed != 1 {
		t.Fatalf("spooled=%d replayed=%d, want 1/1", len(h.spooled), h.eventsReplayed)
	}
	if got := daemon.toolNames(); len(got) != 1 || got[0] != "Bash" {
		t.Fatalf("replayed tools = %v, want [Bash]", got)
	}
}

func TestDrainLeavesPartialTrailingLine(t *testing.T) {
	daemon, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	spool := filepath.Join(t.TempDir(), spoolName)

	writeSpool(t, spool, eventLine("Bash")+"\n"+`{"session_id":"s1","hook_event`)
	c := &collector{offsets: map[string]int64{}}
	c.drain(opts, newHealth(), spool)

	if got := daemon.toolNames(); len(got) != 1 || got[0] != "Bash" {
		t.Fatalf("replayed tools = %v, want [Bash]", got)
	}
	wantOffset := int64(len(eventLine("Bash")) + 1)
	if c.offsets[spool] != wantOffset {
		t.Fatalf("offset = %d, want %d (end of last complete line)", c.offsets[spool], wantOffset)
	}

	// Completing the partial line replays it on the next tick.
	writeSpool(t, spool, `_name":"PreToolUse","tool_name":"Read","tool_use_id":"tu-2"}`+"\n")
	c.drain(opts, newHealth(), spool)
	if got := daemon.toolNames(); len(got) != 2 || got[1] != "Read" {
		t.Fatalf("replayed tools = %v, want [Bash Read]", got)
	}
}

func TestDrainHaltsOnTransportErrorAndRetries(t *testing.T) {
	dir, err := os.MkdirTemp("", "kx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	deadSocket := filepath.Join(dir, "dead.sock")
	opts := testOptions(t, deadSocket)
	spool := filepath.Join(t.TempDir(), spoolName)
	writeSpool(t, spool, eventLine("Bash")+"\n"+eventLine("Read")+"\n")

	c := &collector{offsets: map[string]int64{}}
	c.drain(opts, newHealth(), spool)
	if c.offsets[spool] != 0 {
		t.Fatalf("offset advanced to %d past undelivered events", c.offsets[spool])
	}

	// Daemon comes back; both events are delivered in order.
	daemon, socketPath := startFakeDaemon(t)
	opts.SocketPath = socketPath
	c.drain(opts, newHealth(), spool)
	if got := daemon.toolNames(); len(got) != 2 || got[0] != "Bash" || got[1] != "Read" {
		t.Fatalf("replayed tools = %v, want [Bash Read]", got)
	}
}

func TestDrainSkipsMalformedLines(t *testing.T) {
	daemon, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	spool := filepath.Join(t.TempDir(), spoolName)
	writeSpool(t, spool, "{not json\n"+eventLine("Bash")+"\n")

	c := &collector{offsets: map[string]int64{}}
	c.drain(opts, newHealth(), spool)
	if got := daemon.toolNames(); len(got) != 1 || got[0] != "Bash" {
		t.Fatalf("replayed tools = %v, want [Bash]", got)
	}
	c.drain(opts, newHealth(), spool)
	if got := daemon.toolNames(); len(got) != 1 {
		t.Fatalf("malformed line was retried: %v", got)
	}
}

func TestOffsetsPersistAcrossRestarts(t *testing.T) {
	daemon, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	statePath := filepath.Join(t.TempDir(), "offsets.json")
	spool := filepath.Join(t.TempDir(), spoolName)
	writeSpool(t, spool, eventLine("Bash")+"\n")

	c := newCollector(statePath)
	c.drain(opts, newHealth(), spool)
	c.saveOffsets(opts)

	// A restarted collector must not re-replay the already-ingested event.
	restarted := newCollector(statePath)
	restarted.drain(opts, newHealth(), spool)
	if got := daemon.toolNames(); len(got) != 1 {
		t.Fatalf("replayed tools after restart = %v, want exactly one Bash", got)
	}

	// New events appended after the restart still flow.
	writeSpool(t, spool, eventLine("Grep")+"\n")
	restarted.drain(opts, newHealth(), spool)
	if got := daemon.toolNames(); len(got) != 2 || got[1] != "Grep" {
		t.Fatalf("replayed tools = %v, want [Bash Grep]", got)
	}
}

func TestReplayDecodesCamelCaseAndPermissionMode(t *testing.T) {
	daemon, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	spool := filepath.Join(t.TempDir(), spoolName)
	writeSpool(t, spool, `{"sessionId":"s9","hookEventName":"PreToolUse","toolName":"Bash","toolInput":{"command":"ls"},"toolUseId":"tu-9","cwd":"/w","permission_mode":"acceptEdits"}`+"\n")

	c := &collector{offsets: map[string]int64{}}
	c.drain(opts, newHealth(), spool)

	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	if len(daemon.requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(daemon.requests))
	}
	req := daemon.requests[0]
	if req.SessionID != "cowork-s9" || req.Agent != "cowork" {
		t.Fatalf("session/agent = %q/%q", req.SessionID, req.Agent)
	}
	if req.ToolName != "Bash" || req.ToolUseID != "tu-9" {
		t.Fatalf("camelCase fields dropped: tool=%q toolUseID=%q", req.ToolName, req.ToolUseID)
	}
	if req.PermissionMode != "acceptEdits" {
		t.Fatalf("permission mode dropped: %q", req.PermissionMode)
	}
	if !bytes.Contains(req.ToolInput, []byte(`"ls"`)) {
		t.Fatalf("tool input dropped: %s", req.ToolInput)
	}
}

func TestCollectCleansUpDrainedIdleSpools(t *testing.T) {
	_, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	sessionDir := filepath.Join(opts.SessionsRoot, "acct", "ws", "local_abc")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(sessionDir, spoolName)
	writeSpool(t, spool, eventLine("Bash")+"\n")

	c := &collector{offsets: map[string]int64{}}
	h := newHealth()
	c.collect(opts, h)
	if _, err := os.Stat(spool); err != nil {
		t.Fatalf("fresh drained spool was removed: %v", err)
	}

	// Once idle past the retention window, the drained spool is deleted and
	// its offset entry dropped.
	old := time.Now().Add(-2 * spoolRetention)
	if err := os.Chtimes(spool, old, old); err != nil {
		t.Fatal(err)
	}
	c.collect(opts, h)
	if _, err := os.Stat(spool); !os.IsNotExist(err) {
		t.Fatalf("idle drained spool still present (err=%v)", err)
	}
	if _, ok := c.offsets[spool]; ok {
		t.Fatal("offset entry for removed spool not pruned")
	}
}

func TestCollectKeepsUndrainedSpools(t *testing.T) {
	dir, err := os.MkdirTemp("", "kx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	opts := testOptions(t, filepath.Join(dir, "dead.sock")) // daemon down: nothing drains
	sessionDir := filepath.Join(opts.SessionsRoot, "acct", "ws", "local_abc")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(sessionDir, spoolName)
	writeSpool(t, spool, eventLine("Bash")+"\n")
	old := time.Now().Add(-2 * spoolRetention)
	if err := os.Chtimes(spool, old, old); err != nil {
		t.Fatal(err)
	}

	c := &collector{offsets: map[string]int64{}}
	c.collect(opts, newHealth())
	if _, err := os.Stat(spool); err != nil {
		t.Fatalf("undrained spool was removed: %v", err)
	}
}

func TestEnforceReplayWritesDecisionFile(t *testing.T) {
	daemon, socketPath := startFakeDaemon(t)
	daemon.setResult(localruntime.EvaluateResult{
		Type:     "result",
		Decision: "deny",
		Allowed:  false,
		Reason:   "blocked by policy",
	})
	opts := testOptions(t, socketPath)
	sessionDir := filepath.Join(opts.SessionsRoot, "acct", "ws", "local_abc")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(sessionDir, spoolName)
	writeSpool(t, spool, `{"rid":"123-456","event":`+eventLine("Bash")+`}`+"\n")

	c := &collector{offsets: map[string]int64{}}
	h := newHealth()
	c.collect(opts, h)

	decision, err := os.ReadFile(filepath.Join(sessionDir, decisionsDirName, "123-456.json"))
	if err != nil {
		t.Fatalf("decision file not written: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(decision, &out); err != nil {
		t.Fatalf("decision is not valid JSON: %v", err)
	}
	specific := out["hookSpecificOutput"].(map[string]any)
	if specific["permissionDecision"] != "deny" {
		t.Fatalf("permissionDecision = %v, want deny", specific["permissionDecision"])
	}
	if specific["permissionDecisionReason"] != "blocked by policy" {
		t.Fatalf("reason = %v", specific["permissionDecisionReason"])
	}
	if h.denied != 1 {
		t.Fatalf("denied counter = %d, want 1", h.denied)
	}
}

func TestObserveLinesWriteNoDecision(t *testing.T) {
	_, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	sessionDir := filepath.Join(opts.SessionsRoot, "acct", "ws", "local_abc")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, filepath.Join(sessionDir, spoolName), eventLine("Bash")+"\n")

	c := &collector{offsets: map[string]int64{}}
	c.collect(opts, newHealth())
	if _, err := os.Stat(filepath.Join(sessionDir, decisionsDirName)); !os.IsNotExist(err) {
		t.Fatalf("decisions dir created for observe-mode line (err=%v)", err)
	}
}

func TestReplayRejectsUnsafeRequestIDs(t *testing.T) {
	daemon, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	sessionDir := filepath.Join(opts.SessionsRoot, "acct", "ws", "local_abc")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(sessionDir, spoolName)
	writeSpool(t, spool, `{"rid":"../escape","event":`+eventLine("Bash")+`}`+"\n")

	c := &collector{offsets: map[string]int64{}}
	c.collect(opts, newHealth())

	// The event is still ingested, but no decision file may be written for a
	// rid that could steer the path (".." alone has no separator, but the
	// pattern rejects "/" outright).
	if got := daemon.toolNames(); len(got) != 1 {
		t.Fatalf("replayed tools = %v, want the event ingested", got)
	}
	if _, err := os.Stat(filepath.Join(sessionDir, decisionsDirName)); !os.IsNotExist(err) {
		t.Fatalf("decision written for unsafe rid (err=%v)", err)
	}
}

func TestDrainResetsOffsetWhenSpoolShrinks(t *testing.T) {
	daemon, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	spool := filepath.Join(t.TempDir(), spoolName)
	writeSpool(t, spool, eventLine("Bash")+"\n")

	c := &collector{offsets: map[string]int64{}}
	c.drain(opts, newHealth(), spool)

	// Spool recreated (e.g. cleaned up and the hook started a fresh one). The
	// fresh file is smaller than the old offset, which signals the reset.
	if err := os.Remove(spool); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, spool, `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_use_id":"t"}`+"\n")
	c.drain(opts, newHealth(), spool)
	if got := daemon.toolNames(); len(got) != 2 || got[1] != "Read" {
		t.Fatalf("replayed tools = %v, want [Bash Read]", got)
	}
}
