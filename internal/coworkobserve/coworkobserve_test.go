package coworkobserve

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

// fakeDaemon accepts localruntime evaluate requests on a unix socket and
// records them, mimicking the managed-observe daemon.
type fakeDaemon struct {
	listener net.Listener
	mu       sync.Mutex
	requests []localruntime.EvaluateRequest
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
				d.mu.Unlock()
				_ = localruntime.WriteMessage(conn, localruntime.EvaluateResult{Type: "result", Allowed: true})
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

func TestDrainLeavesPartialTrailingLine(t *testing.T) {
	daemon, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	spool := filepath.Join(t.TempDir(), spoolName)

	writeSpool(t, spool, eventLine("Bash")+"\n"+`{"session_id":"s1","hook_event`)
	c := &collector{offsets: map[string]int64{}}
	c.drain(opts, spool)

	if got := daemon.toolNames(); len(got) != 1 || got[0] != "Bash" {
		t.Fatalf("replayed tools = %v, want [Bash]", got)
	}
	wantOffset := int64(len(eventLine("Bash")) + 1)
	if c.offsets[spool] != wantOffset {
		t.Fatalf("offset = %d, want %d (end of last complete line)", c.offsets[spool], wantOffset)
	}

	// Completing the partial line replays it on the next tick.
	writeSpool(t, spool, `_name":"PreToolUse","tool_name":"Read","tool_use_id":"tu-2"}`+"\n")
	c.drain(opts, spool)
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
	c.drain(opts, spool)
	if c.offsets[spool] != 0 {
		t.Fatalf("offset advanced to %d past undelivered events", c.offsets[spool])
	}

	// Daemon comes back; both events are delivered in order.
	daemon, socketPath := startFakeDaemon(t)
	opts.SocketPath = socketPath
	c.drain(opts, spool)
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
	c.drain(opts, spool)
	if got := daemon.toolNames(); len(got) != 1 || got[0] != "Bash" {
		t.Fatalf("replayed tools = %v, want [Bash]", got)
	}
	c.drain(opts, spool)
	if got := daemon.toolNames(); len(got) != 1 {
		t.Fatalf("malformed line was retried: %v", got)
	}
}

func TestDrainResetsOffsetWhenSpoolShrinks(t *testing.T) {
	daemon, socketPath := startFakeDaemon(t)
	opts := testOptions(t, socketPath)
	spool := filepath.Join(t.TempDir(), spoolName)
	writeSpool(t, spool, eventLine("Bash")+"\n")

	c := &collector{offsets: map[string]int64{}}
	c.drain(opts, spool)

	// Spool recreated (e.g. cleaned up and the hook started a fresh one). The
	// fresh file is smaller than the old offset, which signals the reset.
	if err := os.Remove(spool); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, spool, `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_use_id":"t"}`+"\n")
	c.drain(opts, spool)
	if got := daemon.toolNames(); len(got) != 2 || got[1] != "Read" {
		t.Fatalf("replayed tools = %v, want [Bash Read]", got)
	}
}
