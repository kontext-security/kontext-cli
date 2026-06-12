// Package coworkobserve adds Claude Cowork observation to the managed-observe
// daemon, reusing the existing Claude Code pipeline.
//
// Cowork runs the bundled Claude Code CLI inside a per-session VM whose root
// filesystem is rebuilt on every boot, so hooks cannot be baked into the image.
// What does survive is the per-session CLAUDE config dir, which Cowork mounts
// from the host at:
//
//	~/Library/Application Support/Claude/local-agent-mode-sessions/<account>/<workspace>/local_<session>/.claude/
//
// This is the guest's $HOME/.claude — the "user" settings tier, which Cowork's
// CLI loads at startup. Two host-side loops run inside the daemon:
//
//   - injector: writes settings.json with a PreToolUse command hook into each
//     new per-session .claude dir before the in-VM CLI initializes. The hook
//     appends every tool event to a host-mounted spool file in the session dir
//     (no in-VM network needed — the dir is a host mount).
//   - collector: tails those spool files and replays each event into the
//     daemon's existing localruntime socket as agent "cowork", reusing the same
//     classify -> store -> managedstream -> ledger path Claude Code uses.
package coworkobserve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

const (
	// EnvEnabled enables Cowork observation when set to a truthy value.
	EnvEnabled = "KONTEXT_COWORK_OBSERVE"
	// EnvSessionsRoot overrides the Cowork sessions root for testing.
	EnvSessionsRoot = "KONTEXT_COWORK_SESSIONS_ROOT"

	spoolName    = "kontext-cowork-events.jsonl"
	settingsMark = spoolName // settings.json containing this string is ours
	agentName    = "cowork"
)

// Enabled reports whether Cowork observation is turned on via the environment.
func Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvEnabled))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// Options configures the Cowork observer loops.
type Options struct {
	// SocketPath is the daemon's localruntime socket (where events are replayed).
	SocketPath string
	// SessionsRoot is the Cowork sessions root; defaults to the standard path.
	SessionsRoot string
	// StatePath persists collector spool offsets across daemon restarts so a
	// restart does not re-replay already-ingested events as duplicate ledger
	// entries. Empty means offsets are kept in memory only.
	StatePath string
	// PollInterval controls how often the loops scan; defaults to 250ms.
	PollInterval time.Duration
	Diagnostic   diagnostic.Logger
}

// DefaultSessionsRoot returns the standard Cowork sessions root on macOS.
func DefaultSessionsRoot() string {
	if override := strings.TrimSpace(os.Getenv(EnvSessionsRoot)); override != "" {
		return override
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Library", "Application Support", "Claude", "local-agent-mode-sessions")
}

// The command hook reads the full Claude Code hook event from stdin and appends
// it to a spool file one directory above cwd (the session dir, host-mounted),
// then exits 0 so the tool is never blocked.
const hookCommand = `p=$(cat); printf '%s\n' "$p" >> ../` + spoolName + ` 2>/dev/null; true`

func hookEntry() map[string]any {
	return map[string]any{
		"matcher": "*",
		"hooks": []any{
			map[string]any{"type": "command", "command": hookCommand, "timeout": 12},
		},
	}
}

// mergeSettings adds the spool hook to existing settings.json content,
// preserving every other setting and any hooks Cowork or the user put there.
// Existing content that is not valid JSON is replaced — the in-VM CLI could
// not have parsed it either. The second return reports whether a write is
// needed (false when the hook is already present).
func mergeSettings(existing []byte) ([]byte, bool) {
	settings := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if bytes.Contains(existing, []byte(settingsMark)) {
			return nil, false
		}
		if err := json.Unmarshal(existing, &settings); err != nil {
			settings = map[string]any{}
		}
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	pre, _ := hooks["PreToolUse"].([]any)
	hooks["PreToolUse"] = append(pre, hookEntry())
	settings["hooks"] = hooks
	data, err := json.Marshal(settings)
	if err != nil {
		return nil, false
	}
	return data, true
}

// writeFileAtomic writes via temp file + rename so the in-VM CLI can never
// observe a half-written settings.json at startup.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".kontext-tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Run starts the injector and collector loops and blocks until ctx is cancelled.
func Run(ctx context.Context, opts Options) {
	if opts.SessionsRoot == "" {
		opts.SessionsRoot = DefaultSessionsRoot()
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 250 * time.Millisecond
	}
	if opts.SessionsRoot == "" {
		opts.Diagnostic.Printf("cowork observe: no sessions root; disabled\n")
		return
	}
	opts.Diagnostic.Printf("cowork observe: watching %s\n", opts.SessionsRoot)

	c := newCollector(opts.StatePath)
	ticker := time.NewTicker(opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			inject(opts)
			c.collect(opts)
			c.saveOffsets(opts)
		}
	}
}

// inject merges the spool hook into settings.json in any recent per-session
// .claude dir that does not yet carry it.
func inject(opts Options) {
	claudeDirs, _ := filepath.Glob(filepath.Join(opts.SessionsRoot, "*", "*", "local_*", ".claude"))
	cutoff := time.Now().Add(-3 * time.Minute)
	for _, dir := range claudeDirs {
		info, err := os.Stat(dir)
		if err != nil || info.ModTime().Before(cutoff) {
			continue
		}
		settingsPath := filepath.Join(dir, "settings.json")
		existing, err := os.ReadFile(settingsPath)
		if err != nil && !os.IsNotExist(err) {
			continue
		}
		merged, needed := mergeSettings(existing)
		if !needed {
			continue // already ours
		}
		if err := writeFileAtomic(settingsPath, merged, 0o644); err != nil {
			opts.Diagnostic.Printf("cowork observe: inject %s: %v\n", settingsPath, err)
			continue
		}
		opts.Diagnostic.Printf("cowork observe: injected hook into %s\n", settingsPath)
	}
}

type collector struct {
	offsets   map[string]int64
	statePath string
	dirty     bool
}

func newCollector(statePath string) *collector {
	c := &collector{offsets: map[string]int64{}, statePath: statePath}
	if statePath == "" {
		return c
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		return c
	}
	if err := json.Unmarshal(data, &c.offsets); err != nil || c.offsets == nil {
		c.offsets = map[string]int64{}
	}
	return c
}

func (c *collector) setOffset(spool string, off int64) {
	if c.offsets[spool] == off {
		return
	}
	c.offsets[spool] = off
	c.dirty = true
}

// saveOffsets persists the offset map after ticks that changed it, via temp
// file + rename so a crash mid-write cannot corrupt the state.
func (c *collector) saveOffsets(opts Options) {
	if !c.dirty || c.statePath == "" {
		return
	}
	data, err := json.Marshal(c.offsets)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.statePath), 0o700); err != nil {
		opts.Diagnostic.Printf("cowork observe: save offsets: %v\n", err)
		return
	}
	tmp := c.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		opts.Diagnostic.Printf("cowork observe: save offsets: %v\n", err)
		return
	}
	if err := os.Rename(tmp, c.statePath); err != nil {
		opts.Diagnostic.Printf("cowork observe: save offsets: %v\n", err)
		return
	}
	c.dirty = false
}

type coworkEvent struct {
	SessionID     string          `json:"session_id"`
	SessionIDAlt  string          `json:"sessionId"`
	HookEventName string          `json:"hook_event_name"`
	HookEventAlt  string          `json:"hookEventName"`
	ToolName      string          `json:"tool_name"`
	ToolNameAlt   string          `json:"toolName"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolInputAlt  json.RawMessage `json:"toolInput"`
	ToolUseID     string          `json:"tool_use_id"`
	CWD           string          `json:"cwd"`
}

func (c *collector) collect(opts Options) {
	spools, _ := filepath.Glob(filepath.Join(opts.SessionsRoot, "*", "*", "local_*", spoolName))
	for _, spool := range spools {
		c.drain(opts, spool)
	}
}

// errMalformed marks spool lines that can never replay successfully; drain
// drops them. Any other replay error is treated as transient (the daemon
// socket hiccuped), so drain stops before the failed line and retries it on
// the next tick. Retrying after a partial send can deliver an event twice;
// for an audit trail, at-least-once beats silently dropping it.
var errMalformed = errors.New("malformed spool line")

// drain replays complete lines appended since the last tick. The in-VM hook
// may be mid-append while we read, so a trailing chunk without a newline is
// left in place — the offset only ever advances past complete, handled lines.
func (c *collector) drain(opts Options, spool string) {
	f, err := os.Open(spool)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return
	}
	off := c.offsets[spool]
	if info.Size() < off {
		off = 0 // spool was recreated; start over on the new file
	}
	if info.Size() == off {
		return
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return
	}
	consumed := 0
	for {
		idx := bytes.IndexByte(data[consumed:], '\n')
		if idx < 0 {
			break // partial line still being appended; retry next tick
		}
		line := bytes.TrimSpace(data[consumed : consumed+idx])
		if len(line) > 0 {
			if err := c.replay(opts, line); err != nil {
				if !errors.Is(err, errMalformed) {
					opts.Diagnostic.Printf("cowork observe: replay: %v\n", err)
					break
				}
				opts.Diagnostic.Printf("cowork observe: %v\n", err)
			}
		}
		consumed += idx + 1
	}
	c.setOffset(spool, off+int64(consumed))
}

func (c *collector) replay(opts Options, line []byte) error {
	var ev coworkEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return fmt.Errorf("%w: %v", errMalformed, err)
	}
	hookEvent := firstNonEmpty(ev.HookEventName, ev.HookEventAlt)
	if hook.HookName(hookEvent) != hook.HookPreToolUse {
		return nil // injector only wires PreToolUse
	}
	sessionID := firstNonEmpty(ev.SessionID, ev.SessionIDAlt)
	toolInput := ev.ToolInput
	if len(toolInput) == 0 {
		toolInput = ev.ToolInputAlt
	}
	req := localruntime.EvaluateRequest{
		Type:      "evaluate",
		SessionID: "cowork-" + sessionID,
		Agent:     agentName,
		HookEvent: hook.HookPreToolUse.String(),
		ToolName:  firstNonEmpty(ev.ToolName, ev.ToolNameAlt),
		ToolInput: toolInput,
		ToolUseID: ev.ToolUseID,
		CWD:       ev.CWD,
	}
	return send(opts.SocketPath, req)
}

func send(socketPath string, req localruntime.EvaluateRequest) error {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := localruntime.WriteMessage(conn, req); err != nil {
		return err
	}
	var res localruntime.EvaluateResult
	return localruntime.ReadMessage(conn, &res)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
