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

func settingsJSON() []byte {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "*",
					"hooks": []any{
						map[string]any{"type": "command", "command": hookCommand, "timeout": 12},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(settings)
	return data
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

	c := &collector{offsets: map[string]int64{}}
	settings := settingsJSON()
	ticker := time.NewTicker(opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			inject(opts, settings)
			c.collect(ctx, opts)
		}
	}
}

// inject writes settings.json into any recent per-session .claude dir that does
// not yet carry our hook.
func inject(opts Options, settings []byte) {
	claudeDirs, _ := filepath.Glob(filepath.Join(opts.SessionsRoot, "*", "*", "local_*", ".claude"))
	cutoff := time.Now().Add(-3 * time.Minute)
	for _, dir := range claudeDirs {
		info, err := os.Stat(dir)
		if err != nil || info.ModTime().Before(cutoff) {
			continue
		}
		settingsPath := filepath.Join(dir, "settings.json")
		if existing, err := os.ReadFile(settingsPath); err == nil && bytes.Contains(existing, []byte(settingsMark)) {
			continue // already ours
		}
		if err := os.WriteFile(settingsPath, settings, 0o644); err != nil {
			opts.Diagnostic.Printf("cowork observe: inject %s: %v\n", settingsPath, err)
			continue
		}
		opts.Diagnostic.Printf("cowork observe: injected hook into %s\n", settingsPath)
	}
}

type collector struct {
	offsets map[string]int64
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

func (c *collector) collect(ctx context.Context, opts Options) {
	spools, _ := filepath.Glob(filepath.Join(opts.SessionsRoot, "*", "*", "local_*", spoolName))
	for _, spool := range spools {
		c.drain(ctx, opts, spool)
	}
}

func (c *collector) drain(ctx context.Context, opts Options, spool string) {
	data, err := os.ReadFile(spool)
	if err != nil {
		return
	}
	off := c.offsets[spool]
	if int64(len(data)) <= off {
		return
	}
	fresh := data[off:]
	c.offsets[spool] = int64(len(data))
	for _, line := range bytes.Split(fresh, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if err := c.replay(opts, line); err != nil {
			opts.Diagnostic.Printf("cowork observe: replay: %v\n", err)
		}
	}
}

func (c *collector) replay(opts Options, line []byte) error {
	var ev coworkEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return err
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
