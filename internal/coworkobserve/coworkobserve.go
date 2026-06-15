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
//
// # Modes
//
// The posture follows the deployment-level managed.json mode, like every
// other hook edge. In observe mode the hook is fire-and-forget and nothing
// blocks. In enforce mode the hook wraps each event in an envelope with a
// request id, waits up to 10s for the daemon's verdict at
// kontext-cowork-decisions/<rid>.json, and emits it verbatim — the bundled
// CLI honors the permissionDecision. No verdict in time means the hook emits
// deny ("Kontext daemon unavailable"): fail-closed, mirroring the sidecar.
//
// # Caveats
//
// Integrity: the spool is written by code running inside the VM, so anything
// in the VM (including a prompt-injected agent) can append forged events or
// withhold real ones. Cowork-tagged ledger entries are self-reported
// telemetry, not attested records. Enforcement gates agent-via-CLI actions
// only: in-VM code that bypasses the CLI was never reachable by a hook, and
// a tool call that lands before settings injection runs unguarded (the
// health heartbeat surfaces such sessions). A hook killed at the CLI's own
// timeout is treated by Claude Code as allow, so fail-closed is best-effort
// within the timeout budget.
//
// Delivery: events are replayed at-least-once. A replay that fails after a
// partial send is retried, so the ledger may very occasionally see a
// duplicate; it never silently drops a complete spool line.
//
// Coupling: the session-dir layout, the host mount, and the user-tier
// settings load are undocumented Cowork internals; an update can break
// observation without an error. The health heartbeat (sessions seen vs
// hooked vs spooling) exists so that breakage is visible in diagnostics.
//
// Deployment: run the daemon in the session user's context (LaunchAgent,
// not a root LaunchDaemon) — the injector writes settings.json into the
// user's ~/Library and root-owned files there may confuse Cowork or the
// VM mount's UID mapping.
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
	"regexp"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

const (
	// EnvEnabled enables Cowork observation when set to a truthy value.
	EnvEnabled = "KONTEXT_COWORK_OBSERVE"
	// EnvSessionsRoot overrides the Cowork sessions root for testing.
	EnvSessionsRoot = "KONTEXT_COWORK_SESSIONS_ROOT"

	spoolName        = "kontext-cowork-events.jsonl"
	decisionsDirName = "kontext-cowork-decisions"
	settingsMark     = spoolName // hook commands containing this string are ours
	agentName        = "cowork"

	// Enforce-hook budget, mirroring the sidecar conventions: the hook waits
	// up to decisionWait for the daemon's verdict (hookConnDeadline is 10s on
	// the socket side) inside claudemanaged's default 20s hook timeout.
	enforceHookTimeout = 20
	observeHookTimeout = 5
)

// Enabled reports whether Cowork observation is turned on via the environment.
// Managed installs should prefer the cowork_enabled field in managed.json;
// the env var remains as a development/debugging override.
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
	// Mode selects the injected hook: observe installs the fire-and-forget
	// spool append, enforce installs the decision round-trip that blocks the
	// tool until the daemon's verdict lands. Defaults to observe.
	Mode guardhookruntime.Mode
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

// The observe hook reads the full Claude Code hook event from stdin and appends
// it to a spool file in the session dir, then exits 0 so the tool is never
// blocked. The spool path is relative to the hook's cwd, which Cowork sets to
// the session's outputs/ dir (a host mount); `..` is therefore the session dir
// itself, where .claude lives and where the collector globs. NB: the guest
// $HOME is NOT the session dir (Cowork points the CLI at the per-session
// .claude via a config-dir override, not via $HOME), so a $HOME-relative spool
// would land on the ephemeral VM filesystem and never reach the host collector.
const observeHookCommand = `p=$(cat); printf '%s\n' "$p" >> ../` + spoolName + ` 2>/dev/null; true`

// denyJSON is the fail-closed verdict the enforce hook emits itself when no
// decision arrives in time. Reason mirrors the sidecar's enforce behavior on
// daemon unavailability (guard/hookruntime).
const denyJSON = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Kontext daemon unavailable"}}`

// The enforce hook wraps the event in an envelope carrying a hook-generated
// request ID (the shell cannot parse tool_use_id out of the JSON), appends it
// to the spool, then polls for the daemon-rendered decision file and emits it
// verbatim — so the CLI sees exactly the permissionDecision the policy engine
// produced. No decision within 10s (100 x 0.1s) means deny: fail-closed, same
// as the sidecar when the daemon is unreachable. The one gap we cannot close
// is the CLI killing the hook at its 20s timeout, which Claude Code treats as
// allow.
const enforceHookCommand = `p=$(cat)
deny='` + denyJSON + `'
if [ -z "$p" ]; then printf '%s\n' "$deny"; exit 0; fi
rid="$$-$(date +%s%N)"
if ! printf '{"rid":"%s","event":%s}\n' "$rid" "$p" >> ../` + spoolName + ` 2>/dev/null; then printf '%s\n' "$deny"; exit 0; fi
d=../` + decisionsDirName + `/"$rid".json
i=0
while [ "$i" -lt 100 ]; do
  if [ -f "$d" ]; then cat "$d" 2>/dev/null; rm -f "$d" 2>/dev/null; exit 0; fi
  i=$((i+1)); sleep 0.1
done
printf '%s\n' "$deny"`

func hookEntry(mode guardhookruntime.Mode) map[string]any {
	command, timeout := observeHookCommand, observeHookTimeout
	if mode == guardhookruntime.ModeEnforce {
		command, timeout = enforceHookCommand, enforceHookTimeout
	}
	return map[string]any{
		"matcher": "*",
		"hooks": []any{
			map[string]any{"type": "command", "command": command, "timeout": timeout},
		},
	}
}

// mergeSettings adds the given spool hook entry to existing settings.json
// content, preserving every other setting and any hooks Cowork or the user put
// there. Stale variants of our own entry (e.g. after a mode switch) are
// replaced. Existing content that is not valid JSON is replaced wholesale —
// the in-VM CLI could not have parsed it either. The second return reports
// whether a write is needed (false when the current entry is already present).
func mergeSettings(existing []byte, entry map[string]any) ([]byte, bool) {
	settings := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := json.Unmarshal(existing, &settings); err != nil {
			settings = map[string]any{}
		}
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	pre, _ := hooks["PreToolUse"].([]any)
	wantJSON, err := json.Marshal(entry)
	if err != nil {
		return nil, false
	}
	kept := make([]any, 0, len(pre)+1)
	current := false
	for _, candidate := range pre {
		if !entryIsOurs(candidate) {
			kept = append(kept, candidate)
			continue
		}
		if got, err := json.Marshal(candidate); err == nil && bytes.Equal(got, wantJSON) && !current {
			current = true
			kept = append(kept, candidate)
		}
		// stale or duplicate variants of our entry are dropped
	}
	if current && len(kept) == len(pre) {
		return nil, false
	}
	if !current {
		kept = append(kept, entry)
	}
	hooks["PreToolUse"] = kept
	settings["hooks"] = hooks
	data, err := json.Marshal(settings)
	if err != nil {
		return nil, false
	}
	return data, true
}

// entryIsOurs reports whether a PreToolUse matcher group was installed by the
// injector (any of its command hooks references the spool file).
func entryIsOurs(candidate any) bool {
	m, ok := candidate.(map[string]any)
	if !ok {
		return false
	}
	hooks, _ := m["hooks"].([]any)
	for _, h := range hooks {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if command, _ := hm["command"].(string); strings.Contains(command, settingsMark) {
			return true
		}
	}
	return false
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
		// Enforce holds every tool call for the spool round-trip, so scan
		// tighter than the observe default.
		if opts.Mode == guardhookruntime.ModeEnforce {
			opts.PollInterval = 100 * time.Millisecond
		} else {
			opts.PollInterval = 250 * time.Millisecond
		}
	}
	if opts.SessionsRoot == "" {
		opts.Diagnostic.Printf("cowork observe: no sessions root; disabled\n")
		return
	}
	opts.Diagnostic.Printf("cowork observe: watching %s\n", opts.SessionsRoot)

	c := newCollector(opts.StatePath)
	h := newHealth()
	// Re-merge the configured-mode hook into sessions already running when the
	// daemon comes up. The mode is read once from managed.json at startup, so a
	// mode change (observe -> enforce) and a late daemon start are the same
	// event: the daemon starting while sessions already exist. Those sessions'
	// .claude dir modtimes froze long ago (our own settings.json write is the
	// last thing to touch the dir), so the steady-state inject would never
	// re-reach them; this one forced pass does, before they next act.
	reinjectExisting(opts, h)
	ticker := time.NewTicker(opts.PollInterval)
	defer ticker.Stop()
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			inject(opts, h)
			c.collect(opts, h)
			c.saveOffsets(opts)
		case <-heartbeat.C:
			h.logHeartbeat(opts)
		}
	}
}

const heartbeatInterval = 5 * time.Minute

// health tracks whether observation is actually working. The whole mechanism
// depends on undocumented Cowork internals (session dir layout, host mount,
// settings tier), so a Cowork update can break it without any error surfacing.
// The heartbeat makes "no Cowork activity" distinguishable from "observation
// broken" in the daemon diagnostics.
type health struct {
	sessionsSeen map[string]bool // .claude dirs discovered by the injector
	// written is .claude dirs where we wrote (or found current) our hook AND
	// have reason to believe it takes effect — the dir was watched at session
	// start (a new session we seeded before its CLI started, or a re-merge of a
	// hook that was already there). It is not, on its own, proof the hook fires.
	written map[string]bool
	// unverified is .claude dirs where we wrote a first-time hook onto a session
	// whose CLI may already be running. Claude Code's settings watcher only
	// watches dirs that had a settings file when the session started, so such a
	// write may never load. These are best-effort and must not be reported as
	// working until a spool confirms otherwise.
	unverified map[string]bool
	// spooled is session dirs that produced a spool — ground truth that the hook
	// actually fired. A spool promotes a session from unverified to written.
	spooled        map[string]bool
	eventsReplayed int64
	linesDropped   int64
	denied         int64
}

func newHealth() *health {
	return &health{
		sessionsSeen: map[string]bool{},
		written:      map[string]bool{},
		unverified:   map[string]bool{},
		spooled:      map[string]bool{},
	}
}

func (h *health) logHeartbeat(opts Options) {
	opts.Diagnostic.Printf(
		"cowork observe: health: sessions seen=%d written=%d confirmed=%d unverified=%d events replayed=%d denied=%d malformed dropped=%d\n",
		len(h.sessionsSeen), len(h.written), len(h.spooled), len(h.unverified), h.eventsReplayed, h.denied, h.linesDropped,
	)
	if len(h.unverified) > 0 {
		opts.Diagnostic.Printf(
			"cowork observe: warning: %d pre-existing session(s) had a hook written but unconfirmed — their CLI likely started before the hook existed, so it will not fire until the session restarts\n",
			len(h.unverified),
		)
	}
	if seen := len(h.sessionsSeen) - len(h.written) - len(h.unverified); seen > 0 {
		opts.Diagnostic.Printf(
			"cowork observe: warning: %d session(s) never received the hook (injection raced CLI startup, or the daemon started after the session)\n",
			seen,
		)
	}
	if len(h.written) > 0 && len(h.spooled) == 0 {
		opts.Diagnostic.Printf("cowork observe: warning: hook written but no spool has appeared; the Cowork session layout or mount may have changed\n")
	}
}

// inject merges the mode-appropriate spool hook into settings.json in each
// per-session .claude dir freshly created within the cutoff. Steady state only
// needs to catch new sessions: a new session's dir modtime is fresh when it
// appears, and once the daemon is running, the mode cannot change without a
// restart (which runs reinjectExisting again). Sessions older than the cutoff
// are handled at startup, not here.
func inject(opts Options, h *health) {
	claudeDirs, _ := filepath.Glob(filepath.Join(opts.SessionsRoot, "*", "*", "local_*", ".claude"))
	cutoff := time.Now().Add(-3 * time.Minute)
	entry := hookEntry(opts.Mode)
	for _, dir := range claudeDirs {
		info, err := os.Stat(dir)
		if err != nil || info.ModTime().Before(cutoff) {
			continue
		}
		// trustFresh: a brand-new session's CLI has not started yet (we win the
		// race against it), so even a first-time hook will be loaded.
		mergeInto(opts, h, dir, entry, true)
	}
}

// reinjectWindow bounds how far back the startup pass looks. A session whose
// .claude dir has not been touched within this window is treated as abandoned
// and left alone, so the pass does not write into the pile of dead session
// dirs Cowork leaves behind. It is generous because a session's dir modtime
// freezes once we inject, so this is "created/active within the last day",
// not "used in the last day".
const reinjectWindow = 24 * time.Hour

// reinjectExisting force-merges the configured-mode hook into every recent
// session at daemon startup, ignoring the steady-state freshness cutoff that
// inject uses. This is what reaches a session that was already running when
// the daemon came up — whether because the daemon started late or because the
// mode just changed (which requires a restart). Without it, such a session
// keeps whatever hook it had (a stale observe hook, or none) until it happens
// to start a fresh session.
func reinjectExisting(opts Options, h *health) {
	claudeDirs, _ := filepath.Glob(filepath.Join(opts.SessionsRoot, "*", "*", "local_*", ".claude"))
	cutoff := time.Now().Add(-reinjectWindow)
	entry := hookEntry(opts.Mode)
	for _, dir := range claudeDirs {
		info, err := os.Stat(dir)
		if err != nil || info.ModTime().Before(cutoff) {
			continue // abandoned session dir
		}
		// trustFresh is false: this session's CLI may already be running. If we
		// are writing the first settings file into its dir, Claude Code's
		// watcher never watched that dir (it only watches dirs that had a
		// settings file at session start), so the write will not take effect —
		// record it as unverified rather than working.
		mergeInto(opts, h, dir, entry, false)
	}
}

// mergeInto records the session for the heartbeat, then writes entry into its
// settings.json when it is missing or a stale-mode variant is present.
//
// trustFresh says whether a first-time hook write (no hook of ours was already
// present) can be trusted to take effect. It is true for steady-state inject —
// a new session's CLI has not started, so it will load our settings.json — and
// false for the startup pass, where the session may already be running over a
// dir the settings watcher never watched. A write that updates a hook of ours
// already present is always trusted: that dir was watched at session start, so
// the change hot-reloads. Anything written but not trusted is recorded as
// unverified, and only a spool (see collect) confirms it actually fires.
func mergeInto(opts Options, h *health, dir string, entry map[string]any, trustFresh bool) {
	h.sessionsSeen[dir] = true
	settingsPath := filepath.Join(dir, "settings.json")
	existing, err := os.ReadFile(settingsPath)
	if err != nil && !os.IsNotExist(err) {
		return
	}
	hadOurHook := hasOurHook(existing)
	merged, needed := mergeSettings(existing, entry)
	if !needed {
		h.written[dir] = true
		return // already current
	}
	if err := writeFileAtomic(settingsPath, merged, 0o644); err != nil {
		opts.Diagnostic.Printf("cowork observe: inject %s: %v\n", settingsPath, err)
		return
	}
	if hadOurHook || trustFresh {
		h.written[dir] = true
		opts.Diagnostic.Printf("cowork observe: injected hook into %s\n", settingsPath)
		return
	}
	h.unverified[dir] = true
	opts.Diagnostic.Printf("cowork observe: wrote hook into pre-existing session %s (unverified; will not fire until the session restarts unless its dir was already watched)\n", settingsPath)
}

// hasOurHook reports whether settings.json already carries a PreToolUse hook the
// injector installed (i.e. one whose command references the spool). Used to tell
// a mode-switch re-merge (the dir was watched at session start, so the change
// hot-reloads) apart from a first-time hook on an already-running session.
func hasOurHook(existing []byte) bool {
	if len(bytes.TrimSpace(existing)) == 0 {
		return false
	}
	var settings map[string]any
	if json.Unmarshal(existing, &settings) != nil {
		return false
	}
	hooks, _ := settings["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	for _, candidate := range pre {
		if entryIsOurs(candidate) {
			return true
		}
	}
	return false
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

// spoolRetention is how long a fully-drained spool may sit idle before the
// collector deletes it. Spools hold raw, unredacted tool inputs, so they
// should not accumulate on disk indefinitely.
const spoolRetention = time.Hour

func (c *collector) collect(opts Options, h *health) {
	spools, _ := filepath.Glob(filepath.Join(opts.SessionsRoot, "*", "*", "local_*", spoolName))
	live := make(map[string]bool, len(spools))
	for _, spool := range spools {
		live[spool] = true
		sessionDir := filepath.Dir(spool)
		h.spooled[sessionDir] = true
		// A spool is ground truth the hook fired: promote the session out of
		// unverified into written, since the watcher clearly did load it.
		if claudeDir := filepath.Join(sessionDir, ".claude"); h.unverified[claudeDir] {
			delete(h.unverified, claudeDir)
			h.written[claudeDir] = true
		}
		c.drain(opts, h, spool)
		c.cleanup(opts, spool)
		cleanupOrphanDecisions(opts, filepath.Dir(spool))
	}
	// Cowork deleted the session dir; its offset entry is dead weight.
	for spool := range c.offsets {
		if !live[spool] {
			delete(c.offsets, spool)
			c.dirty = true
		}
	}
}

// beforeSpoolRemove, when non-nil, runs inside cleanup after the drained/idle
// checks but before the re-stat guard. It exists only for tests to drive the
// stat/remove race deterministically; production leaves it nil.
var beforeSpoolRemove func(spool string)

// cleanup removes a spool once it is fully drained and idle past the
// retention window. If the session wakes up again, the hook recreates the
// file and drain starts over from offset zero (the shrink reset).
func (c *collector) cleanup(opts Options, spool string) {
	info, err := os.Stat(spool)
	if err != nil {
		return
	}
	if time.Since(info.ModTime()) < spoolRetention {
		return
	}
	if c.offsets[spool] != info.Size() {
		return // not fully drained yet
	}
	if beforeSpoolRemove != nil {
		beforeSpoolRemove(spool) // test seam: simulate a hook appending in the window
	}
	// Re-stat immediately before unlinking. drain ran earlier this tick, but a
	// hook may append between then and now; if the spool grew or its modtime
	// advanced since the check above, a fresh (undrained) event just landed, so
	// leave the file for the next tick to drain rather than unlink data we
	// never replayed. This shrinks — does not fully close — the stat/remove
	// window, but the loss it guards against requires an append landing in that
	// window after a full hour of spool idleness, so a narrow guard suffices.
	if again, err := os.Stat(spool); err != nil || again.Size() != info.Size() || !again.ModTime().Equal(info.ModTime()) {
		return
	}
	if err := os.Remove(spool); err != nil {
		opts.Diagnostic.Printf("cowork observe: remove drained spool %s: %v\n", spool, err)
		return
	}
	delete(c.offsets, spool)
	c.dirty = true
	opts.Diagnostic.Printf("cowork observe: removed drained spool %s\n", spool)
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
func (c *collector) drain(opts Options, h *health, spool string) {
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
			if err := c.replay(opts, h, spool, line); err != nil {
				if !errors.Is(err, errMalformed) {
					opts.Diagnostic.Printf("cowork observe: replay: %v\n", err)
					break
				}
				h.linesDropped++
				opts.Diagnostic.Printf("cowork observe: %v\n", err)
			} else {
				h.eventsReplayed++
			}
		}
		consumed += idx + 1
	}
	c.setOffset(spool, off+int64(consumed))
}

// spoolEnvelope is what the enforce hook appends: the raw event plus the
// hook-generated request ID that names the decision file. Observe-mode lines
// are bare events and unwrap to an empty rid.
type spoolEnvelope struct {
	RID   string          `json:"rid"`
	Event json.RawMessage `json:"event"`
}

func unwrapEnvelope(line []byte) (rid string, payload []byte) {
	var env spoolEnvelope
	if err := json.Unmarshal(line, &env); err == nil && len(env.Event) > 0 {
		return env.RID, env.Event
	}
	return "", line
}

// ridPattern bounds what may name a decision file. The rid comes from inside
// the VM, so anything outside this charset (notably path separators) must be
// rejected before it reaches a filepath.Join.
var ridPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// replay decodes a spool line with the same decoder the Claude Code hook path
// uses (Cowork runs the bundled Claude Code CLI, so the formats are identical)
// and forwards it to the daemon socket as agent "cowork". Lines carrying a
// request ID get the daemon's verdict written back as a decision file for the
// waiting enforce hook.
func (c *collector) replay(opts Options, h *health, spool string, line []byte) error {
	rid, payload := unwrapEnvelope(line)
	event, err := hookruntime.DecodeClaudeEvent(payload, agentName)
	if err != nil {
		return fmt.Errorf("%w: %v", errMalformed, err)
	}
	if event.HookName != hook.HookPreToolUse {
		return nil // injector only wires PreToolUse
	}
	event.SessionID = "cowork-" + event.SessionID
	req, err := localruntime.EvaluateRequestFromEvent(event)
	if err != nil {
		return fmt.Errorf("%w: %v", errMalformed, err)
	}
	res, err := send(opts.SocketPath, req)
	if err != nil {
		return err
	}
	if !res.Allowed {
		h.denied++
	}
	if rid == "" {
		return nil // observe hook: nothing is waiting
	}
	// A failed decision write is logged but not retried: the offset advances
	// (the event is ingested) and the waiting hook fails closed on its own.
	if !ridPattern.MatchString(rid) {
		opts.Diagnostic.Printf("cowork observe: rejected decision request id %q\n", rid)
		return nil
	}
	if err := writeDecision(filepath.Join(filepath.Dir(spool), decisionsDirName), rid, res); err != nil {
		opts.Diagnostic.Printf("cowork observe: write decision %s: %v\n", rid, err)
	}
	return nil
}

// writeDecision renders the verdict in the exact PreToolUse output shape the
// bundled CLI honors and parks it where the enforce hook is polling.
func writeDecision(dir, rid string, res localruntime.EvaluateResult) error {
	result := localruntime.ResultFromEvaluateResult(res)
	data, err := hookruntime.EncodeClaudeResult(hook.HookPreToolUse.String(), result)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, rid+".json"), data, 0o644)
}

// cleanupOrphanDecisions removes decision files nobody consumed (hook killed,
// session gone). The hook deletes its own file on the happy path.
func cleanupOrphanDecisions(opts Options, sessionDir string) {
	files, _ := filepath.Glob(filepath.Join(sessionDir, decisionsDirName, "*.json"))
	cutoff := time.Now().Add(-10 * time.Minute)
	for _, file := range files {
		if info, err := os.Stat(file); err == nil && info.ModTime().Before(cutoff) {
			if err := os.Remove(file); err != nil {
				opts.Diagnostic.Printf("cowork observe: remove orphan decision %s: %v\n", file, err)
			}
		}
	}
}

func send(socketPath string, req localruntime.EvaluateRequest) (localruntime.EvaluateResult, error) {
	var res localruntime.EvaluateResult
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return res, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := localruntime.WriteMessage(conn, req); err != nil {
		return res, err
	}
	if err := localruntime.ReadMessage(conn, &res); err != nil {
		return res, err
	}
	return res, nil
}
