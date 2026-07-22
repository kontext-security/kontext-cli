package managedobserve

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
)

const (
	sessionStartWait = 400 * time.Millisecond
	preToolUseWait   = 250 * time.Millisecond
	asyncHookWait    = 120 * time.Millisecond
	probeTimeout     = 60 * time.Millisecond
)

var launchdMu sync.Mutex

type Lifecycle struct {
	SocketPath string
	Label      string
	Kickstart  func(context.Context, string) error
	Diagnostic diagnostic.Logger
	// Mode is the managed rollout posture ("observe" or "enforce"). Empty is
	// treated as observe. In enforce the daemon's decision is authoritative and
	// passes through unchanged; in observe the hook can never block.
	Mode string
}

func NewLifecycle() Lifecycle {
	return Lifecycle{
		SocketPath: DefaultSocketPath(),
		Label:      DefaultLabel(),
		Kickstart:  KickstartLaunchd,
		Mode:       loadManagedMode(),
	}
}

// loadManagedMode reads the managed rollout posture from the installed managed
// config, defaulting to observe when the config is absent or unreadable (the
// caller only reaches here when Active() already succeeded, so this is a
// defensive fallback).
func loadManagedMode() string {
	cfg, err := managedconfig.Load()
	if err != nil {
		return managedconfig.Mode
	}
	if cfg.Config.Mode == managedconfig.ModeEnforce {
		return managedconfig.ModeEnforce
	}
	return managedconfig.Mode
}

func (l Lifecycle) enforcing() bool {
	return l.Mode == managedconfig.ModeEnforce
}

func Active() bool {
	_, err := managedconfig.Load()
	return err == nil
}

func (l Lifecycle) Process(ctx context.Context, event hook.Event) hook.Result {
	if l.SocketPath == "" {
		l.SocketPath = DefaultSocketPath()
	}
	if l.Label == "" {
		l.Label = DefaultLabel()
	}
	if l.Kickstart == nil {
		l.Kickstart = KickstartLaunchd
	}

	switch event.HookName {
	case hook.HookSessionStart:
		return l.processWithKickstart(ctx, event, sessionStartWait)
	case hook.HookPreToolUse:
		return l.processWithKickstart(ctx, event, preToolUseWait)
	default:
		return l.processIfAvailable(ctx, event, asyncHookWait)
	}
}

func (l Lifecycle) processWithKickstart(ctx context.Context, event hook.Event, budget time.Duration) hook.Result {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	if !l.probe(ctx) {
		launchdMu.Lock()
		if !l.probe(ctx) {
			if err := l.Kickstart(ctx, l.Label); err != nil {
				l.Diagnostic.Printf("managed observe kickstart: %v\n", err)
			}
		}
		launchdMu.Unlock()
	}
	if l.waitForProbe(ctx) {
		result, err := l.call(ctx, event)
		if err != nil {
			return l.daemonUnavailable(event)
		}
		return l.finalize(event, result)
	}
	return l.daemonUnavailable(event)
}

func (l Lifecycle) processIfAvailable(ctx context.Context, event hook.Event, budget time.Duration) hook.Result {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if !l.probe(ctx) {
		return l.daemonUnavailable(event)
	}
	result, err := l.call(ctx, event)
	if err != nil {
		return l.daemonUnavailable(event)
	}
	return l.finalize(event, result)
}

// finalize applies the client-side posture to a daemon result. Enforce accepts
// only an explicit enforce-mode allow or deny; a stale daemon or malformed RPC
// result is not authoritative. Non-blocking hooks are always normalized to
// allow. In observe the hook can never block, so the decision is forced to
// allow with a "would" note.
func (l Lifecycle) finalize(event hook.Event, result hook.Result) hook.Result {
	if l.enforcing() {
		if result.Mode != managedconfig.ModeEnforce ||
			(result.Decision != hook.DecisionAllow && result.Decision != hook.DecisionDeny) {
			return l.daemonUnavailable(event)
		}
		if !event.HookName.CanBlock() {
			result.Decision = hook.DecisionAllow
		}
		return result
	}
	return observeResult(event, result)
}

// daemonUnavailable is the fail path when the managed daemon cannot be reached.
// Observe fails open (it never blocks). Enforce fails closed for blocking
// hooks: enforcement requires an authoritative decision and an unreachable
// daemon cannot provide one. Non-blocking lifecycle hooks remain informational.
func (l Lifecycle) daemonUnavailable(event hook.Event) hook.Result {
	if l.enforcing() {
		decision := hook.DecisionAllow
		if event.HookName.CanBlock() {
			decision = hook.DecisionDeny
		}
		return hook.Result{
			Decision: decision,
			Mode:     managedconfig.ModeEnforce,
			Reason:   "Kontext enforce: managed policy daemon unavailable",
		}
	}
	return observeResult(event, hook.Result{Decision: hook.DecisionAllow, Reason: "managed observe daemon unavailable"})
}

func (l Lifecycle) probe(ctx context.Context) bool {
	dialer := net.Dialer{Timeout: probeTimeout}
	conn, err := dialer.DialContext(ctx, "unix", l.SocketPath)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (l Lifecycle) waitForProbe(ctx context.Context) bool {
	for {
		if l.probe(ctx) {
			return true
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

func (l Lifecycle) call(ctx context.Context, event hook.Event) (hook.Result, error) {
	client := localruntime.NewClient(l.SocketPath)
	client.Timeout = time.Until(deadlineOr(ctx, time.Now().Add(asyncHookWait)))
	if client.Timeout <= 0 {
		client.Timeout = asyncHookWait
	}
	result, err := client.Process(ctx, event)
	if err != nil {
		l.Diagnostic.Printf("managed observe call: %v\n", err)
		return hook.Result{}, err
	}
	return result, nil
}

func observeResult(event hook.Event, result hook.Result) hook.Result {
	result.Mode = string(guardhookruntime.ModeObserve)
	if result.Decision == "" {
		result.Decision = hook.DecisionAllow
	}
	if event.HookName.CanBlock() {
		decision := result.Decision
		if result.Reason == "" {
			result.Reason = "no reason provided"
		}
		if decision != hook.DecisionAllow {
			result.Reason = "Kontext observe mode: would " + string(decision) + "; " + result.Reason
		}
		result.Decision = hook.DecisionAllow
		return result
	}
	result.Decision = hook.DecisionAllow
	return result
}

func deadlineOr(ctx context.Context, fallback time.Time) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return fallback
}

func KickstartLaunchd(ctx context.Context, label string) error {
	return kickstartLaunchd(ctx, label, false)
}

// KickstartLaunchdKill runs launchctl kickstart with -k, which kills the
// running instance first; used to replace a daemon still running a stale binary.
func KickstartLaunchdKill(ctx context.Context, label string) error {
	return kickstartLaunchd(ctx, label, true)
}

func kickstartLaunchd(ctx context.Context, label string, kill bool) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if label == "" {
		return errors.New("launchd label is required")
	}
	args := []string{"kickstart"}
	if kill {
		args = append(args, "-k")
	}
	args = append(args, "gui/"+itoa(os.Getuid())+"/"+label)
	cmd := exec.CommandContext(ctx, "launchctl", args...)
	return cmd.Run()
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
