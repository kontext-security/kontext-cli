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
}

func NewLifecycle() Lifecycle {
	return Lifecycle{
		SocketPath: DefaultSocketPath(),
		Label:      DefaultLabel(),
		Kickstart:  KickstartLaunchd,
	}
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
		return observeResult(event, l.call(ctx, event))
	}
	return observeResult(event, hook.Result{Decision: hook.DecisionAllow, Reason: "managed observe daemon unavailable"})
}

func (l Lifecycle) processIfAvailable(ctx context.Context, event hook.Event, budget time.Duration) hook.Result {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if !l.probe(ctx) {
		return observeResult(event, hook.Result{Decision: hook.DecisionAllow, Reason: "managed observe daemon unavailable"})
	}
	return observeResult(event, l.call(ctx, event))
}

func (l Lifecycle) probe(ctx context.Context) bool {
	dialer := net.Dialer{Timeout: probeTimeout}
	conn, err := dialer.DialContext(ctx, "unix", l.SocketPath)
	if err != nil {
		return false
	}
	if err := conn.Close(); err != nil {
		l.Diagnostic.Printf("managed observe probe close: %v\n", err)
	}
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

func (l Lifecycle) call(ctx context.Context, event hook.Event) hook.Result {
	client := localruntime.NewClient(l.SocketPath)
	client.Timeout = time.Until(deadlineOr(ctx, time.Now().Add(asyncHookWait)))
	if client.Timeout <= 0 {
		client.Timeout = asyncHookWait
	}
	result, err := client.Process(ctx, event)
	if err != nil {
		l.Diagnostic.Printf("managed observe call: %v\n", err)
		return hook.Result{Decision: hook.DecisionAllow, Reason: "managed observe daemon unavailable"}
	}
	return result
}

func observeResult(event hook.Event, result hook.Result) hook.Result {
	result.Mode = string(guardhookruntime.ModeObserve)
	if result.Decision == "" {
		result.Decision = hook.DecisionAllow
	}
	if event.HookName == hook.HookPreToolUse {
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
	if runtime.GOOS != "darwin" {
		return nil
	}
	if label == "" {
		return errors.New("launchd label is required")
	}
	cmd := exec.CommandContext(ctx, "launchctl", "kickstart", "gui/"+itoa(os.Getuid())+"/"+label)
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
