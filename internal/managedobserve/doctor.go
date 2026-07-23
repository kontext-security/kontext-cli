package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedstream"
)

// PrintStatus reports the managed-observe state for `kontext doctor`:
// which managed config (if any) this machine resolves, the installation
// identity, whether the daemon is reachable, the self-serve LaunchAgent, and
// any token-rejection breadcrumb the daemon left behind.
func PrintStatus(out io.Writer, installedVersion string) (staleDaemon bool) {
	return printStatus(out, installedVersion, doctorOptions{
		DBPath:     DefaultDBPath(),
		SocketPath: DefaultSocketPath(),
		Now:        time.Now,
	})
}

type doctorOptions struct {
	DBPath     string
	SocketPath string
	Dial       func(network, address string, timeout time.Duration) (net.Conn, error)
	Now        func() time.Time
}

func printStatus(out io.Writer, installedVersion string, opts doctorOptions) (staleDaemon bool) {
	if opts.DBPath == "" {
		opts.DBPath = DefaultDBPath()
	}
	if opts.SocketPath == "" {
		opts.SocketPath = DefaultSocketPath()
	}
	if opts.Dial == nil {
		opts.Dial = net.DialTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	fmt.Fprintln(out, "Managed observe:")

	loaded, err := managedconfig.Load()
	if errors.Is(err, managedconfig.ErrNotManaged) {
		fmt.Fprintln(out, "  config: not configured (run `kontext setup` to connect this Mac to a workspace)")
		return false
	}
	if err != nil {
		fmt.Fprintf(out, "  config: ERROR %v\n", err)
		return false
	}

	fmt.Fprintf(out, "  config: %s (%s)\n", loaded.Path, describeScope(loaded.Scope))

	identityPath := installationPathForScope(loaded.Scope)
	if state, err := installation.LoadFile(identityPath); err == nil {
		fmt.Fprintf(out, "  installation: %s\n", state.InstallationID)
	} else if errors.Is(err, installation.ErrNotFound) {
		fmt.Fprintf(out, "  installation: not created yet (%s)\n", identityPath)
	} else {
		fmt.Fprintf(out, "  installation: ERROR %v (%s)\n", err, identityPath)
	}

	// Resolve the token through the daemon's exact read path: a locked or
	// missing keychain item is THE silent killer under launchd, and "daemon:
	// not running" alone points the user in the wrong direction.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := managedconfig.ResolveInstallToken(ctx, loaded.Config.Credentials.InstallTokenRef); err == nil {
		fmt.Fprintf(out, "  install token: readable (%s)\n", loaded.Config.Credentials.InstallTokenRef)
	} else {
		fmt.Fprintf(out, "  WARNING: install token is not readable (%v) — the agent cannot stream; re-run `kontext setup` or unlock your login keychain\n", err)
	}

	if conn, err := opts.Dial("unix", opts.SocketPath, 500*time.Millisecond); err == nil {
		conn.Close()
		if status := LoadDaemonStatus(opts.DBPath); status != nil && pidAlive(status.PID) {
			fmt.Fprintf(out, "  daemon: running (v%s, pid %d)\n", status.Version, status.PID)
			if comparableVersion(status.Version) && comparableVersion(installedVersion) && status.Version != installedVersion {
				fmt.Fprintf(out, "  WARNING: daemon is running v%s but v%s is installed — run 'kontext doctor --fix' to restart it\n", status.Version, installedVersion)
				staleDaemon = true
			}
		} else {
			fmt.Fprintln(out, "  daemon: running")
			// A serving daemon with no live status breadcrumb predates the
			// breadcrumb feature — which makes it older than the installed
			// binary by definition. This is exactly the first upgrade into
			// this feature, so it must be fixable; a verified restart of an
			// already-current daemon is the harmless worst case.
			if comparableVersion(installedVersion) {
				fmt.Fprintf(out, "  WARNING: daemon version is unknown — it likely predates v%s; run 'kontext doctor --fix' to restart it\n", installedVersion)
				staleDaemon = true
			}
		}
	} else {
		fmt.Fprintln(out, "  daemon: not running (it starts with your next Claude Code session)")
	}

	exportCtx, exportCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer exportCancel()
	state, err := managedstream.LoadState(managedstream.DefaultStatePathForDB(opts.DBPath))
	if err != nil {
		fmt.Fprintf(out, "  heartbeat: ERROR %v\n", err)
		fmt.Fprintf(out, "  export: ERROR %v\n", err)
	} else {
		printHeartbeat(out, state, opts.Now())
		printExportLag(exportCtx, out, opts.DBPath, state)
	}

	// Self-serve installs have a user LaunchAgent; MDM installs manage theirs
	// under /Library. Having BOTH scopes on one Mac deserves a callout — the
	// system config wins and the user agent should be removed.
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		userPlist := filepath.Join(home, "Library", "LaunchAgents", DefaultLaunchdLabel+".plist")
		if _, err := os.Lstat(userPlist); err == nil {
			fmt.Fprintf(out, "  launch agent: %s\n", userPlist)
			if loaded.Scope == managedconfig.ScopeSystem {
				fmt.Fprintln(out, "  WARNING: this Mac is organization-managed but a self-serve agent is also installed; run `kontext setup --uninstall` to remove it")
			}
		}
	}

	// The LaunchAgent runs the daemon without --db, so the breadcrumb always
	// sits next to the default database. A custom --db (dev-only hidden flag)
	// is invisible here — acceptable for a diagnostics readout.
	if authErr := LoadAuthError(opts.DBPath); authErr != nil {
		switch authErr.Kind {
		case "startup":
			fmt.Fprintf(out, "  WARNING: the agent failed to start — %s (%s)\n", authErr.Message, authErr.At)
		case authErrorKindCorrupt:
			fmt.Fprintf(out, "  WARNING: auth breadcrumb is unreadable — %s\n", authErr.Message)
		default:
			detail := ""
			if authErr.Status > 0 {
				detail = fmt.Sprintf(" (HTTP %d, %s)", authErr.Status, authErr.At)
			}
			fmt.Fprintf(out, "  WARNING: hosted ingest is failing — install token rejected%s; run `kontext setup` with a new token from the dashboard\n", detail)
		}
	}
	return staleDaemon
}

func describeScope(scope managedconfig.Scope) string {
	switch scope {
	case managedconfig.ScopeSystem:
		return "system, managed by your organization"
	case managedconfig.ScopeUser:
		return "user, installed by kontext setup"
	case managedconfig.ScopeEnv:
		return "env override"
	default:
		return string(scope)
	}
}

// WaitForDaemonRestart polls until the socket is serving AND the status
// breadcrumb reports a live daemon on wantVersion (any live daemon when the
// version is not comparable, e.g. dev builds). `doctor --fix` uses it so
// "restarted" is only printed for a verified comeback — launchd can accept a
// kickstart and still have the new daemon exit immediately (unreadable token,
// missing Cellar path).
func WaitForDaemonRestart(ctx context.Context, dbPath, socketPath, wantVersion string) (*DaemonStatus, error) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond); err == nil {
			conn.Close()
			if status := LoadDaemonStatus(dbPath); status != nil && pidAlive(status.PID) {
				if !comparableVersion(wantVersion) || status.Version == wantVersion {
					return status, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func comparableVersion(version string) bool {
	version = strings.TrimSpace(version)
	return version != "" && version != "dev"
}

func printHeartbeat(out io.Writer, state managedstream.State, now time.Time) {
	if strings.TrimSpace(state.LastHeartbeatAt) == "" {
		fmt.Fprintln(out, "  heartbeat: none recorded yet")
		return
	}
	last, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(state.LastHeartbeatAt))
	if err != nil {
		fmt.Fprintln(out, "  heartbeat: none recorded yet")
		return
	}
	age := now.Sub(last)
	if age < 0 {
		age = 0
	}
	fmt.Fprintf(out, "  heartbeat: %s ago\n", doctorDuration(age))
	if age > 5*time.Minute {
		fmt.Fprintf(out, "  WARNING: last heartbeat was %s ago — the daemon may be stalled\n", doctorDuration(age))
	}
}

func printExportLag(ctx context.Context, out io.Writer, dbPath string, state managedstream.State) {
	var cursor *sqlite.LedgerCursor
	if state.UpdatedAfter != nil {
		cursor = &sqlite.LedgerCursor{UpdatedAt: *state.UpdatedAfter, ActionID: state.ActionID}
	}
	newest, pending, err := sqlite.LedgerLag(ctx, dbPath, cursor)
	if err != nil {
		fmt.Fprintf(out, "  export: ERROR %v\n", err)
		return
	}
	if newest == nil {
		fmt.Fprintln(out, "  export: no ledger events yet")
		return
	}
	if cursor == nil {
		// Events exist but no export cursor yet — normal in the first seconds
		// after setup, so report without warning.
		fmt.Fprintf(out, "  export: not started yet (%d pending)\n", pending)
		return
	}
	lag := newest.Sub(cursor.UpdatedAt)
	if lag < 0 {
		lag = 0
	}
	// The export cursor rides 30s behind newest by design (cursorSafetyLag),
	// hence the 10m warning threshold.
	if lag > 10*time.Minute && pending > 0 {
		fmt.Fprintf(out, "  WARNING: export lagging %s (%d events pending) — the daemon may be stalled\n", doctorDuration(lag), pending)
		return
	}
	if pending == 0 {
		fmt.Fprintln(out, "  export: up to date (0 pending)")
		return
	}
	// Never claim "up to date" while rows are waiting — report the facts and
	// let the operator judge.
	fmt.Fprintf(out, "  export: %d pending (cursor %s behind newest)\n", pending, doctorDuration(lag))
}

func doctorDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Minute).String()
}
