package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
)

// PrintStatus reports the managed-observe state for `kontext doctor`:
// which managed config (if any) this machine resolves, the installation
// identity, whether the daemon is reachable, the self-serve LaunchAgent, and
// any token-rejection breadcrumb the daemon left behind.
func PrintStatus(out io.Writer) {
	fmt.Fprintln(out, "Managed observe:")

	loaded, err := managedconfig.Load()
	if errors.Is(err, managedconfig.ErrNotManaged) {
		fmt.Fprintln(out, "  config: not configured (run `kontext setup` to connect this Mac to a workspace)")
		return
	}
	if err != nil {
		fmt.Fprintf(out, "  config: ERROR %v\n", err)
		return
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

	if conn, err := net.DialTimeout("unix", DefaultSocketPath(), 500*time.Millisecond); err == nil {
		conn.Close()
		fmt.Fprintln(out, "  daemon: running")
	} else {
		fmt.Fprintln(out, "  daemon: not running (it starts with your next Claude Code session)")
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
	if authErr := LoadAuthError(DefaultDBPath()); authErr != nil {
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
