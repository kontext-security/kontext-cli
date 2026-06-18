// Package setup implements `kontext setup`: connecting a single Mac to a
// Kontext organization without MDM. It produces the same managed-observe
// pipeline as an enterprise package install — managed config, installation
// identity, Claude Code hooks, LaunchAgent running the daemon — but at user
// scope (~/Library, ~/.claude) with the install token in the login keychain.
package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/kontext-security/kontext-cli/internal/claudemanaged"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedobserve"
)

const (
	DefaultCloudURL = "https://api.kontext.security"

	// KeychainItemName is the generic-password service name. It MUST stay in
	// lockstep with the managed.json token ref below: the daemon reads the
	// token with `security find-generic-password -s <name> -w`.
	KeychainItemName = "kontext-install-token"
	keychainAccount  = "kontext"

	pingPath = "/api/v1/authorization-ledger/ping"

	settingsBackupLabel = "kontext-setup"
)

// Test seams (repo convention, cf. update.go's brewUpgradeFn). All external
// process and terminal interactions go through these so tests never touch
// launchctl/security/scutil or a real TTY.
var (
	execCommand = func(ctx context.Context, stdin string, name string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	readPassword = func(fd int) ([]byte, error) {
		return term.ReadPassword(fd)
	}
	isTerminal = func(fd int) bool {
		return term.IsTerminal(fd)
	}
	executablePath = os.Executable
	resolveToken   = managedconfig.ResolveInstallToken
	dialSocket     = func(path string, timeout time.Duration) error {
		conn, err := net.DialTimeout("unix", path, timeout)
		if err != nil {
			return err
		}
		return conn.Close()
	}
	systemConfigPath = managedconfig.DefaultPath
	goos             = runtime.GOOS
)

type Options struct {
	Token    string
	CloudURL string
	Version  string
	Stdout   io.Writer
	Stderr   io.Writer
	// HTTPClient overrides the ping client (tests). Nil uses a 10s-timeout
	// default.
	HTTPClient *http.Client
}

type pingResponse struct {
	OrganizationID string `json:"organization_id"`
	// JSON null (the legacy env-fallback org) decodes to "".
	OrganizationName string `json:"organization_name"`
}

// Run connects this Mac to the org owning the install token. Steps are
// ordered so every irreversible action happens after the token is proven
// valid, and re-running is always safe (token rotation restarts the agent).
func Run(ctx context.Context, opts Options) error {
	if goos != "darwin" {
		return errors.New("kontext setup is currently macOS-only")
	}
	if err := refuseManagedEnvironments(); err != nil {
		return err
	}

	cloudURL := strings.TrimSpace(opts.CloudURL)
	if cloudURL == "" {
		cloudURL = DefaultCloudURL
	}
	// Same rules the daemon's parser applies, so a bad --cloud-url fails
	// before any state is written.
	if err := managedconfig.ValidateCloudURL(cloudURL); err != nil {
		return err
	}

	token, err := acquireToken(opts)
	if err != nil {
		return err
	}

	ping, err := validateToken(ctx, opts.HTTPClient, cloudURL, token)
	if err != nil {
		return err
	}
	orgLabel := ping.OrganizationID
	if ping.OrganizationName != "" {
		orgLabel = fmt.Sprintf("%s (%s)", ping.OrganizationName, ping.OrganizationID)
	}
	fmt.Fprintf(opts.Stdout, "✓ Token accepted — organization %s\n", orgLabel)

	if err := writeKeychainToken(ctx, token); err != nil {
		return err
	}
	// Read back through the daemon's actual code path so a write/read
	// asymmetry fails HERE, not silently at the first flush under launchd.
	stored, err := resolveToken(ctx, managedconfig.TokenRef{Source: "keychain", Name: KeychainItemName})
	if err != nil {
		return fmt.Errorf("keychain read-back failed: %w", err)
	}
	if stored != token {
		return errors.New("keychain read-back returned a different token; remove stale 'kontext-install-token' keychain items and retry")
	}
	fmt.Fprintf(opts.Stdout, "✓ Install token stored in your login keychain (%s)\n", KeychainItemName)

	configPath, err := writeUserManagedConfig(cloudURL, ping.OrganizationID, deviceLabel(ctx))
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "✓ Managed config written to %s\n", configPath)

	identityPath := installation.UserPath()
	if identityPath == "" {
		return errors.New("cannot resolve your home directory")
	}
	identity, err := installation.EnsureFile(identityPath)
	if err != nil {
		return fmt.Errorf("ensure installation identity: %w", err)
	}
	fmt.Fprintf(opts.Stdout, "✓ Installation identity %s\n", identity.InstallationID)

	binary, binaryNote := stableBinaryPath()
	if binaryNote != "" {
		fmt.Fprintln(opts.Stderr, binaryNote)
	}

	warnings, err := installUserHooks(binary)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		fmt.Fprintf(opts.Stderr, "warning: %s\n", warning)
	}
	fmt.Fprintln(opts.Stdout, "✓ Claude Code hooks installed in ~/.claude/settings.json")

	plistPath, logPath, err := installLaunchAgent(ctx, binary)
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "✓ Background agent installed (%s)\n", plistPath)

	if err := probeDaemon(); err != nil {
		fmt.Fprintf(opts.Stderr, "warning: the background agent has not come up yet (%v); check `tail -f %s`\n", err, logPath)
	} else {
		fmt.Fprintln(opts.Stdout, "✓ Background agent is running")
	}

	fmt.Fprintf(opts.Stdout, "\nDone. Start a Claude Code session — activity appears in your dashboard within seconds.\n")
	return nil
}

// refuseManagedEnvironments keeps self-serve setup away from machines that
// are (or claim to be) organization-managed: a system config under /Library
// always outranks anything setup could write, so proceeding would only
// produce artifacts the daemon ignores.
func refuseManagedEnvironments() error {
	// ANY env override means config resolution is explicitly env-driven —
	// even one pointing at the user path. Setup must not write state whose
	// activation depends on an environment variable it doesn't control.
	if strings.TrimSpace(os.Getenv(managedconfig.EnvPath)) != "" {
		return fmt.Errorf("%s is set; unset it before running setup", managedconfig.EnvPath)
	}
	if _, err := os.Lstat(systemConfigPath); err == nil {
		return errors.New("this Mac already has an organization-managed Kontext install (deployed by your IT admin via MDM); self-serve setup is not needed and would be ignored")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot determine whether this Mac is organization-managed: %w", err)
	}
	return nil
}

// acquireToken never mutates the input: a token containing whitespace fails
// loudly instead of being silently trimmed into something the user didn't
// paste — the stored credential must be byte-identical to the dashboard's.
func acquireToken(opts Options) (string, error) {
	if opts.Token != "" {
		return opts.Token, validateTokenShape(opts.Token)
	}
	fd := int(os.Stdin.Fd())
	if !isTerminal(fd) {
		return "", errors.New("no install token: pass --token in non-interactive environments")
	}
	fmt.Fprint(opts.Stderr, "Paste your install token (from the Kontext dashboard, shown once at creation): ")
	raw, err := readPassword(fd)
	fmt.Fprintln(opts.Stderr)
	if err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	token := string(raw)
	if token == "" {
		return "", errors.New("no install token entered")
	}
	return token, validateTokenShape(token)
}

// validateTokenShape rejects whitespace and control characters — same rule
// the enterprise install script enforces. Besides catching mangled paste
// input early, it guarantees the token can never smuggle a second line into
// the `security -i` command stream.
func validateTokenShape(token string) error {
	for _, r := range token {
		if r <= ' ' || r == 0x7f {
			return errors.New("install token must not contain whitespace or control characters")
		}
	}
	return nil
}

func validateToken(ctx context.Context, client *http.Client, cloudURL, token string) (pingResponse, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cloudURL, "/")+pingPath, nil)
	if err != nil {
		return pingResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return pingResponse{}, fmt.Errorf("cannot reach %s: %w", cloudURL, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return pingResponse{}, errors.New("install token was rejected — it may be revoked or mistyped; create a new one in the dashboard (Deployments page)")
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return pingResponse{}, fmt.Errorf("token validation failed: %s returned HTTP %d", cloudURL, resp.StatusCode)
	}

	var ping pingResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ping); err != nil {
		return pingResponse{}, fmt.Errorf("parse token validation response: %w", err)
	}
	if strings.TrimSpace(ping.OrganizationID) == "" {
		return pingResponse{}, errors.New("server did not return an organization id for this token")
	}
	return ping, nil
}

func deviceLabel(ctx context.Context) string {
	if out, err := execCommand(ctx, "", "scutil", "--get", "ComputerName"); err == nil {
		if label := strings.TrimSpace(out); label != "" {
			return label
		}
	}
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return host
}

func writeUserManagedConfig(cloudURL, organizationID, label string) (string, error) {
	path := managedconfig.UserPath()
	if path == "" {
		return "", errors.New("cannot resolve your home directory")
	}

	cfg := managedconfig.Config{
		Version:        managedconfig.Version,
		OrganizationID: organizationID,
		CloudURL:       cloudURL,
		Mode:           managedconfig.Mode,
		Agent:          managedconfig.Agent,
		Credentials: managedconfig.Credentials{
			InstallTokenRef: managedconfig.TokenRef{Source: "keychain", Name: KeychainItemName},
		},
		Device: managedconfig.Device{Label: label},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	// Self-check through the daemon's parser: setup must never write a config
	// the daemon will refuse to load.
	if _, err := managedconfig.Parse(data); err != nil {
		return "", fmt.Errorf("generated managed config is invalid: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".managed-*.tmp")
	if err != nil {
		return "", err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return "", err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return "", err
	}
	return path, nil
}

// stableBinaryPath picks the path baked into hooks and the LaunchAgent. The
// brew prefix symlink (/opt/homebrew/bin, /usr/local/bin) survives `brew
// upgrade`; a Cellar path dies with the next version, so prefer a stable
// symlink that resolves to the same binary.
func stableBinaryPath() (string, string) {
	exe, err := executablePath()
	if err != nil || exe == "" {
		return claudemanaged.DefaultKontextBinary, ""
	}
	if !strings.Contains(exe, "/Cellar/") {
		return exe, ""
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		real = exe
	}
	for _, candidate := range []string{"/opt/homebrew/bin/kontext", "/usr/local/bin/kontext"} {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		if resolved == real {
			return candidate, ""
		}
	}
	return exe, "note: using a Homebrew Cellar path for hooks; re-run `kontext setup` after `brew upgrade kontext`"
}

func installUserHooks(binary string) ([]string, error) {
	path, err := claudemanaged.UserSettingsPath()
	if err != nil {
		return nil, err
	}
	settings, err := claudemanaged.ReadUserSettings(path)
	if err != nil {
		return nil, err
	}
	warnings, err := claudemanaged.MergeManagedHooks(settings, binary)
	if err != nil {
		return nil, err
	}
	if err := claudemanaged.BackupUserSettings(path, settingsBackupLabel); err != nil {
		return nil, err
	}
	if err := claudemanaged.WriteUserSettings(path, settings); err != nil {
		return nil, err
	}
	return warnings, nil
}

func probeDaemon() error {
	socket := managedobserve.DefaultSocketPath()
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		if lastErr = dialSocket(socket, 500*time.Millisecond); lastErr == nil {
			return nil
		}
	}
	return lastErr
}
