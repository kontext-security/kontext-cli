// Package setup implements `kontext setup`: connecting a single Mac to a
// Kontext organization without MDM. It produces the same managed-observe
// pipeline as an enterprise package install — managed config, installation
// identity, Claude Code hooks, LaunchAgent running the daemon — but at user
// scope (~/Library, ~/.claude) with the install token in the login keychain.
package setup

import (
	"bytes"
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
	runPrivilegedCommand = func(ctx context.Context, name string, args ...string) error {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	isTerminal = func(fd int) bool {
		return term.IsTerminal(fd)
	}
	executablePath = os.Executable
	geteuid        = os.Geteuid
	resolveToken   = managedconfig.ResolveInstallToken
	dialSocket     = func(path string, timeout time.Duration) error {
		conn, err := net.DialTimeout("unix", path, timeout)
		if err != nil {
			return err
		}
		return conn.Close()
	}
	systemConfigPath    = managedconfig.DefaultPath
	managedSettingsPath = claudemanaged.ManagedSettingsDropInPath
	goos                = runtime.GOOS
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

	fmt.Fprintln(opts.Stdout, "Kontext setup")

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
	fmt.Fprintln(opts.Stdout, "\nWorkspace")
	fmt.Fprintf(opts.Stdout, "  ✓ %s\n", orgLabel)

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
	fmt.Fprintf(opts.Stdout, "  ✓ Token saved to Keychain (%s)\n", KeychainItemName)

	fmt.Fprintln(opts.Stdout, "\nMac")

	configPath, err := writeUserManagedConfig(cloudURL, deviceLabel(ctx))
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Config written (%s)\n", configPath)

	identityPath := installation.UserPath()
	if identityPath == "" {
		return errors.New("cannot resolve your home directory")
	}
	identity, err := installation.EnsureFile(identityPath)
	if err != nil {
		return fmt.Errorf("ensure installation identity: %w", err)
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Installation identity ready (%s)\n", identity.InstallationID)

	binary, binaryNote := stableBinaryPath()
	if binaryNote != "" {
		fmt.Fprintln(opts.Stderr, binaryNote)
	}

	settingsPath, warnings, err := installManagedSettings(ctx, binary)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		fmt.Fprintf(opts.Stderr, "warning: %s\n", warning)
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Claude Code managed hooks installed (%s)\n", settingsPath)

	var plistPath, logPath string
	err = runWithStatus(opts.Stdout, "Installing background agent", func() error {
		var err error
		plistPath, logPath, err = installLaunchAgent(ctx, binary)
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Background agent installed (%s)\n", plistPath)

	if err := waitForDaemon(opts.Stdout); err != nil {
		fmt.Fprintln(opts.Stdout, "  ! Background agent is still starting")
		fmt.Fprintf(opts.Stderr, "warning: the background agent has not come up yet (%v); check `tail -f %s`\n", err, logPath)
	} else {
		fmt.Fprintln(opts.Stdout, "  ✓ Background agent running")
	}

	fmt.Fprintln(opts.Stdout, "\nNext")
	fmt.Fprintln(opts.Stdout, "  Return to the Kontext dashboard.")
	fmt.Fprintln(opts.Stdout, "  Run the hello command shown there to confirm this Mac is connected.")
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
		return fmt.Errorf("this Mac is organization-managed\n\nSystem config\n  %s\n\nSelf-serve setup cannot continue because system config wins over user config.\nNothing changed.", systemConfigPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot determine whether this Mac is organization-managed: %w", err)
	}
	if err := refuseUnknownManagedSettingsOwner(); err != nil {
		return err
	}
	return nil
}

func refuseUnknownManagedSettingsOwner() error {
	if _, err := os.Lstat(managedSettingsPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("cannot determine Claude managed hooks ownership: %w", err)
	}
	userConfig := managedconfig.UserPath()
	if userConfig == "" {
		return errors.New("Claude Code managed hooks already exist, but your self-serve config cannot be resolved. Nothing changed.")
	}
	if _, err := managedconfig.LoadFile(userConfig); err != nil {
		return fmt.Errorf("Claude Code managed hooks already exist\n\nManaged hooks\n  %s\n\nSelf-serve setup cannot continue because hook ownership is unknown.\nNothing changed.", managedSettingsPath)
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

func writeUserManagedConfig(cloudURL, label string) (string, error) {
	path := managedconfig.UserPath()
	if path == "" {
		return "", errors.New("cannot resolve your home directory")
	}

	cfg := managedconfig.Config{
		Version:  managedconfig.Version,
		CloudURL: cloudURL,
		Mode:     managedconfig.Mode,
		Agent:    managedconfig.Agent,
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

func installManagedSettings(ctx context.Context, binary string) (string, []string, error) {
	data, err := claudemanaged.TemplateJSON(binary)
	if err != nil {
		return "", nil, err
	}
	if err := claudemanaged.Validate(data, binary); err != nil {
		return "", nil, fmt.Errorf("generated managed settings are invalid: %w", err)
	}
	if err := writePrivilegedFile(ctx, managedSettingsPath, data); err != nil {
		return "", nil, err
	}
	return managedSettingsPath, removeLegacyUserHooks(), nil
}

func writePrivilegedFile(ctx context.Context, path string, data []byte) error {
	if geteuid() == 0 {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		temp, err := os.CreateTemp(dir, ".managed-settings-*.tmp")
		if err != nil {
			return err
		}
		tempPath := temp.Name()
		defer os.Remove(tempPath)
		if err := temp.Chmod(0o644); err != nil {
			temp.Close()
			return err
		}
		if _, err := temp.Write(data); err != nil {
			temp.Close()
			return err
		}
		if err := temp.Sync(); err != nil {
			temp.Close()
			return err
		}
		if err := temp.Close(); err != nil {
			return err
		}
		if err := os.Rename(tempPath, path); err != nil {
			return err
		}
		return os.Chmod(path, 0o644)
	}

	temp, err := os.CreateTemp("", "kontext-managed-settings-*.json")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := runPrivilegedCommand(ctx, "sudo", "mkdir", "-p", filepath.Dir(path)); err != nil {
		return fmt.Errorf("create Claude managed settings directory: %w", err)
	}
	if err := runPrivilegedCommand(ctx, "sudo", "install", "-m", "0644", tempPath, path); err != nil {
		return fmt.Errorf("install Claude managed settings: %w", err)
	}
	return nil
}

func removeLegacyUserHooks() []string {
	path, err := userSettingsPathNoCreate()
	if err != nil {
		return []string{fmt.Sprintf("legacy Claude Code hooks were not cleaned up: %v", err)}
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return []string{fmt.Sprintf("legacy Claude Code hooks were not cleaned up: %v", err)}
	}
	settings, err := claudemanaged.ReadUserSettings(path)
	if err != nil {
		return []string{fmt.Sprintf("legacy Claude Code hooks were not cleaned up: %v", err)}
	}
	before, err := json.Marshal(settings)
	if err != nil {
		return []string{fmt.Sprintf("legacy Claude Code hooks were not cleaned up: %v", err)}
	}
	if err := claudemanaged.RemoveManagedHooks(settings); err != nil {
		return []string{fmt.Sprintf("legacy Claude Code hooks were not cleaned up: %v", err)}
	}
	after, err := json.Marshal(settings)
	if err != nil {
		return []string{fmt.Sprintf("legacy Claude Code hooks were not cleaned up: %v", err)}
	}
	if bytes.Equal(before, after) {
		return nil
	}
	if err := claudemanaged.BackupUserSettings(path, settingsBackupLabel); err != nil {
		return []string{fmt.Sprintf("legacy Claude Code hooks were not cleaned up: %v", err)}
	}
	if err := claudemanaged.WriteUserSettings(path, settings); err != nil {
		return []string{fmt.Sprintf("legacy Claude Code hooks were not cleaned up: %v", err)}
	}
	return nil
}

func waitForDaemon(out io.Writer) error {
	return runWithStatus(out, "Waiting for background agent", probeDaemon)
}

func runWithStatus(out io.Writer, label string, fn func() error) error {
	if !isTerminalWriter(out) {
		fmt.Fprintf(out, "  • %s...\n", label)
		return fn()
	}

	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	frames := []string{"◐", "◓", "◑", "◒"}
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	frame := 0
	for {
		fmt.Fprintf(out, "\r  %s %s...", frames[frame%len(frames)], label)
		frame++
		select {
		case err := <-done:
			fmt.Fprint(out, "\r\033[2K")
			return err
		case <-ticker.C:
		}
	}
}

func isTerminalWriter(w io.Writer) bool {
	file, ok := w.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
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
