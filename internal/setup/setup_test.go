package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/claudemanaged"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
)

type execCall struct {
	stdin string
	name  string
	args  []string
}

// harness stubs every seam so Run/Uninstall never touch launchctl, security,
// scutil, a TTY, or the real /Library — and records what they WOULD have run.
type harness struct {
	t        *testing.T
	home     string
	calls    []execCall
	keychain map[string]string // service -> token, emulating add/delete/find
	out      bytes.Buffer
	errOut   bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, home: t.TempDir(), keychain: map[string]string{}}
	t.Setenv("HOME", h.home)
	t.Setenv(managedconfig.EnvPath, "")
	t.Setenv(installation.EnvPath, "")

	overrideVar(t, &goos, "darwin")
	overrideVar(t, &systemConfigPath, filepath.Join(h.home, "no-system", "managed.json"))
	overrideVar(t, &executablePath, func() (string, error) { return "/opt/homebrew/bin/kontext", nil })
	overrideVar(t, &dialSocket, func(string, time.Duration) error { return nil })
	overrideVar(t, &isTerminal, func(int) bool { return false })
	overrideVar(t, &readPassword, func(int) ([]byte, error) { return nil, errors.New("no tty in tests") })
	overrideVar(t, &resolveToken, func(_ context.Context, ref managedconfig.TokenRef) (string, error) {
		token, ok := h.keychain[ref.Name]
		if !ok {
			return "", errors.New("keychain item not found")
		}
		return token, nil
	})
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		switch name {
		case "scutil":
			return "Test MacBook\n", nil
		case "security":
			if len(args) > 0 && args[0] == "delete-generic-password" {
				if _, ok := h.keychain[KeychainItemName]; ok {
					delete(h.keychain, KeychainItemName)
					return "", nil
				}
				return "security: The specified item could not be found in the keychain.", errors.New("exit status 44")
			}
			// `security -i` add-generic-password via stdin.
			if len(args) > 0 && args[0] == "-i" {
				token := parseAddGenericPassword(h.t, stdin)
				h.keychain[KeychainItemName] = token
				return "", nil
			}
			return "", nil
		case "launchctl":
			return "", nil
		default:
			h.t.Fatalf("unexpected command: %s %v", name, args)
			return "", nil
		}
	})
	return h
}

func overrideVar[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

func parseAddGenericPassword(t *testing.T, stdin string) string {
	t.Helper()
	// add-generic-password -U -s <service> -a <account> -w "<token>"
	start := strings.Index(stdin, `-w "`)
	if start < 0 {
		t.Fatalf("unexpected security stdin: %q", stdin)
	}
	rest := stdin[start+len(`-w "`):]
	end := strings.LastIndex(rest, `"`)
	if end < 0 {
		t.Fatalf("unterminated token quote: %q", stdin)
	}
	return rest[:end]
}

func (h *harness) options(token string, server *httptest.Server) Options {
	return Options{
		Token:      token,
		CloudURL:   server.URL,
		Version:    "0.0.0-test",
		Stdout:     &h.out,
		Stderr:     &h.errOut,
		HTTPClient: server.Client(),
	}
}

func pingServer(t *testing.T, expectToken string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/authorization-ledger/ping" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+expectToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"organization_id":   "org_test",
			"organization_name": "Acme",
		})
	}))
	t.Cleanup(server.Close)
	return server
}

// The httptest server is plain http on a loopback address; the managed.json
// self-check (managedconfig.Parse) only accepts that with the loopback
// escape hatch enabled.
func allowLoopback(t *testing.T) {
	t.Setenv(managedconfig.EnvAllowHTTP, "1")
}

func TestRunFullFlow(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "tok-123")

	if err := Run(context.Background(), h.options("tok-123", server)); err != nil {
		t.Fatalf("Run() error = %v\nstdout:\n%s\nstderr:\n%s", err, h.out.String(), h.errOut.String())
	}

	// Keychain holds the raw token.
	if h.keychain[KeychainItemName] != "tok-123" {
		t.Fatalf("keychain = %q", h.keychain[KeychainItemName])
	}

	// managed.json at the user path parses through the daemon's loader.
	// (Scope resolution itself is covered by managedconfig's own tests — the
	// host machine may have a real /Library config that Load() would pick.)
	loaded, err := managedconfig.LoadFile(managedconfig.UserPath())
	if err != nil {
		t.Fatalf("LoadFile(user path) after setup: %v", err)
	}
	if loaded.Config.OrganizationID != "org_test" {
		t.Fatalf("org = %q", loaded.Config.OrganizationID)
	}
	if loaded.Config.Credentials.InstallTokenRef.String() != "keychain:"+KeychainItemName {
		t.Fatalf("token ref = %q", loaded.Config.Credentials.InstallTokenRef)
	}
	if loaded.Config.Device.Label != "Test MacBook" {
		t.Fatalf("device label = %q", loaded.Config.Device.Label)
	}

	// Installation identity created at the user path.
	if _, err := installation.LoadFile(installation.UserPath()); err != nil {
		t.Fatalf("installation identity: %v", err)
	}

	// Hooks merged into ~/.claude/settings.json with the stable binary path.
	settingsPath := filepath.Join(h.home, ".claude", "settings.json")
	settings, err := claudemanaged.ReadUserSettings(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"hooks": settings["hooks"]})
	if err := claudemanaged.Validate(raw, "/opt/homebrew/bin/kontext"); err != nil {
		t.Fatalf("hooks invalid after setup: %v", err)
	}

	// LaunchAgent plist written and lifecycle ordered bootout -> bootstrap ->
	// kickstart in the user's GUI domain.
	plist := filepath.Join(h.home, "Library", "LaunchAgents", LaunchAgentLabel+".plist")
	if _, err := os.Stat(plist); err != nil {
		t.Fatalf("plist missing: %v", err)
	}
	var launchctl [][]string
	for _, call := range h.calls {
		if call.name == "launchctl" {
			launchctl = append(launchctl, call.args)
		}
	}
	if len(launchctl) != 3 || launchctl[0][0] != "bootout" || launchctl[1][0] != "bootstrap" || launchctl[2][0] != "kickstart" {
		t.Fatalf("launchctl order = %v", launchctl)
	}

	// The raw token never travels in argv — only via `security -i` stdin.
	for _, call := range h.calls {
		for _, arg := range call.args {
			if strings.Contains(arg, "tok-123") {
				t.Fatalf("token leaked into argv: %s %v", call.name, call.args)
			}
		}
	}
}

func TestRunIsIdempotent(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "tok-123")

	if err := Run(context.Background(), h.options("tok-123", server)); err != nil {
		t.Fatal(err)
	}
	identityBefore, err := installation.LoadFile(installation.UserPath())
	if err != nil {
		t.Fatal(err)
	}

	if err := Run(context.Background(), h.options("tok-123", server)); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}

	// Identity survives; hooks not duplicated.
	identityAfter, err := installation.LoadFile(installation.UserPath())
	if err != nil {
		t.Fatal(err)
	}
	if identityBefore.InstallationID != identityAfter.InstallationID {
		t.Fatal("installation identity changed across re-runs")
	}
	settings, err := claudemanaged.ReadUserSettings(filepath.Join(h.home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	groups := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(groups) != 1 {
		t.Fatalf("PreToolUse groups after re-run = %d, want 1", len(groups))
	}
}

func TestRunRejectsRevokedToken(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "valid-token")

	err := Run(context.Background(), h.options("revoked-token", server))
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("Run() error = %v, want rejection", err)
	}
	// Nothing was written before validation failed.
	if len(h.keychain) != 0 {
		t.Fatal("keychain written despite rejected token")
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatal("managed.json written despite rejected token")
	}
}

func TestRunRefusesMDMManagedMac(t *testing.T) {
	h := newHarness(t)
	system := filepath.Join(h.home, "system-managed.json")
	if err := os.WriteFile(system, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	overrideVar(t, &systemConfigPath, system)
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "organization-managed") {
		t.Fatalf("Run() error = %v, want MDM refusal", err)
	}
}

func TestRunRefusesEnvOverride(t *testing.T) {
	h := newHarness(t)
	t.Setenv(managedconfig.EnvPath, "/somewhere/else.json")
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), managedconfig.EnvPath) {
		t.Fatalf("Run() error = %v, want env refusal", err)
	}
}

func TestRunRefusesEnvOverrideEvenAtUserPath(t *testing.T) {
	// Any env override means config resolution is env-driven — including one
	// that happens to equal the user path. Setup must refuse them all.
	h := newHarness(t)
	t.Setenv(managedconfig.EnvPath, managedconfig.UserPath())
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), managedconfig.EnvPath) {
		t.Fatalf("Run() error = %v, want env refusal", err)
	}
}

func TestRunRequiresTokenWithoutTTY(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("", server))
	if err == nil || !strings.Contains(err.Error(), "--token") {
		t.Fatalf("Run() error = %v, want --token guidance", err)
	}
}

func TestRunNonDarwin(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &goos, "linux")
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "macOS-only") {
		t.Fatalf("Run() error = %v, want macOS-only", err)
	}
}

func TestUninstallReversesSetupKeepingIdentity(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "tok-123")
	if err := Run(context.Background(), h.options("tok-123", server)); err != nil {
		t.Fatal(err)
	}

	// A foreign hook installed after setup must survive uninstall.
	settingsPath := filepath.Join(h.home, ".claude", "settings.json")
	settings, err := claudemanaged.ReadUserSettings(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks := settings["hooks"].(map[string]any)
	hooks["PreToolUse"] = append(hooks["PreToolUse"].([]any), map[string]any{
		"matcher": "Edit",
		"hooks":   []any{map[string]any{"type": "command", "command": "lint-check"}},
	})
	if err := claudemanaged.WriteUserSettings(settingsPath, settings); err != nil {
		t.Fatal(err)
	}

	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}

	if len(h.keychain) != 0 {
		t.Fatal("keychain item not removed")
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatal("managed.json not removed")
	}
	plist := filepath.Join(h.home, "Library", "LaunchAgents", LaunchAgentLabel+".plist")
	if _, err := os.Stat(plist); !os.IsNotExist(err) {
		t.Fatal("plist not removed")
	}
	// Identity kept for endpoint continuity.
	if _, err := installation.LoadFile(installation.UserPath()); err != nil {
		t.Fatalf("installation identity removed: %v", err)
	}
	// Our hooks gone, the foreign one intact.
	settings, err = claudemanaged.ReadUserSettings(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	pre := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 || pre[0].(map[string]any)["matcher"] != "Edit" {
		t.Fatalf("foreign hook lost or ours kept: %v", pre)
	}

	// Idempotent: a second uninstall is clean.
	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("second Uninstall() error = %v", err)
	}
}

func TestRunRejectsTokenWithControlCharacters(t *testing.T) {
	// A token must never be able to smuggle a second line into the
	// `security -i` command stream.
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "x")

	// Leading/trailing whitespace must FAIL, never be silently trimmed —
	// the stored credential must be byte-identical to what was pasted.
	for _, token := range []string{"a\nb", "a b", "a\tb", "a\rb", " abc", "abc\n", "abc "} {
		err := Run(context.Background(), h.options(token, server))
		if err == nil || !strings.Contains(err.Error(), "whitespace or control") {
			t.Fatalf("Run(token=%q) error = %v, want shape rejection", token, err)
		}
	}
	if len(h.keychain) != 0 {
		t.Fatal("keychain written despite malformed token")
	}
}

func TestInstallLaunchAgentRejectsLoadedStaleJob(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name == "launchctl" && args[0] == "bootout" {
			return "Boot-out failed", errors.New("exit status 5")
		}
		// `launchctl print` succeeding means the stale service is still loaded.
		return "", nil
	})

	_, _, err := installLaunchAgent(context.Background(), "/opt/homebrew/bin/kontext")
	if err == nil || !strings.Contains(err.Error(), "launchctl bootout failed") {
		t.Fatalf("installLaunchAgent() error = %v, want stale loaded job failure", err)
	}
}

func TestInstallLaunchAgentSurfacesBootstrapFailure(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name == "launchctl" && args[0] == "bootstrap" {
			return "Bootstrap failed: 17: File exists", errors.New("exit status 17")
		}
		return "", nil
	})

	_, _, err := installLaunchAgent(context.Background(), "/opt/homebrew/bin/kontext")
	if err == nil || !strings.Contains(err.Error(), "launchctl bootstrap failed") {
		t.Fatalf("installLaunchAgent() error = %v, want bootstrap failure", err)
	}
}

func TestUninstallWithoutSettingsFileDoesNotCreateOne(t *testing.T) {
	// A removal must never CREATE config: uninstall on a machine with no
	// ~/.claude/settings.json leaves none behind.
	h := newHarness(t)

	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	settingsPath := filepath.Join(h.home, ".claude", "settings.json")
	if _, err := os.Lstat(settingsPath); !os.IsNotExist(err) {
		t.Fatalf("uninstall created %s", settingsPath)
	}
}

func TestUninstallSurfacesKeychainFailures(t *testing.T) {
	// A locked/denied keychain must fail uninstall loudly — not report the
	// token as removed while it still exists.
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name == "security" && len(args) > 0 && args[0] == "delete-generic-password" {
			return "SecKeychainItemDelete: User interaction is not allowed.", errors.New("exit status 36")
		}
		return "", nil
	})

	err := Uninstall(context.Background(), h.options("", pingServer(t, "unused")))
	if err == nil || !strings.Contains(err.Error(), "delete keychain item") {
		t.Fatalf("Uninstall() error = %v, want keychain failure surfaced", err)
	}
}

func TestDeleteKeychainTokensAcceptsNotFoundVariants(t *testing.T) {
	for _, output := range []string{
		"security: The specified item could not be found in the keychain.",
		"SECURITY: THE SPECIFIED ITEM COULD NOT BE FOUND IN THE KEYCHAIN.",
		"item not found",
	} {
		t.Run(output, func(t *testing.T) {
			overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
				return output, errors.New("exit status 44")
			})
			if err := deleteKeychainTokens(context.Background()); err != nil {
				t.Fatalf("deleteKeychainTokens() error = %v, want nil", err)
			}
		})
	}
}

func TestUninstallSurfacesLaunchAgentBootoutFailure(t *testing.T) {
	h := newHarness(t)
	plistPath := filepath.Join(h.home, "Library", "LaunchAgents", LaunchAgentLabel+".plist")
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plistPath, []byte("plist"), 0o644); err != nil {
		t.Fatal(err)
	}
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name == "launchctl" && args[0] == "bootout" {
			return "permission denied", errors.New("exit status 5")
		}
		return "", nil
	})

	err := Uninstall(context.Background(), h.options("", pingServer(t, "unused")))
	if err == nil || !strings.Contains(err.Error(), "launchctl bootout failed") {
		t.Fatalf("Uninstall() error = %v, want bootout failure surfaced", err)
	}
}

func TestUninstallSurfacesLoadedLaunchAgentWithoutPlist(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name == "launchctl" && args[0] == "bootout" {
			return "No such file", errors.New("exit status 5")
		}
		if name == "launchctl" && args[0] == "print" {
			return "service is loaded", nil
		}
		return "", nil
	})

	err := Uninstall(context.Background(), h.options("", pingServer(t, "unused")))
	if err == nil || !strings.Contains(err.Error(), "still loaded") {
		t.Fatalf("Uninstall() error = %v, want loaded service failure", err)
	}
}

func TestUninstallBootsOutByPlistPath(t *testing.T) {
	// Bootout must target OUR plist, not the shared label — a label-target
	// bootout could unload an MDM agent holding the same label.
	h := newHarness(t)
	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatal(err)
	}
	for _, call := range h.calls {
		if call.name == "launchctl" && call.args[0] == "bootout" {
			if len(call.args) != 3 || !strings.HasSuffix(call.args[2], ".plist") {
				t.Fatalf("bootout args = %v, want domain + plist path", call.args)
			}
			return
		}
	}
	t.Fatal("no bootout call recorded")
}

func TestSecurityQuote(t *testing.T) {
	cases := map[string]string{
		`plain`:      `"plain"`,
		`with"quote`: `"with\"quote"`,
		`back\slash`: `"back\\slash"`,
	}
	for in, want := range cases {
		if got := securityQuote(in); got != want {
			t.Errorf("securityQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestStableBinaryPathPrefersBrewSymlink(t *testing.T) {
	// Non-Cellar paths pass through untouched.
	overrideVar(t, &executablePath, func() (string, error) { return "/usr/local/bin/kontext", nil })
	if got, note := stableBinaryPath(); got != "/usr/local/bin/kontext" || note != "" {
		t.Fatalf("stableBinaryPath() = %q, %q", got, note)
	}

	// Cellar path with no matching stable symlink keeps the Cellar path and
	// warns about brew upgrades.
	overrideVar(t, &executablePath, func() (string, error) {
		return "/usr/local/Cellar/kontext/1.0.0/bin/kontext", nil
	})
	got, note := stableBinaryPath()
	if got != "/usr/local/Cellar/kontext/1.0.0/bin/kontext" || !strings.Contains(note, "brew upgrade") {
		t.Fatalf("stableBinaryPath() = %q, %q", got, note)
	}
}
