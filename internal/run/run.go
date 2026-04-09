// Package run implements the `kontext start` orchestrator.
package run

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cli/browser"

	agentv1 "github.com/kontext-dev/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-dev/kontext-cli/internal/agent"
	"github.com/kontext-dev/kontext-cli/internal/auth"
	"github.com/kontext-dev/kontext-cli/internal/backend"
	"github.com/kontext-dev/kontext-cli/internal/credential"
	"github.com/kontext-dev/kontext-cli/internal/sidecar"
)

// Options configures a kontext start run.
type Options struct {
	Agent        string
	TemplateFile string
	IssuerURL    string
	ClientID     string
	Args         []string
}

// Start is the main entry point for `kontext start`.
func Start(ctx context.Context, opts Options) error {
	if _, ok := agent.Get(opts.Agent); !ok {
		return fmt.Errorf("unsupported agent %q (supported: %s)", opts.Agent, strings.Join(supportedAgents(), ", "))
	}

	// 1. Auth
	session, err := ensureSession(ctx, opts.IssuerURL, opts.ClientID)
	if err != nil {
		return err
	}
	identity := session.User.Email
	if identity == "" {
		identity = session.User.Name
	}
	if identity == "" {
		identity = "authenticated"
	}
	fmt.Fprintf(os.Stderr, "✓ Authenticated as %s\n", identity)

	// 2. Backend client — token source refreshes automatically on expiry
	client := backend.NewClient(backend.BaseURL(), newSessionTokenSource(ctx, session))

	// 3. Create session via ConnectRPC
	hostname, _ := os.Hostname()
	cwd, _ := os.Getwd()
	createResp, err := client.CreateSession(ctx, &agentv1.CreateSessionRequest{
		UserId:   identity,
		Agent:    opts.Agent,
		Hostname: hostname,
		Cwd:      cwd,
		ClientInfo: map[string]string{
			"name": "kontext-cli",
			"os":   runtime.GOOS,
		},
	})
	if err != nil {
		return fmt.Errorf("create managed session: %w", err)
	}

	sessionID := createResp.SessionId
	fmt.Fprintf(os.Stderr, "✓ Session: %s (%s)\n", createResp.SessionName, truncateID(sessionID))

	// 4. Resolve credentials (before sidecar starts — no background goroutines yet,
	//    so reading session fields is safe without synchronization)
	var resolved []credential.Resolved
	if _, err := os.Stat(opts.TemplateFile); err == nil {
		entries, err := credential.ParseTemplate(opts.TemplateFile)
		if err != nil {
			return fmt.Errorf("parse template: %w", err)
		}
		if len(entries) > 0 {
			resolved, err = resolveCredentials(ctx, session, entries, opts.ClientID)
			if err != nil {
				return err
			}
		}
	}

	// 5. Start sidecar
	// Use /tmp (not $TMPDIR) with a short ID to keep the Unix socket path
	// under macOS's 104-byte sun_path limit.
	sessionDir := filepath.Join("/tmp", "kontext", truncateID(sessionID))
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	sc, err := sidecar.New(sessionDir, client, sessionID, opts.Agent)
	if err != nil {
		return fmt.Errorf("sidecar: %w", err)
	}
	if err := sc.Start(ctx); err != nil {
		return fmt.Errorf("sidecar start: %w", err)
	}
	defer sc.Stop()

	// 6. Generate hook settings
	kontextBin, _ := os.Executable()
	settingsPath, err := GenerateSettings(sessionDir, kontextBin, opts.Agent)
	if err != nil {
		return fmt.Errorf("generate settings: %w", err)
	}

	// 7. Build env
	env := buildEnv(resolved)
	env = append(env, "KONTEXT_SOCKET="+sc.SocketPath())
	env = append(env, "KONTEXT_SESSION_ID="+sessionID)

	// 8. Launch agent with hooks
	fmt.Fprintf(os.Stderr, "\nLaunching %s...\n\n", opts.Agent)
	agentErr := launchAgentWithSettings(ctx, opts.Agent, env, opts.Args, settingsPath)

	// 9. Teardown (always runs, even on non-zero agent exit)
	endCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = client.EndSession(endCtx, sessionID)
	fmt.Fprintf(os.Stderr, "\n✓ Session ended (%s)\n", truncateID(sessionID))

	os.RemoveAll(sessionDir)

	return agentErr
}

// ensureSession loads the session or triggers an interactive login.
func ensureSession(ctx context.Context, issuerURL, clientID string) (*auth.Session, error) {
	session, err := auth.Preflight(ctx)
	if err == nil {
		return session, nil
	}

	fmt.Fprintln(os.Stderr, "No session found. Opening browser to log in...")
	result, err := auth.Login(ctx, issuerURL, clientID)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	if err := auth.SaveSession(result.Session); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	return result.Session, nil
}

// resolveCredentials exchanges each template entry for a live credential.
func resolveCredentials(ctx context.Context, session *auth.Session, entries []credential.Entry, clientID string) ([]credential.Resolved, error) {
	fmt.Fprintln(os.Stderr, "\nResolving credentials...")
	var resolved []credential.Resolved

	for _, entry := range entries {
		fmt.Fprintf(os.Stderr, "  %s (%s)... ", entry.EnvVar, entry.Target())

		value, err := exchangeCredential(ctx, session, entry, clientID)
		if err != nil {
			if isNotConnectedError(err) {
				fmt.Fprintln(os.Stderr, "not connected")
				connectURL, connectErr := fetchConnectURL(ctx, session)
				if connectErr != nil {
					err = fmt.Errorf("create connect session: %w", connectErr)
				} else {
					fmt.Fprintf(os.Stderr, "  Opening browser to connect %s...\n", entry.Provider)
					fmt.Fprintf(os.Stderr, "  If the browser doesn't open, visit:\n    %s\n", connectURL)
					_ = browser.OpenURL(connectURL)
					fmt.Fprint(os.Stderr, "  Press Enter after connecting...")
					bufio.NewReader(os.Stdin).ReadString('\n')
					value, err = exchangeCredential(ctx, session, entry, clientID)
				}
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠ skipped (%v)\n", err)
				continue
			}
		}

		fmt.Fprintln(os.Stderr, "✓")
		resolved = append(resolved, credential.Resolved{Entry: entry, Value: value})
	}

	return resolved, nil
}

func fetchConnectURL(ctx context.Context, session *auth.Session) (string, error) {
	connectSessionURL := strings.TrimRight(session.IssuerURL, "/") + "/mcp/connect-session"

	req, err := http.NewRequestWithContext(ctx, "POST", connectSessionURL, strings.NewReader("{}"))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("connect session request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return "", fmt.Errorf("connect session request failed: %s", resp.Status)
		}

		msg := strings.TrimSpace(string(body))
		if msg == "" {
			return "", fmt.Errorf("connect session request failed: %s", resp.Status)
		}
		return "", fmt.Errorf("connect session request failed: %s: %s", resp.Status, msg)
	}

	var result struct {
		ConnectURL string `json:"connectUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode connect session response: %w", err)
	}
	if result.ConnectURL == "" {
		return "", fmt.Errorf("connect session response missing connectUrl")
	}

	return result.ConnectURL, nil
}

// exchangeCredential calls POST /oauth2/token with RFC 8693 token exchange
// to resolve a provider credential. The user's access token serves as both
// the subject_token and the Bearer auth — no client secret needed.
func exchangeCredential(ctx context.Context, session *auth.Session, entry credential.Entry, clientID string) (string, error) {
	meta, err := auth.DiscoverEndpoints(ctx, session.IssuerURL)
	if err != nil {
		return "", fmt.Errorf("oauth discovery: %w", err)
	}

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {clientID},
		"subject_token":      {session.AccessToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {entry.Target()},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ProviderKind string `json:"provider_kind"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode token exchange response: %w", err)
	}

	if result.Error != "" {
		if result.Error == "invalid_target" && strings.Contains(result.ErrorDesc, "not allowed") {
			return "", fmt.Errorf("provider not connected: %s", entry.Provider)
		}
		return "", fmt.Errorf("token exchange failed: %s: %s", result.Error, result.ErrorDesc)
	}

	if result.AccessToken == "" {
		return "", fmt.Errorf("token exchange returned empty access_token")
	}

	return result.AccessToken, nil
}

func isNotConnectedError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "not connected") ||
		strings.Contains(msg, "provider not found") ||
		strings.Contains(msg, "provider_reauthorization_required")
}

func buildEnv(resolved []credential.Resolved) []string {
	env := append(os.Environ(), "KONTEXT_RUN=1")
	return credential.BuildEnv(resolved, env)
}

func supportedAgents() []string {
	names := agent.Names()
	slices.Sort(names)
	return names
}

// newSessionTokenSource returns a TokenSource that transparently refreshes
// the OIDC access token when it expires, so long-running sessions keep working.
func newSessionTokenSource(ctx context.Context, session *auth.Session) backend.TokenSource {
	mu := &sync.Mutex{}
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()

		if !session.IsExpired() {
			return session.AccessToken, nil
		}

		refreshed, err := auth.RefreshSession(ctx, session)
		if err != nil {
			return "", fmt.Errorf("token expired and refresh failed: %w", err)
		}

		// Persist so other processes (and the next `kontext start`) see the new token
		if saveErr := auth.SaveSession(refreshed); saveErr != nil {
			fmt.Fprintf(os.Stderr, "⚠ Could not persist refreshed session: %v\n", saveErr)
		}

		// Update the shared session pointer for subsequent calls
		*session = *refreshed
		return session.AccessToken, nil
	}
}

func launchAgentWithSettings(_ context.Context, agentName string, env, extraArgs []string, settingsPath string) error {
	binaryPath, err := exec.LookPath(agentName)
	if err != nil {
		return fmt.Errorf("agent %q not found in PATH: %w", agentName, err)
	}

	var args []string
	if settingsPath != "" {
		args = append(args, "--settings", settingsPath)
	}
	args = append(args, filterArgs(extraArgs)...)

	cmd := exec.Command(binaryPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch %s: %w", agentName, err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	return err
}

// flagName extracts the flag name from an arg, handling --flag=value syntax.
func flagName(arg string) string {
	if i := strings.Index(arg, "="); i != -1 {
		return arg[:i]
	}
	return arg
}

func filterArgs(args []string) []string {
	blocked := map[string]bool{
		"--bare":                         true,
		"--dangerously-skip-permissions": true,
	}
	// Flags that take a value argument — strip the flag AND the next arg.
	blockedWithValue := map[string]bool{
		"--settings":        true,
		"--setting-sources": true,
	}

	var filtered []string
	skip := false
	for _, arg := range args {
		if skip {
			skip = false
			continue
		}
		name := flagName(arg)
		if blocked[name] {
			fmt.Fprintf(os.Stderr, "⚠ Stripped blocked flag: %s\n", arg)
			continue
		}
		if blockedWithValue[name] {
			fmt.Fprintf(os.Stderr, "⚠ Stripped blocked flag: %s\n", arg)
			if !strings.Contains(arg, "=") {
				skip = true // skip the next arg (the value)
			}
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

func truncateID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}
