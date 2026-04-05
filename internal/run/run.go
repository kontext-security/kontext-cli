// Package run implements the `kontext start` orchestrator.
package run

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cli/browser"
	"github.com/google/uuid"

	agentv1 "github.com/kontext-dev/kontext-cli/gen/kontext/agent/v1"
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

	// 2. Backend client (native ConnectRPC)
	backendCfg, err := backend.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ Backend not configured: %v\n", err)
		fmt.Fprintln(os.Stderr, "  Launching without telemetry (set KONTEXT_CLIENT_ID + KONTEXT_CLIENT_SECRET)")
		return launchAgentDirect(ctx, opts)
	}
	client := backend.NewClient(backendCfg)

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
			"os":   fmt.Sprintf("%s", os.Getenv("GOOS")),
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ Session creation failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "  Launching without telemetry")
		return launchAgentDirect(ctx, opts)
	}

	sessionID := createResp.SessionId
	fmt.Fprintf(os.Stderr, "✓ Session: %s (%s)\n", createResp.SessionName, sessionID[:8])

	traceID := uuid.New().String()

	// 4. Start sidecar
	sessionDir := filepath.Join(os.TempDir(), "kontext", sessionID)
	os.MkdirAll(sessionDir, 0700)

	sc, err := sidecar.New(sessionDir, client, sessionID, traceID, opts.Agent)
	if err != nil {
		return fmt.Errorf("sidecar: %w", err)
	}
	if err := sc.Start(ctx); err != nil {
		return fmt.Errorf("sidecar start: %w", err)
	}
	defer sc.Stop()

	// 5. Generate hook settings
	kontextBin, _ := os.Executable()
	settingsPath, err := GenerateSettings(sessionDir, kontextBin, opts.Agent)
	if err != nil {
		return fmt.Errorf("generate settings: %w", err)
	}

	// 6. Env template + credentials (optional)
	var resolved []credential.Resolved
	if _, err := os.Stat(opts.TemplateFile); err == nil {
		entries, err := credential.ParseTemplate(opts.TemplateFile)
		if err != nil {
			return fmt.Errorf("parse template: %w", err)
		}
		if len(entries) > 0 {
			resolved, err = resolveCredentials(ctx, session, entries)
			if err != nil {
				return err
			}
		}
	}

	// 7. Build env
	env := buildEnv(resolved)
	env = append(env, "KONTEXT_SOCKET="+sc.SocketPath())
	env = append(env, "KONTEXT_SESSION_ID="+sessionID)

	// 8. Launch agent with hooks
	fmt.Fprintf(os.Stderr, "\nLaunching %s...\n\n", opts.Agent)
	startTime := time.Now()
	agentErr := launchAgentWithSettings(ctx, opts.Agent, env, opts.Args, settingsPath)

	// 9. Teardown
	_ = time.Since(startTime)
	endCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = client.EndSession(endCtx, sessionID)
	fmt.Fprintf(os.Stderr, "\n✓ Session ended (%s)\n", sessionID[:8])

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

// initTemplate interactively creates a .env.kontext on first run.
func initTemplate(path string) error {
	providers := []struct {
		Name   string
		EnvVar string
		Handle string
	}{
		{"GitHub", "GITHUB_TOKEN", "github"},
		{"Google Workspace", "GOOGLE_TOKEN", "google-workspace"},
		{"Stripe", "STRIPE_KEY", "stripe"},
		{"Linear", "LINEAR_API_KEY", "linear"},
		{"Slack", "SLACK_TOKEN", "slack"},
		{"PostgreSQL", "DATABASE_URL", "postgres"},
	}

	fmt.Fprintln(os.Stderr, "\nNo .env.kontext found. Which providers does this project need?")
	reader := bufio.NewReader(os.Stdin)

	var lines []string
	for _, p := range providers {
		fmt.Fprintf(os.Stderr, "  %s? [y/N] ", p.Name)
		input, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(input)) == "y" {
			lines = append(lines, fmt.Sprintf("%s={{kontext:%s}}", p.EnvVar, p.Handle))
		}
	}

	if len(lines) == 0 {
		lines = append(lines, "# Add providers: VAR_NAME={{kontext:provider-handle}}")
	}

	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "✓ Wrote %s\n\n", path)
	return nil
}

// resolveCredentials exchanges each template entry for a live credential.
func resolveCredentials(ctx context.Context, session *auth.Session, entries []credential.Entry) ([]credential.Resolved, error) {
	fmt.Fprintln(os.Stderr, "\nResolving credentials...")
	var resolved []credential.Resolved

	for _, entry := range entries {
		fmt.Fprintf(os.Stderr, "  %s (%s)... ", entry.EnvVar, entry.Provider)

		value, err := exchangeCredential(ctx, session, entry)
		if err != nil {
			if isNotConnectedError(err) {
				fmt.Fprintln(os.Stderr, "not connected")
				fmt.Fprintf(os.Stderr, "  Opening browser to connect %s...\n", entry.Provider)
				connectURL := fmt.Sprintf("%s/connect/%s", auth.DefaultIssuerURL, entry.Provider)
				_ = browser.OpenURL(connectURL)
				fmt.Fprint(os.Stderr, "  Press Enter after connecting...")
				bufio.NewReader(os.Stdin).ReadString('\n')
				value, err = exchangeCredential(ctx, session, entry)
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

func exchangeCredential(_ context.Context, _ *auth.Session, _ credential.Entry) (string, error) {
	return "", fmt.Errorf("credential exchange not yet connected to backend")
}

func isNotConnectedError(err error) bool {
	return strings.Contains(err.Error(), "not connected") ||
		strings.Contains(err.Error(), "provider not found")
}

func buildEnv(resolved []credential.Resolved) []string {
	env := append(os.Environ(), "KONTEXT_RUN=1")
	return credential.BuildEnv(resolved, env)
}

func launchAgentDirect(ctx context.Context, opts Options) error {
	fmt.Fprintf(os.Stderr, "\nLaunching %s...\n\n", opts.Agent)
	return launchAgentWithSettings(ctx, opts.Agent, os.Environ(), opts.Args, "")
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

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func filterArgs(args []string) []string {
	blocked := map[string]bool{
		"--bare":                         true,
		"--dangerously-skip-permissions": true,
	}

	var filtered []string
	for _, arg := range args {
		if blocked[arg] {
			fmt.Fprintf(os.Stderr, "⚠ Stripped blocked flag: %s\n", arg)
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}
