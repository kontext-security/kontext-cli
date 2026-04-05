// Package run implements the `kontext start` orchestrator.
// It handles the full lifecycle: auth → init → credentials → sidecar → subprocess → cleanup.
package run

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cli/browser"

	"github.com/kontext-dev/kontext-cli/internal/auth"
	"github.com/kontext-dev/kontext-cli/internal/credential"
)

// Options configures a kontext start run.
type Options struct {
	Agent        string
	TemplateFile string
	IssuerURL    string
	ClientID     string
	Args         []string // extra args to pass to the agent
}

// Start is the main entry point for `kontext start`.
func Start(ctx context.Context, opts Options) error {
	// 1. Auth — login inline if no session
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

	// 2. Ensure env template exists (create interactively on first run)
	templatePath := opts.TemplateFile
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		if err := initTemplate(templatePath); err != nil {
			return err
		}
	}

	// 3. Parse template and resolve credentials
	var resolved []credential.Resolved
	entries, err := credential.ParseTemplate(templatePath)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	if len(entries) > 0 {
		resolved, err = resolveCredentials(ctx, session, entries)
		if err != nil {
			return err
		}
	}

	// 5. Build environment
	env := buildEnv(resolved)

	// 6. Launch agent
	fmt.Fprintf(os.Stderr, "\nLaunching %s...\n\n", opts.Agent)
	return launchAgent(ctx, opts.Agent, env, opts.Args)
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
		// Write an empty template so it doesn't prompt again
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
	if len(entries) == 0 {
		return nil, nil
	}

	fmt.Fprintln(os.Stderr, "\nResolving credentials...")
	var resolved []credential.Resolved

	for _, entry := range entries {
		fmt.Fprintf(os.Stderr, "  %s (%s)... ", entry.EnvVar, entry.Provider)

		value, err := exchangeCredential(ctx, session, entry)
		if err != nil {
			// Check if this is a "not connected" error — prompt to connect
			if isNotConnectedError(err) {
				fmt.Fprintln(os.Stderr, "not connected")
				fmt.Fprintf(os.Stderr, "  Opening browser to connect %s...\n", entry.Provider)

				connectURL := fmt.Sprintf("%s/connect/%s", auth.DefaultIssuerURL, entry.Provider)
				_ = browser.OpenURL(connectURL)

				fmt.Fprint(os.Stderr, "  Press Enter after connecting...")
				bufio.NewReader(os.Stdin).ReadString('\n')

				// Retry
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

// exchangeCredential calls the Kontext backend to resolve a single credential.
// TODO: Replace with actual gRPC ExchangeCredential call.
func exchangeCredential(_ context.Context, _ *auth.Session, _ credential.Entry) (string, error) {
	// Placeholder — will be wired to gRPC ExchangeCredential RPC
	return "", fmt.Errorf("credential exchange not yet connected to backend")
}

func isNotConnectedError(err error) bool {
	return strings.Contains(err.Error(), "not connected") ||
		strings.Contains(err.Error(), "provider not found")
}

// buildEnv constructs the environment for the agent subprocess.
func buildEnv(resolved []credential.Resolved) []string {
	// Pass through the parent environment + add Kontext session indicator +
	// overlay resolved credentials. In the future, this should be tightened
	// to a minimal allowlist to prevent leaking existing secrets.
	env := append(os.Environ(), "KONTEXT_RUN=1")
	return credential.BuildEnv(resolved, env)
}

// launchAgent spawns the agent as a subprocess with the given environment.
func launchAgent(_ context.Context, agentName string, env []string, extraArgs []string) error {
	binary, err := exec.LookPath(agentName)
	if err != nil {
		return fmt.Errorf("agent %q not found in PATH: %w", agentName, err)
	}

	// Filter out dangerous flags that could bypass governance
	filtered := filterArgs(extraArgs)

	cmd := exec.Command(binary, filtered...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	// Set process group for clean signal forwarding
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch %s: %w", agentName, err)
	}

	// Forward signals
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

// filterArgs removes flags that could bypass governance.
func filterArgs(args []string) []string {
	blocked := map[string]bool{
		"--bare":                          true,
		"--dangerously-skip-permissions":  true,
		"--settings":                      true,
		"--setting-sources":               true,
	}

	var filtered []string
	skip := false
	for _, arg := range args {
		if skip {
			skip = false
			continue
		}
		if blocked[arg] {
			fmt.Fprintf(os.Stderr, "⚠ Stripped blocked flag: %s\n", arg)
			// If this flag takes a value, skip the next arg too
			if arg == "--settings" || arg == "--setting-sources" {
				skip = true
			}
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}
