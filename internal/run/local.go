package run

import (
	"context"
	"fmt"
	"os"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/runtimehost"
)

// StartLocal launches an agent with a wrapper-owned local runtime.
func StartLocal(ctx context.Context, opts Options) error {
	diagnostics := diagnostic.New(os.Stderr, opts.Verbose || diagnostic.EnabledFromEnv())
	diagnostics.Printf("start local: agent=%s\n", opts.Agent)

	agentPath, err := preflightAgent(opts.Agent)
	if err != nil {
		return err
	}
	diagnostics.Printf("agent preflight: %s -> %s\n", opts.Agent, agentPath)

	mode, err := runtimehost.ResolveMode(os.Getenv("KONTEXT_MODE"))
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	host, err := runtimehost.Start(ctx, runtimehost.Options{
		AgentName:           opts.Agent,
		CWD:                 cwd,
		DBPath:              os.Getenv("KONTEXT_DB"),
		ModelPath:           os.Getenv("KONTEXT_MODEL"),
		DashboardAddr:       os.Getenv("KONTEXT_ADDR"),
		StartDashboard:      true,
		JudgeConfigFromEnv:  true,
		JudgeManagedDefault: true,
		Mode:                string(mode),
		Diagnostic:          diagnostics,
		Out:                 os.Stderr,
	})
	if err != nil {
		return err
	}
	defer func() {
		_ = host.Close(context.Background())
	}()

	kontextBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve kontext executable: %w", err)
	}
	settingsPath, err := GenerateLocalSettings(host.SessionDir, kontextBin, opts.Agent, host.SocketPath, string(host.Mode))
	if err != nil {
		return fmt.Errorf("generate settings: %w", err)
	}

	env := append(os.Environ(), "KONTEXT_RUN=1")
	env = append(env, "KONTEXT_SOCKET="+host.SocketPath)
	env = append(env, "KONTEXT_SESSION_ID="+host.SessionID)
	env = append(env, "KONTEXT_MODE="+string(host.Mode))

	fmt.Fprintf(os.Stderr, "✓ Local session: %s\n", truncateID(host.SessionID))
	if host.DashboardURL != "" {
		fmt.Fprintf(os.Stderr, "✓ Dashboard: %s\n", host.DashboardURL)
	}
	fmt.Fprintf(os.Stderr, "✓ Risk model: %s\n", host.ActiveModelPath)
	if host.LocalJudgeStatus != "" {
		fmt.Fprintf(os.Stderr, "✓ Local judge: %s\n", host.LocalJudgeStatus)
	} else {
		fmt.Fprintln(os.Stderr, "✓ Local judge: disabled")
	}
	printLocalMode(os.Stderr, string(host.Mode))
	fmt.Fprintf(os.Stderr, "\nLaunching %s...\n\n", opts.Agent)

	return launchAgentWithSettings(ctx, opts.Agent, agentPath, env, opts.Args, settingsPath)
}

func printLocalMode(out *os.File, mode string) {
	if mode == "enforce" {
		fmt.Fprintln(out, "Mode: enforce (ask and deny decisions block supported pre-tool actions).")
		return
	}
	fmt.Fprintln(out, "Mode: observe (agent actions run normally; decisions are recorded as would allow / would ask / would deny).")
}
