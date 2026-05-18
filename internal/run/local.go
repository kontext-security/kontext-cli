package run

import (
	"context"
	"fmt"
	"os"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/runtimehost"
)

// StartLocal launches an agent with a wrapper-owned local runtime.
func StartLocal(ctx context.Context, opts Options) error {
	diagnostics := diagnostic.New(os.Stderr, opts.Verbose || diagnostic.EnabledFromEnv())
	diagnostics.Printf("start local: agent=%s\n", opts.Agent)

	preflight, err := preflightAgent(opts.Agent)
	if err != nil {
		return err
	}
	diagnostics.Printf("agent preflight: %s -> %s\n", preflight.Name, preflight.BinaryPath)

	mode, err := runtimehost.ResolveMode(os.Getenv("KONTEXT_MODE"))
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	host, err := runtimehost.Start(ctx, runtimehost.Options{
		AgentName:      preflight.Name,
		CWD:            cwd,
		DBPath:         os.Getenv("KONTEXT_DB"),
		ModelPath:      os.Getenv("KONTEXT_MODEL"),
		DashboardAddr:  os.Getenv("KONTEXT_ADDR"),
		StartDashboard: true,
		Mode:           string(mode),
		Diagnostic:     diagnostics,
		Out:            os.Stderr,
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

	launch, err := prepareLocalAgentLaunch(preflight.Agent, agent.LocalLaunchOptions{
		SessionDir:    host.SessionDir,
		KontextBinary: kontextBin,
		AgentName:     preflight.Name,
		SocketPath:    host.SocketPath,
		Mode:          string(host.Mode),
		BaseEnv:       os.Environ(),
		ExtraArgs:     opts.Args,
	})
	if err != nil {
		return err
	}

	env := append(launch.Env, "KONTEXT_RUN=1")
	env = append(env, "KONTEXT_SOCKET="+host.SocketPath)
	env = append(env, "KONTEXT_SESSION_ID="+host.SessionID)
	env = append(env, "KONTEXT_MODE="+string(host.Mode))

	fmt.Fprintf(os.Stderr, "✓ Local session: %s\n", truncateID(host.SessionID))
	if host.DashboardURL != "" {
		fmt.Fprintf(os.Stderr, "✓ Dashboard: %s\n", host.DashboardURL)
	}
	fmt.Fprintf(os.Stderr, "✓ Risk model: %s\n", host.ActiveModelPath)
	printLocalMode(os.Stderr, string(host.Mode))
	fmt.Fprintf(os.Stderr, "\nLaunching %s...\n\n", preflight.Name)

	return launchAgent(ctx, preflight.Name, preflight.BinaryPath, env, launch.Args)
}

func prepareLocalAgentLaunch(a agent.Agent, opts agent.LocalLaunchOptions) (agent.LocalLaunch, error) {
	opts.BaseEnv = append([]string{}, opts.BaseEnv...)
	opts.ExtraArgs = filterArgs(opts.ExtraArgs)

	if launcher, ok := a.(agent.LocalLauncher); ok {
		return launcher.PrepareLocalLaunch(opts)
	}
	if a.Name() != "claude" {
		return agent.LocalLaunch{}, fmt.Errorf("local launch unsupported for agent %q", a.Name())
	}

	settingsPath, err := GenerateLocalSettings(opts.SessionDir, opts.KontextBinary, a.Name(), opts.SocketPath, opts.Mode)
	if err != nil {
		return agent.LocalLaunch{}, fmt.Errorf("generate Claude settings: %w", err)
	}
	args := append([]string{"--settings", settingsPath}, opts.ExtraArgs...)
	return agent.LocalLaunch{Env: opts.BaseEnv, Args: args}, nil
}

func printLocalMode(out *os.File, mode string) {
	if mode == "enforce" {
		fmt.Fprintln(out, "Mode: enforce (ask and deny decisions block supported pre-tool actions).")
		return
	}
	fmt.Fprintln(out, "Mode: observe (agent actions run normally; decisions are recorded as would allow / would ask / would deny).")
}
