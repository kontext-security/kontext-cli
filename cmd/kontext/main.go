package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/auth"
	guardcli "github.com/kontext-security/kontext-cli/internal/guard/cli"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/hookcmd"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/run"
	"github.com/kontext-security/kontext-cli/internal/update"

	_ "github.com/kontext-security/kontext-cli/internal/agent/claude"
)

var version = "dev"

var (
	startLocal   = run.StartLocal
	startManaged = run.StartManaged
)

func main() {
	root := &cobra.Command{
		Use:     "kontext",
		Short:   "Kontext CLI — governed agent sessions",
		Version: version,
	}

	root.AddCommand(startCmd())
	root.AddCommand(loginCmd())
	root.AddCommand(logoutCmd())
	root.AddCommand(hookCmd())
	root.AddCommand(doctorCmd())
	root.AddCommand(guardCmd())
	root.AddCommand(statusCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type statusReport struct {
	ManagedState     managedconfig.State       `json:"managed_state"`
	OrganizationID   string                    `json:"organization_id,omitempty"`
	InstallationID   string                    `json:"installation_id,omitempty"`
	CloudURL         string                    `json:"cloud_url,omitempty"`
	Mode             string                    `json:"mode,omitempty"`
	Agent            string                    `json:"agent,omitempty"`
	CredentialSource string                    `json:"credential_source,omitempty"`
	ConfigSource     managedconfig.Source      `json:"config_source"`
	Validation       statusValidation          `json:"validation"`
	Installation     statusInstallationSummary `json:"installation"`
}

type statusValidation struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type statusInstallationSummary struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Error  string `json:"error,omitempty"`
}

func statusCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show managed enrollment status",
		RunE: func(cmd *cobra.Command, args []string) error {
			report := buildStatusReport(time.Now())
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			printStatusReport(cmd.OutOrStdout(), report)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print status as JSON")
	return cmd
}

func buildStatusReport(now time.Time) statusReport {
	managed := managedconfig.LoadDefault(now)
	installPath := installation.PathFromEnv()
	record, exists, installErr := installation.Load(installPath)

	report := statusReport{
		ManagedState: managed.State,
		ConfigSource: managed.Source,
		Validation: statusValidation{
			OK:    managed.State != managedconfig.StateManagedInvalid,
			Error: managed.Error,
		},
		Installation: statusInstallationSummary{
			Path:   installPath,
			Exists: exists,
		},
	}
	if installErr != nil {
		report.Installation.Error = installErr.Error()
	} else if exists {
		report.InstallationID = record.InstallationID
	}
	if managed.Config != nil {
		report.OrganizationID = managed.Config.OrganizationID
		report.CloudURL = managed.Config.CloudURL
		report.Mode = managed.Config.Mode
		report.Agent = managed.Config.Agent
		report.CredentialSource = managedconfig.RedactTokenRef(managed.Config.Credentials.InstallTokenRef)
	}
	return report
}

func printStatusReport(out io.Writer, report statusReport) {
	fmt.Fprintf(out, "Managed state: %s\n", report.ManagedState)
	if report.OrganizationID != "" {
		fmt.Fprintf(out, "Organization ID: %s\n", report.OrganizationID)
	}
	if report.InstallationID != "" {
		fmt.Fprintf(out, "Installation ID: %s\n", report.InstallationID)
	} else if report.Installation.Error != "" {
		fmt.Fprintf(out, "Installation ID: invalid (%s)\n", report.Installation.Error)
	} else {
		fmt.Fprintln(out, "Installation ID: not present")
	}
	if report.CloudURL != "" {
		fmt.Fprintf(out, "Cloud URL: %s\n", report.CloudURL)
	}
	if report.Mode != "" {
		fmt.Fprintf(out, "Mode: %s\n", report.Mode)
	}
	if report.Agent != "" {
		fmt.Fprintf(out, "Agent: %s\n", report.Agent)
	}
	if report.CredentialSource != "" {
		fmt.Fprintf(out, "Credential source: %s\n", report.CredentialSource)
	}
	fmt.Fprintf(out, "Config source: %s\n", report.ConfigSource.Path)
	if report.ConfigSource.Checksum != "" {
		fmt.Fprintf(out, "Config checksum: %s\n", report.ConfigSource.Checksum)
	}
	fmt.Fprintf(out, "Config loaded at: %s\n", report.ConfigSource.LoadedAt.Format(time.RFC3339))
	if report.Validation.OK {
		fmt.Fprintln(out, "Validation: ok")
	} else {
		fmt.Fprintf(out, "Validation: invalid (%s)\n", report.Validation.Error)
	}
}

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Inspect local Kontext CLI setup",
		RunE: func(cmd *cobra.Command, args []string) error {
			guardcli.PrintHookStatus(cmd.OutOrStdout())
			return nil
		},
	}
}

func guardCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "guard",
		Short:              "Run local-only Kontext Guard mode",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return guardcli.Run(context.Background(), args, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
}

func startCmd() *cobra.Command {
	var (
		agentName    string
		templateFile string
		managed      bool
		verbose      bool
	)

	cmd := &cobra.Command{
		Use:   "start [flags] [-- extra-agent-args...]",
		Short: "Launch an agent with Kontext runtime security",
		Long: "Launch an agent with Kontext runtime security.\n\n" +
			"By default, this starts a local-only runtime with no hosted login. " +
			"Use --managed when you need hosted credentials, shared traces, and team governance.",
		Example: "  kontext start\n" +
			"  KONTEXT_MODE=enforce kontext start\n" +
			"  kontext start --managed",
		RunE: func(cmd *cobra.Command, args []string) error {
			if isInteractivePrompt() {
				if latest := update.Available(version); latest != "" {
					upgraded, _ := update.PromptAndUpgrade(os.Stdin, os.Stderr, version, latest)
					if upgraded {
						return nil
					}
				}
			} else {
				update.CheckAsync(version)
			}
			if !managed && cmd.Flags().Changed("env-template") {
				return errors.New("--env-template is only used with --managed sessions")
			}
			ctx := context.Background()
			opts := run.Options{
				Agent:        agentName,
				TemplateFile: templateFile,
				IssuerURL:    auth.DefaultIssuerURL,
				ClientID:     auth.DefaultClientID,
				Verbose:      verbose,
				Args:         args,
			}
			var err error
			if managed {
				err = startManaged(ctx, opts)
			} else {
				err = startLocal(ctx, opts)
			}
			if exitErr, ok := err.(*run.AgentExitError); ok {
				fmt.Fprintf(os.Stderr, "Error: %v\n", exitErr)
				os.Exit(exitErr.ExitCode())
			}
			return err
		},
	}

	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent to launch (currently: claude)")
	cmd.Flags().StringVar(&templateFile, "env-template", ".env.kontext", "Path to env template file for --managed sessions")
	cmd.Flags().BoolVar(&managed, "managed", false, "Launch with hosted managed credentials and shared traces")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show redacted diagnostic output")

	return cmd
}

func loginCmd() *cobra.Command {
	var issuerURL, clientID string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Kontext via browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			result, err := auth.Login(ctx, issuerURL, clientID)
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			if err := auth.SaveSession(result.Session); err != nil {
				return fmt.Errorf("save session: %w", err)
			}

			if display := result.Session.DisplayIdentity(); display != "" {
				fmt.Fprintf(os.Stderr, "Logged in as %s\n", display)
			} else {
				fmt.Fprintln(os.Stderr, "Logged in.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&issuerURL, "issuer-url", auth.DefaultIssuerURL, "OIDC issuer URL")
	cmd.Flags().StringVar(&clientID, "client-id", auth.DefaultClientID, "OAuth client ID")

	return cmd
}

func logoutCmd() *cobra.Command {
	return newLogoutCmd(auth.ClearSession)
}

func newLogoutCmd(clearSession func() error) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out and clear stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := clearSession(); err != nil {
				if errors.Is(err, keyring.ErrNotFound) {
					return errors.New("already logged out")
				}
				return fmt.Errorf("logout failed: %w", err)
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Logged out successfully.")
			return nil
		},
	}
}

func hookCmd() *cobra.Command {
	var (
		agentName  string
		socketPath string
		mode       string
	)

	cmd := &cobra.Command{
		Use:    "hook",
		Short:  "Process a hook event (called by the agent, not by users)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, ok := agent.Get(agentName)
			if !ok {
				fmt.Fprintf(os.Stderr, "unknown agent: %s\n", agentName)
				os.Exit(2)
			}

			resolvedSocketPath := resolveHookSocketPath(socketPath)
			if mode != "" {
				hookMode, err := guardhookruntime.ParseMode(mode)
				if err != nil {
					return err
				}
				adapter := guardhookruntime.AgentAdapter{Agent: a, AgentName: agentName}
				processor := rootHookProcessor{socketPath: resolvedSocketPath, mode: hookMode}
				return guardhookruntime.Run(context.Background(), adapter, processor, hookMode, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
			}
			hookcmd.Run(a, func(e hook.Event) (hook.Result, error) {
				return evaluateHookWithSidecar(resolvedSocketPath, e)
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent type")
	cmd.Flags().StringVar(&socketPath, "socket", "", "Unix socket path for local hook runtime")
	cmd.Flags().StringVar(&mode, "mode", "", "hook mode: observe or enforce")

	return cmd
}

type rootHookProcessor struct {
	socketPath string
	mode       guardhookruntime.Mode
}

func (p rootHookProcessor) Process(_ context.Context, event hook.Event) (hook.Result, error) {
	return evaluateHookWithSidecarForMode(p.socketPath, event, string(p.mode))
}

func resolveHookSocketPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if socketPath := os.Getenv("KONTEXT_SOCKET"); socketPath != "" {
		return socketPath
	}
	return localruntime.DefaultSocketPath()
}

func evaluateHookWithSidecar(socketPath string, event hook.Event) (hook.Result, error) {
	return evaluateHookWithSidecarForMode(socketPath, event, "")
}

func evaluateHookWithSidecarForMode(socketPath string, event hook.Event, mode string) (hook.Result, error) {
	if socketPath == "" {
		return sidecarFailureResult(event, "sidecar socket missing", mode), nil
	}
	return evaluateViaSidecarForMode(socketPath, event, mode)
}

func evaluateViaSidecar(socketPath string, event hook.Event) (hook.Result, error) {
	return evaluateViaSidecarForMode(socketPath, event, "")
}

func evaluateViaSidecarForMode(socketPath string, event hook.Event, mode string) (hook.Result, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return sidecarFailureResult(event, "sidecar unreachable", mode), nil
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return sidecarFailureResult(event, "sidecar deadline error", mode), nil
	}

	req, err := localruntime.EvaluateRequestFromEvent(event)
	if err != nil {
		return sidecarFailureResult(event, "sidecar marshal error", mode), nil
	}

	if err := localruntime.WriteMessage(conn, req); err != nil {
		return sidecarFailureResult(event, "sidecar write error", mode), nil
	}

	var result localruntime.EvaluateResult
	if err := localruntime.ReadMessage(conn, &result); err != nil {
		return sidecarFailureResult(event, "sidecar read error", mode), nil
	}

	return localruntime.ResultFromEvaluateResult(result), nil
}

func sidecarFailureResult(event hook.Event, reason, mode string) hook.Result {
	if event.HookName != hook.HookPreToolUse {
		return hook.Result{Decision: hook.DecisionAllow, Reason: reason}
	}
	if hookMode := normalizedHookMode(mode); hookMode != "" {
		if hookMode != "enforce" {
			return hook.Result{Decision: hook.DecisionAllow, Reason: reason, Mode: hookMode}
		}
		return hook.Result{Decision: hook.DecisionDeny, Reason: reason, Mode: "enforce"}
	}
	if currentHostedAccessMode() == "enforce" {
		return hook.Result{Decision: hook.DecisionDeny, Reason: reason, Mode: "enforce"}
	}
	return hook.Result{Decision: hook.DecisionAllow, Reason: reason}
}

func normalizedHookMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "observe", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func currentHostedAccessMode() string {
	if modePath := os.Getenv("KONTEXT_ACCESS_MODE_PATH"); modePath != "" {
		data, err := os.ReadFile(modePath)
		if err != nil {
			return "enforce"
		}
		if mode := normalizedHostedAccessMode(string(data)); mode != "" {
			return mode
		}
		return "enforce"
	}
	return normalizedHostedAccessMode(os.Getenv("KONTEXT_ACCESS_MODE"))
}

func normalizedHostedAccessMode(value string) string {
	mode := strings.TrimSpace(value)
	if mode == "disabled" || mode == "no_policy" {
		return mode
	}
	if mode == "enforce" {
		return "enforce"
	}
	return ""
}

// isInteractivePrompt reports whether both stdin (where the answer is read)
// and stderr (where the prompt is written) are terminals. If either is
// redirected, the user cannot meaningfully answer the prompt, so we fall
// back to a background update check.
func isInteractivePrompt() bool {
	return isCharDevice(os.Stdin) && isCharDevice(os.Stderr)
}

func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
