package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"

	"github.com/kontext-dev/kontext-cli/internal/agent"
	"github.com/kontext-dev/kontext-cli/internal/auth"
	"github.com/kontext-dev/kontext-cli/internal/hook"
	"github.com/kontext-dev/kontext-cli/internal/run"
	"github.com/kontext-dev/kontext-cli/internal/sidecar"
	"github.com/kontext-dev/kontext-cli/internal/update"

	// Register agent adapters
	_ "github.com/kontext-dev/kontext-cli/internal/agent/claude"
)

var version = "dev"

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

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func startCmd() *cobra.Command {
	var (
		agentName    string
		templateFile string
	)

	cmd := &cobra.Command{
		Use:   "start [flags] [-- extra-agent-args...]",
		Short: "Launch an agent with Kontext governance",
		RunE: func(cmd *cobra.Command, args []string) error {
			update.CheckAsync(version)
			ctx := context.Background()
			err := run.Start(ctx, run.Options{
				Agent:        agentName,
				TemplateFile: templateFile,
				IssuerURL:    auth.DefaultIssuerURL,
				ClientID:     auth.DefaultClientID,
				Args:         args,
			})
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return err
		},
	}

	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent to launch (currently: claude)")
	cmd.Flags().StringVar(&templateFile, "env-template", ".env.kontext", "Path to env template file")

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

			fmt.Fprintf(os.Stderr, "Logged in as %s (%s)\n", result.Session.User.Name, result.Session.User.Email)
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
	var agentName string

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

			socketPath := os.Getenv("KONTEXT_SOCKET")
			if socketPath == "" {
				// No sidecar — fail-open
				hook.Run(a, func(e *agent.HookEvent) (bool, string, error) {
					return true, "no sidecar", nil
				})
				return nil // unreachable
			}

			hook.Run(a, func(e *agent.HookEvent) (bool, string, error) {
				return evaluateViaSidecar(socketPath, agentName, e)
			})
			return nil // unreachable (hook.Run calls os.Exit)
		},
	}

	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent type")

	return cmd
}

func evaluateViaSidecar(socketPath, agentName string, e *agent.HookEvent) (bool, string, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		// Sidecar unreachable — fail-open
		return true, "sidecar unreachable", nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := sidecar.EvaluateRequest{
		Type:      "evaluate",
		Agent:     agentName,
		HookEvent: e.HookEventName,
		ToolName:  e.ToolName,
		ToolUseID: e.ToolUseID,
		CWD:       e.CWD,
	}

	// Marshal tool input/response to JSON
	if e.ToolInput != nil {
		data, _ := marshalJSON(e.ToolInput)
		req.ToolInput = data
	}
	if e.ToolResponse != nil {
		data, _ := marshalJSON(e.ToolResponse)
		req.ToolResponse = data
	}

	if err := sidecar.WriteMessage(conn, req); err != nil {
		return true, "sidecar write error", nil
	}

	var result sidecar.EvaluateResult
	if err := sidecar.ReadMessage(conn, &result); err != nil {
		return true, "sidecar read error", nil
	}

	return result.Allowed, result.Reason, nil
}

func marshalJSON(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}
