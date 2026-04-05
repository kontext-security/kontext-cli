package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kontext-dev/kontext-cli/internal/auth"

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
	root.AddCommand(hookCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func startCmd() *cobra.Command {
	var (
		agentName    string
		user         string
		templateFile string
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Launch an agent with Kontext governance",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stderr, "kontext start --agent %s (not yet implemented)\n", agentName)
			// TODO:
			// 1. Load session from keyring
			// 2. Connect to backend via gRPC (CreateSession)
			// 3. Parse env template, resolve credentials (ExchangeCredential)
			// 4. Start sidecar on Unix socket
			// 5. Generate agent hook config pointing to `kontext hook`
			// 6. Launch agent subprocess with injected env
			// 7. Stream hook events via sidecar → backend (ProcessHookEvent)
			// 8. On exit: EndSession, cleanup
			return nil
		},
	}

	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent to launch (claude, cursor, codex)")
	cmd.Flags().StringVar(&user, "user", "", "Developer identity (email)")
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

func hookCmd() *cobra.Command {
	var agentName string

	cmd := &cobra.Command{
		Use:    "hook",
		Short:  "Process a hook event (called by the agent, not by users)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stderr, "kontext hook (not yet implemented)")
			// TODO:
			// 1. Read stdin (hook event JSON)
			// 2. Connect to sidecar via KONTEXT_SOCKET
			// 3. Send event, receive decision
			// 4. Write decision to stdout, exit with appropriate code
			return nil
		},
	}

	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent type")

	return cmd
}
