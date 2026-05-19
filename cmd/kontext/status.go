package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
)

const managedConfigEnv = "KONTEXT_MANAGED_CONFIG"

type statusPayload struct {
	Managed managedStatus `json:"managed"`
}

type managedStatus struct {
	State             managedconfig.StateKind `json:"state"`
	StreamingEnabled  bool                    `json:"streaming_enabled,omitempty"`
	OrganizationID    string                  `json:"organization_id,omitempty"`
	InstallationID    string                  `json:"installation_id,omitempty"`
	CloudURL          string                  `json:"cloud_url,omitempty"`
	Mode              string                  `json:"mode,omitempty"`
	Agent             string                  `json:"agent,omitempty"`
	CredentialSource  string                  `json:"credential_source,omitempty"`
	Config            *statusConfig           `json:"config,omitempty"`
	InstallationState *statusInstallation     `json:"installation,omitempty"`
	Validation        statusValidation        `json:"validation"`
}

type statusConfig struct {
	Source     string `json:"source,omitempty"`
	SourceKind string `json:"source_kind,omitempty"`
	Checksum   string `json:"checksum,omitempty"`
	LoadedAt   string `json:"loaded_at,omitempty"`
}

type statusInstallation struct {
	Source string `json:"source,omitempty"`
}

type statusValidation struct {
	Status string                          `json:"status"`
	Errors []managedconfig.ValidationError `json:"errors"`
}

func statusCmd() *cobra.Command {
	var (
		jsonOutput       bool
		managedPath      string
		installationPath string
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show local Kontext enrollment status",
		RunE: func(cmd *cobra.Command, args []string) error {
			configSource := managedconfig.SourceFile
			if managedPath == "" {
				if envPath := os.Getenv(managedConfigEnv); envPath != "" {
					managedPath = envPath
					configSource = managedconfig.SourceEnvOverride
				}
			}
			payload := buildStatus(context.Background(), managedPath, configSource, installationPath)
			if jsonOutput {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(payload)
			}
			printStatus(cmd.OutOrStdout(), payload)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print status as JSON")
	cmd.Flags().StringVar(&managedPath, "managed-config", "", "Path to managed config file")
	cmd.Flags().StringVar(&installationPath, "installation-state", "", "Path to installation state file")
	_ = cmd.Flags().MarkHidden("managed-config")
	_ = cmd.Flags().MarkHidden("installation-state")
	return cmd
}

func buildStatus(ctx context.Context, managedPath string, sourceKind managedconfig.SourceKind, installationPath string) statusPayload {
	state := managedconfig.Load(ctx, managedconfig.Options{Path: managedPath, SourceKind: sourceKind})
	status := managedStatus{
		State: state.Kind,
		Config: &statusConfig{
			Source:     state.SourcePath,
			SourceKind: string(state.SourceKind),
			Checksum:   state.Checksum,
			LoadedAt:   state.LoadedAt.Format("2006-01-02T15:04:05Z07:00"),
		},
		Validation: statusValidation{Status: "ok", Errors: []managedconfig.ValidationError{}},
	}
	switch state.Kind {
	case managedconfig.StateUnmanaged:
		status.Config = nil
		status.Validation.Status = "not_configured"
	case managedconfig.StateManagedInvalid:
		status.StreamingEnabled = false
		status.Validation.Status = "invalid"
		status.Validation.Errors = append([]managedconfig.ValidationError(nil), state.Errors...)
		fillConfigFields(&status, state)
	case managedconfig.StateManagedActive:
		fillConfigFields(&status, state)
		instPath := installationPath
		if instPath == "" {
			instPath = installation.DefaultPath()
		}
		status.InstallationState = &statusInstallation{Source: instPath}
		inst, err := installation.Load(instPath)
		if err != nil {
			status.State = managedconfig.StateManagedInvalid
			status.StreamingEnabled = false
			status.Validation.Status = "invalid"
			status.Validation.Errors = []managedconfig.ValidationError{{
				Code:    "installation_state_invalid",
				Field:   "installation",
				Message: err.Error(),
			}}
			break
		}
		status.StreamingEnabled = true
		status.InstallationID = inst.InstallationID
	}
	return statusPayload{Managed: status}
}

func fillConfigFields(status *managedStatus, state managedconfig.State) {
	status.OrganizationID = state.Config.OrganizationID
	status.CloudURL = state.Config.CloudURL
	status.Mode = state.Config.Mode
	status.Agent = state.Config.Agent
	status.CredentialSource = managedconfig.RedactCredentialRef(state.Config.Credentials.InstallTokenRef)
}

func printStatus(w io.Writer, payload statusPayload) {
	managed := payload.Managed
	switch managed.State {
	case managedconfig.StateUnmanaged:
		fmt.Fprintln(w, "Managed endpoint: unmanaged")
		return
	case managedconfig.StateManagedActive:
		fmt.Fprintln(w, "Managed endpoint: active")
	case managedconfig.StateManagedInvalid:
		fmt.Fprintln(w, "Managed endpoint: invalid")
	default:
		fmt.Fprintf(w, "Managed endpoint: %s\n", managed.State)
	}
	if managed.OrganizationID != "" {
		fmt.Fprintf(w, "Organization: %s\n", managed.OrganizationID)
	}
	if managed.InstallationID != "" {
		fmt.Fprintf(w, "Installation ID: %s\n", managed.InstallationID)
	}
	if managed.CloudURL != "" {
		fmt.Fprintf(w, "Cloud URL: %s\n", managed.CloudURL)
	}
	if managed.Mode != "" {
		fmt.Fprintf(w, "Mode: %s\n", managed.Mode)
	}
	if managed.Agent != "" {
		fmt.Fprintf(w, "Agent: %s\n", managed.Agent)
	}
	if managed.CredentialSource != "" {
		fmt.Fprintf(w, "Credential: %s\n", managed.CredentialSource)
	}
	if managed.Config != nil {
		fmt.Fprintf(w, "Config source: %s\n", managed.Config.Source)
		if managed.Config.Checksum != "" {
			fmt.Fprintf(w, "Config checksum: %s\n", managed.Config.Checksum)
		}
		if managed.Config.LoadedAt != "" {
			fmt.Fprintf(w, "Loaded at: %s\n", managed.Config.LoadedAt)
		}
	}
	if managed.Validation.Status == "ok" {
		fmt.Fprintln(w, "Validation: ok")
		return
	}
	if len(managed.Validation.Errors) > 0 {
		fmt.Fprintln(w, "Validation:")
		for _, err := range managed.Validation.Errors {
			fmt.Fprintf(w, "- %s: %s\n", err.Code, err.Message)
		}
	}
}
