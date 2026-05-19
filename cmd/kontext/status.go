package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
)

const (
	managedStateUnmanaged = "unmanaged"
	managedStateActive    = "managed_active"
	managedStateInvalid   = "managed_invalid"
)

type statusReport struct {
	ManagedState string `json:"managed_state"`

	ConfigPath      string `json:"config_path"`
	ConfigChecksum  string `json:"config_checksum,omitempty"`
	ValidationError string `json:"validation_error,omitempty"`

	OrganizationID string `json:"organization_id,omitempty"`
	CloudURL       string `json:"cloud_url,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Agent          string `json:"agent,omitempty"`

	InstallationID string `json:"installation_id,omitempty"`

	CredentialRef *credentialRefReport `json:"credential_ref,omitempty"`
}

type credentialRefReport struct {
	Source string `json:"source"`
	Name   string `json:"name"`
}

func statusCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show local managed install status",
		RunE: func(cmd *cobra.Command, args []string) error {
			report := buildStatusReport()
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

func buildStatusReport() statusReport {
	report := statusReport{
		ManagedState: managedStateUnmanaged,
		ConfigPath:   managedconfig.PathFromEnv(),
	}

	loaded, err := managedconfig.Load()
	report.ConfigPath = loaded.Path
	report.ConfigChecksum = loaded.Checksum
	switch {
	case err == nil:
		report.ManagedState = managedStateActive
		cfg := loaded.Config
		report.OrganizationID = cfg.OrganizationID
		report.CloudURL = cfg.CloudURL
		report.Mode = cfg.Mode
		report.Agent = cfg.Agent
		report.CredentialRef = &credentialRefReport{
			Source: cfg.Credentials.InstallTokenRef.Source,
			Name:   cfg.Credentials.InstallTokenRef.Name,
		}
	case errors.Is(err, managedconfig.ErrNotManaged):
		report.ManagedState = managedStateUnmanaged
	default:
		report.ManagedState = managedStateInvalid
		report.ValidationError = err.Error()
	}

	state, err := installation.Load()
	if err == nil {
		report.InstallationID = state.InstallationID
	}
	return report
}

func printStatusReport(w io.Writer, report statusReport) {
	fmt.Fprintf(w, "Managed state: %s\n", report.ManagedState)
	fmt.Fprintf(w, "Config path: %s\n", report.ConfigPath)
	if report.ConfigChecksum != "" {
		fmt.Fprintf(w, "Config checksum: %s\n", report.ConfigChecksum)
	}
	if report.ValidationError != "" {
		fmt.Fprintf(w, "Validation error: %s\n", report.ValidationError)
	}
	if report.OrganizationID != "" {
		fmt.Fprintf(w, "Organization ID: %s\n", report.OrganizationID)
	}
	if report.CloudURL != "" {
		fmt.Fprintf(w, "Cloud URL: %s\n", report.CloudURL)
	}
	if report.Mode != "" {
		fmt.Fprintf(w, "Mode: %s\n", report.Mode)
	}
	if report.Agent != "" {
		fmt.Fprintf(w, "Agent: %s\n", report.Agent)
	}
	if report.InstallationID != "" {
		fmt.Fprintf(w, "Installation ID: %s\n", report.InstallationID)
	}
	if report.CredentialRef != nil {
		fmt.Fprintf(w, "Credential ref: %s:%s\n", report.CredentialRef.Source, report.CredentialRef.Name)
	}
}
