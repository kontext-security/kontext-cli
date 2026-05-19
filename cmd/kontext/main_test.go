package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/run"
	"github.com/zalando/go-keyring"
)

func TestLogoutCmdSuccess(t *testing.T) {
	cmd := newLogoutCmd(func() error { return nil })

	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE() error = %v", err)
	}

	if got, want := stderr.String(), "Logged out successfully.\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestStartCmdHasVerboseFlag(t *testing.T) {
	cmd := startCmd()
	flag := cmd.Flags().Lookup("verbose")
	if flag == nil {
		t.Fatal("start command missing --verbose flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--verbose default = %q, want false", flag.DefValue)
	}
}

func TestStartCmdHasManagedFlag(t *testing.T) {
	cmd := startCmd()
	flag := cmd.Flags().Lookup("managed")
	if flag == nil {
		t.Fatal("start command missing --managed flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--managed default = %q, want false", flag.DefValue)
	}
}

func TestStartCmdDefaultsToLocalStart(t *testing.T) {
	oldLocal := startLocal
	oldManaged := startManaged
	defer func() {
		startLocal = oldLocal
		startManaged = oldManaged
	}()

	called := ""
	startLocal = func(_ context.Context, opts run.Options) error {
		called = "local"
		if opts.Agent != "claude" {
			t.Fatalf("Agent = %q, want claude", opts.Agent)
		}
		return nil
	}
	startManaged = func(context.Context, run.Options) error {
		t.Fatal("managed start should not be called")
		return nil
	}

	cmd := startCmd()
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE() error = %v", err)
	}
	if called != "local" {
		t.Fatalf("called = %q, want local", called)
	}
}

func TestStartCmdManagedFlagRoutesToHostedStart(t *testing.T) {
	oldLocal := startLocal
	oldManaged := startManaged
	defer func() {
		startLocal = oldLocal
		startManaged = oldManaged
	}()

	called := ""
	startLocal = func(context.Context, run.Options) error {
		t.Fatal("local start should not be called")
		return nil
	}
	startManaged = func(_ context.Context, opts run.Options) error {
		called = "managed"
		if opts.TemplateFile != "custom.env" {
			t.Fatalf("TemplateFile = %q, want custom.env", opts.TemplateFile)
		}
		return nil
	}

	cmd := startCmd()
	if err := cmd.Flags().Set("managed", "true"); err != nil {
		t.Fatalf("Set managed error = %v", err)
	}
	if err := cmd.Flags().Set("env-template", "custom.env"); err != nil {
		t.Fatalf("Set env-template error = %v", err)
	}
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE() error = %v", err)
	}
	if called != "managed" {
		t.Fatalf("called = %q, want managed", called)
	}
}

func TestStartCmdRejectsEnvTemplateWithoutManaged(t *testing.T) {
	cmd := startCmd()
	if err := cmd.Flags().Set("env-template", "custom.env"); err != nil {
		t.Fatalf("Set env-template error = %v", err)
	}

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("RunE() error = nil, want --env-template error")
	}
	if !strings.Contains(err.Error(), "--env-template is only used with --managed") {
		t.Fatalf("error = %q, want env-template managed error", err.Error())
	}
}

func TestGuardCmdRoutesToLocalGuardMode(t *testing.T) {
	cmd := guardCmd()
	if cmd.Use != "guard" {
		t.Fatalf("Use = %q, want guard", cmd.Use)
	}
	if !cmd.DisableFlagParsing {
		t.Fatal("guard command should pass flags through to the local Guard command parser")
	}
}

func TestStatusCmdReportsUnmanagedWithoutCreatingInstallationState(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "managed.json")
	installationPath := filepath.Join(t.TempDir(), "installation.json")
	t.Setenv("KONTEXT_MANAGED_CONFIG", configPath)
	t.Setenv("KONTEXT_INSTALLATION_STATE", installationPath)

	var stdout bytes.Buffer
	cmd := statusCmd()
	cmd.SetOut(&stdout)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "Managed state: unmanaged") {
		t.Fatalf("stdout = %q, want unmanaged state", stdout.String())
	}
	if _, err := os.Stat(installationPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("installation state stat error = %v, want not exist", err)
	}
}

func TestStatusCmdJSONReportsManagedActiveWithoutSecretResolution(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "managed.json")
	installationPath := filepath.Join(dir, "installation.json")
	if err := os.WriteFile(configPath, []byte(`{
		"version": "managed-install-v1",
		"organization_id": "org_123",
		"cloud_url": "https://api.kontext.dev",
		"mode": "observe",
		"agent": "claude",
		"credentials": {"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"}
	}`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	if err := os.WriteFile(installationPath, []byte(`{"installation_id":"ins_existing"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(installation) error = %v", err)
	}
	t.Setenv("KONTEXT_MANAGED_CONFIG", configPath)
	t.Setenv("KONTEXT_INSTALLATION_STATE", installationPath)
	t.Setenv("KONTEXT_INSTALL_TOKEN", "super-secret")

	var stdout bytes.Buffer
	cmd := statusCmd()
	cmd.SetOut(&stdout)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("Set(json) error = %v", err)
	}

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE() error = %v", err)
	}
	if strings.Contains(stdout.String(), "super-secret") {
		t.Fatalf("stdout leaked resolved secret: %q", stdout.String())
	}

	var report statusReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("Unmarshal(status) error = %v", err)
	}
	if report.ManagedState != "managed_active" {
		t.Fatalf("ManagedState = %q, want managed_active", report.ManagedState)
	}
	if report.InstallationID != "ins_existing" {
		t.Fatalf("InstallationID = %q, want ins_existing", report.InstallationID)
	}
	if report.CredentialRef == nil || report.CredentialRef.Source != "env" || report.CredentialRef.Name != "KONTEXT_INSTALL_TOKEN" {
		t.Fatalf("CredentialRef = %+v, want env/KONTEXT_INSTALL_TOKEN", report.CredentialRef)
	}
}

func TestStatusCmdReportsManagedInvalid(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(configPath, []byte(`{"version":"wrong"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	t.Setenv("KONTEXT_MANAGED_CONFIG", configPath)
	t.Setenv("KONTEXT_INSTALLATION_STATE", filepath.Join(t.TempDir(), "installation.json"))

	var stdout bytes.Buffer
	cmd := statusCmd()
	cmd.SetOut(&stdout)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "Managed state: managed_invalid") {
		t.Fatalf("stdout = %q, want managed_invalid state", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Validation error:") {
		t.Fatalf("stdout = %q, want validation error", stdout.String())
	}
}

func TestHookCmdModeDoesNotDefaultFromEnv(t *testing.T) {
	t.Setenv("KONTEXT_MODE", "observe")

	cmd := hookCmd()
	flag := cmd.Flags().Lookup("mode")
	if flag == nil {
		t.Fatal("hook command missing --mode flag")
	}
	if flag.DefValue != "" {
		t.Fatalf("--mode default = %q, want empty", flag.DefValue)
	}
}

func TestLogoutCmdAlreadyLoggedOut(t *testing.T) {
	cmd := newLogoutCmd(func() error { return keyring.ErrNotFound })

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("RunE() error = nil, want non-nil")
	}
	if got, want := err.Error(), "already logged out"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestLogoutCmdWrapsUnexpectedErrors(t *testing.T) {
	boom := errors.New("boom")
	cmd := newLogoutCmd(func() error { return boom })

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("RunE() error = nil, want non-nil")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("errors.Is(err, boom) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "logout failed: boom") {
		t.Fatalf("error = %q, want wrapped logout failure", err.Error())
	}
}

func TestEvaluateViaSidecarFailsOpenOnMarshalErrors(t *testing.T) {
	t.Parallel()

	socketPath := fmt.Sprintf("/tmp/kontext-test-%d.sock", time.Now().UnixNano())
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	tests := []struct {
		name  string
		event hook.Event
	}{
		{
			name: "tool input",
			event: hook.Event{
				Agent:     "claude",
				HookName:  hook.HookPreToolUse,
				ToolInput: map[string]any{"bad": func() {}},
			},
		},
		{
			name: "tool response",
			event: hook.Event{
				Agent:        "claude",
				HookName:     hook.HookPreToolUse,
				ToolResponse: map[string]any{"bad": func() {}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluateViaSidecar(socketPath, tt.event)
			if err != nil {
				t.Fatalf("evaluateViaSidecar() error = %v", err)
			}
			if !result.Allowed() {
				t.Fatal("evaluateViaSidecar() allowed = false, want true")
			}
			if result.Reason != "sidecar marshal error" {
				t.Fatalf("evaluateViaSidecar() reason = %q, want sidecar marshal error", result.Reason)
			}
		})
	}
}

func TestEvaluateViaSidecarFailsClosedWhenEnforceSidecarUnavailable(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "enforce")

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want DENY", result.Decision)
	}
	if result.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", result.Mode)
	}
}

func TestEvaluateViaSidecarObserveModeIgnoresStaleHostedEnforce(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "enforce")

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecarForMode(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	}, "observe")
	if err != nil {
		t.Fatalf("evaluateViaSidecarForMode() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want ALLOW", result.Decision)
	}
	if result.Mode != "observe" {
		t.Fatalf("mode = %q, want observe", result.Mode)
	}
}

func TestEvaluateViaSidecarFailsClosedWhenAccessModePathSet(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE_PATH", "/tmp/kontext-missing-mode")

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want DENY", result.Decision)
	}
	if result.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", result.Mode)
	}
	if result.Reason != "sidecar unreachable" {
		t.Fatalf("reason = %q, want sidecar failure reason", result.Reason)
	}
}

func TestEvaluateViaSidecarFailsOpenWhenNoPolicyModePathSet(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "no_policy")
	modePath := fmt.Sprintf("/tmp/kontext-mode-%d", time.Now().UnixNano())
	if err := os.WriteFile(modePath, []byte("no_policy\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(modePath) })
	t.Setenv("KONTEXT_ACCESS_MODE_PATH", modePath)

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want ALLOW", result.Decision)
	}
}

func TestEvaluateViaSidecarUsesRefreshedEnforceModeFromPath(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "no_policy")
	modePath := fmt.Sprintf("/tmp/kontext-mode-%d", time.Now().UnixNano())
	if err := os.WriteFile(modePath, []byte("enforce\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(modePath) })
	t.Setenv("KONTEXT_ACCESS_MODE_PATH", modePath)

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want DENY", result.Decision)
	}
	if result.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", result.Mode)
	}
}

func TestEvaluateHookWithSidecarFailsClosedWhenEnforceSocketMissing(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "enforce")

	result, err := evaluateHookWithSidecar("", hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateHookWithSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want DENY", result.Decision)
	}
	if result.Reason != "sidecar socket missing" {
		t.Fatalf("reason = %q, want missing socket", result.Reason)
	}
}

func TestEvaluateHookWithSidecarModeFailsClosedWhenEnforceSocketMissing(t *testing.T) {
	result, err := evaluateHookWithSidecarForMode("", hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	}, "enforce")
	if err != nil {
		t.Fatalf("evaluateHookWithSidecarForMode() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want DENY", result.Decision)
	}
	if result.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", result.Mode)
	}
	if result.Reason != "sidecar socket missing" {
		t.Fatalf("reason = %q, want missing socket", result.Reason)
	}
}

func TestEvaluateHookWithSidecarAllowsPostToolUseWhenSocketMissing(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "enforce")

	result, err := evaluateHookWithSidecar("", hook.Event{
		Agent:    "claude",
		HookName: hook.HookPostToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateHookWithSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want ALLOW", result.Decision)
	}
	if result.Reason != "sidecar socket missing" {
		t.Fatalf("reason = %q, want missing socket", result.Reason)
	}
}

func TestEvaluateViaSidecarUsesRefreshedNoPolicyModeFromPath(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "enforce")
	modePath := fmt.Sprintf("/tmp/kontext-mode-%d", time.Now().UnixNano())
	if err := os.WriteFile(modePath, []byte("no_policy\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(modePath) })
	t.Setenv("KONTEXT_ACCESS_MODE_PATH", modePath)

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want ALLOW", result.Decision)
	}
}

func TestEvaluateViaSidecarFailsOpenWhenObserveSidecarUnavailable(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "no_policy")

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want ALLOW", result.Decision)
	}
}
