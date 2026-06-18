package managedobserve

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
)

func TestPrintStatusReportsInstallationLoadError(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "managed.json")
	installationPath := filepath.Join(dir, "installation.json")

	writeTestManagedConfig(t, configPath)
	if err := os.WriteFile(installationPath, []byte(`{"installation_id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managedconfig.EnvPath, configPath)
	t.Setenv(installation.EnvPath, installationPath)
	t.Setenv("KONTEXT_INSTALL_TOKEN", "test-install-token")

	var out bytes.Buffer
	PrintStatus(&out)
	output := out.String()
	if !strings.Contains(output, "installation: ERROR") {
		t.Fatalf("PrintStatus() output = %q, want installation error", output)
	}
	if strings.Contains(output, "installation: not created yet") {
		t.Fatalf("PrintStatus() output = %q, must not hide invalid state as missing", output)
	}
	if strings.Contains(output, "\n  organization:") {
		t.Fatalf("PrintStatus() output = %q, must not print local organization", output)
	}
}
