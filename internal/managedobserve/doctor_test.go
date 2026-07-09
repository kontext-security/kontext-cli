package managedobserve

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	sqlitestore "github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedstream"
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
	PrintStatus(&out, "1.2.3")
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

func TestPrintStatusDaemonVersionMatch(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")

	var out bytes.Buffer
	stale := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if stale {
		t.Fatal("staleDaemon = true, want false")
	}
	if !strings.Contains(output, "  daemon: running (v1.2.3, pid ") {
		t.Fatalf("output = %q, want daemon version and pid", output)
	}
	if strings.Contains(output, "WARNING: daemon is running") {
		t.Fatalf("output = %q, want no version warning", output)
	}
}

func TestPrintStatusDaemonVersionMismatch(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.2")

	var out bytes.Buffer
	stale := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if !stale {
		t.Fatal("staleDaemon = false, want true")
	}
	if !strings.Contains(output, "WARNING: daemon is running v1.2.2 but v1.2.3 is installed") {
		t.Fatalf("output = %q, want mismatch warning", output)
	}
}

func TestPrintStatusDaemonDevVersionDoesNotWarn(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "dev")

	var out bytes.Buffer
	stale := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if stale {
		t.Fatal("staleDaemon = true, want false")
	}
	if strings.Contains(output, "WARNING: daemon is running") {
		t.Fatalf("output = %q, want no dev mismatch warning", output)
	}
}

func TestPrintStatusDaemonDeadPIDFallsBackToPlainRunning(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, deadPID(t), "1.2.2")

	var out bytes.Buffer
	stale := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if stale {
		t.Fatal("staleDaemon = true, want false")
	}
	if !strings.Contains(output, "  daemon: running\n") {
		t.Fatalf("output = %q, want plain running line", output)
	}
	if strings.Contains(output, "pid ") || strings.Contains(output, "WARNING: daemon is running") {
		t.Fatalf("output = %q, want no stale dead-pid status", output)
	}
}

func TestPrintStatusHeartbeatFreshAndExportUpToDate(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")
	cursor := env.seedLedger(t)
	if err := managedstream.SaveState(managedstream.DefaultStatePathForDB(env.dbPath), managedstream.State{
		UpdatedAfter:    &cursor.UpdatedAt,
		ActionID:        cursor.ActionID,
		LastHeartbeatAt: env.now.Add(-20 * time.Second).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	stale := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if stale {
		t.Fatal("staleDaemon = true, want false")
	}
	if !strings.Contains(output, "  heartbeat: 20s ago") {
		t.Fatalf("output = %q, want fresh heartbeat", output)
	}
	if !strings.Contains(output, "  export: up to date (0 pending)") {
		t.Fatalf("output = %q, want export up to date", output)
	}
}

func TestPrintStatusHeartbeatOldAndExportLagging(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")
	env.seedLedger(t)
	updatedAfter := time.Unix(0, 0).UTC()
	if err := managedstream.SaveState(managedstream.DefaultStatePathForDB(env.dbPath), managedstream.State{
		UpdatedAfter:    &updatedAfter,
		LastHeartbeatAt: env.now.Add(-6 * time.Minute).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	stale := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if stale {
		t.Fatal("staleDaemon = true, want false")
	}
	if !strings.Contains(output, "WARNING: last heartbeat was 6m0s ago") {
		t.Fatalf("output = %q, want old heartbeat warning", output)
	}
	if !strings.Contains(output, "WARNING: export lagging") || !strings.Contains(output, "events pending") {
		t.Fatalf("output = %q, want export lag warning", output)
	}
}

func TestPrintStatusExportPendingWithinThresholdReportsFacts(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")
	env.seedLedger(t)
	// Cursor a minute behind the just-seeded event: pending but not lagging.
	updatedAfter := time.Now().UTC().Add(-time.Minute)
	if err := managedstream.SaveState(managedstream.DefaultStatePathForDB(env.dbPath), managedstream.State{
		UpdatedAfter:    &updatedAfter,
		LastHeartbeatAt: env.now.Add(-20 * time.Second).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if !strings.Contains(output, "pending (cursor ") {
		t.Fatalf("output = %q, want pending facts line", output)
	}
	if strings.Contains(output, "export: up to date") {
		t.Fatalf("output = %q, want no up-to-date claim while rows are pending", output)
	}
	if strings.Contains(output, "WARNING: export lagging") {
		t.Fatalf("output = %q, want no lag warning under threshold", output)
	}
}

func TestWaitForDaemonRestartSucceeds(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")
	// Unix socket paths cap at 104 bytes on macOS; t.TempDir is too deep.
	socketDir, err := os.MkdirTemp("/tmp", "kontext-doctor-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "kontext.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, err := WaitForDaemonRestart(ctx, env.dbPath, socketPath, "1.2.3")
	if err != nil {
		t.Fatalf("WaitForDaemonRestart() error = %v", err)
	}
	if status.Version != "1.2.3" || status.PID != os.Getpid() {
		t.Fatalf("status = %+v, want current pid on v1.2.3", status)
	}
}

func TestWaitForDaemonRestartTimesOutWithoutDaemon(t *testing.T) {
	env := newDoctorTestEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := WaitForDaemonRestart(ctx, env.dbPath, env.socketPath, "1.2.3"); err == nil {
		t.Fatal("WaitForDaemonRestart() error = nil, want timeout")
	}
}

type doctorTestEnv struct {
	dir        string
	dbPath     string
	socketPath string
	now        time.Time
}

func newDoctorTestEnv(t *testing.T) doctorTestEnv {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "managed.json")
	installationPath := filepath.Join(dir, "installation.json")
	writeTestManagedConfig(t, configPath)
	writeTestInstallation(t, installationPath)
	t.Setenv(installation.EnvPath, installationPath)
	t.Setenv("HOME", dir)
	return doctorTestEnv{
		dir:        dir,
		dbPath:     filepath.Join(dir, "guard.db"),
		socketPath: filepath.Join(dir, "kontext.sock"),
		now:        time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
	}
}

func (e doctorTestEnv) options() doctorOptions {
	return doctorOptions{
		DBPath:     e.dbPath,
		SocketPath: e.socketPath,
		Dial: func(string, string, time.Duration) (net.Conn, error) {
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
		Now: func() time.Time { return e.now },
	}
}

func (e doctorTestEnv) writeDaemonStatus(t *testing.T, pid int, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(DaemonStatusPath(e.dbPath)), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"version":"` + version + `","pid":` + itoa(pid) + `,"started_at":"2026-07-09T12:00:00Z"}` + "\n")
	if err := os.WriteFile(DaemonStatusPath(e.dbPath), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e doctorTestEnv) seedLedger(t *testing.T) *sqlitestore.LedgerCursor {
	t.Helper()
	store, err := sqlitestore.OpenStore(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-1",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "ok",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	}); err != nil {
		t.Fatal(err)
	}
	batch, err := store.LedgerBatch(context.Background(), sqlitestore.LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Cursor == nil {
		t.Fatal("LedgerBatch cursor = nil")
	}
	return batch.Cursor
}

func deadPID(t *testing.T) int {
	t.Helper()
	for pid := os.Getpid() + 100000; pid < os.Getpid()+101000; pid++ {
		if !pidAlive(pid) {
			return pid
		}
	}
	t.Fatal("could not find a dead pid")
	return 0
}
