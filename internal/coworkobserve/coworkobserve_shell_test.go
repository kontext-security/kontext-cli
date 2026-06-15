package coworkobserve

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests run the actual generated hook command strings under /bin/sh, the
// way Cowork's bundled CLI does. They guard the shell behavior the rest of the
// suite cannot reach: $-relative path resolution, rid generation, the spool
// append, the decision poll, the stdout shape, and fail-closed timeout. The
// commands write to ../ (the session dir) because the hook's cwd is the
// session's outputs/ mount, so each test runs sh with cwd = <session>/outputs.

func shellTestDir(t *testing.T) (sessionDir, outputsDir string) {
	t.Helper()
	sessionDir = t.TempDir()
	outputsDir = filepath.Join(sessionDir, "outputs")
	if err := os.MkdirAll(outputsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return sessionDir, outputsDir
}

func runHook(t *testing.T, command, cwd, stdin string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", command)
	cmd.Dir = cwd
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	return string(out), err
}

func TestShellObserveAppendsToSessionSpool(t *testing.T) {
	sessionDir, outputsDir := shellTestDir(t)
	spool := filepath.Join(sessionDir, spoolName)

	out, err := runHook(t, observeHookCommand, outputsDir, eventLine("Bash"))
	if err != nil {
		t.Fatalf("observe hook exited non-zero: %v", err)
	}
	if out != "" {
		t.Fatalf("observe hook wrote to stdout: %q", out)
	}
	data, err := os.ReadFile(spool)
	if err != nil {
		t.Fatalf("spool not written at the session dir: %v", err)
	}
	if string(data) != eventLine("Bash")+"\n" {
		t.Fatalf("spool = %q, want the event line", data)
	}

	// A second invocation appends rather than truncating.
	if _, err := runHook(t, observeHookCommand, outputsDir, eventLine("Read")); err != nil {
		t.Fatalf("second observe hook exited non-zero: %v", err)
	}
	data, _ = os.ReadFile(spool)
	if want := eventLine("Bash") + "\n" + eventLine("Read") + "\n"; string(data) != want {
		t.Fatalf("spool after two events = %q, want %q", data, want)
	}
}

func TestShellEnforceEmptyStdinDenies(t *testing.T) {
	sessionDir, outputsDir := shellTestDir(t)

	out, err := runHook(t, enforceHookCommand, outputsDir, "")
	if err != nil {
		t.Fatalf("enforce hook exited non-zero: %v", err)
	}
	if out != denyJSON+"\n" {
		t.Fatalf("stdout = %q, want the deny verdict", out)
	}
	if _, err := os.Stat(filepath.Join(sessionDir, spoolName)); !os.IsNotExist(err) {
		t.Fatalf("spool created for empty stdin (err=%v)", err)
	}
}

func TestShellEnforceEmitsParkedDecision(t *testing.T) {
	sessionDir, outputsDir := shellTestDir(t)

	cmd := exec.Command("sh", "-c", enforceHookCommand)
	cmd.Dir = outputsDir
	cmd.Stdin = strings.NewReader(eventLine("Bash"))
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// The rid is generated inside the shell, so we cannot predict it. The hook
	// writes the envelope (carrying the rid) before it starts polling, so read
	// the spool to learn the rid, then park the decision the hook is waiting on.
	spool := filepath.Join(sessionDir, spoolName)
	var rid string
	for i := 0; i < 100 && rid == ""; i++ {
		if line := bytes.TrimSpace(readFileMaybe(spool)); len(line) > 0 {
			var env spoolEnvelope
			if json.Unmarshal(line, &env) == nil {
				rid = env.RID
			}
		}
		if rid == "" {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if rid == "" {
		_ = cmd.Process.Kill()
		t.Fatal("hook never spooled an envelope with a rid")
	}
	if !ridPattern.MatchString(rid) {
		_ = cmd.Process.Kill()
		t.Fatalf("shell-generated rid %q does not match ridPattern", rid)
	}

	decision := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"ok"}}`
	decDir := filepath.Join(sessionDir, decisionsDirName)
	if err := os.MkdirAll(decDir, 0o755); err != nil {
		t.Fatal(err)
	}
	decFile := filepath.Join(decDir, rid+".json")
	if err := writeFileAtomic(decFile, []byte(decision), 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("hook exited non-zero: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("hook did not exit after the decision was parked")
	}

	if !strings.Contains(stdout.String(), decision) {
		t.Fatalf("stdout = %q, want the parked decision", stdout.String())
	}
	if _, err := os.Stat(decFile); !os.IsNotExist(err) {
		t.Fatalf("hook did not delete its consumed decision file (err=%v)", err)
	}
}

func TestShellEnforceFailsClosedWithoutDecision(t *testing.T) {
	// The real poll loop is 100 x 0.1s = 10s. Substitute a 3-iteration loop so
	// the test stays fast while exercising the same fail-closed path, and
	// assert the real constant still has the 100-count loop so the substitution
	// cannot silently drift out of sync.
	if !strings.Contains(enforceHookCommand, `"$i" -lt 100`) {
		t.Fatal("enforce poll-loop bound changed; update this test's substitution")
	}
	fast := strings.Replace(enforceHookCommand, `"$i" -lt 100`, `"$i" -lt 3`, 1)

	sessionDir, outputsDir := shellTestDir(t)
	out, err := runHook(t, fast, outputsDir, eventLine("Bash"))
	if err != nil {
		t.Fatalf("hook exited non-zero: %v", err)
	}
	if out != denyJSON+"\n" {
		t.Fatalf("stdout = %q, want the deny verdict", out)
	}
	// The event is still spooled before the poll loop, so the daemon ingests it
	// even though the in-VM call was denied.
	data, err := os.ReadFile(filepath.Join(sessionDir, spoolName))
	if err != nil {
		t.Fatalf("spool not written before the poll loop: %v", err)
	}
	if !bytes.Contains(data, []byte(`"rid"`)) {
		t.Fatalf("envelope not spooled: %s", data)
	}
}

func readFileMaybe(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}
