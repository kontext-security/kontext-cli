package run

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/credential"
	"gopkg.in/yaml.v3"
)

func TestWriteHermesEnv(t *testing.T) {
	dir := t.TempDir()
	resolved := []credential.Resolved{
		{Entry: credential.Entry{EnvVar: "GITHUB_TOKEN"}, Value: "ghs_abc"},
		{Entry: credential.Entry{EnvVar: "LINEAR_API_KEY"}, Value: "lin_xyz"},
	}
	if err := writeHermesEnv(dir, resolved); err != nil {
		t.Fatalf("writeHermesEnv: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	got := string(b)
	if !containsLine(got, `GITHUB_TOKEN=ghs_abc`) {
		t.Errorf(".env missing GITHUB_TOKEN line: %q", got)
	}
	if !containsLine(got, `LINEAR_API_KEY=lin_xyz`) {
		t.Errorf(".env missing LINEAR_API_KEY line: %q", got)
	}
}

func containsLine(haystack, needle string) bool {
	for _, line := range splitLines(haystack) {
		if line == needle {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func TestMergeHermesConfig_NoBase(t *testing.T) {
	dir := t.TempDir()
	err := writeHermesConfig(dir, "", "/bin/kontext", "/tmp/x.sock", "sess-1", []string{"GITHUB_TOKEN"})
	if err != nil {
		t.Fatalf("writeHermesConfig: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	servers, ok := doc["mcp_servers"].(map[string]any)
	if !ok {
		t.Fatalf("mcp_servers missing: %v", doc)
	}
	k, ok := servers["kontext"].(map[string]any)
	if !ok {
		t.Fatalf("kontext entry missing: %v", servers)
	}
	if k["command"] != "/bin/kontext" {
		t.Errorf("command: got %v", k["command"])
	}
	args, _ := k["args"].([]any)
	if len(args) == 0 || args[0] != "mcp-serve" {
		t.Errorf("args: got %v", args)
	}
	env, _ := k["env"].(map[string]any)
	if env["KONTEXT_SESSION_ID"] != "sess-1" {
		t.Errorf("env session id: got %v", env)
	}
}

func TestMergeHermesConfig_WithBase(t *testing.T) {
	baseDir := t.TempDir()
	basePath := filepath.Join(baseDir, "config.yaml")
	base := []byte(`
model:
  provider: openai
mcp_servers:
  github:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
  kontext:
    command: /old/binary
`)
	if err := os.WriteFile(basePath, base, 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := writeHermesConfig(dir, basePath, "/bin/kontext", "/tmp/x.sock", "sess-2", nil); err != nil {
		t.Fatalf("writeHermesConfig: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	var doc map[string]any
	_ = yaml.Unmarshal(b, &doc)

	model, _ := doc["model"].(map[string]any)
	if model["provider"] != "openai" {
		t.Errorf("model.provider lost")
	}
	servers := doc["mcp_servers"].(map[string]any)
	if _, ok := servers["github"]; !ok {
		t.Errorf("github server lost")
	}
	k := servers["kontext"].(map[string]any)
	if k["command"] != "/bin/kontext" {
		t.Errorf("kontext command not overwritten: %v", k["command"])
	}
}
