package run

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/credential"
	"gopkg.in/yaml.v3"
)

// writeHermesEnv writes resolved credentials into <dir>/.env in KEY=VALUE form,
// sorted by env var name for deterministic output. Values that contain
// whitespace, '#', or quotes are wrapped in double quotes with escaping.
func writeHermesEnv(dir string, resolved []credential.Resolved) error {
	entries := make([]credential.Resolved, len(resolved))
	copy(entries, resolved)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].EnvVar < entries[j].EnvVar
	})

	var b strings.Builder
	for _, r := range entries {
		fmt.Fprintf(&b, "%s=%s\n", r.EnvVar, dotenvQuote(r.Value))
	}

	path := filepath.Join(dir, ".env")
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func dotenvQuote(value string) string {
	if !strings.ContainsAny(value, " \t\"#'\\\n") {
		return value
	}
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// writeHermesConfig writes <sessionDir>/config.yaml, merging the user's base
// config (if basePath != "" and exists) with a `kontext` entry under
// mcp_servers. passthroughEnv is the list of env var names whose resolved
// values will be forwarded to the mcp-serve subprocess via the yaml env block.
func writeHermesConfig(sessionDir, basePath, kontextBin, socketPath, sessionID string, passthroughEnv []string) error {
	doc := map[string]any{}
	if basePath != "" {
		if data, err := os.ReadFile(basePath); err == nil {
			if err := yaml.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("parse base hermes config: %w", err)
			}
			if doc == nil {
				doc = map[string]any{}
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("read base hermes config: %w", err)
		}
	}

	servers, _ := doc["mcp_servers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}

	envMap := map[string]any{
		"KONTEXT_SESSION_ID": sessionID,
		"KONTEXT_SOCKET":     socketPath,
	}
	for _, name := range passthroughEnv {
		envMap[name] = "${" + name + "}"
	}

	servers["kontext"] = map[string]any{
		"command": kontextBin,
		"args":    []any{"mcp-serve", "--agent", "hermes", "--socket", socketPath},
		"env":     envMap,
	}
	doc["mcp_servers"] = servers

	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal hermes config: %w", err)
	}
	path := filepath.Join(sessionDir, "config.yaml")
	return os.WriteFile(path, out, 0o600)
}

// BuildHermesHome seeds a session-scoped HERMES_HOME under parentDir and
// returns the absolute path to use as HERMES_HOME.
func BuildHermesHome(parentDir, kontextBin, socketPath, sessionID string, resolved []credential.Resolved) (string, error) {
	dir := filepath.Join(parentDir, "hermes")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create hermes home: %w", err)
	}

	if err := writeHermesEnv(dir, resolved); err != nil {
		return "", err
	}

	basePath := ""
	if home, err := os.UserHomeDir(); err == nil {
		basePath = filepath.Join(home, ".hermes", "config.yaml")
	}

	passthrough := make([]string, 0, len(resolved))
	for _, r := range resolved {
		passthrough = append(passthrough, r.EnvVar)
	}

	if err := writeHermesConfig(dir, basePath, kontextBin, socketPath, sessionID, passthrough); err != nil {
		return "", err
	}
	return dir, nil
}
