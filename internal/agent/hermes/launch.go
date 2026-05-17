package hermes

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"gopkg.in/yaml.v3"
)

const localHookTimeoutSeconds = 20

type hermesSource struct {
	Home string
	Root string
}

type shellHookAllowlist struct {
	Approvals []shellHookApproval `json:"approvals"`
}

type shellHookApproval struct {
	Event      string `json:"event"`
	Command    string `json:"command"`
	ApprovedAt string `json:"approved_at"`
}

func (h *Hermes) PrepareLocalLaunch(opts agent.LocalLaunchOptions) (agent.LocalLaunch, error) {
	source := resolveHermesSource()
	hermesHome, err := generateLocalHermesHome(opts.SessionDir, source, opts.KontextBinary, opts.AgentName, opts.SocketPath, opts.Mode)
	if err != nil {
		return agent.LocalLaunch{}, fmt.Errorf("generate Hermes runtime config: %w", err)
	}

	env := append([]string{}, opts.BaseEnv...)
	env = append(env, "HERMES_HOME="+hermesHome)
	return agent.LocalLaunch{Env: env, Args: append([]string{}, opts.ExtraArgs...)}, nil
}

func generateLocalHermesHome(sessionDir string, source hermesSource, kontextBinary, agentName, socketPath, mode string) (string, error) {
	hermesRoot := filepath.Join(sessionDir, "hermes")
	hermesHome := filepath.Join(hermesRoot, "profiles", "kontext")
	if err := os.MkdirAll(hermesHome, 0o700); err != nil {
		return "", fmt.Errorf("create temporary Hermes home: %w", err)
	}

	if err := snapshotHermesState(source, hermesRoot, hermesHome); err != nil {
		return "", err
	}

	hookCmd := hookCommand(kontextBinary, agentName, socketPath, mode)
	if err := writeHermesConfig(filepath.Join(source.Home, "config.yaml"), filepath.Join(hermesHome, "config.yaml"), hookCmd); err != nil {
		return "", err
	}
	if err := writeHermesHookAllowlist(filepath.Join(hermesHome, "shell-hooks-allowlist.json"), hookCmd); err != nil {
		return "", err
	}

	return hermesHome, nil
}

func resolveHermesSource() hermesSource {
	if envHome := strings.TrimSpace(os.Getenv("HERMES_HOME")); envHome != "" {
		return hermesSource{Home: envHome, Root: hermesRootForHome(envHome)}
	}

	root := filepath.Join(os.Getenv("HOME"), ".hermes")
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		root = filepath.Join(home, ".hermes")
	}
	if profile := activeHermesProfile(root); profile != "" {
		return hermesSource{Home: filepath.Join(root, "profiles", profile), Root: root}
	}
	return hermesSource{Home: root, Root: root}
}

func hermesRootForHome(home string) string {
	if filepath.Base(filepath.Dir(home)) == "profiles" {
		return filepath.Dir(filepath.Dir(home))
	}
	return home
}

func activeHermesProfile(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "active_profile"))
	if err != nil {
		return ""
	}
	profile := strings.TrimSpace(string(data))
	if profile == "" || profile == "default" {
		return ""
	}
	return profile
}

func snapshotHermesState(source hermesSource, targetRoot, targetHome string) error {
	if source.Root != "" && source.Root != source.Home {
		if err := copySnapshotFile(source.Root, targetRoot, "auth.json"); err != nil {
			return err
		}
		if err := copySnapshotDir(filepath.Join(source.Root, "auth"), filepath.Join(targetRoot, "auth")); err != nil {
			return err
		}
	}
	for _, name := range []string{".env", "auth.json"} {
		if err := copySnapshotFile(source.Home, targetHome, name); err != nil {
			return err
		}
	}
	return copySnapshotDir(filepath.Join(source.Home, "auth"), filepath.Join(targetHome, "auth"))
}

func copySnapshotFile(sourceDir, targetDir, name string) error {
	sourcePath := filepath.Join(sourceDir, name)
	info, err := os.Lstat(sourcePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect Hermes file %s: %w", sourcePath, err)
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	return copyRegularFile(sourcePath, filepath.Join(targetDir, name))
}

func copySnapshotDir(sourceDir, targetDir string) error {
	info, err := os.Lstat(sourceDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect Hermes directory %s: %w", sourceDir, err)
	}
	if !info.IsDir() {
		return nil
	}
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return fmt.Errorf("create Hermes snapshot directory %s: %w", targetDir, err)
	}
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("read Hermes directory %s: %w", sourceDir, err)
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(sourceDir, entry.Name())
		targetPath := filepath.Join(targetDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect Hermes entry %s: %w", sourcePath, err)
		}
		switch {
		case info.IsDir():
			if err := copySnapshotDir(sourcePath, targetPath); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if err := copyRegularFile(sourcePath, targetPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyRegularFile(sourcePath, targetPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open Hermes file %s: %w", sourcePath, err)
	}
	defer source.Close()

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return fmt.Errorf("create Hermes file directory %s: %w", filepath.Dir(targetPath), err)
	}
	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create Hermes snapshot file %s: %w", targetPath, err)
	}
	defer target.Close()

	if _, err := io.Copy(target, source); err != nil {
		return fmt.Errorf("copy Hermes file %s: %w", sourcePath, err)
	}
	return nil
}

func writeHermesConfig(sourcePath, targetPath, hookCmd string) error {
	config := map[string]any{}
	data, err := os.ReadFile(sourcePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read Hermes config: %w", err)
	}
	if len(strings.TrimSpace(string(data))) > 0 {
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("parse Hermes config: %w", err)
		}
		if config == nil {
			config = map[string]any{}
		}
	}

	config["hooks"] = map[string]any{
		"pre_tool_call":  []any{hermesHookEntry(hookCmd)},
		"post_tool_call": []any{hermesHookEntry(hookCmd)},
	}

	out, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal Hermes config: %w", err)
	}
	if err := os.WriteFile(targetPath, out, 0o600); err != nil {
		return fmt.Errorf("write Hermes config: %w", err)
	}
	return nil
}

func writeHermesHookAllowlist(targetPath, hookCmd string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	allowlist := shellHookAllowlist{
		Approvals: []shellHookApproval{
			{Event: "pre_tool_call", Command: hookCmd, ApprovedAt: now},
			{Event: "post_tool_call", Command: hookCmd, ApprovedAt: now},
		},
	}
	data, err := json.MarshalIndent(allowlist, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal Hermes hook allowlist: %w", err)
	}
	if err := os.WriteFile(targetPath, data, 0o600); err != nil {
		return fmt.Errorf("write Hermes hook allowlist: %w", err)
	}
	return nil
}

func hookCommand(kontextBinary, agentName, socketPath, mode string) string {
	return fmt.Sprintf(
		"%s hook --agent %s --mode %s --socket %s",
		shellQuote(kontextBinary),
		shellQuote(agentName),
		shellQuote(mode),
		shellQuote(socketPath),
	)
}

func hermesHookEntry(hookCmd string) map[string]any {
	return map[string]any{
		"command": hookCmd,
		"timeout": localHookTimeoutSeconds,
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
