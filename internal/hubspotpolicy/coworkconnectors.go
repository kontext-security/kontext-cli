package hubspotpolicy

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// HubspotMCPHost is the host of HubSpot's remote MCP server. Identification
// keys on the URL host — where the connector's calls actually go — never on
// its display name, which is free text.
const HubspotMCPHost = "mcp.hubspot.com"

// maxSessionConfigBytes caps how much of a Cowork session config the resolver
// reads. Real configs (with full tool schemas) run a few hundred KB.
const maxSessionConfigBytes = 8 << 20

// coworkSessionConfig is the subset of Cowork's per-session config file
// (local_<id>.json) the resolver needs: the connector registry mapping each
// connector-instance uuid to its server URL.
//
// This is an undocumented Claude-internal format. The resolver is therefore
// best-effort by design: any read/parse failure reports "unresolved" and the
// classifier's tool-name fallback decides.
type coworkSessionConfig struct {
	RemoteMCPServersConfig []struct {
		UUID string `json:"uuid"`
		URL  string `json:"url"`
	} `json:"remoteMcpServersConfig"`
}

// ConnectorResolverForCWD returns a ConnectorResolver backed by the Cowork
// session config next to the hook event's working directory, memoized so the
// file is read at most once per classification. A non-Cowork cwd (no session
// config anywhere above it) yields a resolver that never resolves.
//
// Cowork session layout: hook cwd points at (or below)
// …/local_<id>/outputs, and the session config is the sibling file
// …/local_<id>.json.
func ConnectorResolverForCWD(cwd string) ConnectorResolver {
	loaded := false
	var hosts map[string]string
	return func(serverSegment string) (bool, bool) {
		if !loaded {
			loaded = true
			hosts = connectorHostsForCWD(cwd)
		}
		host, ok := hosts[serverSegment]
		if !ok {
			return false, false
		}
		return host == HubspotMCPHost, true
	}
}

// connectorHostsForCWD walks up from cwd looking for the Cowork session
// config and returns connector uuid → server URL host. nil means "no
// registry" (not a Cowork session, unreadable file, unparseable JSON).
func connectorHostsForCWD(cwd string) map[string]string {
	configPath := sessionConfigPath(cwd)
	if configPath == "" {
		return nil
	}
	info, err := os.Stat(configPath)
	if err != nil || info.Size() > maxSessionConfigBytes {
		return nil
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}
	var config coworkSessionConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil
	}
	hosts := make(map[string]string, len(config.RemoteMCPServersConfig))
	for _, server := range config.RemoteMCPServersConfig {
		if server.UUID == "" {
			continue
		}
		parsed, err := url.Parse(server.URL)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		hosts[server.UUID] = parsed.Hostname()
	}
	return hosts
}

// sessionConfigPath finds the Cowork session config for a cwd by walking up a
// few levels looking for a directory whose sibling file "<dirname>.json"
// exists (…/local_<id>/outputs → …/local_<id>.json). The walk is bounded: a
// hook cwd is at most a couple of levels below the session directory.
func sessionConfigPath(cwd string) string {
	dir := filepath.Clean(strings.TrimSpace(cwd))
	if dir == "" || dir == "." {
		return ""
	}
	for range [4]int{} {
		base := filepath.Base(dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		if strings.HasPrefix(base, "local_") {
			candidate := filepath.Join(parent, base+".json")
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
		dir = parent
	}
	return ""
}
