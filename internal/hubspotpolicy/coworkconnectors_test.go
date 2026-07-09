package hubspotpolicy

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCoworkSession lays out the observed Cowork session shape:
// <dir>/local_<id>.json next to <dir>/local_<id>/outputs (the hook cwd).
func writeCoworkSession(t *testing.T, config string) (cwd string) {
	t.Helper()
	root := t.TempDir()
	sessionDir := filepath.Join(root, "local_0056ddd3-e8cd")
	cwd = filepath.Join(sessionDir, "outputs")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "local_0056ddd3-e8cd.json"), []byte(config), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return cwd
}

const sessionConfig = `{
  "sessionId": "abc",
  "remoteMcpServersConfig": [
    {"uuid": "5c56899e-3e6c-4803-85ca-ff1912393966", "name": "HubSpot", "url": "https://mcp.hubspot.com/anthropic"},
    {"uuid": "100744ce-4ed5-4792-86f4-d44cb3e57a24", "name": "Linear", "url": "https://mcp.linear.app/mcp"}
  ]
}`

func TestConnectorResolverForCWDResolvesByURLHost(t *testing.T) {
	cwd := writeCoworkSession(t, sessionConfig)
	resolver := ConnectorResolverForCWD(cwd)

	isHubspot, resolved := resolver("5c56899e-3e6c-4803-85ca-ff1912393966")
	if !resolved || !isHubspot {
		t.Fatalf("hubspot uuid = (%v, %v), want (true, true)", isHubspot, resolved)
	}
	// Another connector resolves definitively to NOT hubspot — the
	// counter-signal that suppresses same-named tools on other servers.
	isHubspot, resolved = resolver("100744ce-4ed5-4792-86f4-d44cb3e57a24")
	if !resolved || isHubspot {
		t.Fatalf("linear uuid = (%v, %v), want (false, true)", isHubspot, resolved)
	}
	// Unknown ids are unresolved, not counter-signals.
	if _, resolved := resolver("deadbeef-0000"); resolved {
		t.Fatal("unknown uuid should be unresolved")
	}
}

func TestConnectorResolverForCWDHandlesDeeperCWDs(t *testing.T) {
	cwd := writeCoworkSession(t, sessionConfig)
	deeper := filepath.Join(cwd, "some", "subdir")
	if err := os.MkdirAll(deeper, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if isHubspot, resolved := ConnectorResolverForCWD(deeper)("5c56899e-3e6c-4803-85ca-ff1912393966"); !resolved || !isHubspot {
		t.Fatalf("deeper cwd = (%v, %v), want (true, true)", isHubspot, resolved)
	}
}

func TestConnectorResolverForCWDNonCoworkAndMalformed(t *testing.T) {
	// A plain project directory: no session config anywhere above.
	if _, resolved := ConnectorResolverForCWD(t.TempDir())("5c56899e"); resolved {
		t.Fatal("non-cowork cwd should never resolve")
	}
	// Malformed JSON is best-effort: unresolved, never an error.
	cwd := writeCoworkSession(t, "{not json")
	if _, resolved := ConnectorResolverForCWD(cwd)("5c56899e"); resolved {
		t.Fatal("malformed session config should be unresolved")
	}
	if _, resolved := ConnectorResolverForCWD("")(""); resolved {
		t.Fatal("empty cwd should be unresolved")
	}
}
