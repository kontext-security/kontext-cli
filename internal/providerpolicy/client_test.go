package providerpolicy

import (
	"strings"
	"testing"
)

func testConfig() Config {
	return Config{
		ProviderKey:      "testprov",
		SnapshotEndpoint: "/api/v1/policy/testprov/snapshot",
		RequestSchema:    "testprov-policy-snapshot-v2",
		Schemas: []SchemaSupport{
			{Version: "testprov-policy-snapshot-v2", GroupLayer: true, Directory: true},
			{Version: "testprov-policy-snapshot-v1"},
		},
		CacheFileName:    "testprov-policy-snapshot.json",
		CacheTempPattern: ".testprov-policy-*.tmp",
	}
}

func testPtr(value string) *string { return &value }

func snapshotForValidation(schemaVersion string, rules ...Rule) Snapshot {
	return Snapshot{
		SchemaVersion:  schemaVersion,
		OrganizationID: "org_test",
		ProviderKey:    "testprov",
		Mode:           ModeObserve,
		Epoch:          1,
		Hash:           "hash-1",
		Rules:          rules,
	}
}

func mustSchema(t *testing.T, config Config, version string) SchemaSupport {
	t.Helper()
	schema, ok := config.schemaSupport(version)
	if !ok {
		t.Fatalf("schemaSupport(%q) missing from test config", version)
	}
	return schema
}

func TestValidateSnapshotAcceptsEndpointLayer(t *testing.T) {
	// Regression: endpoint-layer rules must pass validation, otherwise a fetch
	// that includes them fails and the daemon silently keeps a stale snapshot.
	config := testConfig()
	snapshot := snapshotForValidation("testprov-policy-snapshot-v1",
		Rule{ID: "r-org", Layer: LayerOrg, SubjectID: "org_test", Effect: EffectDeny},
		Rule{ID: "r-endpoint", Layer: LayerEndpoint, SubjectID: "ins_device1", ResourceID: testPtr("acme/api"), Effect: EffectAllow},
		Rule{ID: "r-user", Layer: LayerUser, SubjectID: "user-1", Effect: EffectAllow},
		Rule{ID: "r-agent", Layer: LayerAgent, SubjectID: "app-1", Effect: EffectAllow},
	)
	schema := mustSchema(t, config, snapshot.SchemaVersion)
	if err := validateSnapshot(snapshot, schema, "", config); err != nil {
		t.Fatalf("validateSnapshot() = %v, want nil for all known layers", err)
	}
}

func TestValidateSnapshotRejectsUnknownLayer(t *testing.T) {
	config := testConfig()
	snapshot := snapshotForValidation("testprov-policy-snapshot-v1",
		Rule{ID: "r-bad", Layer: "device", SubjectID: "x", Effect: EffectAllow},
	)
	schema := mustSchema(t, config, snapshot.SchemaVersion)
	err := validateSnapshot(snapshot, schema, "", config)
	if err == nil || !strings.Contains(err.Error(), "unknown layer") {
		t.Fatalf("validateSnapshot() = %v, want unknown-layer error", err)
	}
}

func TestValidateSnapshotRejectsGroupRuleWithoutGroupSupport(t *testing.T) {
	config := testConfig()
	snapshot := snapshotForValidation("testprov-policy-snapshot-v1",
		Rule{ID: "r-group", Layer: LayerGroup, SubjectID: "group-uuid-1", Effect: EffectDeny},
	)
	schema := mustSchema(t, config, snapshot.SchemaVersion)
	err := validateSnapshot(snapshot, schema, "", config)
	if err == nil || !strings.Contains(err.Error(), "layer") {
		t.Fatalf("validateSnapshot() = %v, want group-layer rejection on a non-group schema", err)
	}
}

func TestValidateSnapshotAcceptsGroupRuleWithGroupSupport(t *testing.T) {
	config := testConfig()
	snapshot := snapshotForValidation("testprov-policy-snapshot-v2",
		Rule{ID: "r-group", Layer: LayerGroup, SubjectID: "group-uuid-1", Effect: EffectDeny},
	)
	snapshot.EndpointDirectory = &EndpointDirectory{
		InstallationID:  "ins_device1",
		DirectoryUserID: testPtr("dir-user-1"),
		GroupIDs:        []string{"group-uuid-1"},
	}
	schema := mustSchema(t, config, snapshot.SchemaVersion)
	if err := validateSnapshot(snapshot, schema, "ins_device1", config); err != nil {
		t.Fatalf("validateSnapshot() = %v, want nil", err)
	}
}

func TestValidateSnapshotRequiresDirectoryWhenSchemaPromisesOne(t *testing.T) {
	config := testConfig()
	snapshot := snapshotForValidation("testprov-policy-snapshot-v2",
		Rule{ID: "r-org", Layer: LayerOrg, SubjectID: "org_test", Effect: EffectAllow},
	)
	schema := mustSchema(t, config, snapshot.SchemaVersion)
	err := validateSnapshot(snapshot, schema, "ins_device1", config)
	if err == nil || !strings.Contains(err.Error(), "endpoint directory") {
		t.Fatalf("validateSnapshot() = %v, want missing-directory rejection", err)
	}
}
