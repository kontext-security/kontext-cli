package githubpolicy

import (
	"strings"
	"testing"
)

func snapshotForValidation(rules ...Rule) Snapshot {
	return Snapshot{
		SchemaVersion:  SchemaVersion,
		OrganizationID: "org_test",
		ProviderKey:    "github",
		Mode:           ModeObserve,
		Epoch:          1,
		Hash:           "hash-1",
		Rules:          rules,
	}
}

func TestValidateSnapshotAcceptsEndpointLayer(t *testing.T) {
	// Regression: endpoint-layer rules must pass validation, otherwise a fetch
	// that includes them fails and the daemon silently keeps a stale snapshot.
	snapshot := snapshotForValidation(
		Rule{ID: "r-org", Layer: LayerOrg, SubjectID: "org_test", Effect: EffectDeny},
		Rule{ID: "r-endpoint", Layer: LayerEndpoint, SubjectID: "ins_device1", ResourceID: ptr("acme/api"), Effect: EffectAllow},
		Rule{ID: "r-user", Layer: LayerUser, SubjectID: "user-1", Effect: EffectAllow},
		Rule{ID: "r-agent", Layer: LayerAgent, SubjectID: "app-1", Effect: EffectAllow},
	)
	if err := validateSnapshot(snapshot); err != nil {
		t.Fatalf("validateSnapshot() = %v, want nil for all known layers", err)
	}
}

func TestValidateSnapshotRejectsUnknownLayer(t *testing.T) {
	snapshot := snapshotForValidation(
		Rule{ID: "r-bad", Layer: "device", SubjectID: "x", Effect: EffectAllow},
	)
	err := validateSnapshot(snapshot)
	if err == nil || !strings.Contains(err.Error(), "unknown layer") {
		t.Fatalf("validateSnapshot() = %v, want unknown-layer error", err)
	}
}
