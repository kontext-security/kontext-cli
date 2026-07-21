package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

func TestCedarDecisionEvidenceCategoryIsNeverAuthoritative(t *testing.T) {
	cases := []struct {
		mode cedareval.RolloutMode
		want string
	}{
		{cedareval.RolloutModeEnforce, "dry_run"},
		{cedareval.RolloutModeObserve, "dry_run"},
		{cedareval.RolloutModeDisabled, "dry_run"},
	}
	for _, tc := range cases {
		got := cedarDecisionCategory(risk.CedarEvidence{AppliedRolloutMode: tc.mode})
		if got != tc.want {
			t.Errorf("cedarDecisionCategory(mode=%q) = %q, want %q", tc.mode, got, tc.want)
		}
	}
}

func TestSaveDecisionWritesOneAuthoritativeEnforceDecision(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	decision := risk.RiskDecision{
		Decision:   risk.DecisionDeny,
		Reason:     "local Cedar policy decision",
		ReasonCode: string(cedareval.ReasonExplicitForbid),
		RiskEvent: risk.RiskEvent{
			Decision:      risk.DecisionDeny,
			DecisionStage: "cedar_policy",
		},
		Cedar: &risk.CedarEvidence{
			PolicyHash:         strings.Repeat("a", 64),
			AppliedRolloutMode: cedareval.RolloutModeEnforce,
			Mapping: cedareval.DecisionMapping{
				DerivedCedarAction:  cedareval.DerivedCedarActionDeny,
				EffectiveReasonCode: cedareval.ReasonExplicitForbid,
			},
		},
	}
	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "session-1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolUseID:     "tool-1",
	}, decision); err != nil {
		t.Fatal(err)
	}

	var authoritative, evidence int
	err = store.db.QueryRowContext(context.Background(), `
select
  count(*) filter (where coalesce(decision_category, '') <> 'dry_run'),
  count(*) filter (where provider = 'cedar' and decision_category = 'dry_run')
from authorization_actions
where canonical_event_type = 'request.decided'
	`).Scan(&authoritative, &evidence)
	if err != nil {
		t.Fatal(err)
	}
	if authoritative != 1 || evidence != 1 {
		t.Fatalf("decision rows = authoritative %d evidence %d, want 1 and 1", authoritative, evidence)
	}
}
