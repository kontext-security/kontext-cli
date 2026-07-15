package sqlite

import (
	"testing"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

// A Cedar row is a dry-run shadow in observe mode and an authoritative decision
// in enforce mode; the category must distinguish them so authoritative denials
// are not filtered out as shadows.
func TestCedarDecisionCategoryReflectsAppliedMode(t *testing.T) {
	cases := []struct {
		mode cedareval.RolloutMode
		want string
	}{
		{cedareval.RolloutModeEnforce, "cedar_policy"},
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
