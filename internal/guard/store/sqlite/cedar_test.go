package sqlite

import (
	"testing"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
)

// ledgerAcceptedDecisionResults is the set the authorization-ledger upload
// contract accepts for decision_result on a decided action ({allow, deny},
// the same values the non-Cedar path emits). Emitting anything else is
// rejected on upload. This test pins the projection so it cannot drift back to
// uppercase or a third value.
var ledgerAcceptedDecisionResults = map[string]struct{}{
	"allow": {},
	"deny":  {},
}

func TestCedarLedgerDecisionResultMatchesIngestContract(t *testing.T) {
	cases := []struct {
		action cedareval.DerivedCedarAction
		want   string
	}{
		{cedareval.DerivedCedarActionAllow, "allow"},
		{cedareval.DerivedCedarActionDeny, "deny"},
		// No approval channel in v1: an ask collapses to a fail-closed deny.
		{cedareval.DerivedCedarActionAsk, "deny"},
	}

	for _, tc := range cases {
		got := cedarLedgerDecisionResult(tc.action)
		if got != tc.want {
			t.Errorf("cedarLedgerDecisionResult(%q) = %q, want %q", tc.action, got, tc.want)
		}
		if _, ok := ledgerAcceptedDecisionResults[got]; !ok {
			t.Errorf("cedarLedgerDecisionResult(%q) = %q, which the ingest boundary rejects", tc.action, got)
		}
	}
}
