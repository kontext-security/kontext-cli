package githubpolicy

import (
	"testing"
)

const testOrgID = "org_test"

func ptr(value string) *string {
	return &value
}

func orgAllowAll(id string) Rule {
	return Rule{ID: id, Layer: LayerOrg, SubjectID: testOrgID, Effect: EffectAllow}
}

func snapshotWithRules(rules ...Rule) Snapshot {
	return Snapshot{
		SchemaVersion:  SchemaVersion,
		OrganizationID: testOrgID,
		ProviderKey:    "github",
		Mode:           ModeObserve,
		Epoch:          5,
		Hash:           "hash-5",
		Rules:          rules,
	}
}

func TestEvaluateNoRulesMeansNothingToDryRun(t *testing.T) {
	_, ok := Evaluate(snapshotWithRules(), Status{}, Request{Action: "github.pr.write"})
	if ok {
		t.Fatal("Evaluate() with zero rules should not produce a decision")
	}
}

func TestEvaluateOrgAllowAloneAllowsOrgWide(t *testing.T) {
	snapshot := snapshotWithRules(orgAllowAll("rule-allow"))
	for _, request := range []Request{
		{Action: "github.pr.write", Resource: "acme/api", BranchOrRef: "main"},
		{Action: "github.repo.read"},
	} {
		evaluation, ok := Evaluate(snapshot, Status{}, request)
		if !ok || evaluation.Result != EffectAllow {
			t.Fatalf("Evaluate(%+v) = %+v, want org-wide allow", request, evaluation)
		}
		if evaluation.ReasonCode != ReasonCodeAllow {
			t.Fatalf("ReasonCode = %q, want %q", evaluation.ReasonCode, ReasonCodeAllow)
		}
		if evaluation.DecidingRuleID != "rule-allow" {
			t.Fatalf("DecidingRuleID = %q, want rule-allow", evaluation.DecidingRuleID)
		}
	}
}

func TestEvaluateDenyBeatsAllowRegardlessOfSpecificity(t *testing.T) {
	snapshot := snapshotWithRules(
		Rule{
			ID: "rule-deny", Layer: LayerOrg, SubjectID: testOrgID,
			ResourceID: ptr("acme/api"), ActionName: ptr("github.pr.write"), Effect: EffectDeny, Specificity: 5,
		},
		orgAllowAll("rule-allow"),
	)

	denied, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", Resource: "acme/api"})
	if !ok || denied.Result != EffectDeny || denied.ReasonCode != ReasonCodeDeny {
		t.Fatalf("targeted request = %+v, want deny", denied)
	}
	if denied.DecidingRuleID != "rule-deny" {
		t.Fatalf("DecidingRuleID = %q, want rule-deny", denied.DecidingRuleID)
	}
	var decidedMarked bool
	for _, rule := range denied.MatchedRules {
		if rule.ID == "rule-deny" && rule.Decided {
			decidedMarked = true
		}
	}
	if !decidedMarked {
		t.Fatalf("MatchedRules = %+v, want rule-deny marked decided", denied.MatchedRules)
	}

	// The deny is scoped: everything off-target still allows.
	allowed, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", Resource: "acme/web"})
	if !ok || allowed.Result != EffectAllow {
		t.Fatalf("off-target request = %+v, want allow", allowed)
	}
}

func TestEvaluateOrgLayerIsStrict(t *testing.T) {
	// A user-layer rule alone activates nothing for the org layer: zero org
	// rules deny everything.
	snapshot := snapshotWithRules(
		Rule{ID: "rule-user", Layer: LayerUser, SubjectID: "user-1", Effect: EffectAllow},
	)
	evaluation, ok := Evaluate(snapshot, Status{}, Request{Action: "github.repo.read", UserID: "user-1"})
	if !ok || evaluation.Result != EffectDeny {
		t.Fatalf("Evaluate() = %+v, want deny from strict org layer", evaluation)
	}
}

func TestEvaluateUserLayerAbstainsUntilItHasRulesThenSilenceVetoes(t *testing.T) {
	// No user rules: layer abstains, org allow carries the decision.
	abstaining := snapshotWithRules(orgAllowAll("rule-org"))
	evaluation, ok := Evaluate(abstaining, Status{}, Request{Action: "github.pr.write", UserID: "user-1"})
	if !ok || evaluation.Result != EffectAllow {
		t.Fatalf("abstaining user layer = %+v, want allow", evaluation)
	}

	// One user rule for someone else: the layer is active, silence vetoes.
	active := snapshotWithRules(
		orgAllowAll("rule-org"),
		Rule{ID: "rule-user", Layer: LayerUser, SubjectID: "user-2", Effect: EffectAllow},
	)
	evaluation, ok = Evaluate(active, Status{}, Request{Action: "github.pr.write", UserID: "user-1"})
	if !ok || evaluation.Result != EffectDeny {
		t.Fatalf("active user layer without matching allow = %+v, want deny", evaluation)
	}

	// The covered user is allowed.
	evaluation, ok = Evaluate(active, Status{}, Request{Action: "github.pr.write", UserID: "user-2"})
	if !ok || evaluation.Result != EffectAllow {
		t.Fatalf("active user layer with matching allow = %+v, want allow", evaluation)
	}
}

func TestEvaluateAgentLayerMirrorsUserLayer(t *testing.T) {
	snapshot := snapshotWithRules(
		orgAllowAll("rule-org"),
		Rule{ID: "rule-agent", Layer: LayerAgent, SubjectID: "app-1", Effect: EffectAllow},
	)
	evaluation, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", ApplicationID: "app-2"})
	if !ok || evaluation.Result != EffectDeny {
		t.Fatalf("agent layer veto = %+v, want deny", evaluation)
	}
}

func TestEvaluateUnresolvedSubjectsCannotMatchUserOrAgentRules(t *testing.T) {
	snapshot := snapshotWithRules(
		orgAllowAll("rule-org"),
		Rule{ID: "rule-user", Layer: LayerUser, SubjectID: "user-1", Effect: EffectAllow},
	)
	// The managed endpoint resolves no Kontext user: the user layer is active
	// and silence vetoes, flagged as unresolved subject on the evaluation.
	evaluation, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write"})
	if !ok || evaluation.Result != EffectDeny {
		t.Fatalf("unresolved user subject = %+v, want deny", evaluation)
	}
	if evaluation.SubjectsResolved {
		t.Fatal("SubjectsResolved = true, want false for unresolved identity")
	}
}

func TestEvaluateExactDimensionMatchingWithNullWildcards(t *testing.T) {
	snapshot := snapshotWithRules(Rule{
		ID: "rule-main", Layer: LayerOrg, SubjectID: testOrgID,
		ResourceID:  ptr("acme/api"),
		ActionName:  ptr("github.repo.write"),
		BranchOrRef: ptr("main"),
		Effect:      EffectAllow,
	})

	cases := []struct {
		request Request
		want    string
	}{
		{Request{Action: "github.repo.write", Resource: "acme/api", BranchOrRef: "main"}, EffectAllow},
		{Request{Action: "github.repo.write", Resource: "acme/api", BranchOrRef: "dev"}, EffectDeny},
		{Request{Action: "github.repo.write", Resource: "acme/api"}, EffectDeny},
		{Request{Action: "github.repo.read", Resource: "acme/api", BranchOrRef: "main"}, EffectDeny},
		// No globs: a prefix of the slug must not match.
		{Request{Action: "github.repo.write", Resource: "acme/api-v2", BranchOrRef: "main"}, EffectDeny},
	}
	for _, testCase := range cases {
		evaluation, ok := Evaluate(snapshot, Status{}, testCase.request)
		if !ok || evaluation.Result != testCase.want {
			t.Fatalf("Evaluate(%+v) = %+v, want %s", testCase.request, evaluation, testCase.want)
		}
	}
}

func TestEvaluateRecordsSnapshotVersionAndStaleness(t *testing.T) {
	snapshot := snapshotWithRules(orgAllowAll("rule-org"))
	evaluation, ok := Evaluate(snapshot, Status{Stale: true}, Request{Action: "github.pr.read"})
	if !ok {
		t.Fatal("Evaluate() returned no decision")
	}
	if evaluation.Epoch != 5 || evaluation.Hash != "hash-5" {
		t.Fatalf("Epoch/Hash = %d/%q, want 5/hash-5", evaluation.Epoch, evaluation.Hash)
	}
	if !evaluation.Stale {
		t.Fatal("Stale = false, want true when serving an unconfirmed snapshot")
	}
	if evaluation.Mode != ModeObserve {
		t.Fatalf("Mode = %q, want observe", evaluation.Mode)
	}
}
