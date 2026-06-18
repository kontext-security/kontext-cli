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

func TestEvaluateNoMatchingRuleDefaultsToDeny(t *testing.T) {
	// Rules exist but none cover this repo: default deny.
	snapshot := snapshotWithRules(Rule{
		ID: "rule-other", Layer: LayerOrg, SubjectID: testOrgID,
		ResourceID: ptr("acme/api"), Effect: EffectAllow,
	})
	evaluation, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", Resource: "acme/web"})
	if !ok || evaluation.Result != EffectDeny || evaluation.ReasonCode != ReasonCodeDeny {
		t.Fatalf("Evaluate() = %+v, want default deny for unmatched request", evaluation)
	}
	if evaluation.DecidingRuleID != "" {
		t.Fatalf("DecidingRuleID = %q, want empty when no rule matched", evaluation.DecidingRuleID)
	}
}

func TestEvaluateMoreSpecificDenyBeatsBroaderAllow(t *testing.T) {
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

	// The deny is scoped: everything off-target still allows via the broad allow.
	allowed, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", Resource: "acme/web"})
	if !ok || allowed.Result != EffectAllow {
		t.Fatalf("off-target request = %+v, want allow", allowed)
	}
}

func TestEvaluateMoreSpecificAllowBeatsBroaderDeny(t *testing.T) {
	// A broad org deny is overridden by a more specific user allow: the user is
	// carved out of an otherwise org-wide block.
	snapshot := snapshotWithRules(
		Rule{ID: "rule-org-deny", Layer: LayerOrg, SubjectID: testOrgID, ResourceID: ptr("acme/api"), Effect: EffectDeny},
		Rule{ID: "rule-user-allow", Layer: LayerUser, SubjectID: "user-1", ResourceID: ptr("acme/api"), Effect: EffectAllow},
	)

	allowed, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", Resource: "acme/api", UserID: "user-1"})
	if !ok || allowed.Result != EffectAllow {
		t.Fatalf("carved-out user = %+v, want allow", allowed)
	}
	if allowed.DecidingRuleID != "rule-user-allow" {
		t.Fatalf("DecidingRuleID = %q, want rule-user-allow", allowed.DecidingRuleID)
	}

	// Everyone else still hits the org deny.
	denied, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", Resource: "acme/api", UserID: "user-2"})
	if !ok || denied.Result != EffectDeny {
		t.Fatalf("other user = %+v, want deny", denied)
	}
}

func TestEvaluateCarveOutScenario(t *testing.T) {
	// The reported scenario:
	//   1. org deny  — any action on acme/api
	//   2. user allow — user-1 on acme/api (exception to the org block)
	//   3. user deny  — user-1, github.issue.read on acme/api (exception to the
	//      exception)
	snapshot := snapshotWithRules(
		Rule{ID: "r1-org-deny", Layer: LayerOrg, SubjectID: testOrgID, ResourceID: ptr("acme/api"), Effect: EffectDeny},
		Rule{ID: "r2-user-allow", Layer: LayerUser, SubjectID: "user-1", ResourceID: ptr("acme/api"), Effect: EffectAllow},
		Rule{ID: "r3-user-deny", Layer: LayerUser, SubjectID: "user-1", ResourceID: ptr("acme/api"), ActionName: ptr("github.issue.read"), Effect: EffectDeny},
	)

	cases := []struct {
		name    string
		request Request
		want    string
		ruleID  string
	}{
		{"user-1 allowed for a normal action", Request{Action: "github.pr.write", Resource: "acme/api", UserID: "user-1"}, EffectAllow, "r2-user-allow"},
		{"user-1 denied for the carved-out action", Request{Action: "github.issue.read", Resource: "acme/api", UserID: "user-1"}, EffectDeny, "r3-user-deny"},
		{"another user denied org-wide", Request{Action: "github.pr.write", Resource: "acme/api", UserID: "user-2"}, EffectDeny, "r1-org-deny"},
		{"another user also denied for issue.read", Request{Action: "github.issue.read", Resource: "acme/api", UserID: "user-2"}, EffectDeny, "r1-org-deny"},
	}
	for _, testCase := range cases {
		evaluation, ok := Evaluate(snapshot, Status{}, testCase.request)
		if !ok || evaluation.Result != testCase.want {
			t.Fatalf("%s: Evaluate(%+v) = %+v, want %s", testCase.name, testCase.request, evaluation, testCase.want)
		}
		if evaluation.DecidingRuleID != testCase.ruleID {
			t.Fatalf("%s: DecidingRuleID = %q, want %q", testCase.name, evaluation.DecidingRuleID, testCase.ruleID)
		}
	}
}

func TestEvaluateUserAllowGrantsThatUserWithoutAnOrgRule(t *testing.T) {
	// Org is no longer a mandatory ceiling: a user allow alone grants that user,
	// while an unrelated user falls through to default deny.
	snapshot := snapshotWithRules(
		Rule{ID: "rule-user", Layer: LayerUser, SubjectID: "user-1", Effect: EffectAllow},
	)

	allowed, ok := Evaluate(snapshot, Status{}, Request{Action: "github.repo.read", UserID: "user-1"})
	if !ok || allowed.Result != EffectAllow {
		t.Fatalf("covered user = %+v, want allow", allowed)
	}

	denied, ok := Evaluate(snapshot, Status{}, Request{Action: "github.repo.read", UserID: "user-2"})
	if !ok || denied.Result != EffectDeny {
		t.Fatalf("uncovered user = %+v, want default deny", denied)
	}
}

func TestEvaluateUnrelatedSubjectRuleDoesNotRestrictOthers(t *testing.T) {
	// A rule bound to user-2 is irrelevant to user-1; the broad org allow still
	// governs user-1. (Under the old layered-AND model this denied user-1.)
	snapshot := snapshotWithRules(
		orgAllowAll("rule-org"),
		Rule{ID: "rule-user", Layer: LayerUser, SubjectID: "user-2", Effect: EffectAllow},
	)

	for _, userID := range []string{"user-1", "user-2"} {
		evaluation, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", UserID: userID})
		if !ok || evaluation.Result != EffectAllow {
			t.Fatalf("user %q = %+v, want allow", userID, evaluation)
		}
	}
}

func TestEvaluateUserDenyCarvesAnExceptionOutOfOrgAllow(t *testing.T) {
	snapshot := snapshotWithRules(
		orgAllowAll("rule-org"),
		Rule{ID: "rule-user-deny", Layer: LayerUser, SubjectID: "user-1", Effect: EffectDeny},
	)

	denied, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", UserID: "user-1"})
	if !ok || denied.Result != EffectDeny || denied.DecidingRuleID != "rule-user-deny" {
		t.Fatalf("user-1 = %+v, want deny by rule-user-deny", denied)
	}

	allowed, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", UserID: "user-2"})
	if !ok || allowed.Result != EffectAllow {
		t.Fatalf("user-2 = %+v, want allow", allowed)
	}
}

func TestEvaluateAgentLayerMirrorsUserLayer(t *testing.T) {
	// Agent-layer rules behave like user-layer rules: a rule for app-1 carves an
	// exception for app-1 only; app-2 follows the broad org allow.
	snapshot := snapshotWithRules(
		orgAllowAll("rule-org"),
		Rule{ID: "rule-agent-deny", Layer: LayerAgent, SubjectID: "app-1", Effect: EffectDeny},
	)

	denied, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", ApplicationID: "app-1"})
	if !ok || denied.Result != EffectDeny {
		t.Fatalf("app-1 = %+v, want deny", denied)
	}

	allowed, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", ApplicationID: "app-2"})
	if !ok || allowed.Result != EffectAllow {
		t.Fatalf("app-2 = %+v, want allow", allowed)
	}
}

func TestEvaluateUnresolvedSubjectsCannotMatchUserOrAgentRules(t *testing.T) {
	// The managed endpoint resolves no Kontext user/app: user and agent rules
	// cannot match their subject, so org rules govern and the evaluation is
	// flagged as unresolved.
	allowSnapshot := snapshotWithRules(
		orgAllowAll("rule-org"),
		Rule{ID: "rule-user", Layer: LayerUser, SubjectID: "user-1", Effect: EffectAllow},
	)
	evaluation, ok := Evaluate(allowSnapshot, Status{}, Request{Action: "github.pr.write"})
	if !ok || evaluation.Result != EffectAllow {
		t.Fatalf("unresolved subject with org allow = %+v, want allow from org rule", evaluation)
	}
	if evaluation.SubjectsResolved {
		t.Fatal("SubjectsResolved = true, want false for unresolved identity")
	}

	// A user allow cannot unlock anything when the subject is unresolved: the
	// org deny still governs.
	denySnapshot := snapshotWithRules(
		Rule{ID: "rule-org-deny", Layer: LayerOrg, SubjectID: testOrgID, Effect: EffectDeny},
		Rule{ID: "rule-user-allow", Layer: LayerUser, SubjectID: "user-1", Effect: EffectAllow},
	)
	denied, ok := Evaluate(denySnapshot, Status{}, Request{Action: "github.pr.write"})
	if !ok || denied.Result != EffectDeny {
		t.Fatalf("unresolved subject with org deny = %+v, want deny", denied)
	}
}

func TestEvaluateEndpointLayerMatchesInstallationId(t *testing.T) {
	// The managed endpoint resolves no user/app, but it always knows its own
	// installation id, so endpoint-layer rules are matchable locally.
	snapshot := snapshotWithRules(
		Rule{ID: "rule-org-deny", Layer: LayerOrg, SubjectID: testOrgID, ResourceID: ptr("acme/api"), Effect: EffectDeny},
		Rule{ID: "rule-endpoint-allow", Layer: LayerEndpoint, SubjectID: "ins_device1", ResourceID: ptr("acme/api"), Effect: EffectAllow},
	)

	// This endpoint is carved out of the org-wide deny.
	allowed, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", Resource: "acme/api", EndpointID: "ins_device1"})
	if !ok || allowed.Result != EffectAllow || allowed.DecidingRuleID != "rule-endpoint-allow" {
		t.Fatalf("matching endpoint = %+v, want allow by rule-endpoint-allow", allowed)
	}

	// A different endpoint still hits the org deny.
	denied, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", Resource: "acme/api", EndpointID: "ins_device2"})
	if !ok || denied.Result != EffectDeny {
		t.Fatalf("other endpoint = %+v, want deny", denied)
	}

	// An unresolved endpoint (empty id) cannot match the endpoint rule either.
	unresolved, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", Resource: "acme/api"})
	if !ok || unresolved.Result != EffectDeny {
		t.Fatalf("empty endpoint = %+v, want deny", unresolved)
	}
}

func TestEvaluateEndpointCarveOutScenario(t *testing.T) {
	// The reported carve-out, expressed with an endpoint subject (the trusted
	// identity on the managed path):
	//   1. org deny — any action on acme/api
	//   2. endpoint allow — ins_device1 on acme/api
	//   3. endpoint deny — ins_device1, github.issue.read on acme/api
	snapshot := snapshotWithRules(
		Rule{ID: "r1-org-deny", Layer: LayerOrg, SubjectID: testOrgID, ResourceID: ptr("acme/api"), Effect: EffectDeny},
		Rule{ID: "r2-endpoint-allow", Layer: LayerEndpoint, SubjectID: "ins_device1", ResourceID: ptr("acme/api"), Effect: EffectAllow},
		Rule{ID: "r3-endpoint-deny", Layer: LayerEndpoint, SubjectID: "ins_device1", ResourceID: ptr("acme/api"), ActionName: ptr("github.issue.read"), Effect: EffectDeny},
	)

	cases := []struct {
		name    string
		request Request
		want    string
		ruleID  string
	}{
		{"endpoint allowed for a normal action", Request{Action: "github.pr.write", Resource: "acme/api", EndpointID: "ins_device1"}, EffectAllow, "r2-endpoint-allow"},
		{"endpoint denied for the carved-out action", Request{Action: "github.issue.read", Resource: "acme/api", EndpointID: "ins_device1"}, EffectDeny, "r3-endpoint-deny"},
		{"other endpoint denied org-wide", Request{Action: "github.pr.write", Resource: "acme/api", EndpointID: "ins_device2"}, EffectDeny, "r1-org-deny"},
	}
	for _, testCase := range cases {
		evaluation, ok := Evaluate(snapshot, Status{}, testCase.request)
		if !ok || evaluation.Result != testCase.want {
			t.Fatalf("%s: Evaluate(%+v) = %+v, want %s", testCase.name, testCase.request, evaluation, testCase.want)
		}
		if evaluation.DecidingRuleID != testCase.ruleID {
			t.Fatalf("%s: DecidingRuleID = %q, want %q", testCase.name, evaluation.DecidingRuleID, testCase.ruleID)
		}
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
