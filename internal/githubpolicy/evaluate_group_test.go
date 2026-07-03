package githubpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testEndpointID = "ins_device1"
	groupEng       = "grp-engineering"
	groupMkt       = "grp-marketing"
)

// snapshotV3 builds a v3 snapshot whose endpoint directory places this
// endpoint in the given groups.
func snapshotV3(groupIDs []string, rules ...Rule) Snapshot {
	snapshot := snapshotWithRules(rules...)
	snapshot.SchemaVersion = SchemaVersionV3
	userID := "dir-user-1"
	snapshot.EndpointDirectory = &EndpointDirectory{
		InstallationID:  testEndpointID,
		DirectoryUserID: &userID,
		GroupIDs:        groupIDs,
	}
	return snapshot
}

// TestEvaluateGroupLayerMatrix is the shared evaluator matrix for the group
// layer; the API's snapshot/policy specs mirror these cases. Precedence is
// dimensions first, then org < group < user/agent/endpoint, then deny on an
// exact tie.
func TestEvaluateGroupLayerMatrix(t *testing.T) {
	request := Request{Action: "github.pr.write", Resource: "acme/api", EndpointID: testEndpointID}
	cases := []struct {
		name   string
		groups []string
		rules  []Rule
		want   string
		ruleID string
	}{
		{
			name:   "group deny beats org allow (group more specific)",
			groups: []string{groupEng},
			rules: []Rule{
				orgAllowAll("r-org-allow"),
				{ID: "r-group-deny", Layer: LayerGroup, SubjectID: groupEng, Effect: EffectDeny},
			},
			want: EffectDeny, ruleID: "r-group-deny",
		},
		{
			name:   "group allow beats org deny",
			groups: []string{groupEng},
			rules: []Rule{
				{ID: "r-org-deny", Layer: LayerOrg, SubjectID: testOrgID, Effect: EffectDeny},
				{ID: "r-group-allow", Layer: LayerGroup, SubjectID: groupEng, Effect: EffectAllow},
			},
			want: EffectAllow, ruleID: "r-group-allow",
		},
		{
			name:   "endpoint deny beats group allow (endpoint more specific)",
			groups: []string{groupEng},
			rules: []Rule{
				{ID: "r-group-allow", Layer: LayerGroup, SubjectID: groupEng, Effect: EffectAllow},
				{ID: "r-endpoint-deny", Layer: LayerEndpoint, SubjectID: testEndpointID, Effect: EffectDeny},
			},
			want: EffectDeny, ruleID: "r-endpoint-deny",
		},
		{
			name:   "endpoint allow beats group deny",
			groups: []string{groupEng},
			rules: []Rule{
				{ID: "r-group-deny", Layer: LayerGroup, SubjectID: groupEng, Effect: EffectDeny},
				{ID: "r-endpoint-allow", Layer: LayerEndpoint, SubjectID: testEndpointID, Effect: EffectAllow},
			},
			want: EffectAllow, ruleID: "r-endpoint-allow",
		},
		{
			name:   "two groups conflicting at equal dimensions: deny wins the exact tie",
			groups: []string{groupEng, groupMkt},
			rules: []Rule{
				{ID: "r-eng-allow", Layer: LayerGroup, SubjectID: groupEng, Effect: EffectAllow},
				{ID: "r-mkt-deny", Layer: LayerGroup, SubjectID: groupMkt, Effect: EffectDeny},
			},
			want: EffectDeny, ruleID: "r-mkt-deny",
		},
		{
			name:   "group rule with more pinned dimensions beats endpoint wildcard (dimensions before layer)",
			groups: []string{groupEng},
			rules: []Rule{
				{ID: "r-endpoint-allow", Layer: LayerEndpoint, SubjectID: testEndpointID, ResourceID: ptr("acme/api"), Effect: EffectAllow},
				{ID: "r-group-deny", Layer: LayerGroup, SubjectID: groupEng, ResourceID: ptr("acme/api"), ActionName: ptr("github.pr.write"), Effect: EffectDeny},
			},
			want: EffectDeny, ruleID: "r-group-deny",
		},
		{
			name:   "rule for a group this endpoint is not in never matches",
			groups: []string{groupEng},
			rules: []Rule{
				orgAllowAll("r-org-allow"),
				{ID: "r-mkt-deny", Layer: LayerGroup, SubjectID: groupMkt, Effect: EffectDeny},
			},
			want: EffectAllow, ruleID: "r-org-allow",
		},
	}
	for _, testCase := range cases {
		snapshot := snapshotV3(testCase.groups, testCase.rules...)
		evaluation, ok := Evaluate(snapshot, Status{}, request)
		if !ok || evaluation.Result != testCase.want {
			t.Fatalf("%s: Evaluate() = %+v, want %s", testCase.name, evaluation, testCase.want)
		}
		if evaluation.DecidingRuleID != testCase.ruleID {
			t.Fatalf("%s: DecidingRuleID = %q, want %q", testCase.name, evaluation.DecidingRuleID, testCase.ruleID)
		}
		if !evaluation.GroupsResolved {
			t.Fatalf("%s: GroupsResolved = false, want true", testCase.name)
		}
		if evaluation.SchemaVersion != SchemaVersionV3 {
			t.Fatalf("%s: SchemaVersion = %q, want v3", testCase.name, evaluation.SchemaVersion)
		}
	}
}

func TestEvaluateGroupRulesInertWithoutDirectoryIdentity(t *testing.T) {
	rules := []Rule{
		{ID: "r-org-deny", Layer: LayerOrg, SubjectID: testOrgID, Effect: EffectDeny},
		{ID: "r-group-allow", Layer: LayerGroup, SubjectID: groupEng, Effect: EffectAllow},
	}
	request := Request{Action: "github.pr.write", EndpointID: testEndpointID}

	// Empty groupIds (email missing/unmatched/ambiguous): fail closed to org deny.
	empty := snapshotV3(nil, rules...)
	empty.EndpointDirectory.DirectoryUserID = nil
	evaluation, ok := Evaluate(empty, Status{}, request)
	if !ok || evaluation.Result != EffectDeny || evaluation.GroupsResolved {
		t.Fatalf("empty groupIds = %+v, want deny with GroupsResolved=false", evaluation)
	}

	// Nil endpointDirectory (no installation id sent, or v2 snapshot): same.
	noDirectory := snapshotWithRules(rules...)
	evaluation, ok = Evaluate(noDirectory, Status{}, request)
	if !ok || evaluation.Result != EffectDeny || evaluation.GroupsResolved {
		t.Fatalf("nil endpointDirectory = %+v, want deny with GroupsResolved=false", evaluation)
	}
}

func TestFetchSnapshotNegotiatesV3AndAcceptsV2(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		// A pre-v3 server ignores the params and answers v2.
		_ = json.NewEncoder(w).Encode(testSnapshot(3, "hash-3"))
	}))
	t.Cleanup(server.Close)

	snapshot, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token", testEndpointID)
	if err != nil {
		t.Fatalf("FetchSnapshot() error = %v", err)
	}
	if snapshot.SchemaVersion != SchemaVersionV2 {
		t.Fatalf("schema = %q, want accepted v2 during the negotiation window", snapshot.SchemaVersion)
	}
	if !strings.Contains(gotQuery, "schema="+SchemaVersionV3) || !strings.Contains(gotQuery, "installation_id="+testEndpointID) {
		t.Fatalf("query = %q, want schema=v3 and installation_id", gotQuery)
	}
}

func TestFetchSnapshotDecodesV3EndpointDirectory(t *testing.T) {
	served := snapshotV3([]string{groupEng},
		Rule{ID: "r-group", Layer: LayerGroup, SubjectID: groupEng, Effect: EffectAllow})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(served)
	}))
	t.Cleanup(server.Close)

	snapshot, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token", testEndpointID)
	if err != nil {
		t.Fatalf("FetchSnapshot() error = %v", err)
	}
	if snapshot.EndpointDirectory == nil || len(snapshot.EndpointDirectory.GroupIDs) != 1 {
		t.Fatalf("endpointDirectory = %+v", snapshot.EndpointDirectory)
	}
}

func TestFetchSnapshotRejectsGroupRuleInV2Body(t *testing.T) {
	// The server contract filters group rules out of v2 responses; a v2 body
	// containing one is misbehavior and must fail closed, not half-apply.
	served := testSnapshot(3, "hash-3")
	served.Rules = append(served.Rules, Rule{ID: "r-group", Layer: LayerGroup, SubjectID: groupEng, Effect: EffectAllow})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(served)
	}))
	t.Cleanup(server.Close)

	if _, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token", testEndpointID); err == nil {
		t.Fatal("FetchSnapshot() accepted a group rule in a v2 snapshot")
	}
}

func TestEvaluateIgnoresDirectoryForAnotherEndpoint(t *testing.T) {
	// A persisted cache can outlive re-enrollment (new installation id) and
	// carry the previous identity's memberships. Groups must only apply when
	// the directory is for the evaluating endpoint.
	snapshot := snapshotV3([]string{groupEng},
		Rule{ID: "r-org-deny", Layer: LayerOrg, SubjectID: testOrgID, Effect: EffectDeny},
		Rule{ID: "r-group-allow", Layer: LayerGroup, SubjectID: groupEng, Effect: EffectAllow})
	evaluation, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", EndpointID: "ins_reenrolled_device"})
	if !ok || evaluation.Result != EffectDeny || evaluation.GroupsResolved {
		t.Fatalf("foreign directory = %+v, want org deny with GroupsResolved=false", evaluation)
	}
}

func TestFetchSnapshotRejectsGroupIdsWithoutResolvedUser(t *testing.T) {
	// directoryUserId null means missing/unmatched/ambiguous — the contract
	// pins groupIds empty in that case; anything else must fail closed.
	served := snapshotV3([]string{groupEng})
	served.EndpointDirectory.DirectoryUserID = nil
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(served)
	}))
	t.Cleanup(server.Close)

	if _, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token", testEndpointID); err == nil {
		t.Fatal("FetchSnapshot() accepted group ids without a resolved directory user")
	}
}

func TestFetchSnapshotRejectsV3WithoutEndpointDirectory(t *testing.T) {
	// We always identify ourselves via installation_id, so a v3 answer with
	// no directory block is server misbehavior — accepting it would silently
	// strip group-layer carve-out denies.
	served := snapshotV3(nil)
	served.EndpointDirectory = nil
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(served)
	}))
	t.Cleanup(server.Close)

	if _, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token", testEndpointID); err == nil {
		t.Fatal("FetchSnapshot() accepted a v3 snapshot without an endpoint directory")
	}
}

func TestFetchSnapshotRejectsForeignEndpointDirectory(t *testing.T) {
	// A directory echoed for a different installation id (e.g. a response
	// cache ignoring the query string) must fail closed, not apply another
	// user's group memberships.
	served := snapshotV3([]string{groupEng})
	served.EndpointDirectory.InstallationID = "ins_other_device"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(served)
	}))
	t.Cleanup(server.Close)

	if _, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token", testEndpointID); err == nil {
		t.Fatal("FetchSnapshot() accepted a directory for another endpoint")
	}
}

func TestEvaluateGroupRuleWithNilDirectoryIsInert(t *testing.T) {
	// v3 snapshot carrying group rules while this endpoint has no directory
	// identity at all: rules stay inert, org layer governs.
	snapshot := snapshotV3(nil,
		orgAllowAll("r-org-allow"),
		Rule{ID: "r-group-deny", Layer: LayerGroup, SubjectID: groupEng, Effect: EffectDeny})
	snapshot.EndpointDirectory = nil
	evaluation, ok := Evaluate(snapshot, Status{}, Request{Action: "github.pr.write", EndpointID: testEndpointID})
	if !ok || evaluation.Result != EffectAllow || evaluation.GroupsResolved {
		t.Fatalf("nil directory with group rules = %+v, want org allow with GroupsResolved=false", evaluation)
	}
}

func TestFetchSnapshotRejectsUnknownLayerInV3(t *testing.T) {
	served := snapshotV3(nil, Rule{ID: "r-future", Layer: "team", SubjectID: "t-1", Effect: EffectAllow})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(served)
	}))
	t.Cleanup(server.Close)

	if _, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token", testEndpointID); err == nil {
		t.Fatal("FetchSnapshot() accepted an unknown layer")
	}
}
