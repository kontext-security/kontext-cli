// Package githubpolicy syncs the cloud-hosted GitHub access-control policy
// down to the managed endpoint and evaluates classified GitHub activity
// against it locally.
//
// The cloud authors GitHub policy as versioned, epoched rules. The managed
// endpoint fetches the snapshot, caches it by epoch/hash, and evaluates
// GitHub CLI / MCP / API activity locally. For ENG-426 the directive is
// observe-only: the engine records what it *would* allow or deny, but never
// blocks.
//
// Precedence in the local engine is: general deterministic guardrails >
// this synced policy > probabilistic signals.
//
// The contract mirrors packages/shared/src/github-policy-snapshot.ts in the
// kontext cloud repository.
package githubpolicy

// SchemaVersion identifies the snapshot wire format.
const SchemaVersion = "github-policy-snapshot-v1"

// Enforcement directive for the local engine.
//
//   - ModeObserve — evaluate every action and record a dry-run decision, but
//     never block. Anything other than an explicit "enforce" is treated as
//     observe.
//   - ModeEnforce — block denied actions. Reserved for a later, careful step;
//     not emitted during the observer-mode pilot.
const (
	ModeObserve = "observe"
	ModeEnforce = "enforce"
)

// Policy layers. Each rule binds a subject in exactly one layer.
const (
	LayerOrg   = "org"
	LayerUser  = "user"
	LayerAgent = "agent"
	// LayerEndpoint binds a rule to a managed endpoint's installation
	// ("ins_…") id. Unlike user/agent, this subject is always resolvable on
	// the managed endpoint, so it is how device-scoped policy is enforced
	// locally.
	LayerEndpoint = "endpoint"
)

// Rule effects.
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// Rule is a single matchable rule. nil on ResourceID / ActionName /
// BranchOrRef means "matches any" for that dimension; non-nil dimensions are
// exact string matches. For the first GitHub pilot, policy matching uses repo
// (ResourceID) + branch (BranchOrRef) + action; file path and API endpoint
// details are audit context only.
type Rule struct {
	ID    string `json:"id"`
	Layer string `json:"layer"`
	// SubjectID is the org id, kontext user id, application id, or endpoint
	// installation id depending on Layer.
	SubjectID string `json:"subjectId"`
	// ResourceID is a repository slug "owner/repo", or nil for any repository.
	ResourceID *string `json:"resourceId"`
	// ActionName is a canonical action name (e.g. "github.pr.write"), or nil
	// for any action.
	ActionName *string `json:"actionName"`
	// BranchOrRef is a branch or ref constraint, or nil for any branch.
	BranchOrRef *string `json:"branchOrRef"`
	Effect      string  `json:"effect"`
	// Specificity is a diagnostic hint the cloud computes for display/sorting.
	// The evaluator does not read it: it derives precedence from the rule's
	// own dimensions and layer (see Evaluate — most-specific-wins).
	Specificity int `json:"specificity"`
}

// Snapshot is the response body of GET /api/v1/policy/github/snapshot. The
// server resolves the organization from the install token; there is no
// organization parameter.
type Snapshot struct {
	SchemaVersion  string `json:"schemaVersion"`
	OrganizationID string `json:"organizationId"`
	// ProviderID is the GitHub provider id, or nil when the org has no GitHub
	// provider configured.
	ProviderID  *string `json:"providerId"`
	ProviderKey string  `json:"providerKey"`
	Mode        string  `json:"mode"`
	// Epoch is the active policy epoch; 0 when the org has no active policy.
	Epoch int `json:"epoch"`
	// Hash is a stable content hash over {epoch, rules}, independent of
	// GeneratedAt, so an unchanged policy keeps an unchanged hash.
	Hash        string `json:"hash"`
	Rules       []Rule `json:"rules"`
	GeneratedAt string `json:"generatedAt"`
}

// Enforce reports whether the snapshot explicitly directs enforcement.
// Anything other than the literal "enforce" is observe.
func (s Snapshot) Enforce() bool {
	return s.Mode == ModeEnforce
}
