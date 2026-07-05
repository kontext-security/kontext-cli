package providerpolicy

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
	// LayerGroup binds a rule to a SCIM directory group's uuid. It matches
	// when the id is in the snapshot's EndpointDirectory.GroupIDs — the cloud
	// resolves this endpoint's user email against the org's SCIM directory at
	// snapshot-generation time. Only schema versions with GroupLayer support
	// carry group-layer rules.
	LayerGroup = "group"
)

// Rule effects.
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// Rule is a single matchable rule. nil on ResourceID / ActionName /
// BranchOrRef means "matches any" for that dimension; non-nil dimensions are
// exact string matches. What ResourceID and BranchOrRef mean is up to the
// provider (GitHub: repository slug + branch; HubSpot: CRM object type, with
// BranchOrRef unused and always nil).
type Rule struct {
	ID    string `json:"id"`
	Layer string `json:"layer"`
	// SubjectID is the org id, kontext user id, application id, endpoint
	// installation id, or directory group uuid depending on Layer.
	SubjectID string `json:"subjectId"`
	// ResourceID is the provider resource anchor, or nil for any resource.
	ResourceID *string `json:"resourceId"`
	// ActionName is a canonical action name (e.g. "github.pr.write",
	// "hubspot.object.write"), or nil for any action.
	ActionName *string `json:"actionName"`
	// BranchOrRef is a branch or ref constraint, or nil for any branch.
	BranchOrRef *string `json:"branchOrRef"`
	Effect      string  `json:"effect"`
	// Specificity is a diagnostic hint the cloud computes for display/sorting.
	// The evaluator does not read it: it derives precedence from the rule's
	// own dimensions and layer (see Evaluate — most-specific-wins).
	Specificity int `json:"specificity"`
}

// Snapshot is the response body of a provider's snapshot endpoint. The server
// resolves the organization from the install token; there is no organization
// parameter.
type Snapshot struct {
	SchemaVersion  string `json:"schemaVersion"`
	OrganizationID string `json:"organizationId"`
	// ProviderID is the provider row id, or nil when the org's policy is
	// key-only.
	ProviderID  *string `json:"providerId"`
	ProviderKey string  `json:"providerKey"`
	Mode        string  `json:"mode"`
	// Epoch is the active policy epoch; 0 when the org has no active policy.
	Epoch int `json:"epoch"`
	// Hash is a stable content hash over the epoch, rules, and (when the
	// contract carries one) the endpoint directory — a directory membership
	// change changes the hash. Independent of GeneratedAt, so an unchanged
	// policy keeps an unchanged hash.
	Hash  string `json:"hash"`
	Rules []Rule `json:"rules"`
	// PayloadCaptureMode is the org's tool-payload capture directive
	// ("omitted" | "summary" | "full"). Absent on pre-capture servers and on
	// providers that do not carry it (the github snapshot is authoritative).
	// Deliberately EXCLUDED from Hash (server-side decision), so a mode
	// flip arrives on a snapshot whose hash is unchanged — consumers must
	// not gate mode application on hash inequality (see Cache.Apply).
	// Normalize via payloadcapture.NormalizeMode; unknown values fall back
	// to "summary" (never capture on an unrecognized directive).
	PayloadCaptureMode string `json:"payloadCaptureMode,omitempty"`
	// EndpointDirectory is this endpoint's resolved directory identity (nil
	// on versions without directory support or when the request carried no
	// installation id).
	EndpointDirectory *EndpointDirectory `json:"endpointDirectory,omitempty"`
	GeneratedAt       string             `json:"generatedAt"`
}

// EndpointDirectory is the endpoint's directory identity, resolved by the
// cloud at snapshot-generation time from the endpoint-reported user email and
// the org's SCIM directory. Membership is deliberately not baked into policy
// epochs: a SCIM change shows up here on the next snapshot refresh.
//
// DirectoryUserID is nil when the email was missing, unmatched, or ambiguous
// (ambiguity fails closed — never a union of candidate groups); GroupIDs is
// then empty and group-layer rules can never match.
type EndpointDirectory struct {
	InstallationID  string   `json:"installationId"`
	DirectoryUserID *string  `json:"directoryUserId"`
	GroupIDs        []string `json:"groupIds"`
}

// Enforce reports whether the snapshot explicitly directs enforcement.
// Anything other than the literal "enforce" is observe.
func (s Snapshot) Enforce() bool {
	return s.Mode == ModeEnforce
}
