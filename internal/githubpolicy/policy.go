// Package githubpolicy classifies GitHub activity (gh / git / curl / GitHub
// MCP / WebFetch) into canonical provider actions and binds the shared
// provider-policy sync machinery (internal/providerpolicy) to the GitHub
// snapshot contract.
//
// The contract mirrors packages/shared/src/github/policy-snapshot.ts in the
// kontext cloud repository. For ENG-426 the directive is observe-only: the
// engine records what it *would* allow or deny, but never blocks.
package githubpolicy

import (
	"context"
	"net/http"
	"time"

	"github.com/kontext-security/kontext-cli/internal/providerpolicy"
)

// Snapshot wire-format versions. v2 added the endpoint layer and
// most-specific-wins evaluation. v3 added the group layer (SCIM directory
// groups) and the endpointDirectory block carrying this endpoint's resolved
// directory identity.
//
// The client requests v3 but accepts v2 for one release: a pre-v3 server
// ignores the negotiation query params and answers v2 (with group-layer rules
// filtered out server-side). Any other version is rejected (fail closed)
// rather than misread under the wrong semantics.
const (
	SchemaVersionV2 = "github-policy-snapshot-v2"
	SchemaVersionV3 = "github-policy-snapshot-v3"
)

// SnapshotEndpoint is the cloud path serving the GitHub policy snapshot.
// Tenancy is resolved from the install token.
const SnapshotEndpoint = "/api/v1/policy/github/snapshot"

// Config binds the shared sync machinery to the GitHub snapshot contract.
var Config = providerpolicy.Config{
	ProviderKey:      "github",
	SnapshotEndpoint: SnapshotEndpoint,
	RequestSchema:    SchemaVersionV3,
	Schemas: []providerpolicy.SchemaSupport{
		{Version: SchemaVersionV3, GroupLayer: true, Directory: true},
		{Version: SchemaVersionV2},
	},
	CacheFileName:    "github-policy-snapshot.json",
	CacheTempPattern: ".github-policy-*.tmp",
	RefreshEnvVar:    "KONTEXT_GITHUB_POLICY_REFRESH_INTERVAL",
}

// Re-exported shared types: consumers of GitHub policy keep importing this
// package; the semantics live in providerpolicy and are shared verbatim with
// every other provider.
type (
	Rule              = providerpolicy.Rule
	Snapshot          = providerpolicy.Snapshot
	EndpointDirectory = providerpolicy.EndpointDirectory
	Status            = providerpolicy.Status
	SnapshotProvider  = providerpolicy.SnapshotProvider
	Cache             = providerpolicy.Cache
	Request           = providerpolicy.Request
	MatchedRule       = providerpolicy.MatchedRule
	Evaluation        = providerpolicy.Evaluation
)

// Re-exported shared constants.
const (
	ModeObserve = providerpolicy.ModeObserve
	ModeEnforce = providerpolicy.ModeEnforce

	LayerOrg      = providerpolicy.LayerOrg
	LayerUser     = providerpolicy.LayerUser
	LayerAgent    = providerpolicy.LayerAgent
	LayerEndpoint = providerpolicy.LayerEndpoint
	LayerGroup    = providerpolicy.LayerGroup

	EffectAllow = providerpolicy.EffectAllow
	EffectDeny  = providerpolicy.EffectDeny

	ReasonCodeAllow = providerpolicy.ReasonCodeAllow
	ReasonCodeDeny  = providerpolicy.ReasonCodeDeny

	DefaultRefreshInterval = providerpolicy.DefaultRefreshInterval
)

// Evaluate mirrors the cloud evaluator exactly; see providerpolicy.Evaluate
// for the most-specific-wins semantics.
func Evaluate(snapshot Snapshot, status Status, request Request) (Evaluation, bool) {
	return providerpolicy.Evaluate(snapshot, status, request)
}

func NewCache(path string) *Cache {
	return providerpolicy.NewCache(path, Config)
}

// DefaultCachePathForDB stores the snapshot next to the guard database, the
// same convention managedstream uses for its cursor state.
func DefaultCachePathForDB(dbPath string) string {
	return providerpolicy.DefaultCachePathForDB(dbPath, Config)
}

// FetchSnapshot retrieves the GitHub policy snapshot from the cloud using the
// same per-customer install token as the authorization-ledger ingest.
func FetchSnapshot(ctx context.Context, client *http.Client, cloudURL, installToken, installationID string) (Snapshot, error) {
	return providerpolicy.FetchSnapshot(ctx, client, cloudURL, installToken, installationID, Config)
}

func DefaultIntervalFromEnv() time.Duration {
	return providerpolicy.IntervalFromEnv(Config)
}
