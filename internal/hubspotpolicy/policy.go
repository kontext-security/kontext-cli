// Package hubspotpolicy classifies HubSpot activity (the remote HubSpot MCP
// connector used by Claude Cowork and Claude Code) into canonical provider
// actions and binds the shared provider-policy sync machinery
// (internal/providerpolicy) to the HubSpot snapshot contract.
//
// The contract mirrors packages/shared/src/hubspot/policy-snapshot.ts in the
// kontext cloud repository. Like the GitHub pilot the directive is
// observe-only: the engine records what it *would* allow or deny, but never
// blocks.
package hubspotpolicy

import (
	"github.com/kontext-security/kontext-cli/internal/providerpolicy"
)

// SchemaVersionV1 is the only HubSpot snapshot wire format. It ships the
// group layer and endpoint directory from day one — there are no deployed
// pre-v1 clients to negotiate with. Anything else is rejected (fail closed).
const SchemaVersionV1 = "hubspot-policy-snapshot-v1"

// SnapshotEndpoint is the cloud path serving the HubSpot policy snapshot.
// Tenancy is resolved from the install token.
const SnapshotEndpoint = "/api/v1/policy/hubspot/snapshot"

// Config binds the shared sync machinery to the HubSpot snapshot contract.
var Config = providerpolicy.Config{
	ProviderKey:      "hubspot",
	SnapshotEndpoint: SnapshotEndpoint,
	RequestSchema:    SchemaVersionV1,
	Schemas: []providerpolicy.SchemaSupport{
		{Version: SchemaVersionV1, GroupLayer: true, Directory: true},
	},
	CacheFileName:    "hubspot-policy-snapshot.json",
	CacheTempPattern: ".hubspot-policy-*.tmp",
	RefreshEnvVar:    "KONTEXT_HUBSPOT_POLICY_REFRESH_INTERVAL",
}
