// Package providerpolicy syncs a cloud-hosted provider access-control policy
// down to the managed endpoint and evaluates classified provider activity
// against it locally. It is the provider-neutral core shared by the
// per-provider packages (githubpolicy, hubspotpolicy): those own their
// classifier and a Config; everything else — rule matching, precedence,
// caching, fetching, fail-closed schema validation — lives here and MUST stay
// identical across providers.
//
// Precedence in the local engine is: general deterministic guardrails >
// this synced policy > probabilistic signals.
package providerpolicy

// SchemaSupport declares one accepted snapshot wire-format version and which
// contract features it carries. Any version outside the config's list is
// rejected (fail closed) rather than misread under the wrong semantics.
type SchemaSupport struct {
	Version string
	// GroupLayer is true when rules in this version may carry layer=group.
	// A group rule in a version without it is server misbehavior.
	GroupLayer bool
	// Directory is true when a server answering this version must echo the
	// endpointDirectory block whenever the request identified the endpoint.
	// Its absence would silently strip group-layer carve-out denies while
	// keeping broader allows.
	Directory bool
}

// Config is the per-provider parameterization of the sync machinery.
type Config struct {
	// ProviderKey names the provider in error messages ("github", "hubspot").
	ProviderKey string
	// SnapshotEndpoint is the cloud path serving the policy snapshot. Tenancy
	// is resolved from the install token; missing/unknown/revoked tokens get
	// 401.
	SnapshotEndpoint string
	// RequestSchema is the schema version to request via `?schema=`; empty
	// omits the parameter.
	RequestSchema string
	// Schemas lists the accepted wire-format versions, most preferred first.
	Schemas []SchemaSupport
	// CacheFileName is the snapshot's on-disk name next to the guard DB.
	CacheFileName string
	// CacheTempPattern is the os.CreateTemp pattern for atomic persistence.
	CacheTempPattern string
	// RefreshEnvVar optionally overrides the refresh interval.
	RefreshEnvVar string
}

func (c Config) schemaSupport(version string) (SchemaSupport, bool) {
	for _, schema := range c.Schemas {
		if schema.Version == version {
			return schema, true
		}
	}
	return SchemaSupport{}, false
}
