package providerpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNotConfigured reports that the cloud has no snapshot surface for this
// provider/org (HTTP 404) — expected when the org has not activated the
// provider. Callers should treat it as "no policy" rather than a fetch
// failure worth alarming on.
var ErrNotConfigured = errors.New("policy snapshot not configured")

// MaxSnapshotBodyBytes caps how large a snapshot response the client accepts.
const MaxSnapshotBodyBytes = 4 << 20

// FetchSnapshot retrieves the provider's policy snapshot from the cloud using
// the same per-customer install token as the authorization-ledger ingest.
//
// installationID identifies this endpoint ("ins_…") so the cloud can resolve
// its directory identity for group-layer rules; empty is allowed and simply
// yields no group matches. The request asks for config.RequestSchema and
// accepts any version in config.Schemas; anything else is rejected (fail
// closed) rather than misread under the wrong semantics.
func FetchSnapshot(ctx context.Context, client *http.Client, cloudURL, installToken, installationID string, config Config) (Snapshot, error) {
	// Trim once so the query param and the echoed-directory check below see
	// the same value.
	installationID = strings.TrimSpace(installationID)
	endpoint, err := snapshotURL(cloudURL, installationID, config)
	if err != nil {
		return Snapshot{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Snapshot{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(installToken))

	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Snapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Snapshot{}, fmt.Errorf("%s: %w", config.ProviderKey, ErrNotConfigured)
	}
	if resp.StatusCode != http.StatusOK {
		return Snapshot{}, fmt.Errorf("%s policy snapshot fetch failed: status %d", config.ProviderKey, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSnapshotBodyBytes+1))
	if err != nil {
		return Snapshot{}, err
	}
	if len(body) > MaxSnapshotBodyBytes {
		return Snapshot{}, fmt.Errorf("%s policy snapshot exceeds %d bytes", config.ProviderKey, MaxSnapshotBodyBytes)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode %s policy snapshot: %w", config.ProviderKey, err)
	}
	schema, ok := config.schemaSupport(snapshot.SchemaVersion)
	if !ok {
		return Snapshot{}, fmt.Errorf("unsupported %s policy snapshot schema %q", config.ProviderKey, snapshot.SchemaVersion)
	}
	if err := validateSnapshot(snapshot, schema, installationID, config); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func validateSnapshot(snapshot Snapshot, schema SchemaSupport, installationID string, config Config) error {
	if snapshot.Hash == "" {
		return fmt.Errorf("%s policy snapshot is missing hash", config.ProviderKey)
	}
	if directory := snapshot.EndpointDirectory; directory != nil {
		// The install token is per-customer, so the installation id is the
		// only per-device differentiator on this request. A directory echoed
		// for a different endpoint (e.g. a response cache that ignores the
		// query string) would apply another user's group memberships here.
		if installationID != "" && directory.InstallationID != installationID {
			return fmt.Errorf("%s policy snapshot endpoint directory is for %q, not this endpoint", config.ProviderKey, directory.InstallationID)
		}
		// The contract says a null directoryUserId (missing/unmatched/
		// ambiguous email) always comes with empty groupIds; groups without a
		// resolved user would grant an identity the server said it couldn't
		// establish.
		if directory.DirectoryUserID == nil && len(directory.GroupIDs) > 0 {
			return fmt.Errorf("%s policy snapshot has group ids without a resolved directory user", config.ProviderKey)
		}
	} else if schema.Directory && installationID != "" {
		// We identified ourselves, so a directory-capable server must answer
		// with a directory block (possibly unmatched). Its absence would
		// silently strip group-layer carve-out denies while keeping broader
		// allows.
		return fmt.Errorf("%s policy snapshot %s is missing the endpoint directory", config.ProviderKey, snapshot.SchemaVersion)
	}
	for _, rule := range snapshot.Rules {
		switch rule.Layer {
		case LayerOrg, LayerUser, LayerAgent, LayerEndpoint:
		case LayerGroup:
			// The server contract keeps group rules out of versions without
			// group-layer support; one showing up anyway is server
			// misbehavior, not negotiation.
			if !schema.GroupLayer {
				return fmt.Errorf("%s policy rule %s has layer %q in a %s snapshot", config.ProviderKey, rule.ID, rule.Layer, snapshot.SchemaVersion)
			}
		default:
			return fmt.Errorf("%s policy rule %s has unknown layer %q", config.ProviderKey, rule.ID, rule.Layer)
		}
		switch rule.Effect {
		case EffectAllow, EffectDeny:
		default:
			return fmt.Errorf("%s policy rule %s has unknown effect %q", config.ProviderKey, rule.ID, rule.Effect)
		}
		if rule.ID == "" || rule.SubjectID == "" {
			return fmt.Errorf("%s policy rule is missing id or subject", config.ProviderKey)
		}
	}
	return nil
}

func snapshotURL(cloudURL, installationID string, config Config) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cloudURL))
	if err != nil {
		return "", err
	}
	parsed.Path = config.SnapshotEndpoint
	query := url.Values{}
	if config.RequestSchema != "" {
		query.Set("schema", config.RequestSchema)
	}
	if installationID = strings.TrimSpace(installationID); installationID != "" {
		query.Set("installation_id", installationID)
	}
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}
