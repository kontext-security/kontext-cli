package githubpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SnapshotEndpoint is the cloud path serving the policy snapshot. Tenancy is
// resolved from the install token; missing/unknown/revoked tokens get 401.
const SnapshotEndpoint = "/api/v1/policy/github/snapshot"

const maxSnapshotBodyBytes = 4 << 20

// FetchSnapshot retrieves the GitHub policy snapshot from the cloud using the
// same per-customer install token as the authorization-ledger ingest.
//
// installationID identifies this endpoint ("ins_…") so the cloud can resolve
// its directory identity for group-layer rules; empty is allowed and simply
// yields no group matches. The request asks for schema v3 but accepts v2 for
// one release: a pre-v3 server ignores the query params and answers v2.
func FetchSnapshot(ctx context.Context, client *http.Client, cloudURL, installToken, installationID string) (Snapshot, error) {
	// Trim once so the query param and the echoed-directory check below see
	// the same value.
	installationID = strings.TrimSpace(installationID)
	endpoint, err := snapshotURL(cloudURL, installationID)
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
	if resp.StatusCode != http.StatusOK {
		return Snapshot{}, fmt.Errorf("github policy snapshot fetch failed: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSnapshotBodyBytes+1))
	if err != nil {
		return Snapshot{}, err
	}
	if len(body) > maxSnapshotBodyBytes {
		return Snapshot{}, fmt.Errorf("github policy snapshot exceeds %d bytes", maxSnapshotBodyBytes)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode github policy snapshot: %w", err)
	}
	if snapshot.SchemaVersion != SchemaVersionV2 && snapshot.SchemaVersion != SchemaVersionV3 {
		return Snapshot{}, fmt.Errorf("unsupported github policy snapshot schema %q", snapshot.SchemaVersion)
	}
	if err := validateSnapshot(snapshot, installationID); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func validateSnapshot(snapshot Snapshot, installationID string) error {
	if snapshot.Hash == "" {
		return fmt.Errorf("github policy snapshot is missing hash")
	}
	if directory := snapshot.EndpointDirectory; directory != nil {
		// The install token is per-customer, so the installation id is the
		// only per-device differentiator on this request. A directory echoed
		// for a different endpoint (e.g. a response cache that ignores the
		// query string) would apply another user's group memberships here.
		if installationID != "" && directory.InstallationID != installationID {
			return fmt.Errorf("github policy snapshot endpoint directory is for %q, not this endpoint", directory.InstallationID)
		}
		// The contract says a null directoryUserId (missing/unmatched/
		// ambiguous email) always comes with empty groupIds; groups without a
		// resolved user would grant an identity the server said it couldn't
		// establish.
		if directory.DirectoryUserID == nil && len(directory.GroupIDs) > 0 {
			return fmt.Errorf("github policy snapshot has group ids without a resolved directory user")
		}
	} else if snapshot.SchemaVersion == SchemaVersionV3 && installationID != "" {
		// We identified ourselves, so a v3 server must answer with a
		// directory block (possibly unmatched). Its absence would silently
		// strip group-layer carve-out denies while keeping broader allows.
		return fmt.Errorf("github policy snapshot v3 is missing the endpoint directory")
	}
	for _, rule := range snapshot.Rules {
		switch rule.Layer {
		case LayerOrg, LayerUser, LayerAgent, LayerEndpoint:
		case LayerGroup:
			// The server contract filters group rules out of v2 responses; a
			// v2 body containing one is server misbehavior, not negotiation.
			if snapshot.SchemaVersion != SchemaVersionV3 {
				return fmt.Errorf("github policy rule %s has layer %q in a %s snapshot", rule.ID, rule.Layer, snapshot.SchemaVersion)
			}
		default:
			return fmt.Errorf("github policy rule %s has unknown layer %q", rule.ID, rule.Layer)
		}
		switch rule.Effect {
		case EffectAllow, EffectDeny:
		default:
			return fmt.Errorf("github policy rule %s has unknown effect %q", rule.ID, rule.Effect)
		}
		if rule.ID == "" || rule.SubjectID == "" {
			return fmt.Errorf("github policy rule is missing id or subject")
		}
	}
	return nil
}

func snapshotURL(cloudURL, installationID string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cloudURL))
	if err != nil {
		return "", err
	}
	parsed.Path = SnapshotEndpoint
	query := url.Values{"schema": {SchemaVersionV3}}
	if installationID = strings.TrimSpace(installationID); installationID != "" {
		query.Set("installation_id", installationID)
	}
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}
