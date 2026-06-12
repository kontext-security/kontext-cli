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
func FetchSnapshot(ctx context.Context, client *http.Client, cloudURL, installToken string) (Snapshot, error) {
	endpoint, err := snapshotURL(cloudURL)
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
	if snapshot.SchemaVersion != SchemaVersion {
		return Snapshot{}, fmt.Errorf("unsupported github policy snapshot schema %q", snapshot.SchemaVersion)
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.Hash == "" {
		return fmt.Errorf("github policy snapshot is missing hash")
	}
	for _, rule := range snapshot.Rules {
		switch rule.Layer {
		case LayerOrg, LayerUser, LayerAgent:
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

func snapshotURL(cloudURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cloudURL))
	if err != nil {
		return "", err
	}
	parsed.Path = SnapshotEndpoint
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
