package managedstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
)

const (
	SchemaVersion   = "authorization-ledger-v1"
	DefaultEndpoint = "/api/v1/authorization-ledger/batches"

	DefaultBatchLimit = 100
	MaxPayloadBytes   = 192 * 1024
	DefaultInterval   = 10 * time.Second

	maxPayloadSessions = 100
	maxPayloadActions  = 1000
	maxPayloadReceipts = 2000

	maxErrorBodyBytes = 4096

	envStatePath = "KONTEXT_MANAGED_STREAM_STATE"
	envInterval  = "KONTEXT_MANAGED_STREAM_INTERVAL"
)

var hostedErrorSecretPattern = regexp.MustCompile(`(?i)("(?:[^"]*(?:api[_-]?key|authorization|client[_-]?secret|credential|install[_-]?token|password|secret|token)[^"]*)"\s*:\s*")([^"]*)(")`)

type Options struct {
	DBPath            string
	StatePath         string
	CloudURL          string
	InstallationID    string
	InstallToken      string
	DeviceLabel       string
	DeploymentVersion func() string
	Interval          time.Duration
	BatchLimit        int
	HTTPClient        *http.Client
	Diagnostic        diagnostic.Logger
	// OnAuthFailure fires (nil-safe) after several consecutive 401/403
	// rejections — the signature of a revoked or rotated install token,
	// which would otherwise spin silently under launchd. Re-fires
	// periodically so a long-running daemon keeps surfacing it without
	// spamming every flush.
	OnAuthFailure func(status int)
	// OnFlushSuccess fires (nil-safe) after every ACCEPTED hosted post, so
	// callers can clear "token rejected" breadcrumbs. It deliberately does
	// not depend on this process's failure counter (a breadcrumb can outlive
	// a daemon restart) and deliberately does NOT fire on empty flushes that
	// never contacted the server — an idle machine with a revoked token must
	// keep its breadcrumb.
	OnFlushSuccess func()
}

const (
	// authFailureThreshold avoids alerting on a transient 401 during a
	// server-side deploy; three consecutive rejections (~30s at the default
	// interval) means the credential itself is the problem.
	authFailureThreshold = 3
	// authFailureRefire re-surfaces the condition roughly every 8 minutes at
	// the default interval.
	authFailureRefire = 50
)

type Payload struct {
	SchemaVersion      string                           `json:"schema_version"`
	InstallationID     string                           `json:"installation_id"`
	BatchID            string                           `json:"batch_id"`
	SentAt             string                           `json:"sent_at"`
	Device             *Device                          `json:"device,omitempty"`
	Sessions           []sqlite.LedgerRecord            `json:"agent_sessions"`
	Actions            []sqlite.LedgerRecord            `json:"authorization_actions"`
	Receipts           []sqlite.LedgerRecord            `json:"authorization_receipts"`
	ReceiptChainAnchor *sqlite.LedgerReceiptChainAnchor `json:"receipt_chain_anchor,omitempty"`
}

type Device struct {
	Label             string `json:"label,omitempty"`
	DeploymentVersion string `json:"deployment_version,omitempty"`
}

type State struct {
	UpdatedAfter *time.Time
	ActionID     string
}

type persistedState struct {
	UpdatedAfter string `json:"updated_after,omitempty"`
	ActionID     string `json:"action_id,omitempty"`
}

func Run(ctx context.Context, opts Options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}
	interval := opts.Interval
	if interval == 0 {
		interval = DefaultIntervalFromEnv()
	}

	var consecutiveAuthFailures int
	flush := func() {
		// OnFlushSuccess is invoked inside Flush (only after an accepted
		// post); here we only track consecutive auth rejections.
		err := Flush(ctx, opts)
		if err == nil {
			consecutiveAuthFailures = 0
			return
		}
		opts.Diagnostic.Printf("managed stream flush: %v\n", err)

		var hostedErr *hostedIngestError
		if !errors.As(err, &hostedErr) || !isAuthStatus(hostedErr.StatusCode) {
			consecutiveAuthFailures = 0
			return
		}
		consecutiveAuthFailures++
		if opts.OnAuthFailure != nil &&
			(consecutiveAuthFailures == authFailureThreshold ||
				consecutiveAuthFailures%authFailureRefire == 0) {
			opts.OnAuthFailure(hostedErr.StatusCode)
		}
	}

	flush()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			flush()
		}
	}
}

func isAuthStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

func Flush(ctx context.Context, opts Options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}
	store, err := sqlite.OpenStore(opts.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	statePath := opts.StatePath
	if statePath == "" {
		statePath = DefaultStatePathForDB(opts.DBPath)
	}
	state, err := LoadState(statePath)
	if err != nil {
		return err
	}

	limit := batchLimit(opts.BatchLimit)
	for {
		batch, err := store.LedgerBatch(ctx, sqlite.LedgerExportOptions{
			UpdatedAfter:   state.UpdatedAfter,
			UpdatedAfterID: state.ActionID,
			Limit:          limit,
		})
		if err != nil {
			return err
		}
		if len(batch.Actions) == 0 {
			return nil
		}

		payload := Payload{
			SchemaVersion:      SchemaVersion,
			InstallationID:     opts.InstallationID,
			BatchID:            "batch_" + uuid.NewString(),
			SentAt:             time.Now().UTC().Format(time.RFC3339Nano),
			Sessions:           batch.Sessions,
			Actions:            batch.Actions,
			Receipts:           batch.Receipts,
			ReceiptChainAnchor: batch.ReceiptChainAnchor,
		}
		// Resolve the deployment version per flush so an in-place package upgrade
		// is reflected without restarting the daemon.
		label := strings.TrimSpace(opts.DeviceLabel)
		deploymentVersion := ""
		if opts.DeploymentVersion != nil {
			deploymentVersion = strings.TrimSpace(opts.DeploymentVersion())
		}
		if label != "" || deploymentVersion != "" {
			payload.Device = &Device{Label: label, DeploymentVersion: deploymentVersion}
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if reason := payloadLimitViolation(payload, len(body)); reason != "" {
			if limit == 1 {
				return advancePastMinimumBatch(statePath, batch, reason, nil)
			}
			nextLimit := reducedBatchLimit(limit)
			opts.Diagnostic.Printf(
				"managed stream payload exceeds hosted limits (%s); reducing batch limit from %d to %d\n",
				reason,
				limit,
				nextLimit,
			)
			limit = nextLimit
			continue
		}

		if err := post(ctx, opts, body); err != nil {
			var hostedErr *hostedIngestError
			if errors.As(err, &hostedErr) && shouldRetryWithSmallerBatch(hostedErr.StatusCode) {
				if limit == 1 {
					return err
				}
				nextLimit := reducedBatchLimit(limit)
				opts.Diagnostic.Printf(
					"managed stream hosted ingest returned status %d; reducing batch limit from %d to %d\n",
					hostedErr.StatusCode,
					limit,
					nextLimit,
				)
				limit = nextLimit
				continue
			}
			return err
		}

		// The hosted ledger accepted a post with this token — proof the
		// credential works, which is what breadcrumb-clearing needs.
		if opts.OnFlushSuccess != nil {
			opts.OnFlushSuccess()
		}

		if batch.Cursor != nil {
			return saveCursor(statePath, batch)
		}
		return nil
	}
}

func post(ctx context.Context, opts Options, body []byte) error {
	endpoint, err := endpointURL(opts.CloudURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(opts.InstallToken))

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &hostedIngestError{
			StatusCode: resp.StatusCode,
			Body:       responseBodySummary(resp.Body),
		}
	}
	return nil
}

type hostedIngestError struct {
	StatusCode int
	Body       string
}

func (e *hostedIngestError) Error() string {
	body := redactHostedErrorBody(e.Body)
	if body == "" {
		return fmt.Sprintf("hosted ledger ingest failed: status %d", e.StatusCode)
	}
	return fmt.Sprintf("hosted ledger ingest failed: status %d: %s", e.StatusCode, body)
}

func redactHostedErrorBody(body string) string {
	redacted := hostedErrorSecretPattern.ReplaceAllString(strings.TrimSpace(body), `${1}[REDACTED]${3}`)
	return diagnostic.Redact(redacted)
}

func batchLimit(limit int) int {
	if limit <= 0 {
		return DefaultBatchLimit
	}
	if limit > DefaultBatchLimit {
		return DefaultBatchLimit
	}
	return limit
}

func reducedBatchLimit(limit int) int {
	next := limit / 2
	if next < 1 {
		return 1
	}
	return next
}

func shouldRetryWithSmallerBatch(statusCode int) bool {
	return statusCode == http.StatusBadRequest ||
		statusCode == http.StatusRequestEntityTooLarge ||
		statusCode == http.StatusUnprocessableEntity
}

func payloadLimitViolation(payload Payload, bodyBytes int) string {
	switch {
	case len(payload.Sessions) > maxPayloadSessions:
		return fmt.Sprintf("agent_sessions=%d exceeds max %d", len(payload.Sessions), maxPayloadSessions)
	case len(payload.Actions) > maxPayloadActions:
		return fmt.Sprintf("authorization_actions=%d exceeds max %d", len(payload.Actions), maxPayloadActions)
	case len(payload.Receipts) > maxPayloadReceipts:
		return fmt.Sprintf("authorization_receipts=%d exceeds max %d", len(payload.Receipts), maxPayloadReceipts)
	case bodyBytes > MaxPayloadBytes:
		return fmt.Sprintf("body_bytes=%d exceeds max %d", bodyBytes, MaxPayloadBytes)
	default:
		return ""
	}
}

func advancePastMinimumBatch(statePath string, batch sqlite.LedgerBatch, reason string, cause error) error {
	if batch.Cursor == nil {
		if cause != nil {
			return cause
		}
		return fmt.Errorf("managed stream minimum batch rejected: %s", reason)
	}
	if err := saveCursor(statePath, batch); err != nil {
		return err
	}
	if cause != nil {
		return fmt.Errorf("managed stream advanced cursor past rejected minimum batch (%s): %w", reason, cause)
	}
	return fmt.Errorf("managed stream advanced cursor past oversized minimum batch: %s", reason)
}

func saveCursor(statePath string, batch sqlite.LedgerBatch) error {
	updatedAfter := batch.Cursor.UpdatedAt.UTC()
	return SaveState(statePath, State{
		UpdatedAfter: &updatedAfter,
		ActionID:     batch.Cursor.ActionID,
	})
}

func parseStateUpdatedAfter(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %q", value)
}

func responseBodySummary(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, maxErrorBodyBytes+1))
	if err != nil {
		return ""
	}
	truncated := len(data) > maxErrorBodyBytes
	if truncated {
		data = data[:maxErrorBodyBytes]
	}
	summary := strings.Join(strings.Fields(string(data)), " ")
	if truncated {
		summary += "..."
	}
	return summary
}

func endpointURL(cloudURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cloudURL))
	if err != nil {
		return "", err
	}
	parsed.Path = DefaultEndpoint
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func DefaultStatePath() string {
	if path := strings.TrimSpace(os.Getenv(envStatePath)); path != "" {
		return path
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "Kontext", "managed-observe", "stream-state.json")
	}
	return filepath.Join("managed-observe", "stream-state.json")
}

func DefaultStatePathForDB(dbPath string) string {
	if path := strings.TrimSpace(os.Getenv(envStatePath)); path != "" {
		return path
	}
	if dbPath = strings.TrimSpace(dbPath); dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "stream-state.json")
	}
	return DefaultStatePath()
}

func DefaultIntervalFromEnv() time.Duration {
	if value := strings.TrimSpace(os.Getenv(envInterval)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return DefaultInterval
}

func LoadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	var state State
	var persisted persistedState
	if err := json.Unmarshal(data, &persisted); err != nil {
		return State{}, err
	}
	if updatedAfter := strings.TrimSpace(persisted.UpdatedAfter); updatedAfter != "" {
		parsed, err := parseStateUpdatedAfter(updatedAfter)
		if err != nil {
			return State{}, fmt.Errorf("parse managed stream state: %w", err)
		}
		state.UpdatedAfter = &parsed
	}
	state.ActionID = strings.TrimSpace(persisted.ActionID)
	return state, nil
}

func SaveState(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	persisted := persistedState{ActionID: strings.TrimSpace(state.ActionID)}
	if state.UpdatedAfter != nil {
		persisted.UpdatedAfter = state.UpdatedAfter.UTC().Format(time.RFC3339Nano)
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(path), ".stream-state-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func validateOptions(opts Options) error {
	if strings.TrimSpace(opts.DBPath) == "" {
		return errors.New("managed stream requires db path")
	}
	if strings.TrimSpace(opts.CloudURL) == "" {
		return errors.New("managed stream requires cloud url")
	}
	if strings.TrimSpace(opts.InstallationID) == "" {
		return errors.New("managed stream requires installation id")
	}
	if strings.TrimSpace(opts.InstallToken) == "" {
		return errors.New("managed stream requires install token")
	}
	return nil
}
