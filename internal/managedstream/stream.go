package managedstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	DefaultCooldown   = 15 * time.Minute

	maxPayloadSessions = 100
	maxPayloadActions  = 1000
	maxPayloadReceipts = 2000

	maxErrorBodyBytes = 4096

	envStatePath = "KONTEXT_MANAGED_STREAM_STATE"
	envInterval  = "KONTEXT_MANAGED_STREAM_INTERVAL"
)

var hostedErrorSecretPattern = regexp.MustCompile(`(?i)("(?:[^"]*(?:api[_-]?key|authorization|client[_-]?secret|credential|install[_-]?token|password|secret|token)[^"]*)"\s*:\s*")([^"]*)(")`)

type failureKind string

const (
	failureKindTerminalConfig failureKind = "terminal_config"
)

type streamConfigFingerprint string

type Options struct {
	DBPath            string
	StatePath         string
	CloudURL          string
	OrganizationID    string
	InstallationID    string
	InstallToken      string
	DeviceLabel       string
	DeploymentVersion func() string
	Interval          time.Duration
	BatchLimit        int
	HTTPClient        *http.Client
	Diagnostic        diagnostic.Logger
}

type Payload struct {
	SchemaVersion      string                           `json:"schema_version"`
	OrganizationID     string                           `json:"organization_id"`
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
	UpdatedAfter   string                  `json:"updated_after,omitempty"`
	ActionID       string                  `json:"action_id,omitempty"`
	FailureKind    failureKind             `json:"failure_kind,omitempty"`
	FailureStatus  int                     `json:"failure_status,omitempty"`
	FailureMessage string                  `json:"failure_message,omitempty"`
	FailureConfig  streamConfigFingerprint `json:"failure_config,omitempty"`
	FailureCount   int                     `json:"failure_count,omitempty"`
	CooldownUntil  string                  `json:"cooldown_until,omitempty"`
}

func Run(ctx context.Context, opts Options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}
	interval := opts.Interval
	if interval == 0 {
		interval = DefaultIntervalFromEnv()
	}

	if err := Flush(ctx, opts); err != nil {
		opts.Diagnostic.Printf("managed stream flush: %v\n", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := Flush(ctx, opts); err != nil {
				opts.Diagnostic.Printf("managed stream flush: %v\n", err)
			}
		}
	}
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
	configKey := configFingerprint(opts)
	if state.FailureConfig != "" && state.FailureConfig != configKey {
		state = clearFailureState(state)
		if err := SaveState(statePath, state); err != nil {
			return err
		}
	}

	var updatedAfter *time.Time
	if state.UpdatedAfter != "" {
		parsed, err := parseStateUpdatedAfter(state.UpdatedAfter)
		if err != nil {
			return fmt.Errorf("parse managed stream state: %w", err)
		}
		updatedAfter = &parsed
	}

	active, err := cooldownActive(state, configKey, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("parse managed stream cooldown state: %w", err)
	}
	if active {
		return fmt.Errorf("managed stream paused during cooldown after terminal hosted ingest failure until %s: %s", state.CooldownUntil, state.FailureMessage)
	}

	limit := batchLimit(opts.BatchLimit)
	for {
		batch, err := store.LedgerBatch(ctx, sqlite.LedgerExportOptions{
			UpdatedAfter:   updatedAfter,
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
			OrganizationID:     opts.OrganizationID,
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
			if errors.As(err, &hostedErr) {
				if shouldRetryWithSmallerBatch(hostedErr) {
					if limit == 1 || len(batch.Actions) <= 1 {
						if hostedErr.StatusCode != http.StatusRequestEntityTooLarge {
							return recordTerminalConfigFailure(statePath, state, configKey, hostedErr)
						}
						return advancePastMinimumBatch(
							statePath,
							batch,
							fmt.Sprintf("hosted status %d at minimum batch size", hostedErr.StatusCode),
							hostedErr,
						)
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
				if hostedErr.StatusCode == http.StatusBadRequest {
					return recordTerminalConfigFailure(statePath, state, configKey, hostedErr)
				}
				if hostedErr.StatusCode == http.StatusUnprocessableEntity {
					return recordTerminalConfigFailure(statePath, state, configKey, hostedErr)
				}
			}
			return err
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

func shouldRetryWithSmallerBatch(err *hostedIngestError) bool {
	return err.StatusCode == http.StatusRequestEntityTooLarge ||
		((err.StatusCode == http.StatusBadRequest || err.StatusCode == http.StatusUnprocessableEntity) &&
			isHostedPayloadSizeError(err.Body))
}

func isHostedPayloadSizeError(body string) bool {
	body = strings.ToLower(body)
	if strings.Contains(body, "payload too large") ||
		strings.Contains(body, "request entity too large") {
		return true
	}
	if !strings.Contains(body, "must contain no more than") &&
		!strings.Contains(body, "exceeds max") {
		return false
	}
	return strings.Contains(body, "agent_sessions") ||
		strings.Contains(body, "authorization_actions") ||
		strings.Contains(body, "authorization_receipts") ||
		strings.Contains(body, "body_bytes")
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

func recordTerminalConfigFailure(statePath string, state State, configKey streamConfigFingerprint, err *hostedIngestError) error {
	state.FailureKind = failureKindTerminalConfig
	state.FailureStatus = err.StatusCode
	state.FailureMessage = redactHostedErrorBody(err.Body)
	state.FailureConfig = configKey
	state.FailureCount++
	state.CooldownUntil = time.Now().UTC().Add(DefaultCooldown).Format(time.RFC3339Nano)
	if err := SaveState(statePath, state); err != nil {
		return err
	}
	return fmt.Errorf("managed stream entered cooldown after terminal hosted ingest failure: %w", err)
}

func saveCursor(statePath string, batch sqlite.LedgerBatch) error {
	return SaveState(statePath, stateWithCursor(State{}, batch))
}

func stateWithCursor(state State, batch sqlite.LedgerBatch) State {
	if batch.Cursor == nil {
		return state
	}
	state.UpdatedAfter = batch.Cursor.UpdatedAt.UTC().Format(time.RFC3339Nano)
	state.ActionID = batch.Cursor.ActionID
	return state
}

func cooldownActive(state State, configKey streamConfigFingerprint, now time.Time) (bool, error) {
	if state.FailureKind != failureKindTerminalConfig || state.FailureConfig != configKey || state.CooldownUntil == "" {
		return false, nil
	}
	until, err := time.Parse(time.RFC3339Nano, state.CooldownUntil)
	if err != nil {
		return false, err
	}
	return now.Before(until), nil
}

func clearFailureState(state State) State {
	return State{
		UpdatedAfter: state.UpdatedAfter,
		ActionID:     state.ActionID,
	}
}

func configFingerprint(opts Options) streamConfigFingerprint {
	values := strings.Join([]string{
		strings.TrimSpace(opts.CloudURL),
		strings.TrimSpace(opts.OrganizationID),
		strings.TrimSpace(opts.InstallationID),
		strings.TrimSpace(opts.InstallToken),
	}, "\x00")
	sum := sha256.Sum256([]byte(values))
	return streamConfigFingerprint(hex.EncodeToString(sum[:]))
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
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	state.UpdatedAfter = strings.TrimSpace(state.UpdatedAfter)
	state.ActionID = strings.TrimSpace(state.ActionID)
	return state, nil
}

func SaveState(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
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
	if strings.TrimSpace(opts.OrganizationID) == "" {
		return errors.New("managed stream requires organization id")
	}
	if strings.TrimSpace(opts.InstallationID) == "" {
		return errors.New("managed stream requires installation id")
	}
	if strings.TrimSpace(opts.InstallToken) == "" {
		return errors.New("managed stream requires install token")
	}
	return nil
}
