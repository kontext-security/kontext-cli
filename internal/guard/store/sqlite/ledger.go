package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type LedgerRecord map[string]any

type LedgerExportOptions struct {
	UpdatedAfter   *time.Time
	UpdatedAfterID string
	Limit          int
}

type LedgerBatch struct {
	Sessions           []LedgerRecord            `json:"agent_sessions"`
	Actions            []LedgerRecord            `json:"authorization_actions"`
	Receipts           []LedgerRecord            `json:"authorization_receipts"`
	ReceiptChainAnchor *LedgerReceiptChainAnchor `json:"receipt_chain_anchor,omitempty"`
	Cursor             *LedgerCursor             `json:"-"`
}

type LedgerReceiptChainAnchor struct {
	PreviousReceiptHash string `json:"previous_receipt_hash"`
}

type LedgerCursor struct {
	UpdatedAt time.Time
	ActionID  string
}

const (
	ledgerCursorUpdatedAtKeyColumn = "__cursor_updated_at_key"
	ledgerTimestampCursorKeyLayout = "2006-01-02T15:04:05.000000000Z07:00"
)

var ledgerFallbackTimestamp = time.Unix(0, 0).UTC()

const authorizationActionsSelect = `
select id, session_id, turn_id, tool_use_id, trace_id, span_id, parent_span_id,
  runtime_kind, runtime_instance_id, adapter_kind, adapter_version,
  canonical_event_type, adapter_event_name, correlation_key, correlation_confidence,
  tool_name, provider, operation, operation_class, resource_class, resource_id,
  parameters_redacted_json, parameters_hash, identity_context_json, identity_hash,
  context_json, context_hash, policy_id, policy_version, policy_hash, default_posture,
  decision_result, decision_category, adapter_decision, reason_code, reason,
  risk_level, risk_score, risk_threshold, model_version, compositional_risk_score,
  confidence, alignment_score, alignment_threshold, uncertainty_score,
  matched_rules_json, risk_signals_json, risk_event_json, modifications_json,
  approval_context_json, approval_channel, approval_request_id, approval_expires_at,
  deferral_context_json, status, outcome, output_summary, output_hash, error_redacted,
  proposed_at, decision_at, completed_at, created_at, updated_at
from authorization_actions`

const authorizationReceiptsSelect = `
select id, action_id, session_id, receipt_type, decision_result, decision_category,
  reason_code, approval_channel, approval_result, approver_id, approved_at,
  policy_hash, context_hash, identity_hash, risk_evaluation_hash, action_hash,
  outcome_hash, receipt_payload_json, previous_receipt_hash, receipt_hash,
  signature, signature_algorithm, key_id, created_at
from authorization_receipts`

func (s *Store) LedgerBatch(ctx context.Context, opts LedgerExportOptions) (LedgerBatch, error) {
	actions, cursor, err := s.authorizationActionCursorPage(ctx, opts)
	if err != nil {
		return LedgerBatch{}, err
	}
	receipts, err := s.authorizationReceiptRangeForActions(ctx, recordIDs(actions))
	if err != nil {
		return LedgerBatch{}, err
	}
	actions, err = s.authorizationActionsByIDs(ctx, appendMissingIDs(recordIDs(actions), recordStrings(receipts, "action_id")))
	if err != nil {
		return LedgerBatch{}, err
	}
	sessions, err := s.AgentSessions(ctx, sessionIDs(actions, receipts))
	if err != nil {
		return LedgerBatch{}, err
	}
	return LedgerBatch{
		Sessions:           sessions,
		Actions:            actions,
		Receipts:           receipts,
		ReceiptChainAnchor: receiptChainAnchor(receipts),
		Cursor:             cursor,
	}, nil
}

func (s *Store) authorizationActionCursorPage(ctx context.Context, opts LedgerExportOptions) ([]LedgerRecord, *LedgerCursor, error) {
	actions, err := s.authorizationActions(ctx, opts, true)
	if err != nil {
		return nil, nil, err
	}
	cursor, err := ledgerCursor(actions)
	if err != nil {
		return nil, nil, err
	}
	stripLedgerCursorColumns(actions)
	return actions, cursor, nil
}

func receiptChainAnchor(receipts []LedgerRecord) *LedgerReceiptChainAnchor {
	if len(receipts) == 0 {
		return nil
	}
	previousHash, _ := receipts[0]["previous_receipt_hash"].(string)
	return &LedgerReceiptChainAnchor{PreviousReceiptHash: previousHash}
}

func (s *Store) AgentSessions(ctx context.Context, ids []string) ([]LedgerRecord, error) {
	if len(ids) == 0 {
		return []LedgerRecord{}, nil
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	return queryLedgerRecords(ctx, s.db, fmt.Sprintf(`
select id, runtime_kind, runtime_instance_id, adapter_kind, adapter_version, agent_provider, agent,
  conversation_id, trace_id, principal_id, identity_context_json, identity_hash,
  policy_version, policy_hash, cwd, source, status, external_id, closed_at,
  mode, created_at, updated_at
from agent_sessions
where id in (%s)
order by created_at, id
	`, placeholders), args...)
}

func (s *Store) AuthorizationActions(ctx context.Context, opts LedgerExportOptions) ([]LedgerRecord, error) {
	actions, err := s.authorizationActions(ctx, opts, false)
	if err != nil {
		return nil, err
	}
	stripLedgerCursorColumns(actions)
	return actions, nil
}

func (s *Store) authorizationActions(ctx context.Context, opts LedgerExportOptions, includeCursorKey bool) ([]LedgerRecord, error) {
	query := authorizationActionsSelect
	if includeCursorKey {
		query = authorizationActionsSelectWithCursorKey()
	}
	args := []any{}
	if opts.UpdatedAfter != nil {
		updatedAfter := ledgerTimestampCursorKeyFromTime(*opts.UpdatedAfter)
		if opts.UpdatedAfterID != "" {
			query += "\nwhere updated_at_cursor_key > ? or (updated_at_cursor_key = ? and id > ?)"
			args = append(args, updatedAfter, updatedAfter, opts.UpdatedAfterID)
		} else {
			query += "\nwhere updated_at_cursor_key > ?"
			args = append(args, updatedAfter)
		}
	}
	query += "\norder by updated_at_cursor_key, id"
	if opts.Limit > 0 {
		query += "\nlimit ?"
		args = append(args, opts.Limit)
	}
	return queryLedgerRecords(ctx, s.db, query, args...)
}

func ledgerCursor(actions []LedgerRecord) (*LedgerCursor, error) {
	if len(actions) == 0 {
		return nil, nil
	}
	last := actions[len(actions)-1]
	rawUpdatedAt, _ := last["updated_at"].(string)
	updatedAtKey, _ := last[ledgerCursorUpdatedAtKeyColumn].(string)
	actionID, _ := last["id"].(string)
	if updatedAtKey == "" {
		updatedAtKey = ledgerTimestampCursorKeyFromValues(rawUpdatedAt)
	}
	if updatedAtKey == "" || actionID == "" {
		return nil, nil
	}
	updatedAt, err := parseLedgerTimestamp(updatedAtKey)
	if err != nil {
		return nil, err
	}
	return &LedgerCursor{UpdatedAt: updatedAt, ActionID: actionID}, nil
}

func (s *Store) authorizationActionsByIDs(ctx context.Context, ids []string) ([]LedgerRecord, error) {
	ids = uniqueStrings(ids)
	if len(ids) == 0 {
		return []LedgerRecord{}, nil
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	return queryLedgerRecords(ctx, s.db, fmt.Sprintf("%s\nwhere id in (%s)\norder by updated_at_cursor_key, id", authorizationActionsSelect, placeholders), args...)
}

func (s *Store) AuthorizationReceipts(ctx context.Context, opts LedgerExportOptions) ([]LedgerRecord, error) {
	query := authorizationReceiptsSelect
	args := []any{}
	if opts.UpdatedAfter != nil {
		query += "\nwhere created_at > ?"
		args = append(args, opts.UpdatedAfter.Format(time.RFC3339Nano))
	}
	query += "\norder by rowid"
	if opts.Limit > 0 {
		query += "\nlimit ?"
		args = append(args, opts.Limit)
	}
	return queryLedgerRecords(ctx, s.db, query, args...)
}

func (s *Store) authorizationReceiptRangeForActions(ctx context.Context, actionIDs []string) ([]LedgerRecord, error) {
	actionIDs = uniqueStrings(actionIDs)
	if len(actionIDs) == 0 {
		return []LedgerRecord{}, nil
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(actionIDs)), ",")
	args := make([]any, 0, len(actionIDs))
	for _, id := range actionIDs {
		args = append(args, id)
	}
	return queryLedgerRecords(ctx, s.db, fmt.Sprintf(`
with selected_receipts as (
  select rowid
  from authorization_receipts
  where action_id in (%s)
),
receipt_bounds as (
  select min(rowid) as start_rowid, max(rowid) as end_rowid
  from selected_receipts
)
%s, receipt_bounds
where authorization_receipts.rowid between receipt_bounds.start_rowid and receipt_bounds.end_rowid
order by authorization_receipts.rowid
	`, placeholders, authorizationReceiptsSelect), args...)
}

func queryLedgerRecords(ctx context.Context, db *sql.DB, query string, args ...any) ([]LedgerRecord, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	records := []LedgerRecord{}
	for rows.Next() {
		values := make([]any, len(columns))
		valuePtrs := make([]any, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}
		record := LedgerRecord{}
		for i, column := range columns {
			record[column] = normalizeLedgerValue(column, values[i])
		}
		normalizeLedgerRecord(record)
		records = append(records, record)
	}
	return records, rows.Err()
}

func normalizeLedgerValue(column string, value any) any {
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []byte:
		return normalizeLedgerString(column, string(typed))
	case string:
		return normalizeLedgerString(column, typed)
	default:
		return typed
	}
}

func normalizeLedgerString(column, value string) any {
	if strings.HasSuffix(column, "_json") || column == "receipt_payload_json" {
		var decoded any
		if err := json.Unmarshal([]byte(value), &decoded); err == nil {
			return decoded
		}
	}
	return value
}

func normalizeLedgerRecord(record LedgerRecord) {
	fallback := ledgerRecordFallbackTime(record)
	for column, value := range record {
		if !isLedgerTimeColumn(column) {
			continue
		}
		text, ok := value.(string)
		if !ok {
			continue
		}
		record[column] = normalizeLedgerTimeValue(column, text, fallback)
	}
}

func normalizeLedgerTimeValue(column, value string, fallback time.Time) any {
	if parsed, err := parseLedgerTimestamp(value); err == nil {
		return parsed.UTC().Format(time.RFC3339Nano)
	}
	if isRequiredLedgerTimeColumn(column) {
		return fallback.UTC().Format(time.RFC3339Nano)
	}
	return nil
}

func ledgerRecordFallbackTime(record LedgerRecord) time.Time {
	for _, column := range []string{"updated_at", "created_at"} {
		value, _ := record[column].(string)
		if parsed, err := parseLedgerTimestamp(value); err == nil {
			return parsed.UTC()
		}
	}
	return ledgerFallbackTimestamp
}

func authorizationActionsSelectWithCursorKey() string {
	cursorColumn := ",\n  updated_at_cursor_key as " + ledgerCursorUpdatedAtKeyColumn
	return strings.Replace(authorizationActionsSelect, "\nfrom authorization_actions", cursorColumn+"\nfrom authorization_actions", 1)
}

func stripLedgerCursorColumns(records []LedgerRecord) {
	for _, record := range records {
		delete(record, ledgerCursorUpdatedAtKeyColumn)
	}
}

func isLedgerTimeColumn(column string) bool {
	return strings.HasSuffix(column, "_at")
}

func isRequiredLedgerTimeColumn(column string) bool {
	return column == "created_at" || column == "updated_at"
}

func parseLedgerTimestamp(value string) (time.Time, error) {
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

func ledgerTimestampCursorKeyFromTime(value time.Time) string {
	return value.UTC().Format(ledgerTimestampCursorKeyLayout)
}

func ledgerTimestampCursorKeyFromValues(values ...string) string {
	for _, value := range values {
		parsed, err := parseLedgerTimestamp(value)
		if err == nil {
			return ledgerTimestampCursorKeyFromTime(parsed)
		}
	}
	return ledgerTimestampCursorKeyFromTime(ledgerFallbackTimestamp)
}

func sessionIDs(groups ...[]LedgerRecord) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, group := range groups {
		for _, record := range group {
			sessionID, ok := record["session_id"].(string)
			if !ok || sessionID == "" || seen[sessionID] {
				continue
			}
			seen[sessionID] = true
			out = append(out, sessionID)
		}
	}
	return out
}

func recordIDs(records []LedgerRecord) []string {
	return recordStrings(records, "id")
}

func recordStrings(records []LedgerRecord, key string) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		id, ok := record[key].(string)
		if ok && id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func appendMissingIDs(base, extra []string) []string {
	out := append([]string{}, base...)
	seen := map[string]bool{}
	for _, id := range out {
		seen[id] = true
	}
	for _, id := range extra {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
