package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

type Store struct {
	db   *sql.DB
	path string
}

type DecisionRecord struct {
	ID            string         `json:"id"`
	SessionID     string         `json:"session_id"`
	ToolUseID     string         `json:"tool_use_id,omitempty"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name,omitempty"`
	Decision      risk.Decision  `json:"decision"`
	ReasonCode    string         `json:"reason_code"`
	Reason        string         `json:"reason"`
	RiskScore     *float64       `json:"risk_score,omitempty"`
	Threshold     *float64       `json:"threshold,omitempty"`
	ModelVersion  string         `json:"model_version,omitempty"`
	RiskEvent     risk.RiskEvent `json:"risk_event"`
	CreatedAt     time.Time      `json:"created_at"`
}

type Summary struct {
	Critical int `json:"critical"`
	Warnings int `json:"warnings"`
	Actions  int `json:"actions"`
	Sessions int `json:"sessions"`
}

type SessionSummary struct {
	SessionID string    `json:"session_id"`
	Critical  int       `json:"critical"`
	Warnings  int       `json:"warnings"`
	Actions   int       `json:"actions"`
	LatestAt  time.Time `json:"latest_at"`
}

type SessionRecord struct {
	ID         string     `json:"id"`
	Agent      string     `json:"agent,omitempty"`
	CWD        string     `json:"cwd,omitempty"`
	Source     string     `json:"source,omitempty"`
	Status     string     `json:"status,omitempty"`
	ExternalID string     `json:"external_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
}

func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, path: path}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
create table if not exists agent_sessions (
	  id text primary key,
	  agent text,
	  cwd text,
	  source text not null default 'daemon_observed',
	  status text not null default 'open',
	  external_id text,
	  closed_at text,
	  created_at text not null,
	  updated_at text not null
	);

create table if not exists risk_decisions (
  id text primary key,
  session_id text not null,
  tool_use_id text,
  hook_event_name text not null,
  tool_name text,
  decision text not null,
  reason_code text not null,
  reason text not null,
  risk_score real,
  threshold real,
  model_version text,
  risk_event_json text not null,
  created_at text not null
);

create index if not exists idx_risk_decisions_session_created
on risk_decisions(session_id, created_at);
	`)
	if err != nil {
		return err
	}
	for _, column := range []struct {
		name string
		def  string
	}{
		{name: "source", def: "text not null default 'daemon_observed'"},
		{name: "status", def: "text not null default 'open'"},
		{name: "external_id", def: "text"},
		{name: "closed_at", def: "text"},
	} {
		if err := s.ensureColumn(ctx, "agent_sessions", column.name, column.def); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureColumn(ctx context.Context, table, name, def string) error {
	rows, err := s.db.QueryContext(ctx, "pragma table_info("+table+")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var columnName, columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if columnName == name {
			return rows.Err()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf("alter table %s add column %s %s", table, name, def))
	return err
}

func (s *Store) OpenSession(ctx context.Context, sessionID, agent, cwd, source, externalID string) (SessionRecord, error) {
	now := time.Now().UTC()
	sessionID = normalizeSessionID(sessionID)
	if source == "" {
		source = "daemon_observed"
	}
	_, err := s.db.ExecContext(ctx, `
insert into agent_sessions(id, agent, cwd, source, status, external_id, closed_at, created_at, updated_at)
values(?, ?, ?, ?, 'open', ?, null, ?, ?)
on conflict(id) do update set
  agent = coalesce(nullif(excluded.agent, ''), agent_sessions.agent),
  cwd = coalesce(nullif(excluded.cwd, ''), agent_sessions.cwd),
  source = case
    when excluded.source = 'wrapper_owned' then excluded.source
    when agent_sessions.source = 'wrapper_owned' then agent_sessions.source
    else coalesce(nullif(excluded.source, ''), agent_sessions.source)
  end,
  status = 'open',
  external_id = coalesce(nullif(excluded.external_id, ''), agent_sessions.external_id),
  closed_at = null,
  updated_at = excluded.updated_at
	`, sessionID, agent, cwd, source, externalID, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return SessionRecord{}, err
	}
	return s.Session(ctx, sessionID)
}

func (s *Store) EnsureObservedSession(ctx context.Context, sessionID, agent, cwd string) (SessionRecord, error) {
	now := time.Now().UTC()
	sessionID = normalizeSessionID(sessionID)
	_, err := s.db.ExecContext(ctx, `
insert into agent_sessions(id, agent, cwd, source, status, created_at, updated_at)
values(?, ?, ?, 'daemon_observed', 'open', ?, ?)
on conflict(id) do update set
  agent = coalesce(nullif(excluded.agent, ''), agent_sessions.agent),
  cwd = coalesce(nullif(excluded.cwd, ''), agent_sessions.cwd),
  updated_at = excluded.updated_at
	`, sessionID, agent, cwd, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return SessionRecord{}, err
	}
	return s.Session(ctx, sessionID)
}

func (s *Store) CloseSession(ctx context.Context, sessionID string) error {
	sessionID = normalizeSessionID(sessionID)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
update agent_sessions
set status = 'closed', closed_at = ?, updated_at = ?
where id = ?
	`, now, now, sessionID)
	return err
}

func (s *Store) Session(ctx context.Context, sessionID string) (SessionRecord, error) {
	row := s.db.QueryRowContext(ctx, `
select id, coalesce(agent, ''), coalesce(cwd, ''), source, status, coalesce(external_id, ''),
  created_at, updated_at, closed_at
from agent_sessions
where id = ?
	`, sessionID)
	return scanSession(row)
}

func (s *Store) SaveDecision(ctx context.Context, event risk.HookEvent, decision risk.RiskDecision) (DecisionRecord, error) {
	now := time.Now().UTC()
	sessionID := normalizeSessionID(event.SessionID)
	id := "evt_" + uuid.NewString()
	riskEventJSON, err := json.Marshal(decision.RiskEvent)
	if err != nil {
		return DecisionRecord{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DecisionRecord{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	_, err = tx.ExecContext(ctx, `
insert into agent_sessions(id, agent, cwd, source, status, created_at, updated_at)
values(?, ?, ?, 'daemon_observed', 'open', ?, ?)
on conflict(id) do update set
  agent = coalesce(nullif(excluded.agent, ''), agent_sessions.agent),
  cwd = coalesce(nullif(excluded.cwd, ''), agent_sessions.cwd),
  updated_at = excluded.updated_at
	`, sessionID, event.Agent, event.CWD, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return DecisionRecord{}, err
	}
	_, err = tx.ExecContext(ctx, `
insert into risk_decisions(
  id, session_id, tool_use_id, hook_event_name, tool_name, decision, reason_code,
  reason, risk_score, threshold, model_version, risk_event_json, created_at
) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, id, sessionID, event.ToolUseID, event.HookEventName, event.ToolName, decision.Decision, decision.ReasonCode,
		decision.Reason, nullableFloat(decision.RiskScore), nullableFloat(decision.Threshold), decision.ModelVersion,
		string(riskEventJSON), now.Format(time.RFC3339Nano))
	if err != nil {
		return DecisionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return DecisionRecord{}, err
	}
	decision.EventID = id
	return DecisionRecord{
		ID:            id,
		SessionID:     sessionID,
		ToolUseID:     event.ToolUseID,
		HookEventName: event.HookEventName,
		ToolName:      event.ToolName,
		Decision:      decision.Decision,
		ReasonCode:    decision.ReasonCode,
		Reason:        decision.Reason,
		RiskScore:     decision.RiskScore,
		Threshold:     decision.Threshold,
		ModelVersion:  decision.ModelVersion,
		RiskEvent:     decision.RiskEvent,
		CreatedAt:     now,
	}, nil
}

func (s *Store) Summary(ctx context.Context) (Summary, error) {
	var summary Summary
	row := s.db.QueryRowContext(ctx, `
select
  coalesce(sum(case when "decision" = 'deny' then 1 else 0 end), 0),
  coalesce(sum(case when "decision" = 'ask' then 1 else 0 end), 0),
  count(*),
  (select count(*) from agent_sessions)
from risk_decisions
`)
	if err := row.Scan(&summary.Critical, &summary.Warnings, &summary.Actions, &summary.Sessions); err != nil {
		return Summary{}, err
	}
	return summary, nil
}

func (s *Store) Sessions(ctx context.Context) ([]SessionSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
select session_id,
  sum(case when "decision" = 'deny' then 1 else 0 end) as critical,
  sum(case when "decision" = 'ask' then 1 else 0 end) as warnings,
  count(*) as actions,
  max(created_at) as latest_at
from risk_decisions
group by session_id
order by latest_at desc
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := []SessionSummary{}
	for rows.Next() {
		var item SessionSummary
		var latest string
		if err := rows.Scan(&item.SessionID, &item.Critical, &item.Warnings, &item.Actions, &latest); err != nil {
			return nil, err
		}
		latestAt, err := parseStoredTime("session latest_at", latest)
		if err != nil {
			return nil, err
		}
		item.LatestAt = latestAt
		sessions = append(sessions, item)
	}
	return sessions, rows.Err()
}

func (s *Store) SessionSummary(ctx context.Context, sessionID string) (SessionSummary, error) {
	var item SessionSummary
	var latest string
	row := s.db.QueryRowContext(ctx, `
select session_id,
  sum(case when "decision" = 'deny' then 1 else 0 end),
  sum(case when "decision" = 'ask' then 1 else 0 end),
  count(*),
  max(created_at)
from risk_decisions
where session_id = ?
group by session_id
`, sessionID)
	if err := row.Scan(&item.SessionID, &item.Critical, &item.Warnings, &item.Actions, &latest); err != nil {
		return SessionSummary{}, err
	}
	latestAt, err := parseStoredTime("session latest_at", latest)
	if err != nil {
		return SessionSummary{}, err
	}
	item.LatestAt = latestAt
	return item, nil
}

func (s *Store) Events(ctx context.Context, sessionID string) ([]DecisionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, session_id, coalesce(tool_use_id, ''), hook_event_name, coalesce(tool_name, ''),
  decision, reason_code, reason, risk_score, threshold, coalesce(model_version, ''),
  risk_event_json, created_at
from risk_decisions
where session_id = ?
order by created_at desc
`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []DecisionRecord{}
	for rows.Next() {
		record, err := scanDecision(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func scanDecision(scanner interface{ Scan(...any) error }) (DecisionRecord, error) {
	var record DecisionRecord
	var score sql.NullFloat64
	var threshold sql.NullFloat64
	var riskEventJSON string
	var created string
	if err := scanner.Scan(&record.ID, &record.SessionID, &record.ToolUseID, &record.HookEventName, &record.ToolName,
		&record.Decision, &record.ReasonCode, &record.Reason, &score, &threshold, &record.ModelVersion,
		&riskEventJSON, &created); err != nil {
		return DecisionRecord{}, err
	}
	if score.Valid {
		record.RiskScore = &score.Float64
	}
	if threshold.Valid {
		record.Threshold = &threshold.Float64
	}
	if err := json.Unmarshal([]byte(riskEventJSON), &record.RiskEvent); err != nil {
		return DecisionRecord{}, err
	}
	createdAt, err := parseStoredTime("decision created_at", created)
	if err != nil {
		return DecisionRecord{}, err
	}
	record.CreatedAt = createdAt
	return record, nil
}

func scanSession(scanner interface{ Scan(...any) error }) (SessionRecord, error) {
	var record SessionRecord
	var created, updated string
	var closed sql.NullString
	if err := scanner.Scan(
		&record.ID,
		&record.Agent,
		&record.CWD,
		&record.Source,
		&record.Status,
		&record.ExternalID,
		&created,
		&updated,
		&closed,
	); err != nil {
		return SessionRecord{}, err
	}
	createdAt, err := parseStoredTime("session created_at", created)
	if err != nil {
		return SessionRecord{}, err
	}
	updatedAt, err := parseStoredTime("session updated_at", updated)
	if err != nil {
		return SessionRecord{}, err
	}
	record.CreatedAt = createdAt
	record.UpdatedAt = updatedAt
	if closed.Valid && closed.String != "" {
		closedAt, err := parseStoredTime("session closed_at", closed.String)
		if err != nil {
			return SessionRecord{}, err
		}
		record.ClosedAt = &closedAt
	}
	return record, nil
}

func parseStoredTime(label, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s %q: %w", label, value, err)
	}
	return parsed, nil
}

func nullableFloat(value *float64) any {
	if value == nil {
		return nil
	}
	return *value
}

func normalizeSessionID(sessionID string) string {
	if sessionID == "" {
		return "local"
	}
	return sessionID
}
