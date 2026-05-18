package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/policy"
	"github.com/kontext-security/kontext-cli/internal/guard/policyconfig"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
)

func newTestServer(t *testing.T, store *sqlite.Store) *Server {
	t.Helper()
	server, err := NewServer(store)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	return server
}

func newTestServerWithPolicy(t *testing.T, store *sqlite.Store, policy PolicyProvider) *Server {
	t.Helper()
	server, err := NewServerWithPolicy(store, policy)
	if err != nil {
		t.Fatalf("NewServerWithPolicy() error = %v", err)
	}
	return server
}

func newTestServerWithPolicyConfig(t *testing.T, store *sqlite.Store, policyStore *policyconfig.Store) *Server {
	t.Helper()
	server, err := NewServerWithPolicyConfig(store, NewRiskPolicyProvider(), policyStore)
	if err != nil {
		t.Fatalf("NewServerWithPolicyConfig() error = %v", err)
	}
	return server
}

func TestStorePersistsSummaryCounts(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)
	events := []risk.HookEvent{
		{SessionID: "s1", HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": "README.md"}},
		{SessionID: "s1", HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": ".env"}},
		{SessionID: "s1", HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: map[string]any{"command": "drop database"}},
	}
	for _, event := range events {
		if _, err := server.ProcessHookEvent(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 3 || summary.Warnings != 0 || summary.Critical != 2 || summary.Sessions != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestProcessHookEventUsesPolicyProvider(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := recordingPolicy{
		decision: risk.RiskDecision{
			Decision:   risk.DecisionAsk,
			Reason:     "custom policy",
			ReasonCode: "custom_policy",
			RiskEvent: risk.RiskEvent{
				Type: risk.EventUnknown,
			},
		},
	}
	server := newTestServerWithPolicy(t, store, &policy)
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "deploy prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.called {
		t.Fatal("policy provider was not called")
	}
	if decision.Decision != risk.DecisionAsk || decision.ReasonCode != "custom_policy" || decision.EventID == "" {
		t.Fatalf("decision = %+v", decision)
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 1 || summary.Warnings != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestPolicyProfileGetReturnsLoadedDefault(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policyStore, err := policyconfig.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyConfig(t, store, policyStore)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/policy/profile", nil)
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response PolicyProfileResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Profile != policy.ProfileBalanced || response.RecommendedProfile != policy.ProfileBalanced {
		t.Fatalf("response = %+v, want default balanced profile", response)
	}
	if response.Version != policy.DefaultPolicyVersion || response.RulePack != policy.DefaultRulePackID || response.ActivationID == "" {
		t.Fatalf("response metadata = %+v", response)
	}
}

func TestPolicyProfilePostActivatesProfile(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policyStore, err := policyconfig.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyConfig(t, store, policyStore)

	body := bytes.NewBufferString(`{"profile":"strict"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/policy/profile", body)
	request.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response PolicyProfileResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Profile != policy.ProfileStrict {
		t.Fatalf("profile = %q, want strict", response.Profile)
	}
	if policyStore.Current().Config.Profile != policy.ProfileStrict {
		t.Fatalf("current profile = %q, want strict", policyStore.Current().Config.Profile)
	}
}

func TestPolicyProfilePostRejectsInvalidProfile(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policyStore, err := policyconfig.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyConfig(t, store, policyStore)
	initial := policyStore.Current()

	body := bytes.NewBufferString(`{"profile":"paranoid"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/policy/profile", body)
	request.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	current := policyStore.Current()
	if current.Config.Profile != initial.Config.Profile || current.ConfigDigest != initial.ConfigDigest {
		t.Fatalf("current = %+v, want unchanged %+v", current, initial)
	}
}

func TestPolicyProfilePostRejectsCrossOriginRequest(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policyStore, err := policyconfig.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyConfig(t, store, policyStore)
	initial := policyStore.Current()

	body := bytes.NewBufferString(`{"profile":"relaxed"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/policy/profile", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://example.test")
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	current := policyStore.Current()
	if current.Config.Profile != initial.Config.Profile || current.ConfigDigest != initial.ConfigDigest {
		t.Fatalf("current = %+v, want unchanged %+v", current, initial)
	}
}

func TestPolicyProfilePostAllowsTrustedDashboardOrigins(t *testing.T) {
	tests := []struct {
		name   string
		target string
		origin string
	}{
		{name: "same origin", target: "http://127.0.0.1:4765/api/policy/profile", origin: "http://127.0.0.1:4765"},
		{name: "vite dev", target: "http://127.0.0.1:4765/api/policy/profile", origin: devDashboardOrigin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			policyStore, err := policyconfig.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			server := newTestServerWithPolicyConfig(t, store, policyStore)

			body := bytes.NewBufferString(`{"profile":"strict"}`)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, tt.target, body)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", tt.origin)
			server.Handler().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
			}
			if policyStore.Current().Config.Profile != policy.ProfileStrict {
				t.Fatalf("current profile = %q, want strict", policyStore.Current().Config.Profile)
			}
		})
	}
}

func TestPolicyProfilePostRejectsSimpleContentType(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policyStore, err := policyconfig.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyConfig(t, store, policyStore)
	initial := policyStore.Current()

	body := bytes.NewBufferString(`{"profile":"relaxed"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/policy/profile", body)
	request.Header.Set("Content-Type", "text/plain")
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusUnsupportedMediaType, recorder.Body.String())
	}
	current := policyStore.Current()
	if current.Config.Profile != initial.Config.Profile || current.ConfigDigest != initial.ConfigDigest {
		t.Fatalf("current = %+v, want unchanged %+v", current, initial)
	}
}

func TestProcessHookEventEnsuresDaemonObservedSession(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)

	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	}); err != nil {
		t.Fatal(err)
	}

	session, err := store.Session(context.Background(), "local")
	if err != nil {
		t.Fatal(err)
	}
	if session.Source != "daemon_observed" || session.Status != "open" || session.Agent != "claude" {
		t.Fatalf("session = %+v, want daemon-observed local session", session)
	}
	events, err := store.Events(context.Background(), "local")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].SessionID != "local" {
		t.Fatalf("events = %+v, want one local event", events)
	}
}

func TestProcessHookEventPreservesClosedWrapperOwnedSession(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)

	if _, err := store.OpenSession(context.Background(), "session-123", "claude", "/tmp/project", "wrapper_owned", "backend-123"); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(context.Background(), "session-123"); err != nil {
		t.Fatal(err)
	}

	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "session-123",
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	}); err != nil {
		t.Fatal(err)
	}

	session, err := store.Session(context.Background(), "session-123")
	if err != nil {
		t.Fatal(err)
	}
	if session.Source != "wrapper_owned" || session.Status != "closed" || session.ClosedAt == nil {
		t.Fatalf("session = %+v, want closed wrapper-owned session", session)
	}
	events, err := store.Events(context.Background(), "session-123")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one event", events)
	}
}

func TestProcessHookEventPreservesRiskMetadata(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	score := 0.91
	threshold := 0.8
	policy := recordingPolicy{
		decision: risk.RiskDecision{
			Decision:     risk.DecisionDeny,
			Reason:       "custom policy",
			ReasonCode:   "custom_policy",
			RiskScore:    &score,
			Threshold:    &threshold,
			ModelVersion: "model-v1",
			GuardID:      "guard-1",
			RiskEvent: risk.RiskEvent{
				Type:         risk.EventDirectProviderAPICall,
				ModelVersion: "model-v1",
				GuardID:      "guard-1",
			},
		},
	}
	server := newTestServerWithPolicy(t, store, &policy)
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "curl https://api.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.RiskScore == nil || *decision.RiskScore != score {
		t.Fatalf("RiskScore = %+v, want %v", decision.RiskScore, score)
	}
	if decision.Threshold == nil || *decision.Threshold != threshold {
		t.Fatalf("Threshold = %+v, want %v", decision.Threshold, threshold)
	}
	if decision.ModelVersion != "model-v1" || decision.GuardID != "guard-1" || decision.RiskEvent.Type != risk.EventDirectProviderAPICall {
		t.Fatalf("decision metadata = %+v", decision)
	}
}

func TestDashboardEventsHideModelMetadata(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := recordingPolicy{
		decision: risk.RiskDecision{
			Decision:     risk.DecisionDeny,
			Reason:       "local judge denied",
			ReasonCode:   risk.DecisionStageJudgeDeny,
			ModelVersion: "qwen3-0.6b-q4",
			RiskEvent: risk.RiskEvent{
				Type:           risk.EventNormalToolCall,
				DecisionStage:  risk.DecisionStageJudgeDeny,
				ModelVersion:   "qwen3-0.6b-q4",
				JudgeModel:     "qwen3-0.6b-q4",
				JudgeRiskLevel: "high",
			},
		},
	}
	server := newTestServerWithPolicy(t, store, &policy)
	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "curl -X POST https://admin.example/reindex"},
	}); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Events(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 ||
		stored[0].ModelVersion != "qwen3-0.6b-q4" ||
		stored[0].RiskEvent.ModelVersion != "qwen3-0.6b-q4" ||
		stored[0].RiskEvent.JudgeModel != "qwen3-0.6b-q4" {
		t.Fatalf("stored events = %+v, want model metadata retained internally", stored)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sessions/s1/events", nil)
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response []sqlite.DecisionRecord
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response) != 1 ||
		response[0].ModelVersion != "" ||
		response[0].RiskEvent.ModelVersion != "" ||
		response[0].RiskEvent.JudgeModel != "" {
		t.Fatalf("response = %+v, want model metadata hidden", response)
	}
}

func TestJudgePolicyDeniesFromLocalJudge(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionDeny,
				RiskLevel:  judge.RiskLevelHigh,
				Categories: []string{"destructive_operation"},
				Reason:     "Risky operation.",
			},
			Metadata: judge.Metadata{
				Runtime:    "openai-compatible",
				Model:      "qwen3-0.6b-q4",
				DurationMs: 12,
			},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "python scripts/deploy.py --dry-run"},
		CWD:           "/tmp/project",
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	if localJudge.input.Agent != "claude" || localJudge.input.CWDClass != "project" {
		t.Fatalf("judge input = %+v", localJudge.input)
	}
	if decision.Decision != risk.DecisionDeny || decision.ReasonCode != "judge_deny" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.RiskEvent.DecisionStage != risk.DecisionStageJudgeDeny || decision.RiskEvent.JudgeModel != "qwen3-0.6b-q4" || decision.RiskEvent.JudgeRiskLevel != "high" {
		t.Fatalf("risk event = %+v", decision.RiskEvent)
	}
}

func TestJudgePolicyAllowsFromLocalJudge(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionAllow,
				RiskLevel:  judge.RiskLevelLow,
				Categories: []string{"normal_coding"},
				Reason:     "Safe local read.",
			},
			Metadata: judge.Metadata{
				Runtime:    "openai-compatible",
				Model:      "qwen3-0.6b-q4",
				DurationMs: 8,
			},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	if localJudge.input.NormalizedEvent.Type != string(risk.EventNormalToolCall) {
		t.Fatalf("judge input = %+v", localJudge.input)
	}
	if localJudge.input.DeterministicPolicy.Decision != "allow" || localJudge.input.DeterministicPolicy.PolicyVersion != policy.DefaultPolicyVersion {
		t.Fatalf("deterministic context = %+v", localJudge.input.DeterministicPolicy)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != risk.DecisionStageJudgeAllow {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.RiskEvent.DecisionStage != risk.DecisionStageJudgeAllow || decision.RiskEvent.PolicyVersion != policy.DefaultPolicyVersion {
		t.Fatalf("risk event = %+v", decision.RiskEvent)
	}
}

func TestJudgePolicyRedactsCredentialValuesFromJudgeInput(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionAllow,
				RiskLevel:  judge.RiskLevelLow,
				Categories: []string{"normal_coding"},
				Reason:     "Safe.",
			},
			Metadata: judge.Metadata{Runtime: "openai-compatible", Model: "qwen3-0.6b-q4"},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": `echo API_TOKEN=real-secret-123`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	got := localJudge.input.ToolInput.CommandRedacted + " " + localJudge.input.ToolInput.RequestSummary + " " + localJudge.input.NormalizedEvent.CommandSummary + " " + localJudge.input.NormalizedEvent.RequestSummary
	if strings.Contains(got, "real-secret-123") {
		t.Fatalf("judge input leaked credential value: %+v", localJudge.input)
	}
	if !strings.Contains(got, "[redacted-credential]") {
		t.Fatalf("judge input missing redaction marker: %+v", localJudge.input)
	}
}

func TestJudgePolicyFailsOpenWhenJudgeUnavailable(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server, err := NewServerWithOptions(store, Options{
		Judge: &recordingJudge{err: judge.Error{Kind: judge.FailureTimeout, Err: context.DeadlineExceeded}},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "python scripts/deploy.py --dry-run"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != "judge_unavailable_allow" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.RiskEvent.JudgeFailureKind != judge.FailureTimeout || decision.RiskEvent.DecisionStage != risk.DecisionStageJudgeFailOpen {
		t.Fatalf("risk event = %+v", decision.RiskEvent)
	}
}

func TestJudgePolicyDeterministicDecisionSkipsJudge(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "drop database"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 0 {
		t.Fatalf("judge calls = %d, want 0", localJudge.calls)
	}
	if decision.Decision != risk.DecisionDeny || decision.RiskEvent.DecisionStage != risk.DecisionStageDeterministicDeny {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.RiskEvent.PolicyRuleID != "guard.destructive_persistent_resource.v1" ||
		decision.RiskEvent.PolicyRuleCategory != string(policy.CategoryDestructivePersistentResource) ||
		decision.RiskEvent.PolicyVersion != policy.DefaultPolicyVersion {
		t.Fatalf("policy metadata = %+v", decision.RiskEvent)
	}
}

func TestJudgePolicyUsesActiveProfileForDeterministicRules(t *testing.T) {
	dir := t.TempDir()
	policyStore, err := policyconfig.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyStore.ActivateProfile(context.Background(), policy.ProfileRelaxed); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionAllow,
				RiskLevel:  judge.RiskLevelLow,
				Categories: []string{"explicit_profile"},
				Reason:     "Relaxed profile allows this to reach the judge.",
			},
			Metadata: judge.Metadata{Runtime: "openai-compatible", Model: "qwen3-0.6b-q4"},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": ".env"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	if localJudge.input.NormalizedEvent.Type != string(risk.EventCredentialAccess) {
		t.Fatalf("judge input = %+v", localJudge.input)
	}
	if decision.Decision != risk.DecisionAllow || decision.RiskEvent.PolicyProfile != string(policy.ProfileRelaxed) {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestJudgePolicyFallsBackWhenActivePolicyConfigInvalid(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "guard", "policy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "guard", "policy", "active.json"), []byte(`{"version":"invalid-active-policy","profile":"custom","rulePack":"guard-default","nonBypassableRules":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionAllow,
				RiskLevel:  judge.RiskLevelLow,
				Categories: []string{"fallback"},
				Reason:     "Fallback policy allowed this to reach the judge.",
			},
			Metadata: judge.Metadata{Runtime: "openai-compatible", Model: "qwen3-0.6b-q4"},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	if localJudge.input.DeterministicPolicy.PolicyVersion != policy.DefaultPolicyVersion {
		t.Fatalf("deterministic context = %+v", localJudge.input.DeterministicPolicy)
	}
	if decision.RiskEvent.PolicyVersion != policy.DefaultPolicyVersion || decision.RiskEvent.PolicyProfile != string(policy.ProfileBalanced) {
		t.Fatalf("risk event = %+v", decision.RiskEvent)
	}
}

func TestEvaluateHookRejectsTelemetryEvents(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)
	_, err = server.EvaluateHook(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git status"},
	})
	if err == nil {
		t.Fatal("EvaluateHook() error = nil, want telemetry rejection")
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 0 {
		t.Fatalf("summary = %+v, want no persisted action", summary)
	}
}

func TestIngestEventRecordsTelemetry(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)
	decision, err := server.IngestEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git status"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != "async_telemetry" || decision.EventID == "" {
		t.Fatalf("decision = %+v, want telemetry allow decision", decision)
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 1 || summary.Warnings != 0 || summary.Critical != 0 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestIngestEventRejectsBlockingEvents(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)
	_, err = server.IngestEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "drop database"},
	})
	if err == nil {
		t.Fatal("IngestEvent() error = nil, want blocking event rejection")
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 0 {
		t.Fatalf("summary = %+v, want no persisted action", summary)
	}
}

type recordingPolicy struct {
	called   bool
	decision risk.RiskDecision
	err      error
}

type recordingJudge struct {
	calls  int
	input  judge.Input
	result judge.Result
	err    error
}

func (j *recordingJudge) Decide(_ context.Context, input judge.Input) (judge.Result, error) {
	j.calls++
	j.input = input
	if j.err != nil {
		return judge.Result{}, j.err
	}
	return j.result, nil
}

func (p *recordingPolicy) DecideHook(_ context.Context, _ risk.HookEvent) (risk.RiskDecision, error) {
	p.called = true
	return p.decision, p.err
}

func TestStoreListsSessions(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)
	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": ".env"},
	}); err != nil {
		t.Fatal(err)
	}
	sessions, err := store.Sessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].SessionID != "s1" || sessions[0].Critical != 1 {
		t.Fatalf("sessions = %+v", sessions)
	}
}
