package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseOutputValidatesDecisionSchema(t *testing.T) {
	output, err := ParseOutput(`{"decision":"deny","risk_level":"high","categories":["production_mutation"],"reason":"Deletes production data."}`)
	if err != nil {
		t.Fatal(err)
	}
	if output.Decision != DecisionDeny || output.RiskLevel != RiskLevelHigh {
		t.Fatalf("output = %+v", output)
	}
}

func TestParseOutputRejectsAsk(t *testing.T) {
	_, err := ParseOutput(`{"decision":"ask","risk_level":"medium","categories":["review"],"reason":"Needs review."}`)
	if err == nil {
		t.Fatal("ParseOutput() error = nil, want invalid decision")
	}
}

func TestParseOutputRejectsPlaceholderCategory(t *testing.T) {
	for _, placeholder := range []string{"short_snake_case_category", "one_or_more_specific_risk_or_safety_labels", "one_or_more_short_snake_case_labels"} {
		t.Run(placeholder, func(t *testing.T) {
			_, err := ParseOutput(`{"decision":"allow","risk_level":"low","categories":["` + placeholder + `"],"reason":"Looks safe."}`)
			if err == nil {
				t.Fatal("ParseOutput() error = nil, want placeholder category rejection")
			}
		})
	}
}

func TestOpenAICompatibleJudgeCallsChatCompletions(t *testing.T) {
	var request openAIChatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("path = %q, want /v1/chat/completions", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"decision\":\"allow\",\"risk_level\":\"low\",\"categories\":[\"normal_coding\"],\"reason\":\"Reads a project file.\"}"}}]}`))
	}))
	defer server.Close()

	judge, err := NewOpenAICompatibleJudge(HTTPOptions{
		BaseURL: server.URL,
		Model:   "qwen3-0.6b-q4",
		Runtime: "llama-server",
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := judge.Decide(context.Background(), Input{
		ToolName:  "Bash",
		ToolInput: ToolInput{Command: "npx prisma migrate deploy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.Model != "qwen3-0.6b-q4" || len(request.Messages) != 2 {
		t.Fatalf("request = %+v", request)
	}
	if !strings.HasPrefix(request.Messages[1].Content, "/no_think") {
		t.Fatalf("user message should disable thinking, got %q", request.Messages[1].Content)
	}
	if strings.Contains(request.Messages[0].Content, "/no_think") {
		t.Fatalf("system message should not include thinking control token, got %q", request.Messages[0].Content)
	}
	if !strings.Contains(request.Messages[1].Content, `"command":"npx prisma migrate deploy"`) {
		t.Fatalf("user message missing command, got %q", request.Messages[1].Content)
	}
	for _, noisyField := range []string{"normalized_event", "deterministic_policy", "explicit_user_intent", "normal_tool_call"} {
		if strings.Contains(request.Messages[1].Content, noisyField) {
			t.Fatalf("user message includes noisy field %q: %q", noisyField, request.Messages[1].Content)
		}
	}
	if request.MaxTokens != 256 {
		t.Fatalf("max tokens = %d, want 256", request.MaxTokens)
	}
	if result.Output.Decision != DecisionAllow || result.Metadata.Model != "qwen3-0.6b-q4" || result.Metadata.Runtime != "llama-server" {
		t.Fatalf("result = %+v", result)
	}
}

func TestOpenAICompatibleJudgeDoesNotDisableThinkingForGenericModel(t *testing.T) {
	var request openAIChatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"decision\":\"allow\",\"risk_level\":\"low\",\"categories\":[\"normal_coding\"],\"reason\":\"Reads a project file.\"}"}}]}`))
	}))
	defer server.Close()

	localJudge, err := NewOpenAICompatibleJudge(HTTPOptions{
		BaseURL: server.URL,
		Model:   "generic-local-model",
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localJudge.Decide(context.Background(), Input{}); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(request.Messages[1].Content, "/no_think") {
		t.Fatalf("generic model should not receive /no_think, got %q", request.Messages[1].Content)
	}
}

func TestOpenAICompatibleJudgeCanExplicitlyDisableThinking(t *testing.T) {
	var request openAIChatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"decision\":\"allow\",\"risk_level\":\"low\",\"categories\":[\"normal_coding\"],\"reason\":\"Reads a project file.\"}"}}]}`))
	}))
	defer server.Close()

	localJudge, err := NewOpenAICompatibleJudge(HTTPOptions{
		BaseURL:         server.URL,
		Model:           "generic-local-model",
		Timeout:         time.Second,
		DisableThinking: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localJudge.Decide(context.Background(), Input{}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(request.Messages[1].Content, "/no_think") {
		t.Fatalf("user message should disable thinking, got %q", request.Messages[1].Content)
	}
}

func TestOpenAICompatibleJudgeClassifiesTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer server.Close()

	judge, err := NewOpenAICompatibleJudge(HTTPOptions{
		BaseURL: server.URL,
		Model:   "qwen3-0.6b-q4",
		Timeout: time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = judge.Decide(context.Background(), Input{})
	if FailureKind(err) != FailureTimeout {
		t.Fatalf("FailureKind(err) = %q, err=%v", FailureKind(err), err)
	}
}

func TestOpenAICompatibleJudgeDoesNotFollowRedirects(t *testing.T) {
	redirectTargetCalled := false
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirectTarget.Close()
	redirectSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer redirectSource.Close()

	localJudge, err := NewOpenAICompatibleJudge(HTTPOptions{
		BaseURL: redirectSource.URL,
		Model:   "qwen3-0.6b-q4",
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = localJudge.Decide(context.Background(), Input{})
	if FailureKind(err) != FailureUnavailable {
		t.Fatalf("FailureKind(err) = %q, err=%v", FailureKind(err), err)
	}
	if redirectTargetCalled {
		t.Fatal("judge followed redirect target")
	}
}

func TestChatCompletionsEndpointAcceptsV1Base(t *testing.T) {
	endpoint, err := chatCompletionsEndpoint("http://127.0.0.1:8080/v1")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "http://127.0.0.1:8080/v1/chat/completions" {
		t.Fatalf("endpoint = %q", endpoint)
	}
}
