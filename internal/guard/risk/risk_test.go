package risk

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeCredentialFileRead(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Read", ToolInput: map[string]any{"file_path": ".env"}})
	if event.Type != EventCredentialAccess {
		t.Fatalf("type = %s, want %s", event.Type, EventCredentialAccess)
	}
	if event.PathClass != "env_file" {
		t.Fatalf("path class = %s", event.PathClass)
	}
}

func TestNormalizeRelativeCloudCredentialFileRead(t *testing.T) {
	for _, path := range []string{
		".aws/credentials",
		"./.gcloud/application_default_credentials.json",
		".config/railway/config.json",
		"nested/.aws/config",
	} {
		t.Run(path, func(t *testing.T) {
			event := NormalizeHookEvent(HookEvent{ToolName: "Read", ToolInput: map[string]any{"file_path": path}})
			if event.Type != EventCredentialAccess {
				t.Fatalf("type = %s, want %s", event.Type, EventCredentialAccess)
			}
			if event.PathClass != "cloud_credentials" {
				t.Fatalf("path class = %s, want cloud_credentials", event.PathClass)
			}
		})
	}
}

func TestNormalizeShellCredentialAccess(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "cat .env"}})
	if event.Type != EventCredentialAccess {
		t.Fatalf("type = %s", event.Type)
	}
	if event.CredentialSource != "command_output" {
		t.Fatalf("credential source = %s", event.CredentialSource)
	}
}

func TestNormalizeDirectProviderAPI(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "curl https://api.railway.app/graphql -H 'Authorization: Bearer secret'"}})
	if event.Type != EventDirectProviderAPICall {
		t.Fatalf("type = %s", event.Type)
	}
	if !event.CredentialObserved {
		t.Fatal("credential was not observed")
	}
}

func TestNormalizeDestructiveOperation(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "railway volume delete production"}})
	if event.Type != EventDestructiveProviderOperation {
		t.Fatalf("type = %s", event.Type)
	}
	if event.OperationClass != "delete" {
		t.Fatalf("operation class = %s", event.OperationClass)
	}
}

func TestNormalizeDestructiveSourceControlOperation(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "gh repo delete kontext-security/guard"}})
	if event.Type != EventDestructiveProviderOperation {
		t.Fatalf("type = %s", event.Type)
	}
	if event.ProviderCategory != "source_control" {
		t.Fatalf("provider category = %s", event.ProviderCategory)
	}
	if event.ResourceClass != "repo" {
		t.Fatalf("resource class = %s", event.ResourceClass)
	}
}

func TestNormalizeGitCommitIgnoresCommitMessageBody(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `git commit -m "$(cat <<'EOF'
feat: improve dashboard

Mentions production database delete only as copied text.
EOF
)"`}})
	if event.Type != EventNormalToolCall {
		t.Fatalf("type = %s", event.Type)
	}
	if event.OperationClass != "write" {
		t.Fatalf("operation class = %s", event.OperationClass)
	}
	if event.Environment == "production" {
		t.Fatal("environment should not be inferred from commit body")
	}
	if event.CredentialObserved {
		t.Fatal("credential material should not be inferred from commit body")
	}
	for _, signal := range event.Signals {
		if signal == "destructive_verb" || signal == "persistent_resource" {
			t.Fatalf("unexpected signal %s", signal)
		}
	}
}

func TestNormalizeGitHubPRDoesNotTreatBodyAsCredential(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `gh pr create --title "feat: dashboard" --body "$(cat <<'EOF'
This mentions token handling in documentation but does not pass a token.
EOF
)"`}})
	if event.ProviderCategory != "source_control" {
		t.Fatalf("provider category = %s", event.ProviderCategory)
	}
	if event.CredentialObserved {
		t.Fatal("credential material should not be inferred from PR body text")
	}
}

func TestNormalizeDirectProviderAPIStillSeesAuthorizationHeader(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `curl https://api.cloudflare.com/client/v4/zones -H "Authorization: Bearer abc123"`}})
	if event.Type != EventDirectProviderAPICall {
		t.Fatalf("type = %s", event.Type)
	}
	if !event.CredentialObserved {
		t.Fatal("credential material was not observed")
	}
}

func TestNormalizeDirectProviderAPIGoogleCloud(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `curl https://storage.googleapis.com/storage/v1/b/example-bucket/o`}})
	if event.Type != EventDirectProviderAPICall {
		t.Fatalf("type = %s", event.Type)
	}
	if event.Provider != "google_cloud" {
		t.Fatalf("provider = %s, want google_cloud", event.Provider)
	}
	if event.ProviderCategory != "infrastructure" {
		t.Fatalf("provider category = %s, want infrastructure", event.ProviderCategory)
	}
}

func TestNormalizeRedactsCredentialValuesFromSummaries(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `API_TOKEN=real-secret-123 curl https://api.cloudflare.com -H "Authorization: Bearer abc123"`}})
	for _, value := range []string{event.CommandSummary, event.RequestSummary} {
		if strings.Contains(value, "real-secret-123") || strings.Contains(value, "abc123") {
			t.Fatalf("summary leaked credential value: %q", value)
		}
		if !strings.Contains(value, "[redacted-credential]") {
			t.Fatalf("summary did not include redaction marker: %q", value)
		}
	}
}

func TestDeterministicDecisionBlocksDestructiveCommand(t *testing.T) {
	decision, err := DecideRisk(HookEvent{HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: map[string]any{"command": "drop database"}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision = %s", decision.Decision)
	}
}

func TestDeterministicDecisionAllowsNormalToolCalls(t *testing.T) {
	decision, err := DecideRisk(HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": "README.md"}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionAllow {
		t.Fatalf("decision = %s", decision.Decision)
	}
}

func TestDeterministicDecisionBlocksRelativeCloudCredentialRead(t *testing.T) {
	decision, err := DecideRisk(HookEvent{
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": ".aws/credentials"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want %s", decision.Decision, DecisionDeny)
	}
	if decision.ReasonCode != "credential_access_without_intent" {
		t.Fatalf("reason code = %s", decision.ReasonCode)
	}
}

func TestAsyncTelemetryAllowsWithoutRiskModel(t *testing.T) {
	decision, err := DecideRisk(HookEvent{HookEventName: "UserPromptSubmit", ToolName: "Read"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionAllow {
		t.Fatalf("decision = %s", decision.Decision)
	}
}

func TestAddSignalPreservesFirstSeenOrderAndSkipsDuplicates(t *testing.T) {
	t.Parallel()

	event := RiskEvent{}
	signalSet := make(map[string]struct{}, 3)

	addSignal(&event, signalSet, "source_control")
	addSignal(&event, signalSet, "direct_provider_api")
	addSignal(&event, signalSet, "source_control")
	addSignal(&event, signalSet, "credential_observed")
	addSignal(&event, signalSet, "direct_provider_api")

	want := []string{"source_control", "direct_provider_api", "credential_observed"}
	if !reflect.DeepEqual(event.Signals, want) {
		t.Fatalf("signals = %#v, want %#v", event.Signals, want)
	}
}
