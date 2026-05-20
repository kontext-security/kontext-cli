package judge

import (
	"os"
	"strings"
	"testing"
)

func TestLaunchFixturesValidateContract(t *testing.T) {
	fixtures := loadLaunchFixtures(t)
	if len(fixtures) != 61 {
		t.Fatalf("fixtures = %d, want 61", len(fixtures))
	}
	ids := map[string]bool{}
	counts := map[string]int{}
	for _, fixture := range fixtures {
		if ids[fixture.ID] {
			t.Fatalf("duplicate fixture id %q", fixture.ID)
		}
		ids[fixture.ID] = true
		prefix := strings.SplitN(fixture.ID, "_", 2)[0]
		counts[prefix]++

		if fixture.HookEvent.Agent == "" || fixture.HookEvent.HookEventName != "PreToolUse" || fixture.HookEvent.ToolName == "" {
			t.Fatalf("%s hook event = %+v", fixture.ID, fixture.HookEvent)
		}
		if len(fixture.HookEvent.ToolInput) == 0 {
			t.Fatalf("%s hook input is empty", fixture.ID)
		}
		if fixture.DeterministicPolicy.PolicyVersion != "guard-launch-v0" {
			t.Fatalf("%s policy version = %q", fixture.ID, fixture.DeterministicPolicy.PolicyVersion)
		}
		switch fixture.DeterministicPolicy.Decision {
		case string(DecisionAllow):
			if !fixture.JudgeExpected.ShouldCallJudge {
				t.Fatalf("%s deterministic allow should call judge", fixture.ID)
			}
		case string(DecisionDeny):
			if fixture.JudgeExpected.ShouldCallJudge {
				t.Fatalf("%s deterministic deny should skip judge", fixture.ID)
			}
		default:
			t.Fatalf("%s deterministic decision = %q", fixture.ID, fixture.DeterministicPolicy.Decision)
		}
		output := Output{
			Decision:   fixture.JudgeExpected.Decision,
			RiskLevel:  fixture.JudgeExpected.RiskLevel,
			Categories: fixture.JudgeExpected.Categories,
			Reason:     strings.Join(fixture.JudgeExpected.ReasonContains, " "),
		}
		if err := ValidateOutput(output); err != nil {
			t.Fatalf("%s expected output invalid: %v", fixture.ID, err)
		}
		if fixture.JudgeExpected.Decision == DecisionDeny && fixture.JudgeExpected.RiskLevel == RiskLevelLow {
			t.Fatalf("%s deny fixture cannot be low risk", fixture.ID)
		}
		if fixture.NormalizedEvent.Type == "" || fixture.NormalizedEvent.ProviderCategory == "" || fixture.NormalizedEvent.OperationClass == "" || fixture.NormalizedEvent.ResourceClass == "" || fixture.NormalizedEvent.Environment == "" {
			t.Fatalf("%s normalized event has empty required fields: %+v", fixture.ID, fixture.NormalizedEvent)
		}
	}
	wantCounts := map[string]int{
		"safe":     23,
		"deny":     8,
		"risky":    12,
		"trap":     8,
		"explicit": 5,
		"managed":  5,
	}
	for prefix, want := range wantCounts {
		if counts[prefix] != want {
			t.Fatalf("%s fixtures = %d, want %d", prefix, counts[prefix], want)
		}
	}
}

func TestLaunchFixturesMapToJudgeInput(t *testing.T) {
	for _, fixture := range loadLaunchFixtures(t) {
		if !fixture.JudgeExpected.ShouldCallJudge {
			continue
		}
		input := InputFromFixture(fixture)
		if input.ToolName == "" {
			t.Fatalf("%s mapped judge input missing hook metadata: %+v", fixture.ID, input)
		}
		if input.ToolName == "Bash" && input.ToolInput.Command == "" {
			t.Fatalf("%s Bash fixture missing command summary for judge input", fixture.ID)
		}
		if input.ToolInput.Command != fixture.NormalizedEvent.CommandSummary {
			t.Fatalf("%s command = %q, want normalized summary %q", fixture.ID, input.ToolInput.Command, fixture.NormalizedEvent.CommandSummary)
		}
		if fixture.NormalizedEvent.PathClass != "" && input.ToolInput.Path != fixture.NormalizedEvent.PathClass {
			t.Fatalf("%s path = %q, want normalized path class %q", fixture.ID, input.ToolInput.Path, fixture.NormalizedEvent.PathClass)
		}
		if input.ExplicitUserIntent != fixture.NormalizedEvent.ExplicitUserIntent {
			t.Fatalf("%s explicit intent = %t, want %t", fixture.ID, input.ExplicitUserIntent, fixture.NormalizedEvent.ExplicitUserIntent)
		}
		if input.ToolInput.Command == "" && input.ToolInput.Path == "" && input.ToolInput.Request == "" {
			t.Fatalf("%s mapped judge input has empty tool_input", fixture.ID)
		}
	}
}

func TestInputFromFixtureMirrorsSkillRequestMapping(t *testing.T) {
	input := InputFromFixture(Fixture{
		HookEvent: FixtureHookEvent{
			ToolName:  "Skill",
			ToolInput: map[string]any{"skill": "review"},
		},
		NormalizedEvent: FixtureNormalizedEvent{
			RequestSummary: "Skill",
		},
	})
	if input.ToolInput.Request != "Skill review" {
		t.Fatalf("request = %q, want %q", input.ToolInput.Request, "Skill review")
	}
}

func TestInputFromFixturePreservesCredentialPathClass(t *testing.T) {
	input := InputFromFixture(Fixture{
		HookEvent: FixtureHookEvent{
			ToolName:  "Write",
			ToolInput: map[string]any{"file_path": ".env"},
		},
		NormalizedEvent: FixtureNormalizedEvent{
			PathClass: "env_file",
		},
	})
	if input.ToolInput.Request != "Write credential_path env_file" {
		t.Fatalf("request = %q, want credential path context", input.ToolInput.Request)
	}
}

func TestCompareFixtureOutputMatchesCategoriesWithoutOrderDependency(t *testing.T) {
	failures := CompareFixtureOutput(
		Output{
			Decision:   DecisionDeny,
			RiskLevel:  RiskLevelHigh,
			Categories: []string{"production_mutation", "credential_access", "credential_access"},
			Reason:     "Production credential access is blocked.",
		},
		FixtureExpected{
			Decision:       DecisionDeny,
			RiskLevel:      RiskLevelHigh,
			Categories:     []string{"credential_access", "production_mutation"},
			ReasonContains: []string{"production", "credential"},
		},
	)
	if len(failures) != 0 {
		t.Fatalf("CompareFixtureOutput() failures = %v, want none", failures)
	}
}

func loadLaunchFixtures(t *testing.T) []Fixture {
	t.Helper()
	file, err := os.Open("testdata/launch-v0.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	fixtures, err := ReadFixtures(file)
	if err != nil {
		t.Fatal(err)
	}
	return fixtures
}
