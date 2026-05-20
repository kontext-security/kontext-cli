package judge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Fixture struct {
	ID                  string                   `json:"id"`
	Description         string                   `json:"description"`
	HookEvent           FixtureHookEvent         `json:"hook_event"`
	NormalizedEvent     FixtureNormalizedEvent   `json:"normalized_event"`
	DeterministicPolicy FixtureDeterministicRule `json:"deterministic_policy"`
	JudgeExpected       FixtureExpected          `json:"judge_expected"`
	Notes               string                   `json:"notes"`
}

type FixtureHookEvent struct {
	Agent         string         `json:"agent"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
}

type FixtureExpected struct {
	ShouldCallJudge bool      `json:"should_call_judge"`
	Decision        Decision  `json:"decision"`
	RiskLevel       RiskLevel `json:"risk_level"`
	Categories      []string  `json:"categories"`
	ReasonContains  []string  `json:"reason_contains"`
}

type FixtureNormalizedEvent struct {
	Type               string   `json:"type"`
	ProviderCategory   string   `json:"provider_category,omitempty"`
	OperationClass     string   `json:"operation_class,omitempty"`
	ResourceClass      string   `json:"resource_class,omitempty"`
	Environment        string   `json:"environment,omitempty"`
	PathClass          string   `json:"path_class,omitempty"`
	CommandSummary     string   `json:"command_summary,omitempty"`
	RequestSummary     string   `json:"request_summary,omitempty"`
	ExplicitUserIntent bool     `json:"explicit_user_intent"`
	Signals            []string `json:"signals,omitempty"`
}

type FixtureDeterministicRule struct {
	Decision      string   `json:"decision"`
	MatchedRules  []string `json:"matched_rules,omitempty"`
	PolicyVersion string   `json:"policy_version"`
}

func ReadFixtures(r io.Reader) ([]Fixture, error) {
	var fixtures []Fixture
	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var fixture Fixture
		if err := json.Unmarshal([]byte(text), &fixture); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		fixtures = append(fixtures, fixture)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return fixtures, nil
}

func InputFromFixture(fixture Fixture) Input {
	toolInput := ToolInput{
		Command: fixture.NormalizedEvent.CommandSummary,
		Path:    pathClassFromFixture(fixture),
	}
	if toolInput.Command == "" {
		if toolInput.Path != "" {
			toolInput.Request = sanitizedPathRequest(fixture.HookEvent.ToolName, toolInput.Path)
		} else {
			toolInput.Request = fixture.NormalizedEvent.RequestSummary
		}
	}
	return Input{
		ToolName:           fixture.HookEvent.ToolName,
		ExplicitUserIntent: fixture.NormalizedEvent.ExplicitUserIntent,
		ToolInput:          toolInput,
	}
}

func sanitizedPathRequest(toolName, pathClass string) string {
	action := strings.TrimSpace(toolName)
	if action == "" {
		action = "Tool"
	}
	return action + " " + pathClass
}

func pathClassFromFixture(fixture Fixture) string {
	if fixture.NormalizedEvent.PathClass != "" {
		return fixture.NormalizedEvent.PathClass
	}
	for _, key := range []string{"file_path", "path", "filename"} {
		if value, ok := fixture.HookEvent.ToolInput[key].(string); ok && value != "" {
			return "project_file"
		}
	}
	return ""
}

func CompareFixtureOutput(output Output, expected FixtureExpected) []string {
	var failures []string
	if output.Decision != expected.Decision {
		failures = append(failures, fmt.Sprintf("decision=%s want=%s", output.Decision, expected.Decision))
	}
	if output.RiskLevel != expected.RiskLevel {
		failures = append(failures, fmt.Sprintf("risk_level=%s want=%s", output.RiskLevel, expected.RiskLevel))
	}
	outputCategories := make(map[string]struct{}, len(output.Categories))
	for _, category := range output.Categories {
		outputCategories[category] = struct{}{}
	}
	for _, category := range expected.Categories {
		if _, ok := outputCategories[category]; !ok {
			failures = append(failures, fmt.Sprintf("missing category %q", category))
		}
	}
	reason := strings.ToLower(output.Reason)
	for _, want := range expected.ReasonContains {
		if !strings.Contains(reason, strings.ToLower(want)) {
			failures = append(failures, fmt.Sprintf("reason missing %q", want))
		}
	}
	return failures
}
