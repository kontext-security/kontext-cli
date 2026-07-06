package payloadcapture

import (
	"regexp"
	"strings"
	"testing"
)

type coverageVectors struct {
	ValueVectors []struct {
		Name           string   `json:"name"`
		RuleID         string   `json:"ruleId"`
		Input          string   `json:"input"`
		MustNotSurvive []string `json:"mustNotSurvive"`
	} `json:"valueVectors"`
	KeyVectors []struct {
		Name      string `json:"name"`
		Key       string `json:"key"`
		Sensitive bool   `json:"sensitive"`
	} `json:"keyVectors"`
}

func TestRulesetCompilesAndIsVersioned(t *testing.T) {
	t.Parallel()

	// Compilation itself is enforced by package init (a bad pattern panics
	// before any test runs); this pins the version format the capture
	// records report.
	if !regexp.MustCompile(`^rules/\d+$`).MatchString(RedactorVersion) {
		t.Fatalf("unexpected redactor version %q", RedactorVersion)
	}
	if len(compiledKeyRules) == 0 || len(compiledValueRules) == 0 {
		t.Fatal("ruleset compiled empty")
	}
}

func TestRedactionCoverage(t *testing.T) {
	t.Parallel()

	var vectors coverageVectors
	loadTestdata(t, "redaction-coverage-vectors.json", &vectors)
	if len(vectors.ValueVectors) == 0 || len(vectors.KeyVectors) == 0 {
		t.Fatal("no coverage vectors loaded")
	}

	covered := map[string]bool{}
	for _, vector := range vectors.ValueVectors {
		covered[vector.RuleID] = true
	}
	for _, rule := range compiledValueRules {
		if !covered[rule.id] {
			t.Errorf("value rule %q has no coverage vector", rule.id)
		}
	}

	for _, vector := range vectors.ValueVectors {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()

			redacted, changed := redactText(vector.Input)
			if !changed {
				t.Fatalf("input was not redacted: %q", vector.Input)
			}
			for _, secret := range vector.MustNotSurvive {
				if strings.Contains(redacted, secret) {
					t.Fatalf("secret survived redaction: %q in %q", secret, redacted)
				}
			}
			if !strings.Contains(redacted, RedactedPlaceholder) {
				t.Fatalf("placeholder missing from %q", redacted)
			}
		})
	}

	for _, vector := range vectors.KeyVectors {
		t.Run("key/"+vector.Name, func(t *testing.T) {
			t.Parallel()

			if got := isSensitiveKey(vector.Key); got != vector.Sensitive {
				t.Fatalf("isSensitiveKey(%q) = %v, want %v", vector.Key, got, vector.Sensitive)
			}
		})
	}
}

func TestRedactJSONDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"apiKey": "raw-secret-value",
		"nested": map[string]any{"command": "GITHUB_TOKEN=leaked gh api"},
	}

	redacted, changed := RedactJSON(input)
	if !changed {
		t.Fatal("expected redaction changes")
	}
	if input["apiKey"] != "raw-secret-value" {
		t.Fatal("input map was mutated")
	}
	if redacted["apiKey"] != RedactedPlaceholder {
		t.Fatalf("sensitive key not replaced: %v", redacted["apiKey"])
	}
}
