package payloadcapture

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
)

// RedactedPlaceholder replaces every redacted key value and pattern match.
const RedactedPlaceholder = "[REDACTED_SECRET]"

// ruleset.json is a mirror of the shared redaction ruleset artifact. Patterns
// are RE2-safe by contract so the same file drives every engine; do not edit
// it independently of the source artifact.
//
//go:embed ruleset.json
var rulesetJSON []byte

type redactionRule struct {
	ID              string `json:"id"`
	Description     string `json:"description"`
	Pattern         string `json:"pattern"`
	CaseInsensitive bool   `json:"caseInsensitive"`
	Provenance      string `json:"provenance"`
}

type redactionRuleset struct {
	Version          string          `json:"version"`
	KeyNormalization string          `json:"keyNormalization"`
	KeyPatterns      []redactionRule `json:"keyPatterns"`
	ValuePatterns    []redactionRule `json:"valuePatterns"`
}

type compiledRule struct {
	id string
	re *regexp.Regexp
}

var (
	// RedactorVersion identifies the ruleset that produced redacted bytes.
	// It is reported on every captured payload record and always comes from
	// the embedded artifact, never from a separate constant.
	RedactorVersion string

	compiledKeyRules   []compiledRule
	compiledValueRules []compiledRule
	camelBoundary      = regexp.MustCompile(`([a-z])([A-Z])`)
)

func init() {
	var ruleset redactionRuleset
	if err := json.Unmarshal(rulesetJSON, &ruleset); err != nil {
		panic(fmt.Sprintf("payloadcapture: invalid embedded ruleset: %v", err))
	}
	if ruleset.KeyNormalization != "camel_to_snake" {
		panic(fmt.Sprintf(
			"payloadcapture: unsupported key normalization %q",
			ruleset.KeyNormalization,
		))
	}

	RedactorVersion = ruleset.Version
	compiledKeyRules = compileRules(ruleset.KeyPatterns)
	compiledValueRules = compileRules(ruleset.ValuePatterns)
}

func compileRules(rules []redactionRule) []compiledRule {
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		pattern := rule.Pattern
		if rule.CaseInsensitive {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			panic(fmt.Sprintf(
				"payloadcapture: rule %q does not compile: %v",
				rule.ID, err,
			))
		}
		compiled = append(compiled, compiledRule{id: rule.ID, re: re})
	}
	return compiled
}

func isSensitiveKey(key string) bool {
	normalized := camelBoundary.ReplaceAllString(key, "${1}_${2}")
	for _, rule := range compiledKeyRules {
		if rule.re.MatchString(normalized) {
			return true
		}
	}
	return false
}

// RedactText runs the ruleset's value patterns over a flat string, replacing
// every match with RedactedPlaceholder, and reports whether anything changed.
// Key patterns do not apply: a flat string carries no structure to classify.
func RedactText(value string) (string, bool) {
	changed := false
	for _, rule := range compiledValueRules {
		next := rule.re.ReplaceAllString(value, RedactedPlaceholder)
		if next != value {
			changed = true
			value = next
		}
	}
	return value, changed
}
