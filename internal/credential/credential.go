// Package credential handles env template parsing and credential resolution.
package credential

import (
	"fmt"
	"regexp"
	"strings"
)

// placeholder matches {{kontext:<provider>}} or {{kontext:<provider>/<resource>}} patterns.
var placeholder = regexp.MustCompile(`^\{\{kontext:([^}]+)\}\}$`)

func normalizePlaceholderValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if idx := inlineCommentIndex(trimmed); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[:idx])
	}

	return trimMatchingQuotes(trimmed)
}

// NormalizeEnvValue trims surrounding quotes from dotenv-style values so the
// launched process receives the literal token, not the quote characters.
func NormalizeEnvValue(value string) string {
	return normalizePlaceholderValue(value)
}

func trimMatchingQuotes(value string) string {
	if len(value) < 2 {
		return value
	}

	if (value[0] == '"' && value[len(value)-1] == '"') ||
		(value[0] == '\'' && value[len(value)-1] == '\'') {
		return strings.TrimSpace(value[1 : len(value)-1])
	}

	return value
}

func inlineCommentIndex(value string) int {
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(value); i++ {
		ch := value[i]
		if escaped {
			escaped = false
			continue
		}

		switch ch {
		case '\\':
			if inDouble {
				escaped = true
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && (i == 0 || isInlineCommentWhitespace(value[i-1])) {
				return i
			}
		}
	}

	return -1
}

func isInlineCommentWhitespace(ch byte) bool {
	switch ch {
	case ' ', '\t':
		return true
	default:
		return false
	}
}

// Entry represents a single credential placeholder from the env template.
type Entry struct {
	EnvVar   string // e.g., "GITHUB_TOKEN"
	Provider string // e.g., "github"
	Resource string // e.g., "readonly" (optional, after /)
	Raw      string // e.g., "{{kontext:github}}"
}

// Target returns the full provider target used for token exchange.
func (e Entry) Target() string {
	if e.Resource == "" {
		return e.Provider
	}
	return e.Provider + "/" + e.Resource
}

// Resolved is a credential entry with its resolved value.
type Resolved struct {
	Entry
	Value string // The resolved credential value
}

// ParseTemplate reads an env template file and extracts credential placeholders.
func ParseTemplate(path string) ([]Entry, error) {
	doc, err := LoadTemplateFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	return doc.Entries, nil
}

// BuildEnv converts resolved credentials into environment variable assignments.
func BuildEnv(resolved []Resolved, base []string) []string {
	env := make([]string, len(base))
	copy(env, base)
	for _, r := range resolved {
		env = append(env, fmt.Sprintf("%s=%s", r.EnvVar, r.Value))
	}
	return env
}
