// Package credential handles env template parsing and credential resolution.
package credential

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// placeholder matches {{kontext:<provider>}} or {{kontext:<provider>/<resource>}} patterns.
var placeholder = regexp.MustCompile(`\{\{kontext:([^}]+)\}\}`)

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
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open env template: %w", err)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		envVar := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		matches := placeholder.FindStringSubmatch(value)
		if matches == nil {
			continue
		}

		providerSpec := matches[1]
		provider, resource, _ := strings.Cut(providerSpec, "/")

		entries = append(entries, Entry{
			EnvVar:   envVar,
			Provider: provider,
			Resource: resource,
			Raw:      matches[0],
		})
	}

	return entries, scanner.Err()
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
