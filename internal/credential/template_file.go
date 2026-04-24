package credential

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ManagedProvider struct {
	EnvVar         string
	Placeholder    string
	SeedOnFirstRun bool
}

type InvalidPlaceholder struct {
	EnvVar string
	Value  string
}

type TemplateFile struct {
	Entries              []Entry
	ExistingValues       map[string]string
	InvalidPlaceholders  []InvalidPlaceholder
	SafeToMutate         bool
	MutationWarning      string
	HasManagedPlaceholds bool
}

type SyncResult struct {
	Created          bool
	Updated          bool
	Added            []ManagedProvider
	CollisionSkipped []ManagedProvider
	Template         *TemplateFile
}

const managedHeader = "# Managed by Kontext CLI (local file).\n# You can add your own variables; the CLI will append managed entries as needed.\n"

func LoadTemplateFile(path string) (*TemplateFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open env template: %w", err)
	}
	defer f.Close()

	result := &TemplateFile{
		ExistingValues: make(map[string]string),
		SafeToMutate:   true,
	}

	type effectiveAssignment struct {
		entry     *Entry
		invalid   *InvalidPlaceholder
		lastIndex int
	}

	assignments := make(map[string]effectiveAssignment)
	seenKeys := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	lineIndex := 0
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		envVar := strings.TrimSpace(parts[0])
		if envVar == "" {
			result.SafeToMutate = false
			result.MutationWarning = "Skipping env file sync because it contains an entry with an empty key."
			continue
		}
		if _, exists := seenKeys[envVar]; exists {
			result.SafeToMutate = false
			result.MutationWarning = fmt.Sprintf(
				"Skipping env file sync because %s is declared more than once.",
				envVar,
			)
		} else {
			seenKeys[envVar] = struct{}{}
		}

		value := strings.TrimSpace(parts[1])
		normalizedValue := normalizePlaceholderValue(value)
		result.ExistingValues[envVar] = value
		assignment := effectiveAssignment{lastIndex: lineIndex}
		lineIndex++

		matches := placeholder.FindStringSubmatch(normalizedValue)
		if matches != nil {
			scheme := matches[1]
			providerSpec := matches[2]
			if !IsSupportedCredentialScheme(scheme) {
				assignments[envVar] = assignment
				continue
			}
			provider, resource, _ := strings.Cut(providerSpec, "/")
			if strings.TrimSpace(provider) == "" {
				assignment.invalid = &InvalidPlaceholder{
					EnvVar: envVar,
					Value:  value,
				}
				assignments[envVar] = assignment
				continue
			}
			assignment.entry = &Entry{
				Scheme:   scheme,
				EnvVar:   envVar,
				Provider: provider,
				Resource: resource,
				Raw:      normalizedValue,
			}
			assignments[envVar] = assignment
			continue
		}

		if strings.Contains(normalizedValue, "{{kontext:") || strings.Contains(normalizedValue, "{{bitwarden:") {
			assignment.invalid = &InvalidPlaceholder{
				EnvVar: envVar,
				Value:  value,
			}
		}
		assignments[envVar] = assignment
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(assignments))
	for envVar := range assignments {
		keys = append(keys, envVar)
	}
	sort.Slice(keys, func(i, j int) bool {
		return assignments[keys[i]].lastIndex < assignments[keys[j]].lastIndex
	})
	for _, envVar := range keys {
		assignment := assignments[envVar]
		if assignment.invalid != nil {
			result.InvalidPlaceholders = append(result.InvalidPlaceholders, *assignment.invalid)
			continue
		}
		if assignment.entry != nil {
			result.HasManagedPlaceholds = true
			result.Entries = append(result.Entries, *assignment.entry)
		}
	}

	return result, nil
}

func EnsureManagedTemplate(path string, managed []ManagedProvider) (*SyncResult, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		createdProviders := make([]ManagedProvider, 0, len(managed))
		lines := []string{strings.TrimRight(managedHeader, "\n")}
		for _, provider := range managed {
			if !provider.SeedOnFirstRun {
				continue
			}
			createdProviders = append(createdProviders, provider)
			lines = append(lines, fmt.Sprintf("%s=%s", provider.EnvVar, provider.Placeholder))
		}
		content := strings.Join(lines, "\n") + "\n"
		if err := writeFileAtomically(path, []byte(content), 0o600); err != nil {
			return nil, err
		}
		template, err := LoadTemplateFile(path)
		if err != nil {
			return nil, err
		}
		return &SyncResult{
			Created:  true,
			Added:    createdProviders,
			Template: template,
		}, nil
	} else if err != nil {
		return nil, err
	}

	template, err := LoadTemplateFile(path)
	if err != nil {
		return nil, err
	}

	result := &SyncResult{Template: template}
	if !template.SafeToMutate {
		return result, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read env template: %w", err)
	}
	trimmedRight := strings.TrimRight(string(raw), "\n")
	lines := []string{}
	if trimmedRight != "" {
		lines = append(lines, strings.Split(trimmedRight, "\n")...)
	}

	for _, provider := range managed {
		existingValue, exists := template.ExistingValues[provider.EnvVar]
		if exists {
			if normalizePlaceholderValue(existingValue) != normalizePlaceholderValue(provider.Placeholder) {
				result.CollisionSkipped = append(result.CollisionSkipped, provider)
			}
			continue
		}

		lines = append(lines, fmt.Sprintf("%s=%s", provider.EnvVar, provider.Placeholder))
		template.ExistingValues[provider.EnvVar] = provider.Placeholder
		result.Added = append(result.Added, provider)
		result.Updated = true
	}

	if !result.Updated {
		return result, nil
	}

	content := strings.Join(lines, "\n") + "\n"
	if err := writeFileAtomically(path, []byte(content), 0o600); err != nil {
		return nil, err
	}

	template, err = LoadTemplateFile(path)
	if err != nil {
		return nil, err
	}
	result.Template = template
	return result, nil
}

func writeFileAtomically(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create env template dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".env.kontext.*.tmp")
	if err != nil {
		return fmt.Errorf("create temp env template: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp env template: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp env template: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp env template: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace env template: %w", err)
	}
	return nil
}
