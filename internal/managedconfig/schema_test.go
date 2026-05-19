package managedconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestSchemaParityExamples(t *testing.T) {
	schema := loadManagedSchema(t)
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{name: "valid", input: strings.ReplaceAll(validConfigJSON, "$CLOUD_URL", "https://api.kontext.dev"), valid: true},
		{name: "userinfo", input: strings.ReplaceAll(validConfigJSON, "$CLOUD_URL", "https://token@api.kontext.dev"), valid: false},
		{name: "query", input: strings.ReplaceAll(validConfigJSON, "$CLOUD_URL", "https://api.kontext.dev?x=1"), valid: false},
		{name: "fragment", input: strings.ReplaceAll(validConfigJSON, "$CLOUD_URL", "https://api.kontext.dev#x"), valid: false},
		{name: "token ref extra colon", input: strings.Replace(strings.ReplaceAll(validConfigJSON, "$CLOUD_URL", "https://api.kontext.dev"), `"keychain:kontext-install"`, `"env:FOO:BAR"`, 1), valid: false},
		{name: "unknown", input: strings.Replace(strings.ReplaceAll(validConfigJSON, "$CLOUD_URL", "https://api.kontext.dev"), `"device"`, `"unknown": true, "device"`, 1), valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, goErr := Parse([]byte(tt.input))
			schemaErr := schemaValidate(schema, []byte(tt.input))
			if (goErr == nil) != tt.valid {
				t.Fatalf("Go validity = %v, want %v, err = %v", goErr == nil, tt.valid, goErr)
			}
			if (schemaErr == nil) != tt.valid {
				t.Fatalf("schema validity = %v, want %v, err = %v", schemaErr == nil, tt.valid, schemaErr)
			}
		})
	}
}

type managedSchema struct {
	AdditionalProperties bool                         `json:"additionalProperties"`
	Required             []string                     `json:"required"`
	Properties           map[string]managedSchemaProp `json:"properties"`
}

type managedSchemaProp struct {
	Const                string                       `json:"const"`
	Type                 string                       `json:"type"`
	Pattern              string                       `json:"pattern"`
	AdditionalProperties bool                         `json:"additionalProperties"`
	Required             []string                     `json:"required"`
	Properties           map[string]managedSchemaProp `json:"properties"`
}

func loadManagedSchema(t *testing.T) managedSchema {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", "managed.v1.json"))
	if err != nil {
		t.Fatalf("ReadFile(schema) error = %v", err)
	}
	var schema managedSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("Unmarshal(schema) error = %v", err)
	}
	return schema
}

func schemaValidate(schema managedSchema, data []byte) error {
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	return validateObject(value, schema.Required, schema.Properties, !schema.AdditionalProperties)
}

func validateObject(value map[string]any, required []string, props map[string]managedSchemaProp, rejectUnknown bool) error {
	for _, name := range required {
		if _, ok := value[name]; !ok {
			return os.ErrInvalid
		}
	}
	for name, raw := range value {
		prop, ok := props[name]
		if !ok {
			if rejectUnknown {
				return os.ErrInvalid
			}
			continue
		}
		if prop.Const != "" && raw != prop.Const {
			return os.ErrInvalid
		}
		if prop.Type == "object" {
			nested, ok := raw.(map[string]any)
			if !ok {
				return os.ErrInvalid
			}
			if err := validateObject(nested, prop.Required, prop.Properties, !prop.AdditionalProperties); err != nil {
				return err
			}
			continue
		}
		if prop.Type == "string" {
			text, ok := raw.(string)
			if !ok {
				return os.ErrInvalid
			}
			if prop.Pattern != "" && !regexp.MustCompile(prop.Pattern).MatchString(text) {
				return os.ErrInvalid
			}
		}
	}
	return nil
}
