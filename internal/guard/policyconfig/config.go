package policyconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/kontext-security/kontext-cli/internal/guard/policy"
)

const (
	fileMode = 0o600
	dirMode  = 0o755
)

type Config struct {
	Version            string         `json:"version"`
	Profile            policy.Profile `json:"profile"`
	RulePack           string         `json:"rulePack"`
	NonBypassableRules *bool          `json:"nonBypassableRules"`
}

func DefaultConfig() Config {
	nonBypassableRules := true
	return Config{
		Version:            policy.DefaultPolicyVersion,
		Profile:            policy.ProfileBalanced,
		RulePack:           policy.DefaultRulePackID,
		NonBypassableRules: &nonBypassableRules,
	}
}

func cloneConfig(cfg Config) Config {
	if cfg.NonBypassableRules != nil {
		nonBypassableRules := *cfg.NonBypassableRules
		cfg.NonBypassableRules = &nonBypassableRules
	}
	return cfg
}

func decodeConfig(data []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, ValidationError{Reason: err.Error()}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, ValidationError{Reason: "unexpected trailing JSON value"}
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateConfig(cfg Config) error {
	if cfg.Version != policy.DefaultPolicyVersion {
		return ValidationError{Reason: fmt.Sprintf("version must be %q", policy.DefaultPolicyVersion)}
	}
	switch cfg.Profile {
	case policy.ProfileRelaxed, policy.ProfileBalanced, policy.ProfileStrict:
	default:
		return ValidationError{Reason: fmt.Sprintf("unknown profile %q", cfg.Profile)}
	}
	if cfg.RulePack != policy.DefaultRulePackID {
		return ValidationError{Reason: fmt.Sprintf("unknown rule pack %q", cfg.RulePack)}
	}
	if cfg.NonBypassableRules == nil {
		return ValidationError{Reason: "nonBypassableRules is required"}
	}
	if !*cfg.NonBypassableRules {
		return ValidationError{Reason: "nonBypassableRules must be true"}
	}
	return nil
}

func encodeConfig(cfg Config) ([]byte, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func toPolicyConfig(cfg Config) policy.Config {
	return policy.Config{
		Version:            cfg.Version,
		Profile:            cfg.Profile,
		RulePack:           cfg.RulePack,
		NonBypassableRules: cfg.NonBypassableRules,
	}
}
