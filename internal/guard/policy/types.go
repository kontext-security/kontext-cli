package policy

import "fmt"

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

type Stage string

const (
	StageDeterministic Stage = "deterministic"
)

type Profile string

const (
	ProfileRelaxed  Profile = "relaxed"
	ProfileBalanced Profile = "balanced"
	ProfileStrict   Profile = "strict"
)

type RuleCategory string

const (
	CategoryCredentialAccess              RuleCategory = "credential_access"
	CategoryDirectInfraAPIWithCredentials RuleCategory = "direct_infra_api_with_credentials"
	CategoryDestructivePersistentResource RuleCategory = "destructive_persistent_resource"
	CategoryProductionMutation            RuleCategory = "production_mutation"
	CategoryUnknownHighRiskCommand        RuleCategory = "unknown_high_risk_command"
	CategoryManagedTool                   RuleCategory = "managed_tool"
	CategorySourceControlWrite            RuleCategory = "source_control_write"
	CategoryProviderAPICall               RuleCategory = "provider_api_call"
)

const (
	DefaultPolicyVersion = "guard-policy-v1"
	DefaultRulePackID    = "guard-default"
)

type Config struct {
	Version            string  `json:"version"`
	Profile            Profile `json:"profile"`
	RulePack           string  `json:"rule_pack"`
	NonBypassableRules *bool   `json:"non_bypassable_rules,omitempty"`
}

func DefaultConfig() Config {
	nonBypassableRules := true
	return Config{
		Version:            DefaultPolicyVersion,
		Profile:            ProfileBalanced,
		RulePack:           DefaultRulePackID,
		NonBypassableRules: &nonBypassableRules,
	}
}

func (c Config) withDefaults() Config {
	defaultConfig := DefaultConfig()
	if c.Version == "" {
		c.Version = defaultConfig.Version
	}
	if c.Profile == "" {
		c.Profile = defaultConfig.Profile
	}
	if c.RulePack == "" {
		c.RulePack = defaultConfig.RulePack
	}
	if c.NonBypassableRules == nil {
		c.NonBypassableRules = defaultConfig.NonBypassableRules
	}
	return c
}

func (c Config) Validate() error {
	c = c.withDefaults()
	switch c.Profile {
	case ProfileRelaxed, ProfileBalanced, ProfileStrict:
	default:
		return fmt.Errorf("unknown policy profile %q", c.Profile)
	}
	if c.RulePack != DefaultRulePackID {
		return fmt.Errorf("unknown rule pack %q", c.RulePack)
	}
	return nil
}

type Result struct {
	Decision       Decision     `json:"decision"`
	Stage          Stage        `json:"stage"`
	Matched        bool         `json:"matched"`
	RuleID         string       `json:"rule_id,omitempty"`
	Category       RuleCategory `json:"category,omitempty"`
	Profile        Profile      `json:"profile"`
	PolicyVersion  string       `json:"policy_version"`
	RulePack       string       `json:"rule_pack"`
	ReasonCode     string       `json:"reason_code"`
	Reason         string       `json:"reason"`
	NonBypassable  bool         `json:"non_bypassable"`
	MatchedSignals []string     `json:"matched_signals,omitempty"`
}
