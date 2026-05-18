package policyconfig

import (
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/policy"
)

type Source string

const (
	SourceActiveFile    Source = "active-file"
	SourceDefault       Source = "default"
	SourceLastKnownGood Source = "last-known-good"
)

type Status string

const (
	StatusOK               Status = "ok"
	StatusDefaultedMissing Status = "defaulted_missing"
	StatusRecoveredLKG     Status = "recovered_lkg"
	StatusDefaultedInvalid Status = "defaulted_invalid"
)

type Snapshot struct {
	Config Config

	ConfigDigest string
	ActivationID string
	Source       Source
	Status       Status
	LoadedAt     time.Time

	PolicyVersion   string
	RulePack        string
	RulePackVersion string
}

type DecisionMetadata struct {
	ConfigDigest       string `json:"config_digest"`
	ActivationID       string `json:"activation_id"`
	ConfigSource       string `json:"config_source"`
	ConfigStatus       string `json:"config_status"`
	PolicyVersion      string `json:"policy_version"`
	RulePack           string `json:"rule_pack"`
	RulePackVersion    string `json:"rule_pack_version"`
	Profile            string `json:"profile"`
	NonBypassableRules bool   `json:"non_bypassable_rules"`
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	snapshot.Config = cloneConfig(snapshot.Config)
	return snapshot
}

func (s Snapshot) ToPolicyConfig() policy.Config {
	return toPolicyConfig(cloneConfig(s.Config))
}

func (s Snapshot) DecisionMetadata() DecisionMetadata {
	nonBypassableRules := s.Config.NonBypassableRules != nil && *s.Config.NonBypassableRules
	return DecisionMetadata{
		ConfigDigest:       s.ConfigDigest,
		ActivationID:       s.ActivationID,
		ConfigSource:       string(s.Source),
		ConfigStatus:       string(s.Status),
		PolicyVersion:      s.PolicyVersion,
		RulePack:           s.RulePack,
		RulePackVersion:    s.RulePackVersion,
		Profile:            string(s.Config.Profile),
		NonBypassableRules: nonBypassableRules,
	}
}
