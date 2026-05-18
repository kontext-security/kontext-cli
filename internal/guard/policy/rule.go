package policy

import "github.com/kontext-security/kontext-cli/internal/guard/risk"

type Rule struct {
	ID             string
	Category       RuleCategory
	ReasonCode     string
	Reason         string
	NonBypassable  bool
	MatchedSignals []string
	When           func(risk.RiskEvent) bool
}

type RulePack struct {
	ID      string
	Version string
	Rules   []Rule
}
