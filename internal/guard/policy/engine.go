package policy

import "github.com/kontext-security/kontext-cli/internal/guard/risk"

type Engine struct {
	pack RulePack
}

func NewEngine(pack RulePack) Engine {
	if pack.ID == "" {
		pack = DefaultRulePack()
	}
	return Engine{pack: pack}
}

func (e Engine) Evaluate(event risk.RiskEvent, cfg Config) Result {
	if e.pack.ID == "" {
		e.pack = DefaultRulePack()
	}
	cfg = cfg.withDefaults()
	if cfg.RulePack == "" {
		cfg.RulePack = e.pack.ID
	}

	for _, rule := range e.pack.Rules {
		if !categoryEnabled(cfg.Profile, rule.Category) || !rule.When(event) {
			continue
		}
		return Result{
			Decision:       DecisionDeny,
			Stage:          StageDeterministic,
			Matched:        true,
			RuleID:         rule.ID,
			Category:       rule.Category,
			Profile:        cfg.Profile,
			PolicyVersion:  cfg.Version,
			RulePack:       e.pack.ID,
			ReasonCode:     rule.ReasonCode,
			Reason:         rule.Reason,
			NonBypassable:  *cfg.NonBypassableRules && rule.NonBypassable,
			MatchedSignals: matchedSignals(event.Signals, rule.MatchedSignals),
		}
	}

	return Result{
		Decision:      DecisionAllow,
		Stage:         StageDeterministic,
		Matched:       false,
		Profile:       cfg.Profile,
		PolicyVersion: cfg.Version,
		RulePack:      e.pack.ID,
		ReasonCode:    "no_policy_rule_matched",
		Reason:        "no deterministic policy rule matched",
	}
}

func matchedSignals(eventSignals, ruleSignals []string) []string {
	if len(eventSignals) == 0 || len(ruleSignals) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(ruleSignals))
	for _, signal := range ruleSignals {
		allowed[signal] = true
	}
	matched := make([]string, 0, len(ruleSignals))
	for _, signal := range eventSignals {
		if allowed[signal] {
			matched = append(matched, signal)
		}
	}
	return matched
}
