package githubpolicy

import (
	"fmt"
	"strings"
)

// Reason codes shared with the cloud evaluator.
const (
	ReasonCodeAllow = "ALLOWED_POLICY_CHECK"
	ReasonCodeDeny  = "DENY_POLICY_CHECK"
)

// Request is one classified GitHub action to evaluate. UserID and
// ApplicationID are the Kontext user and application subjects; the managed
// endpoint's trusted identity is the service account + installation, so both
// are typically empty (unresolved) and user/agent-layer rules then never
// match their subject.
type Request struct {
	Action        string
	Resource      string
	BranchOrRef   string
	UserID        string
	ApplicationID string
}

// MatchedRule records one rule that matched the request, and whether it was
// the rule that decided the outcome.
type MatchedRule struct {
	ID      string `json:"id"`
	Layer   string `json:"layer"`
	Effect  string `json:"effect"`
	Decided bool   `json:"decided,omitempty"`
}

// Evaluation is the would-be decision for one request under one snapshot.
type Evaluation struct {
	Request      Request
	Result       string // "allow" | "deny"
	ReasonCode   string
	Reason       string
	MatchedRules []MatchedRule
	// DecidingRuleID is the rule that determined the outcome: the first
	// matching deny, or the org-layer allow that anchored an allow. Empty
	// when a layer vetoed by silence.
	DecidingRuleID string
	Mode           string
	Epoch          int
	Hash           string
	// Stale is true when the snapshot used was not confirmed by the cloud on
	// the most recent refresh attempt.
	Stale bool
	// SubjectsResolved is false when no Kontext user/application identity was
	// available, so user/agent-layer rules could not match their subject.
	SubjectsResolved bool
}

// Evaluate mirrors the cloud evaluator exactly:
//
//  1. A rule matches when its layer subject matches and each non-null
//     dimension equals the request value exactly (null = wildcard, no globs).
//  2. Any matching deny ⇒ deny, regardless of specificity.
//  3. Otherwise allow only if every layer consents. The org layer is strict:
//     it needs a matching allow. The user and agent layers abstain (consent)
//     while the snapshot has zero rules in that layer; once a layer has any
//     rule it is active and silence vetoes again.
//
// The boolean result is false when the snapshot carries no rules at all (no
// active policy authored yet) — there is nothing to dry-run.
func Evaluate(snapshot Snapshot, status Status, request Request) (Evaluation, bool) {
	if len(snapshot.Rules) == 0 {
		return Evaluation{}, false
	}

	evaluation := Evaluation{
		Request:          request,
		Mode:             snapshot.Mode,
		Epoch:            snapshot.Epoch,
		Hash:             snapshot.Hash,
		Stale:            status.Stale,
		SubjectsResolved: request.UserID != "" || request.ApplicationID != "",
	}

	layerSubjects := map[string]string{
		LayerOrg:   snapshot.OrganizationID,
		LayerUser:  request.UserID,
		LayerAgent: request.ApplicationID,
	}

	var matched []MatchedRule
	var decidingDeny *Rule
	allowLayers := map[string]bool{}
	var firstOrgAllow *Rule
	for i := range snapshot.Rules {
		rule := &snapshot.Rules[i]
		subject := layerSubjects[rule.Layer]
		if subject == "" || rule.SubjectID != subject || !ruleMatchesRequest(rule, request) {
			continue
		}
		matched = append(matched, MatchedRule{ID: rule.ID, Layer: rule.Layer, Effect: rule.Effect})
		if rule.Effect == EffectDeny {
			if decidingDeny == nil {
				decidingDeny = rule
			}
			continue
		}
		allowLayers[rule.Layer] = true
		if rule.Layer == LayerOrg && firstOrgAllow == nil {
			firstOrgAllow = rule
		}
	}

	if decidingDeny != nil {
		markDecided(matched, decidingDeny.ID)
		evaluation.Result = EffectDeny
		evaluation.ReasonCode = ReasonCodeDeny
		evaluation.Reason = fmt.Sprintf("denied by %s-layer deny rule on %s", decidingDeny.Layer, ruleScopeSummary(*decidingDeny))
		evaluation.MatchedRules = matched
		evaluation.DecidingRuleID = decidingDeny.ID
		return evaluation, true
	}

	// User and agent layers consent by abstention while they hold no rules at
	// all; the org layer is the mandatory ceiling and stays strict.
	for _, layer := range []string{LayerUser, LayerAgent} {
		if !snapshotHasLayerRules(snapshot, layer) {
			allowLayers[layer] = true
		}
	}

	var vetoLayers []string
	for _, layer := range []string{LayerOrg, LayerUser, LayerAgent} {
		if !allowLayers[layer] {
			vetoLayers = append(vetoLayers, layer)
		}
	}
	if len(vetoLayers) > 0 {
		evaluation.Result = EffectDeny
		evaluation.ReasonCode = ReasonCodeDeny
		evaluation.Reason = fmt.Sprintf("no matching allow rule in active layer(s): %s", strings.Join(vetoLayers, ", "))
		evaluation.MatchedRules = matched
		return evaluation, true
	}

	if firstOrgAllow != nil {
		markDecided(matched, firstOrgAllow.ID)
		evaluation.DecidingRuleID = firstOrgAllow.ID
	}
	evaluation.Result = EffectAllow
	evaluation.ReasonCode = ReasonCodeAllow
	evaluation.Reason = "allowed by policy: every layer consents"
	evaluation.MatchedRules = matched
	return evaluation, true
}

func ruleMatchesRequest(rule *Rule, request Request) bool {
	if rule.ActionName != nil && *rule.ActionName != request.Action {
		return false
	}
	if rule.ResourceID != nil && *rule.ResourceID != request.Resource {
		return false
	}
	if rule.BranchOrRef != nil && *rule.BranchOrRef != request.BranchOrRef {
		return false
	}
	return true
}

func snapshotHasLayerRules(snapshot Snapshot, layer string) bool {
	for i := range snapshot.Rules {
		if snapshot.Rules[i].Layer == layer {
			return true
		}
	}
	return false
}

func markDecided(matched []MatchedRule, ruleID string) {
	for i := range matched {
		if matched[i].ID == ruleID {
			matched[i].Decided = true
			return
		}
	}
}

func ruleScopeSummary(rule Rule) string {
	action := "any action"
	if rule.ActionName != nil {
		action = *rule.ActionName
	}
	resource := "any repo"
	if rule.ResourceID != nil {
		resource = *rule.ResourceID
	}
	summary := action + " @ " + resource
	if rule.BranchOrRef != nil {
		summary += " (" + *rule.BranchOrRef + ")"
	}
	return summary
}
