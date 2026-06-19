package githubpolicy

import (
	"fmt"
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
// match their subject. EndpointID is the installation ("ins_…") identity of
// this managed endpoint — it is always known locally, so endpoint-layer rules
// are the way to scope policy to a specific device on the managed path.
type Request struct {
	Action        string
	Resource      string
	BranchOrRef   string
	UserID        string
	ApplicationID string
	EndpointID    string
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

// Evaluate mirrors the cloud evaluator exactly. It is most-specific-wins:
//
//  1. A rule matches when its layer subject matches and each non-null
//     dimension equals the request value exactly (null = wildcard, no globs).
//  2. Among the matching rules the most specific one decides, by this order:
//     (a) more pinned dimensions (action/resource/branch) beats fewer; then
//     (b) a user- or agent-layer rule beats an org-layer rule; then
//     (c) on an exact tie of (a) and (b), deny beats allow.
//     A broad org deny is therefore overridden by a more specific user/agent
//     allow, which is in turn overridden by an even more specific deny.
//  3. If no rule matches the request, it is denied (default deny).
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
		LayerOrg:      snapshot.OrganizationID,
		LayerUser:     request.UserID,
		LayerAgent:    request.ApplicationID,
		LayerEndpoint: request.EndpointID,
	}

	var matched []MatchedRule
	var winner *Rule
	for i := range snapshot.Rules {
		rule := &snapshot.Rules[i]
		subject := layerSubjects[rule.Layer]
		if subject == "" || rule.SubjectID != subject || !ruleMatchesRequest(rule, request) {
			continue
		}
		matched = append(matched, MatchedRule{ID: rule.ID, Layer: rule.Layer, Effect: rule.Effect})
		if winner == nil || rulePrecedes(rule, winner) {
			winner = rule
		}
	}

	evaluation.MatchedRules = matched

	if winner == nil {
		// Rules exist but none match this request: default deny.
		evaluation.Result = EffectDeny
		evaluation.ReasonCode = ReasonCodeDeny
		evaluation.Reason = "no matching policy rule (default deny)"
		return evaluation, true
	}

	markDecided(matched, winner.ID)
	evaluation.DecidingRuleID = winner.ID
	if effectIsAllow(winner.Effect) {
		evaluation.Result = EffectAllow
		evaluation.ReasonCode = ReasonCodeAllow
		evaluation.Reason = fmt.Sprintf("allowed by most-specific %s-layer allow rule on %s", winner.Layer, ruleScopeSummary(*winner))
	} else {
		evaluation.Result = EffectDeny
		evaluation.ReasonCode = ReasonCodeDeny
		evaluation.Reason = fmt.Sprintf("denied by most-specific %s-layer deny rule on %s", winner.Layer, ruleScopeSummary(*winner))
	}
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

// rulePrecedes reports whether candidate should win over the current best under
// most-specific-wins: more pinned dimensions, then user/agent over org, then
// deny over allow on an exact tie. Returning false on a full tie keeps the
// earlier rule, so evaluation is deterministic in snapshot order.
func rulePrecedes(candidate, best *Rule) bool {
	if dc, db := ruleDimensions(candidate), ruleDimensions(best); dc != db {
		return dc > db
	}
	if lc, lb := layerRank(candidate.Layer), layerRank(best.Layer); lc != lb {
		return lc > lb
	}
	// Same specificity: a deny outranks an allow.
	return !effectIsAllow(candidate.Effect) && effectIsAllow(best.Effect)
}

// ruleDimensions counts the pinned (non-wildcard) dimensions of a rule.
func ruleDimensions(rule *Rule) int {
	count := 0
	if rule.ActionName != nil {
		count++
	}
	if rule.ResourceID != nil {
		count++
	}
	if rule.BranchOrRef != nil {
		count++
	}
	return count
}

// layerRank orders subjects from least to most specific. A rule bound to a
// specific user, application, or endpoint is more specific than an org-wide
// rule; those specific-principal layers rank equally, so a conflict between
// them falls through to deny-wins.
func layerRank(layer string) int {
	if layer == LayerOrg {
		return 0
	}
	return 1
}

func effectIsAllow(effect string) bool {
	return effect == EffectAllow
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
