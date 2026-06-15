package server

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/githubpolicy"
	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	guardpolicy "github.com/kontext-security/kontext-cli/internal/guard/policy"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

type PolicyProvider interface {
	DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error)
}

type PolicyConfigProvider interface {
	ActivePolicyConfig(context.Context) (guardpolicy.Config, error)
}

type RiskPolicyProvider struct {
	judge        judge.Judge
	policyEngine guardpolicy.Engine
	policyConfig PolicyConfigProvider
	githubPolicy githubpolicy.SnapshotProvider
}

type RiskPolicyProviderOptions struct {
	Judge                judge.Judge
	PolicyEngine         guardpolicy.Engine
	PolicyConfig         guardpolicy.Config
	PolicyConfigProvider PolicyConfigProvider
	GithubPolicy         githubpolicy.SnapshotProvider
}

type staticPolicyConfigProvider struct {
	config guardpolicy.Config
}

func (p staticPolicyConfigProvider) ActivePolicyConfig(context.Context) (guardpolicy.Config, error) {
	return p.config, nil
}

func NewRiskPolicyProviderWithOptions(opts RiskPolicyProviderOptions) RiskPolicyProvider {
	configProvider := opts.PolicyConfigProvider
	if configProvider == nil {
		configProvider = staticPolicyConfigProvider{config: opts.PolicyConfig}
	}
	return RiskPolicyProvider{
		judge:        opts.Judge,
		policyEngine: opts.PolicyEngine,
		policyConfig: configProvider,
		githubPolicy: opts.GithubPolicy,
	}
}

func (p RiskPolicyProvider) DecideHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	if event.HookEventName != "PreToolUse" {
		return p.asyncTelemetryDecision(event), nil
	}
	riskEvent := risk.NormalizeHookEvent(event)
	policyResult := p.policyEngine.Evaluate(riskEvent, p.activePolicyConfig(ctx))
	applyPolicyMetadata(&riskEvent, policyResult)
	// Local layering: deterministic guardrails > synced GitHub policy >
	// probabilistic signals. A guardrail deny stands regardless of what the
	// synced policy would have said; the synced policy (when enforcing)
	// pre-empts the judge.
	githubEvaluations, githubEnforce := p.evaluateGithubPolicy(event)
	if policyResult.Decision == guardpolicy.DecisionDeny {
		return withGithubPolicy(deterministicDenyDecision(riskEvent, policyResult), githubEvaluations), nil
	}
	if githubEnforce && len(githubEvaluations) > 0 {
		return withGithubPolicy(githubPolicyDecision(riskEvent, githubEvaluations), githubEvaluations), nil
	}
	if p.judge == nil {
		return withGithubPolicy(deterministicAllowDecision(riskEvent, policyResult), githubEvaluations), nil
	}

	result, err := p.judge.Decide(ctx, judgeInputFromRiskEvent(event, riskEvent))
	if err != nil {
		return withGithubPolicy(judgeFailOpenDecision(riskEvent, p.judge, err), githubEvaluations), nil
	}
	return withGithubPolicy(judgeDecision(riskEvent, result), githubEvaluations), nil
}

// evaluateGithubPolicy classifies the event into canonical GitHub actions and
// evaluates each against the synced policy snapshot. The managed endpoint's
// trusted identity is the service account + installation — Claude hook
// payloads are not trusted human identity — so requests carry no Kontext
// user/application subject and user/agent-layer rules cannot match their
// subject (the evaluation flags this via SubjectsResolved).
//
// The boolean result reports whether the snapshot explicitly directs
// enforcement; anything else is observe and never influences the decision.
func (p RiskPolicyProvider) evaluateGithubPolicy(event risk.HookEvent) ([]githubpolicy.Evaluation, bool) {
	if p.githubPolicy == nil {
		return nil, false
	}
	snapshot, status, ok := p.githubPolicy.CurrentSnapshot()
	if !ok || len(snapshot.Rules) == 0 {
		return nil, false
	}
	actions := githubpolicy.ClassifyProviderActionsWithCWD(event.ToolName, event.ToolInput, event.CWD, func(cwd string) githubpolicy.GitContext {
		return githubpolicy.GitContextFromCWD(cwd)
	})
	if len(actions) == 0 {
		return nil, false
	}
	evaluations := make([]githubpolicy.Evaluation, 0, len(actions))
	for _, action := range actions {
		evaluation, ok := githubpolicy.Evaluate(snapshot, status, githubpolicy.Request{
			Action:      action.Action,
			Resource:    action.Resource,
			BranchOrRef: action.BranchOrRef,
		})
		if ok {
			evaluations = append(evaluations, evaluation)
		}
	}
	return evaluations, snapshot.Enforce()
}

func withGithubPolicy(decision risk.RiskDecision, evaluations []githubpolicy.Evaluation) risk.RiskDecision {
	decision.GithubPolicy = evaluations
	return decision
}

// githubPolicyDecision is the enforce-mode path, reserved for after the
// observer pilot: the synced policy outranks probabilistic signals, so its
// verdict decides instead of the judge. Any denied action denies the event.
func githubPolicyDecision(riskEvent risk.RiskEvent, evaluations []githubpolicy.Evaluation) risk.RiskDecision {
	for _, evaluation := range evaluations {
		if evaluation.Result == githubpolicy.EffectDeny {
			riskEvent.Decision = risk.DecisionDeny
			riskEvent.ReasonCode = evaluation.ReasonCode
			riskEvent.DecisionStage = "github_policy_deny"
			return risk.RiskDecision{
				Decision:   risk.DecisionDeny,
				Reason:     evaluation.Reason,
				ReasonCode: evaluation.ReasonCode,
				GuardID:    evaluation.DecidingRuleID,
				RiskEvent:  riskEvent,
			}
		}
	}
	allowed := evaluations[0]
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = allowed.ReasonCode
	riskEvent.DecisionStage = "github_policy_allow"
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     allowed.Reason,
		ReasonCode: allowed.ReasonCode,
		GuardID:    allowed.DecidingRuleID,
		RiskEvent:  riskEvent,
	}
}

func (p RiskPolicyProvider) asyncTelemetryDecision(event risk.HookEvent) risk.RiskDecision {
	riskEvent := risk.NormalizeHookEvent(event)
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = "async_telemetry"
	riskEvent.DecisionStage = "async_telemetry"
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "async telemetry event recorded",
		ReasonCode: "async_telemetry",
		RiskEvent:  riskEvent,
	}
}

func deterministicDenyDecision(riskEvent risk.RiskEvent, policyResult guardpolicy.Result) risk.RiskDecision {
	riskEvent.Decision = risk.DecisionDeny
	riskEvent.ReasonCode = policyResult.ReasonCode
	riskEvent.GuardID = policyResult.RuleID
	riskEvent.DecisionStage = risk.DecisionStageDeterministicDeny
	return risk.RiskDecision{
		Decision:   risk.DecisionDeny,
		Reason:     policyResult.Reason,
		ReasonCode: policyResult.ReasonCode,
		GuardID:    policyResult.RuleID,
		RiskEvent:  riskEvent,
	}
}

func deterministicAllowDecision(riskEvent risk.RiskEvent, policyResult guardpolicy.Result) risk.RiskDecision {
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = policyResult.ReasonCode
	riskEvent.DecisionStage = "deterministic_allow"
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     policyResult.Reason,
		ReasonCode: policyResult.ReasonCode,
		RiskEvent:  riskEvent,
	}
}

func judgeFailOpenDecision(riskEvent risk.RiskEvent, localJudge judge.Judge, err error) risk.RiskDecision {
	failureKind := judge.FailureKind(err)
	metadata := judgeMetadata(localJudge)
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = "judge_unavailable_allow"
	riskEvent.DecisionStage = risk.DecisionStageJudgeFailOpen
	riskEvent.JudgeRuntime = metadata.Runtime
	riskEvent.JudgeModel = metadata.Model
	riskEvent.JudgeFailureKind = failureKind
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "local judge unavailable; allowing by fail-open policy",
		ReasonCode: "judge_unavailable_allow",
		RiskEvent:  riskEvent,
	}
}

func judgeDecision(riskEvent risk.RiskEvent, result judge.Result) risk.RiskDecision {
	decision := risk.DecisionAllow
	reasonCode := risk.DecisionStageJudgeAllow
	if result.Output.Decision == judge.DecisionDeny {
		decision = risk.DecisionDeny
		reasonCode = risk.DecisionStageJudgeDeny
	}
	duration := result.Metadata.DurationMs
	riskEvent.Decision = decision
	riskEvent.ReasonCode = reasonCode
	riskEvent.DecisionStage = reasonCode
	riskEvent.GuardID = "local_llm_judge"
	riskEvent.JudgeRuntime = result.Metadata.Runtime
	riskEvent.JudgeModel = result.Metadata.Model
	riskEvent.JudgeDurationMs = &duration
	riskEvent.JudgeRiskLevel = string(result.Output.RiskLevel)
	riskEvent.JudgeCategories = result.Output.Categories

	return risk.RiskDecision{
		Decision:   decision,
		Reason:     result.Output.Reason,
		ReasonCode: reasonCode,
		GuardID:    "local_llm_judge",
		RiskEvent:  riskEvent,
	}
}

func (p RiskPolicyProvider) activePolicyConfig(ctx context.Context) guardpolicy.Config {
	if p.policyConfig == nil {
		return guardpolicy.DefaultConfig()
	}
	config, err := p.policyConfig.ActivePolicyConfig(ctx)
	if err != nil {
		return guardpolicy.DefaultConfig()
	}
	if err := config.Validate(); err != nil {
		return guardpolicy.DefaultConfig()
	}
	return config
}

func applyPolicyMetadata(event *risk.RiskEvent, result guardpolicy.Result) {
	event.PolicyVersion = result.PolicyVersion
	event.PolicyHash = result.PolicyHash
	event.PolicyProfile = string(result.Profile)
	event.PolicyRulePack = result.RulePack
	if !result.Matched {
		return
	}
	event.PolicyRuleID = result.RuleID
	event.PolicyRuleCategory = string(result.Category)
	event.PolicySignals = result.MatchedSignals
}

func judgeInputFromRiskEvent(event risk.HookEvent, riskEvent risk.RiskEvent) judge.Input {
	toolInput := judge.ToolInput{
		Command: riskEvent.CommandSummary,
		Path:    pathClassForJudge(event.ToolInput, riskEvent.PathClass),
	}
	if toolInput.Command == "" {
		switch {
		case toolInput.Path != "":
			toolInput.Request = sanitizedPathRequest(event.ToolName, toolInput.Path)
		case strings.EqualFold(event.ToolName, "Skill"):
			toolInput.Request = skillRequest(event.ToolInput)
		default:
			toolInput.Request = riskEvent.RequestSummary
		}
	}
	return judge.Input{
		ToolName:           event.ToolName,
		ExplicitUserIntent: riskEvent.ExplicitUserIntent,
		ToolInput:          toolInput,
	}
}

func sanitizedPathRequest(toolName, pathClass string) string {
	action := strings.TrimSpace(toolName)
	if action == "" {
		action = "Tool"
	}
	if isCredentialPathClass(pathClass) {
		return action + " credential_path " + pathClass
	}
	return action + " " + pathClass
}

func isCredentialPathClass(pathClass string) bool {
	switch pathClass {
	case "credential_file", "env_file", "cloud_credentials":
		return true
	default:
		return false
	}
}

func skillRequest(input map[string]any) string {
	name, _ := input["skill"].(string)
	name = strings.TrimSpace(name)
	if name == "" {
		return "Skill"
	}
	return "Skill " + name
}

func pathClassForJudge(input map[string]any, normalizedClass string) string {
	if normalizedClass != "" {
		return normalizedClass
	}
	for _, key := range []string{"file_path", "path", "filename"} {
		if value, ok := input[key].(string); ok {
			if value != "" {
				return judgePathClass(value)
			}
		}
	}
	return ""
}

func judgePathClass(path string) string {
	clean := strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	base := filepath.Base(clean)
	switch base {
	case ".env", ".npmrc", ".pypirc", ".netrc":
		return "env_file"
	}
	if pathHasSegmentPrefix(clean, ".aws") ||
		pathHasSegmentPrefix(clean, ".gcloud") ||
		pathHasSegmentPrefix(clean, ".config/railway") {
		return "cloud_credentials"
	}
	return "project_file"
}

func pathHasSegmentPrefix(clean, prefix string) bool {
	return clean == prefix ||
		strings.HasPrefix(clean, prefix+"/") ||
		strings.Contains(clean, "/"+prefix+"/") ||
		strings.HasSuffix(clean, "/"+prefix)
}

func judgeMetadata(localJudge judge.Judge) judge.Metadata {
	if provider, ok := localJudge.(judge.MetadataProvider); ok {
		return provider.Metadata()
	}
	return judge.Metadata{}
}
