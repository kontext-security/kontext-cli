package hook

import "strings"

type HookName string

const (
	HookSessionStart      HookName = "SessionStart"
	HookPreToolUse        HookName = "PreToolUse"
	HookPostToolUse       HookName = "PostToolUse"
	HookPostToolUseFailed HookName = "PostToolUseFailure"
	HookSessionEnd        HookName = "SessionEnd"
	HookUserPromptSubmit  HookName = "UserPromptSubmit"
)

func (h HookName) String() string {
	return string(h)
}

func (h HookName) IsKnown() bool {
	switch h {
	case HookSessionStart, HookPreToolUse, HookPostToolUse, HookPostToolUseFailed, HookSessionEnd, HookUserPromptSubmit:
		return true
	default:
		return false
	}
}

func (h HookName) CanBlock() bool {
	return h == HookPreToolUse
}

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

func NormalizeDecision(value string) (Decision, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(DecisionAllow):
		return DecisionAllow, true
	case string(DecisionDeny):
		return DecisionDeny, true
	default:
		return "", false
	}
}

type Event struct {
	SessionID      string
	Agent          string
	HookName       HookName
	ToolName       string
	ToolInput      map[string]any
	ToolResponse   map[string]any
	ToolUseID      string
	CWD            string
	PermissionMode string
	DurationMs     *int64
	Error          string
	IsInterrupt    *bool
}

type Result struct {
	Decision     Decision
	Reason       string
	ReasonCode   string
	RequestID    string
	EventID      string
	Mode         string
	Epoch        string
	UpdatedInput map[string]any
	metadata     any
}

func WithMetadata(result Result, metadata any) Result {
	result.metadata = metadata
	return result
}

func (r Result) Metadata() any {
	return r.metadata
}

func (r Result) Allowed() bool {
	return r.Decision == DecisionAllow
}

func (r Result) Blocking() bool {
	return r.Decision == DecisionDeny
}

func (r Result) ClaudeReason() string {
	reason := r.Reason
	if reason == "" && r.Decision == DecisionDeny {
		return "Blocked by Kontext access policy."
	}
	return reason
}
