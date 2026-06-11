package hook

import "testing"

func TestNormalizeDecision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want Decision
		ok   bool
	}{
		{name: "allow lowercase", in: "allow", want: DecisionAllow, ok: true},
		{name: "allow uppercase", in: "ALLOW", want: DecisionAllow, ok: true},
		{name: "deny mixed case", in: "DeNy", want: DecisionDeny, ok: true},
		{name: "ask unsupported", in: " ask ", ok: false},
		{name: "unknown", in: "retry", ok: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := NormalizeDecision(tt.in)
			if ok != tt.ok {
				t.Fatalf("NormalizeDecision(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("NormalizeDecision(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestResultClaudeReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   Result
		want string
	}{
		{
			name: "deny default",
			in:   Result{Decision: DecisionDeny},
			want: "Blocked by Kontext access policy.",
		},
		{
			name: "allow custom",
			in:   Result{Decision: DecisionAllow, Reason: "allowed"},
			want: "allowed",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.in.ClaudeReason(); got != tt.want {
				t.Fatalf("ClaudeReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHookNameCanBlock(t *testing.T) {
	t.Parallel()

	if !HookPreToolUse.CanBlock() {
		t.Fatalf("HookPreToolUse.CanBlock() = false, want true")
	}
	if HookPostToolUse.CanBlock() {
		t.Fatalf("HookPostToolUse.CanBlock() = true, want false")
	}
	if HookUserPromptSubmit.CanBlock() {
		t.Fatalf("HookUserPromptSubmit.CanBlock() = true, want false")
	}
}

func TestHookNameIsKnown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name HookName
		want bool
	}{
		{name: HookSessionStart, want: true},
		{name: HookPreToolUse, want: true},
		{name: HookPostToolUse, want: true},
		{name: HookPostToolUseFailed, want: true},
		{name: HookSessionEnd, want: true},
		{name: HookUserPromptSubmit, want: true},
		{name: HookName("pretooluse"), want: false},
		{name: HookName(""), want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name.String(), func(t *testing.T) {
			t.Parallel()

			if got := tt.name.IsKnown(); got != tt.want {
				t.Fatalf("HookName(%q).IsKnown() = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
