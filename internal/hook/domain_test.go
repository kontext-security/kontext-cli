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
		{name: "ask padded", in: " ask ", want: DecisionAsk, ok: true},
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
			name: "ask includes request id",
			in:   Result{Decision: DecisionAsk, Reason: "approval required", RequestID: "req-123"},
			want: "approval required Request ID: req-123",
		},
		{
			name: "ask does not duplicate request id",
			in:   Result{Decision: DecisionAsk, Reason: "approval required request id: req-123", RequestID: "req-123"},
			want: "approval required request id: req-123",
		},
		{
			name: "ask default",
			in:   Result{Decision: DecisionAsk},
			want: "Kontext access policy requires approval.",
		},
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
