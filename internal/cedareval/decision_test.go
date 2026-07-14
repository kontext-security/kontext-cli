package cedareval

import "testing"

func TestMapDecisionRejectsInvalidStates(t *testing.T) {
	t.Parallel()

	principal := &EvaluationPrincipal{
		EntityType: PrincipalEntityType,
		EntityID:   "alice@example.com",
	}
	tests := []struct {
		name  string
		input DecisionMappingInput
	}{
		{
			name: "unsupported rollout mode",
			input: DecisionMappingInput{
				RolloutMode: RolloutMode("invalid"),
				Evaluation: EvaluationOutcome{
					State:  EvaluationStateFailed,
					Reason: ReasonEngineError,
				},
			},
		},
		{
			name: "disabled mode evaluates",
			input: DecisionMappingInput{
				RolloutMode:            RolloutModeDisabled,
				CurrentAuthorityAction: EffectiveExecutionActionAllow,
				Evaluation: EvaluationOutcome{
					State:                EvaluationStateEvaluated,
					Decision:             DecisionAllow,
					DeterminingPolicyIDs: []string{"permit"},
				},
			},
		},
		{
			name: "observe mode is not evaluated",
			input: DecisionMappingInput{
				RolloutMode:            RolloutModeObserve,
				CurrentAuthorityAction: EffectiveExecutionActionAllow,
				Evaluation: EvaluationOutcome{
					State:  EvaluationStateNotEvaluated,
					Reason: ReasonEnforcementNotReady,
				},
			},
		},
		{
			name: "enforce readiness contradicts evaluation",
			input: DecisionMappingInput{
				RolloutMode:      RolloutModeEnforce,
				EnforcementReady: true,
				Evaluation: EvaluationOutcome{
					State:  EvaluationStateNotEvaluated,
					Reason: ReasonEnforcementNotReady,
				},
			},
		},
		{
			name: "enforce carries disabled-policy reason",
			input: DecisionMappingInput{
				RolloutMode:      RolloutModeEnforce,
				EnforcementReady: true,
				Evaluation: EvaluationOutcome{
					State:  EvaluationStateNotEvaluated,
					Reason: ReasonPolicyDisabled,
				},
			},
		},
		{
			name: "enforce without readiness evaluates",
			input: DecisionMappingInput{
				RolloutMode: RolloutModeEnforce,
				Evaluation: EvaluationOutcome{
					State:  EvaluationStateFailed,
					Reason: ReasonEngineError,
				},
			},
		},
		{
			name: "deny derives ask",
			input: DecisionMappingInput{
				RolloutMode:      RolloutModeEnforce,
				EnforcementReady: true,
				Evaluation: EvaluationOutcome{
					State:    EvaluationStateEvaluated,
					Decision: DecisionDeny,
					Ask:      true,
				},
			},
		},
		{
			name: "allow has no determining permit",
			input: DecisionMappingInput{
				RolloutMode:      RolloutModeEnforce,
				EnforcementReady: true,
				Evaluation: EvaluationOutcome{
					State:    EvaluationStateEvaluated,
					Decision: DecisionAllow,
				},
			},
		},
		{
			name: "unresolved principal includes fallback",
			input: DecisionMappingInput{
				RolloutMode:            RolloutModeObserve,
				CurrentAuthorityAction: EffectiveExecutionActionAllow,
				EvaluationPrincipal:    principal,
				Evaluation: EvaluationOutcome{
					State:  EvaluationStatePrincipalUnresolved,
					Reason: ReasonPrincipalUnresolved,
				},
			},
		},
		{
			name: "failed evaluation includes Cedar decision",
			input: DecisionMappingInput{
				RolloutMode:            RolloutModeObserve,
				CurrentAuthorityAction: EffectiveExecutionActionAllow,
				Evaluation: EvaluationOutcome{
					State:    EvaluationStateFailed,
					Reason:   ReasonEngineError,
					Decision: DecisionDeny,
				},
			},
		},
		{
			name: "enforce uses migration authority",
			input: DecisionMappingInput{
				RolloutMode:            RolloutModeEnforce,
				CurrentAuthorityAction: EffectiveExecutionActionAllow,
				EnforcementReady:       true,
				Evaluation: EvaluationOutcome{
					State:  EvaluationStateFailed,
					Reason: ReasonEngineError,
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := MapDecision(test.input); err == nil {
				t.Fatal("MapDecision() error = nil, want invalid-state rejection")
			}
		})
	}
}
