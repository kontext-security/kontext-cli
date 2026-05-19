package policy

import "github.com/kontext-security/kontext-cli/internal/guard/risk"

func DefaultRulePack() RulePack {
	return RulePack{
		ID:      DefaultRulePackID,
		Version: "v0.2.0",
		Rules: []Rule{
			{
				ID:             "guard.destructive_persistent_resource.v2",
				Category:       CategoryDestructivePersistentResource,
				ReasonCode:     "destructive_operation_without_intent",
				Reason:         "destructive persistent-resource operation requires explicit user intent",
				NonBypassable:  true,
				MatchedSignals: []string{"destructive_verb", "persistent_resource"},
				When: func(event risk.RiskEvent) bool {
					return event.Type == risk.EventDestructiveProviderOperation &&
						risk.IsPersistentResourceClass(event.ResourceClass) &&
						!event.ExplicitUserIntent
				},
			},
			{
				ID:             "guard.direct_infra_api_with_credentials.v2",
				Category:       CategoryDirectInfraAPIWithCredentials,
				ReasonCode:     "direct_infra_api_with_credential",
				Reason:         "direct infrastructure API call included credential material",
				NonBypassable:  true,
				MatchedSignals: []string{"direct_provider_api", "credential_observed"},
				When: func(event risk.RiskEvent) bool {
					return event.Type == risk.EventDirectProviderAPICall &&
						event.ProviderCategory == "infrastructure" &&
						event.CredentialObserved
				},
			},
			{
				ID:             "guard.production_mutation.v2",
				Category:       CategoryProductionMutation,
				ReasonCode:     "production_mutation",
				Reason:         "production mutation blocked by deterministic policy",
				MatchedSignals: []string{"production", "managed_tool_write", "provider_cli"},
				When: func(event risk.RiskEvent) bool {
					return event.Environment == "production" &&
						event.OperationClass != "" &&
						event.OperationClass != "unknown" &&
						event.OperationClass != "read"
				},
			},
			{
				ID:             "guard.credential_access.v2",
				Category:       CategoryCredentialAccess,
				ReasonCode:     "credential_access_without_intent",
				Reason:         "credential access blocked by deterministic policy",
				MatchedSignals: []string{"credential_path", "credential_file_write", "shell_credential_access", "credential_observed"},
				When: func(event risk.RiskEvent) bool {
					return event.Type == risk.EventCredentialAccess && !event.ExplicitUserIntent
				},
			},
			{
				ID:             "guard.source_control_remote_write.v2",
				Category:       CategorySourceControlWrite,
				ReasonCode:     "source_control_remote_write",
				Reason:         "remote source-control write requires explicit user intent",
				MatchedSignals: []string{"source_control_remote_write"},
				When: func(event risk.RiskEvent) bool {
					return event.ProviderCategory == "source_control" &&
						event.OperationClass != "read" &&
						!event.ExplicitUserIntent &&
						hasSignal(event.Signals, "source_control_remote_write")
				},
			},
			{
				ID:             "guard.managed_tool_write.v2",
				Category:       CategoryManagedTool,
				ReasonCode:     "managed_tool_write_without_intent",
				Reason:         "managed tool mutation requires explicit user intent",
				MatchedSignals: []string{"managed_tool", "managed_tool_write"},
				When: func(event risk.RiskEvent) bool {
					return event.Type == risk.EventManagedToolCall &&
						event.OperationClass != "" &&
						event.OperationClass != "unknown" &&
						event.OperationClass != "read" &&
						!event.ExplicitUserIntent
				},
			},
			{
				ID:             "guard.direct_infra_api_mutation.v2",
				Category:       CategoryProviderAPICall,
				ReasonCode:     "direct_infra_api_mutation",
				Reason:         "direct infrastructure API mutation requires explicit user intent",
				MatchedSignals: []string{"direct_provider_api"},
				When: func(event risk.RiskEvent) bool {
					return event.Type == risk.EventDirectProviderAPICall &&
						event.ProviderCategory == "infrastructure" &&
						event.OperationClass != "" &&
						event.OperationClass != "unknown" &&
						event.OperationClass != "read" &&
						!event.ExplicitUserIntent
				},
			},
			{
				ID:             "guard.unknown_high_risk.v2",
				Category:       CategoryUnknownHighRiskCommand,
				ReasonCode:     "unknown_high_risk_command",
				Reason:         "unknown high-risk command blocked by strict deterministic policy",
				MatchedSignals: []string{"unknown_high_risk"},
				When: func(event risk.RiskEvent) bool {
					return event.Type == risk.EventUnknown
				},
			},
		},
	}
}
