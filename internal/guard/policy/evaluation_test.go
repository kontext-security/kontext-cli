package policy

import (
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

func TestStrictPolicyEvaluationV02(t *testing.T) {
	tests := []struct {
		name             string
		event            risk.HookEvent
		want             Decision
		wantCategory     RuleCategory
		baselineDecision Decision
	}{
		{
			name: "deny quoted psql drop database",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": `psql "$PROD_DATABASE_URL" -c "DROP DATABASE production;"`},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryDestructivePersistentResource,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny mysql drop table",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": `mysql --database app -e "DROP TABLE users"`},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryDestructivePersistentResource,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny redis flushall",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "redis-cli FLUSHALL"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryDestructivePersistentResource,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny recursive prod bucket delete",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "aws s3 rm s3://prod-bucket --recursive"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryDestructivePersistentResource,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny rds database delete",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "aws rds delete-db-instance --db-instance-identifier prod-db --skip-final-snapshot"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryDestructivePersistentResource,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny terraform production destroy",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "terraform destroy -var env=production -auto-approve"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryDestructivePersistentResource,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny kubernetes namespace delete",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "kubectl delete namespace production --wait=false"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryDestructivePersistentResource,
			baselineDecision: DecisionDeny,
		},
		{
			name: "deny docker compose volume teardown",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "docker compose --context prod down -v"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryDestructivePersistentResource,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny github repo delete",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "gh repo delete org/prod-repo --yes"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryDestructivePersistentResource,
			baselineDecision: DecisionDeny,
		},
		{
			name: "deny remote branch delete",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "git push origin --delete main"},
			},
			want:             DecisionDeny,
			wantCategory:     CategorySourceControlWrite,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny managed production restart",
			event: risk.HookEvent{
				ToolName:  "mcp__railway__restart_service",
				ToolInput: map[string]any{"project": "prod-api", "environment": "production", "service": "api"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryProductionMutation,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny managed production bucket policy write",
			event: risk.HookEvent{
				ToolName:  "mcp__aws__put_bucket_policy",
				ToolInput: map[string]any{"bucket": "prod-assets", "policy": "public-read"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryProductionMutation,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny credential file write",
			event: risk.HookEvent{
				ToolName:  "Write",
				ToolInput: map[string]any{"file_path": ".env", "content": "TOKEN=secret"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryCredentialAccess,
			baselineDecision: DecisionAllow,
		},
		{
			name: "deny direct infra api mutation",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "curl -X DELETE https://api.railway.app/graphql"},
			},
			want:             DecisionDeny,
			wantCategory:     CategoryProviderAPICall,
			baselineDecision: DecisionAllow,
		},
		{
			name: "allow local go tests",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "go test ./..."},
			},
			want:             DecisionAllow,
			baselineDecision: DecisionAllow,
		},
		{
			name: "allow grep for dangerous string",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": `grep -R "DROP DATABASE" tests`},
			},
			want:             DecisionAllow,
			baselineDecision: DecisionAllow,
		},
		{
			name: "allow docs commit with dangerous words",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": `git commit -m "docs: explain why not to delete production database" docs/guard.md`},
			},
			want:             DecisionAllow,
			baselineDecision: DecisionAllow,
		},
		{
			name: "allow docs write with fake bearer token",
			event: risk.HookEvent{
				ToolName:  "Write",
				ToolInput: map[string]any{"file_path": "docs/security.md", "content": "Use Bearer sk_test_placeholder in examples."},
			},
			want:             DecisionAllow,
			baselineDecision: DecisionAllow,
		},
		{
			name: "allow managed linear list issues",
			event: risk.HookEvent{
				ToolName:  "mcp__linear__list_issues",
				ToolInput: map[string]any{"teamKey": "KG", "limit": 20},
			},
			want:             DecisionAllow,
			baselineDecision: DecisionAllow,
		},
		{
			name: "allow production rollout status read",
			event: risk.HookEvent{
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "kubectl rollout status deployment/api -n production"},
			},
			want:             DecisionAllow,
			baselineDecision: DecisionAllow,
		},
	}

	engine := NewEngine(DefaultRulePack())
	cfg := DefaultConfig()
	cfg.Profile = ProfileStrict
	var caught int
	var baselineCaught int

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(risk.NormalizeHookEvent(tt.event), cfg)
			if result.Decision != tt.want {
				t.Fatalf("decision = %s, want %s: %+v", result.Decision, tt.want, result)
			}
			if tt.want == DecisionDeny && result.Category != tt.wantCategory {
				t.Fatalf("category = %s, want %s: %+v", result.Category, tt.wantCategory, result)
			}
			if tt.want == DecisionAllow && result.Matched {
				t.Fatalf("allow result matched a rule: %+v", result)
			}
		})
		if tt.want == DecisionDeny {
			caught++
			if tt.baselineDecision == DecisionDeny {
				baselineCaught++
			}
		}
	}

	if caught != 14 {
		t.Fatalf("v0.2 caught %d deny fixtures, want 14", caught)
	}
	if baselineCaught != 2 {
		t.Fatalf("baseline caught %d deny fixtures, want 2", baselineCaught)
	}
	t.Logf("strict policy v0.2 caught %d/%d deny fixtures; launch baseline caught %d/%d", caught, caught, baselineCaught, caught)
}
