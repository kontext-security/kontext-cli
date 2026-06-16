package policy

import "testing"

func TestCategoryEnabledByProfile(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
		want    map[RuleCategory]bool
	}{
		{
			name:    "relaxed keeps only always-on categories",
			profile: ProfileRelaxed,
			want: map[RuleCategory]bool{
				CategoryDirectInfraAPIWithCredentials: true,
				CategoryDestructivePersistentResource: true,
			},
		},
		{
			name:    "balanced enables shared guarded categories",
			profile: ProfileBalanced,
			want: map[RuleCategory]bool{
				CategoryDirectInfraAPIWithCredentials: true,
				CategoryDestructivePersistentResource: true,
				CategoryProductionMutation:            true,
				CategoryCredentialAccess:              true,
				CategorySourceControlWrite:            true,
			},
		},
		{
			name:    "strict enables every built-in category",
			profile: ProfileStrict,
			want: map[RuleCategory]bool{
				CategoryDirectInfraAPIWithCredentials: true,
				CategoryDestructivePersistentResource: true,
				CategoryProductionMutation:            true,
				CategoryCredentialAccess:              true,
				CategorySourceControlWrite:            true,
				CategoryUnknownHighRiskCommand:        true,
				CategoryManagedTool:                   true,
				CategoryProviderAPICall:               true,
			},
		},
		{
			name:    "unknown profile falls back to strict behavior",
			profile: Profile("paranoid"),
			want: map[RuleCategory]bool{
				CategoryDirectInfraAPIWithCredentials: true,
				CategoryDestructivePersistentResource: true,
				CategoryProductionMutation:            true,
				CategoryCredentialAccess:              true,
				CategorySourceControlWrite:            true,
				CategoryUnknownHighRiskCommand:        true,
				CategoryManagedTool:                   true,
				CategoryProviderAPICall:               true,
			},
		},
	}

	categories := []RuleCategory{
		CategoryDirectInfraAPIWithCredentials,
		CategoryDestructivePersistentResource,
		CategoryProductionMutation,
		CategoryCredentialAccess,
		CategorySourceControlWrite,
		CategoryUnknownHighRiskCommand,
		CategoryManagedTool,
		CategoryProviderAPICall,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, category := range categories {
				got := categoryEnabled(tt.profile, category)
				if got != tt.want[category] {
					t.Fatalf("categoryEnabled(%q, %q) = %t, want %t", tt.profile, category, got, tt.want[category])
				}
			}
		})
	}
}
