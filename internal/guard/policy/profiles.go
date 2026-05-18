package policy

func enabledCategories(profile Profile) map[RuleCategory]bool {
	categories := map[RuleCategory]bool{
		CategoryDirectInfraAPIWithCredentials: true,
		CategoryDestructivePersistentResource: true,
	}
	switch profile {
	case ProfileRelaxed:
		return categories
	case ProfileBalanced:
		categories[CategoryProductionMutation] = true
		categories[CategoryCredentialAccess] = true
		categories[CategorySourceControlWrite] = true
	case ProfileStrict:
		categories[CategoryProductionMutation] = true
		categories[CategoryCredentialAccess] = true
		categories[CategorySourceControlWrite] = true
		categories[CategoryUnknownHighRiskCommand] = true
		categories[CategoryManagedTool] = true
		categories[CategoryProviderAPICall] = true
	default:
		categories[CategoryProductionMutation] = true
		categories[CategoryCredentialAccess] = true
		categories[CategorySourceControlWrite] = true
		categories[CategoryUnknownHighRiskCommand] = true
		categories[CategoryManagedTool] = true
		categories[CategoryProviderAPICall] = true
	}
	return categories
}

func categoryEnabled(profile Profile, category RuleCategory) bool {
	return enabledCategories(profile)[category]
}
