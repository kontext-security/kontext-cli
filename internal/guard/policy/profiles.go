package policy

func categoryEnabled(profile Profile, category RuleCategory) bool {
	switch category {
	case CategoryDirectInfraAPIWithCredentials, CategoryDestructivePersistentResource:
		return true
	case CategoryProductionMutation, CategoryCredentialAccess, CategorySourceControlWrite:
		return profile != ProfileRelaxed
	case CategoryUnknownHighRiskCommand, CategoryManagedTool, CategoryProviderAPICall:
		return profile == ProfileStrict || (profile != ProfileRelaxed && profile != ProfileBalanced)
	default:
		return false
	}
}
