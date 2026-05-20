package judge

func IsUnavailable(localJudge Judge) bool {
	if localJudge == nil {
		return false
	}
	switch localJudge.(type) {
	case UnavailableJudge, *UnavailableJudge:
		return true
	}
	metadataProvider, ok := localJudge.(MetadataProvider)
	return ok && metadataProvider.Metadata().FailureKind == FailureUnavailable
}
