package judge

import (
	"context"
	"errors"
	"strings"
)

type UnavailableJudge struct {
	Runtime string
	Model   string
	Kind    string
	Err     error
}

func (j UnavailableJudge) Decide(context.Context, Input) (Result, error) {
	kind := strings.TrimSpace(j.Kind)
	if kind == "" {
		kind = FailureUnavailable
	}
	err := j.Err
	if err == nil {
		err = errors.New("judge unavailable")
	}
	return Result{}, Error{Kind: kind, Err: err}
}

func (j UnavailableJudge) Metadata() Metadata {
	kind := strings.TrimSpace(j.Kind)
	if kind == "" {
		kind = FailureUnavailable
	}
	return Metadata{
		Runtime:     strings.TrimSpace(j.Runtime),
		Model:       strings.TrimSpace(j.Model),
		FailureKind: kind,
	}
}
