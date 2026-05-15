package policyconfig

import "fmt"

type ValidationError struct {
	Reason string
}

func (e ValidationError) Error() string {
	if e.Reason == "" {
		return "invalid policy config"
	}
	return fmt.Sprintf("invalid policy config: %s", e.Reason)
}
