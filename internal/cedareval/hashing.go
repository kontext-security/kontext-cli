package cedareval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	PolicyHashDomain         = "kontext:cedar-policy:v1\x00"
	DeploymentIdentityDomain = "kontext:cedar-deployment:v1"
)

type DeploymentIdentityInput struct {
	ResponseVersion        int
	RequestContractVersion int
	Revision               string
	PolicyHash             string
	RolloutMode            string
	EvaluationPrincipal    EvaluationPrincipal
}

func ComputePolicyHash(policyText string) string {
	sum := sha256.Sum256([]byte(PolicyHashDomain + policyText))
	return hex.EncodeToString(sum[:])
}

func DeploymentIdentityPreimage(input DeploymentIdentityInput) (string, error) {
	value := []any{
		DeploymentIdentityDomain,
		input.ResponseVersion,
		input.RequestContractVersion,
		input.Revision,
		input.PolicyHash,
		input.RolloutMode,
		input.EvaluationPrincipal.EntityType,
		input.EvaluationPrincipal.EntityID,
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", fmt.Errorf("cedareval: encode deployment identity: %w", err)
	}
	return string(bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))), nil
}

func ComputeDeploymentIdentity(input DeploymentIdentityInput) (string, error) {
	preimage, err := DeploymentIdentityPreimage(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(preimage))
	return hex.EncodeToString(sum[:]), nil
}
