package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Fetch loads policy settings and rules from the backend, returning a ready Engine.
// If policy is disabled, returns an Engine that allows everything.
func Fetch(ctx context.Context, baseURL string, accessToken string) (*Engine, error) {
	baseURL = strings.TrimRight(baseURL, "/")

	settings, err := fetchJSON[policySettings](ctx, baseURL+"/api/v1/policy/settings", accessToken)
	if err != nil {
		return nil, fmt.Errorf("fetch policy settings: %w", err)
	}

	if !settings.PolicyEnabled {
		return NewEngine(false, nil), nil
	}

	rules, err := fetchRules(ctx, baseURL+"/api/v1/policy/rules", accessToken)
	if err != nil {
		return nil, fmt.Errorf("fetch policy rules: %w", err)
	}

	return NewEngine(true, rules), nil
}

type policySettings struct {
	PolicyEnabled bool `json:"policyEnabled"`
}

type ruleResponse struct {
	Action   string `json:"action"`
	Scope    string `json:"scope"`
	Level    string `json:"level"`
	ToolName string `json:"toolName"`
}

func fetchRules(ctx context.Context, url string, token string) ([]Rule, error) {
	raw, err := fetchJSON[[]ruleResponse](ctx, url, token)
	if err != nil {
		return nil, err
	}
	rules := make([]Rule, len(*raw))
	for i, r := range *raw {
		rules[i] = Rule{
			Action:   r.Action,
			Scope:    r.Scope,
			Level:    r.Level,
			ToolName: r.ToolName,
		}
	}
	return rules, nil
}

func fetchJSON[T any](ctx context.Context, url string, token string) (*T, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}
