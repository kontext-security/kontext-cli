package sidecar

import (
	"encoding/json"
	"fmt"
	"reflect"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func HookResultFromHostedResult(result *backend.ProcessHookEventResult, accessMode backend.HostedAccessMode) hook.Result {
	if result == nil {
		return hook.Result{
			Decision: hook.DecisionDeny,
			Reason:   "Kontext access policy could not be evaluated.",
			Mode:     string(accessMode),
		}
	}
	resp := result.Response
	out := hook.Result{
		Reason:     resp.GetReason(),
		ReasonCode: result.ReasonCode,
		RequestID:  result.RequestID,
		Mode:       string(accessMode),
		Epoch:      result.PolicySetEpoch,
	}
	if accessMode != backend.HostedAccessModeEnforce {
		out.Decision = hook.DecisionAllow
		return out
	}
	switch resp.GetDecision() {
	case agentv1.Decision_DECISION_ALLOW:
		out.Decision = hook.DecisionAllow
	case agentv1.Decision_DECISION_ASK:
		out.Decision = hook.DecisionAsk
	case agentv1.Decision_DECISION_DENY:
		fallthrough
	default:
		out.Decision = hook.DecisionDeny
	}
	return out
}

func marshalMap(value map[string]any) (json.RawMessage, error) {
	if value == nil {
		return nil, nil
	}
	data, err := json.Marshal(value)
	if err == nil {
		return data, nil
	}

	// Preserve hook flow, but surface the failure to callers.
	sanitized := sanitizeMapForJSON(value, 12)
	sanitizedData, sanitizeErr := json.Marshal(sanitized)
	if sanitizeErr == nil {
		return sanitizedData, err
	}

	// Last resort: ensure we emit valid JSON.
	fallback, _ := json.Marshal(map[string]any{
		"kontextMarshalError":         err.Error(),
		"kontextMarshalFallbackError": sanitizeErr.Error(),
		"kontextMarshalValueType":     fmt.Sprintf("%T", value),
	})
	return fallback, err
}

func sanitizeMapForJSON(value map[string]any, maxDepth int) map[string]any {
	seen := map[uintptr]bool{}
	out := make(map[string]any, len(value))
	for key, val := range value {
		out[key] = sanitizeJSONValue(val, 0, maxDepth, seen)
	}
	return out
}

func sanitizeJSONValue(value any, depth, maxDepth int, seen map[uintptr]bool) any {
	if value == nil {
		return nil
	}
	if depth >= maxDepth {
		return fmt.Sprintf("<max_depth:%T>", value)
	}

	switch v := value.(type) {
	case json.RawMessage:
		if json.Valid(v) {
			return v
		}
		return string(v)
	case *json.RawMessage:
		if v == nil {
			return nil
		}
		if json.Valid(*v) {
			return *v
		}
		return string(*v)
	case error:
		return v.Error()
	}

	rv := reflect.ValueOf(value)
	for rv.Kind() == reflect.Interface || rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}

	switch rv.Kind() {
	case reflect.Map:
		if rv.IsNil() {
			return nil
		}
		ptr := rv.Pointer()
		if ptr != 0 && seen[ptr] {
			return "<cycle>"
		}
		if ptr != 0 {
			seen[ptr] = true
		}

		out := map[string]any{}
		iter := rv.MapRange()
		for iter.Next() {
			key := fmt.Sprint(iter.Key().Interface())
			out[key] = sanitizeJSONValue(iter.Value().Interface(), depth+1, maxDepth, seen)
		}
		return out
	case reflect.Slice, reflect.Array:
		// Keep []byte as-is; encoding/json can handle it.
		if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8 {
			return rv.Bytes()
		}
		if rv.Kind() == reflect.Slice {
			ptr := rv.Pointer()
			if ptr != 0 && seen[ptr] {
				return "<cycle>"
			}
			if ptr != 0 {
				seen[ptr] = true
			}
		}

		n := rv.Len()
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, sanitizeJSONValue(rv.Index(i).Interface(), depth+1, maxDepth, seen))
		}
		return out
	case reflect.Struct:
		// Avoid re-triggering marshal failures on structs with unsupported fields.
		return fmt.Sprintf("%v", value)
	case reflect.Func, reflect.Chan, reflect.Complex64, reflect.Complex128, reflect.UnsafePointer:
		return fmt.Sprintf("<unsupported:%T>", value)
	default:
		// Most scalars (string/bool/numbers) pass through fine.
		return value
	}
}
