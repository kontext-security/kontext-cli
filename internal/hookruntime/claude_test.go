package hookruntime

import (
	"encoding/json"
	"testing"
)

func TestDecodeClaudeEventToolResponseObject(t *testing.T) {
	t.Parallel()

	input := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"ok","stderr":""}}`)
	ev, err := DecodeClaudeEvent(input, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent() error = %v", err)
	}
	if got := ev.ToolResponse["stdout"]; got != "ok" {
		t.Fatalf("ToolResponse[stdout] = %v, want \"ok\"", got)
	}
}

func TestDecodeClaudeEventToolResponseArray(t *testing.T) {
	t.Parallel()

	// MCP tools (e.g. Linear) return tool_response as an array of content blocks.
	input := []byte(`{"hook_event_name":"PostToolUse","tool_name":"mcp__linear__get_issue","tool_response":[{"type":"text","text":"hello"}]}`)
	ev, err := DecodeClaudeEvent(input, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent() error = %v, array tool_response must not break decoding", err)
	}
	content, ok := ev.ToolResponse["content"].([]any)
	if !ok {
		t.Fatalf("ToolResponse[content] type = %T, want []any", ev.ToolResponse["content"])
	}
	if len(content) != 1 {
		t.Fatalf("len(content) = %d, want 1", len(content))
	}
}

func TestDecodeClaudeEventToolResponsePreservesLargeNumbers(t *testing.T) {
	t.Parallel()

	// Large IDs must not be rounded through float64, for both array (MCP) and
	// object (built-in) payloads.
	arrInput := []byte(`{"hook_event_name":"PostToolUse","tool_name":"mcp__x__get","tool_response":[{"id":9007199254740993}]}`)
	arrEv, err := DecodeClaudeEvent(arrInput, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent(array) error = %v", err)
	}
	arrID := arrEv.ToolResponse["content"].([]any)[0].(map[string]any)["id"]
	if num, ok := arrID.(json.Number); !ok || num.String() != "9007199254740993" {
		t.Fatalf("array id = %v (%T), want json.Number 9007199254740993", arrID, arrID)
	}

	objInput := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"id":9007199254740993}}`)
	objEv, err := DecodeClaudeEvent(objInput, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent(object) error = %v", err)
	}
	objID := objEv.ToolResponse["id"]
	if num, ok := objID.(json.Number); !ok || num.String() != "9007199254740993" {
		t.Fatalf("object id = %v (%T), want json.Number 9007199254740993", objID, objID)
	}
}

func TestDecodeClaudeEventToolResponseAbsent(t *testing.T) {
	t.Parallel()

	input := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	ev, err := DecodeClaudeEvent(input, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent() error = %v", err)
	}
	if ev.ToolResponse != nil {
		t.Fatalf("ToolResponse = %v, want nil", ev.ToolResponse)
	}
}
