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

	// Large IDs must not be rounded through float64 when wrapping array payloads.
	input := []byte(`{"hook_event_name":"PostToolUse","tool_name":"mcp__x__get","tool_response":[{"id":9007199254740993}]}`)
	ev, err := DecodeClaudeEvent(input, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent() error = %v", err)
	}
	content := ev.ToolResponse["content"].([]any)
	id := content[0].(map[string]any)["id"]
	num, ok := id.(json.Number)
	if !ok {
		t.Fatalf("id type = %T, want json.Number (UseNumber)", id)
	}
	if num.String() != "9007199254740993" {
		t.Fatalf("id = %s, want 9007199254740993 (no float rounding)", num.String())
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
