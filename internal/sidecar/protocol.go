package sidecar

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

type EvaluateRequest struct {
	Type         string          `json:"type"`
	Agent        string          `json:"agent"`
	HookEvent    string          `json:"hook_event"`
	ToolName     string          `json:"tool_name"`
	ToolInput    json.RawMessage `json:"tool_input,omitempty"`
	ToolResponse json.RawMessage `json:"tool_response,omitempty"`
	ToolUseID    string          `json:"tool_use_id"`
	CWD          string          `json:"cwd"`
}

type EvaluateResult struct {
	Type    string `json:"type"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func WriteMessage(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	length := uint32(len(data))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

func ReadMessage(conn net.Conn, v any) error {
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return fmt.Errorf("read length: %w", err)
	}

	if length > 10*1024*1024 {
		return fmt.Errorf("message too large: %d bytes", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	return json.Unmarshal(data, v)
}
