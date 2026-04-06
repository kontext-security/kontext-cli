package sidecar

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWriteAndReadMessage(t *testing.T) {
	var buf bytes.Buffer

	msg := []byte(`{"tool_name":"Bash"}`)
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	if !bytes.Equal(got, msg) {
		t.Errorf("got %q, want %q", got, msg)
	}
}

func TestReadMessageEmptyStream(t *testing.T) {
	var buf bytes.Buffer
	_, err := ReadMessage(&buf)
	if err == nil {
		t.Fatal("expected error on empty stream")
	}
}

func TestReadMessageTooLarge(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(2<<20))
	_, err := ReadMessage(&buf)
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
}
