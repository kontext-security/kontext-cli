package sidecar

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WriteMessage writes a length-prefixed message: 4-byte big-endian length + body.
func WriteMessage(w io.Writer, data []byte) error {
	length := uint32(len(data))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	return nil
}

// ReadMessage reads a length-prefixed message.
func ReadMessage(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	if length > 1<<20 { // 1MB safety limit
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return data, nil
}
