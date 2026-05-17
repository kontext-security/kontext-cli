package localruntime

import (
	"encoding/json"
	"net"
	"testing"
)

func TestWriteReadMessagePreservesLargeJSONNumbersInUpdatedInput(t *testing.T) {
	t.Parallel()

	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- WriteMessage(server, EvaluateResult{
			Type:    "result",
			Allowed: true,
			UpdatedInput: JSONObject{
				"id": json.Number("9007199254740993"),
			},
		})
	}()

	var got EvaluateResult
	if err := ReadMessage(client, &got); err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}

	number, ok := got.UpdatedInput["id"].(json.Number)
	if !ok {
		t.Fatalf("updated_input.id type = %T, want json.Number", got.UpdatedInput["id"])
	}
	if number.String() != "9007199254740993" {
		t.Fatalf("updated_input.id = %s, want exact large number", number.String())
	}
}
