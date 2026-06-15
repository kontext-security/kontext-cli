package hook

import (
	"encoding/json"
	"testing"
)

func TestMarshalMapJSONNil(t *testing.T) {
	t.Parallel()

	data, err := MarshalMapJSON(nil)
	if err != nil {
		t.Fatalf("MarshalMapJSON(nil) error = %v", err)
	}
	if data != nil {
		t.Fatalf("MarshalMapJSON(nil) = %v, want nil", data)
	}
}

func TestUnmarshalMapJSONPreservesLargeNumbers(t *testing.T) {
	t.Parallel()

	value, err := UnmarshalMapJSON(json.RawMessage(`{"id":9007199254740993}`))
	if err != nil {
		t.Fatalf("UnmarshalMapJSON() error = %v", err)
	}
	got, ok := value["id"].(json.Number)
	if !ok {
		t.Fatalf("id type = %T, want json.Number", value["id"])
	}
	if got.String() != "9007199254740993" {
		t.Fatalf("id = %s, want exact large number", got.String())
	}
}

func TestUnmarshalJSONUseNumberPreservesLargeNumbersInArrays(t *testing.T) {
	t.Parallel()

	var value any
	if err := UnmarshalJSONUseNumber([]byte(`[{"id":9007199254740993}]`), &value); err != nil {
		t.Fatalf("UnmarshalJSONUseNumber() error = %v", err)
	}
	got := value.([]any)[0].(map[string]any)["id"]
	num, ok := got.(json.Number)
	if !ok {
		t.Fatalf("id type = %T, want json.Number", got)
	}
	if num.String() != "9007199254740993" {
		t.Fatalf("id = %s, want exact large number", num.String())
	}
}
