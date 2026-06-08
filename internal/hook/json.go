package hook

import (
	"bytes"
	"encoding/json"
)

func MarshalMapJSON(value map[string]any) (json.RawMessage, error) {
	if value == nil {
		return nil, nil
	}
	return json.Marshal(value)
}

func UnmarshalMapJSON(data json.RawMessage) (map[string]any, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var value map[string]any
	if err := UnmarshalJSONUseNumber(data, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func UnmarshalJSONUseNumber(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode(dst)
}
