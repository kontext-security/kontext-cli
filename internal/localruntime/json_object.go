package localruntime

import (
	"bytes"
	"encoding/json"
)

type JSONObject map[string]any

type jsonObjectNoMethods map[string]any

func (o JSONObject) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonObjectNoMethods(o))
}

func (o *JSONObject) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*o = nil
		return nil
	}

	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}

	*o = value
	return nil
}
