package cedareval

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
)

const (
	ContextMaxDepth  = 32
	ContextMaxValues = 10_000
	maxSafeInteger   = int64(9_007_199_254_740_991)
)

type ContextDiagnostic struct {
	Code string `json:"code"`
	Path string `json:"path"`
}

type ConversionError struct {
	Code string
	Path string
	msg  string
}

func (e *ConversionError) Error() string {
	return e.msg
}

type conversionState struct {
	diagnostics []ContextDiagnostic
	valuesSeen  int
}

func ConvertToolInput(toolInput map[string]any) (cedar.Record, []ContextDiagnostic, error) {
	state := conversionState{diagnostics: make([]ContextDiagnostic, 0)}
	value, err := convertValue(toolInput, "", 0, &state, false)
	if err != nil {
		return cedar.Record{}, nil, err
	}
	record, ok := value.(cedar.Record)
	if !ok {
		return cedar.Record{}, nil, newConversionError(
			"invalid_json_value",
			"",
			"cedar context root must be an object",
		)
	}
	sort.Slice(state.diagnostics, func(i, j int) bool {
		return state.diagnostics[i].Path < state.diagnostics[j].Path
	})
	return record, state.diagnostics, nil
}

func convertValue(value any, path string, depth int, state *conversionState, insideSet bool) (cedar.Value, error) {
	if depth > ContextMaxDepth {
		return nil, newConversionError(
			"maximum_depth_exceeded",
			path,
			fmt.Sprintf("cedar context exceeds depth %d", ContextMaxDepth),
		)
	}

	state.valuesSeen++
	if state.valuesSeen > ContextMaxValues {
		return nil, newConversionError(
			"maximum_values_exceeded",
			path,
			fmt.Sprintf("cedar context exceeds %d values", ContextMaxValues),
		)
	}

	if value == nil {
		if insideSet {
			return nil, newConversionError(
				"null_in_set",
				path,
				"json null cannot be represented in a cedar set",
			)
		}
		state.diagnostics = append(state.diagnostics, ContextDiagnostic{
			Code: "null_omitted",
			Path: path,
		})
		return nil, nil
	}

	switch v := value.(type) {
	case string:
		return cedar.String(v), nil
	case bool:
		return cedar.Boolean(v), nil
	case json.Number:
		return convertNumber(v.String(), path)
	case float64:
		return convertFloat(v, path)
	case float32:
		return convertFloat(float64(v), path)
	case int:
		return convertSigned(int64(v), path)
	case int8:
		return convertSigned(int64(v), path)
	case int16:
		return convertSigned(int64(v), path)
	case int32:
		return convertSigned(int64(v), path)
	case int64:
		return convertSigned(v, path)
	case uint:
		return convertUnsigned(uint64(v), path)
	case uint8:
		return convertUnsigned(uint64(v), path)
	case uint16:
		return convertUnsigned(uint64(v), path)
	case uint32:
		return convertUnsigned(uint64(v), path)
	case uint64:
		return convertUnsigned(v, path)
	case []any:
		values := make([]cedar.Value, len(v))
		for i, item := range v {
			converted, err := convertValue(item, pointer(path, strconv.Itoa(i)), depth+1, state, true)
			if err != nil {
				return nil, err
			}
			if converted == nil {
				return nil, newConversionError(
					"null_in_set",
					pointer(path, strconv.Itoa(i)),
					"null cannot appear in a cedar set",
				)
			}
			values[i] = converted
		}
		return cedar.NewSet(values...), nil
	case map[string]any:
		if _, ok := v["__entity"]; ok {
			return nil, reservedEscapeError(path)
		}
		if _, ok := v["__extn"]; ok {
			return nil, reservedEscapeError(path)
		}

		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		record := make(cedar.RecordMap, len(v))
		for _, key := range keys {
			nested := v[key]
			converted, err := convertValue(nested, pointer(path, key), depth+1, state, false)
			if err != nil {
				return nil, err
			}
			if converted != nil {
				record[cedar.String(key)] = converted
			}
		}
		return cedar.NewRecord(record), nil
	default:
		return nil, newConversionError(
			"invalid_json_value",
			path,
			fmt.Sprintf("unsupported json value %T", value),
		)
	}
}

func convertNumber(number string, path string) (cedar.Value, error) {
	value, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return nil, newConversionError("invalid_json_value", path, "cedar context numbers must be finite")
	}
	return convertFloat(value, path)
}

func convertFloat(value float64, path string) (cedar.Value, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return nil, newConversionError("invalid_json_value", path, "cedar context numbers must be finite")
	}
	if math.Trunc(value) == value {
		if math.Abs(value) > float64(maxSafeInteger) {
			return nil, unsafeIntegerError(path)
		}
		if value == 0 {
			return cedar.Long(0), nil
		}
		return cedar.Long(int64(value)), nil
	}

	scaled := value * 10_000
	if math.Trunc(scaled) != scaled || math.Abs(scaled) > float64(maxSafeInteger) {
		return nil, newConversionError(
			"unsupported_decimal",
			path,
			"cedar decimals must be exactly representable with at most four fractional digits within javascript safe-integer precision",
		)
	}
	decimal, err := cedar.NewDecimal(int64(scaled), -4)
	if err != nil {
		return nil, newConversionError("unsupported_decimal", path, "cedar decimal is outside the portable range")
	}
	return decimal, nil
}

func convertSigned(value int64, path string) (cedar.Value, error) {
	if value < -maxSafeInteger || value > maxSafeInteger {
		return nil, unsafeIntegerError(path)
	}
	return cedar.Long(value), nil
}

func convertUnsigned(value uint64, path string) (cedar.Value, error) {
	if value > uint64(maxSafeInteger) {
		return nil, unsafeIntegerError(path)
	}
	return cedar.Long(value), nil
}

func unsafeIntegerError(path string) error {
	return newConversionError(
		"unsafe_integer",
		path,
		"cedar long input must be exactly representable as a javascript safe integer",
	)
}

func reservedEscapeError(path string) error {
	return newConversionError(
		"reserved_cedar_escape",
		path,
		"raw tool input cannot inject cedar __entity or __extn escape objects",
	)
}

func newConversionError(code, path, message string) *ConversionError {
	return &ConversionError{Code: code, Path: path, msg: message}
}

func pointer(path, segment string) string {
	escaped := strings.ReplaceAll(segment, "~", "~0")
	escaped = strings.ReplaceAll(escaped, "/", "~1")
	return path + "/" + escaped
}
