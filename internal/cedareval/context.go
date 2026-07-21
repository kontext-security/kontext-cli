package cedareval

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
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
	// Request-contract v1 gives JSON numbers their interoperable binary64
	// meaning, matching JSON.parse in the TypeScript contract runtime. The
	// lexical spellings 1e-4 and 0.00010000000000000001 therefore both denote
	// the same binary64 value before Cedar's decimal range is checked.
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
		return cedar.Long(int64(value)), nil
	}

	// Match ECMAScript Number.prototype.toFixed(4) exactly before applying the
	// same round-trip check as the TypeScript contract runtime. Go's 'f'
	// formatter uses round-to-even while ECMAScript selects the larger integer
	// on a tie, so using FormatFloat here would diverge for some large doubles.
	fixed, scaled, ok := ecmaFixed4(value)
	if !ok {
		return nil, newConversionError(
			"unsupported_decimal",
			path,
			"cedar decimals must lie within -922337203685477.5808..922337203685477.5807",
		)
	}
	round, err := strconv.ParseFloat(fixed, 64)
	if err != nil || round != value {
		return nil, newConversionError(
			"unsupported_decimal",
			path,
			"cedar decimals must be exactly representable with at most four fractional digits",
		)
	}
	decimal, err := cedar.NewDecimal(scaled, -4)
	if err != nil {
		return nil, newConversionError("unsupported_decimal", path, "cedar decimal is outside the portable range")
	}
	return decimal, nil
}

func ecmaFixed4(value float64) (string, int64, bool) {
	absolute := new(big.Rat).SetFloat64(math.Abs(value))
	absolute.Mul(absolute, big.NewRat(10_000, 1))

	scaled := new(big.Int)
	remainder := new(big.Int)
	scaled.QuoRem(absolute.Num(), absolute.Denom(), remainder)
	twiceRemainder := new(big.Int).Lsh(new(big.Int).Set(remainder), 1)
	if twiceRemainder.Cmp(absolute.Denom()) >= 0 {
		scaled.Add(scaled, big.NewInt(1))
	}
	if math.Signbit(value) {
		scaled.Neg(scaled)
	}
	if !scaled.IsInt64() {
		return "", 0, false
	}

	digits := new(big.Int).Abs(new(big.Int).Set(scaled)).String()
	if len(digits) < 5 {
		digits = strings.Repeat("0", 5-len(digits)) + digits
	}
	separator := len(digits) - 4
	fixed := digits[:separator] + "." + digits[separator:]
	if scaled.Sign() < 0 {
		fixed = "-" + fixed
	}
	return fixed, scaled.Int64(), true
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
