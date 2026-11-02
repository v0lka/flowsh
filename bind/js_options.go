package bind

import (
	"math"
	"slices"
	"strconv"

	"github.com/v0lka/flowsh/front/js"
	"github.com/v0lka/flowsh/kb"
)

// jsOptionsValid reports whether value fits model's option shape.
func jsOptionsValid(value js.Value, model *kb.JSCall) bool {
	if value.Kind() == "undefined" || value.Kind() == "null" {
		return true
	}
	if _, ok := value.String(); ok {
		return model.OptionShape == "encoding" || model.OptionShape == "mode" && jsModeValid(value)
	}
	if number, ok := value.Number(); ok {
		if model.OptionShape == "number" {
			return jsUint(number, 7)
		}
		return model.OptionShape == "mode" && jsUint(number, 0o777)
	}
	keys, ok := value.Keys()
	if !ok || model.OptionShape == "number" {
		return false
	}
	for _, key := range keys {
		if !slices.Contains(model.OptionKeys, key) {
			return false
		}
		field, _ := value.Property(key)
		if field.Kind() == "undefined" {
			continue
		}
		switch key {
		case "fd", "fs", "signal":
			if field.Kind() != "null" {
				return false
			}
		case "recursive", "force", "bigint", "throwIfNoEntry", "flush", "autoClose", "emitClose":
			if _, known := field.Boolean(); !known {
				return false
			}
		case "encoding":
			if field.Kind() != "string" && field.Kind() != "null" {
				return false
			}
		case "flag", "flags":
			if _, _, known := jsOpenFlags(field); !known {
				return false
			}
		case "mode":
			if !jsModeValid(field) {
				return false
			}
		default:
			number, known := field.Number()
			if !known || !jsUint(number, 1<<53) {
				return false
			}
		}
	}
	return true
}

// jsModeValid reports whether value is a mode in 0..0o777,
// given as a number or an octal string.
func jsModeValid(value js.Value) bool {
	mode, known := value.Number()
	if text, ok := value.String(); ok {
		mode, known = jsOctalMode(text)
	}
	return known && jsUint(mode, 0o777)
}

// jsUint reports whether n is an integer in 0..limit.
func jsUint(n, limit float64) bool {
	return n >= 0 && n <= limit && math.Trunc(n) == n
}

func jsOctalMode(text string) (float64, bool) {
	number, err := strconv.ParseUint(text, 8, 32)
	return float64(number), err == nil
}

func jsOpenFlags(value js.Value) (read, write, known bool) {
	if text, ok := value.String(); ok {
		switch text {
		case "r", "rs", "sr":
			return true, false, true
		case "w", "wx", "xw", "a", "ax", "xa", "as", "sa":
			return false, true, true
		case "r+", "rs+", "sr+", "w+", "wx+", "xw+", "a+", "ax+", "xa+", "as+", "sa+":
			return true, true, true
		default:
			return true, true, false
		}
	}
	// Numeric access modes: O_RDONLY, O_WRONLY, O_RDWR.
	if number, ok := value.Number(); ok {
		switch number {
		case 0:
			return true, false, true
		case 1:
			return false, true, true
		case 2:
			return true, true, true
		}
	}
	return true, true, false
}
