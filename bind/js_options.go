package bind

import (
	"math"
	"slices"
	"strconv"

	"github.com/v0lka/flowsh/front/js"
	"github.com/v0lka/flowsh/kb"
)

func jsOptionsValid(value js.Value, model *kb.JSCall) bool {
	if value.Kind() == "undefined" || value.Kind() == "null" {
		return true
	}
	if text, ok := value.String(); ok {
		if model.OptionShape == "encoding" {
			return true
		}
		_, valid := jsOctalMode(text)
		return model.OptionShape == "mode" && valid
	}
	if number, ok := value.Number(); ok {
		if model.OptionShape == "number" {
			return number >= 0 && number <= 7 && math.Trunc(number) == number
		}
		return model.OptionShape == "mode" && number >= 0 && number <= 0777 && math.Trunc(number) == number
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
			number, known := field.Number()
			if text, ok := field.String(); ok {
				number, known = jsOctalMode(text)
			}
			if !known || number < 0 || number > 0777 || math.Trunc(number) != number {
				return false
			}
		default:
			number, known := field.Number()
			if !known || number < 0 || number > 1<<53 || math.Trunc(number) != number {
				return false
			}
		}
	}
	return true
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
	// Numeric access modes follow the POSIX model.
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
