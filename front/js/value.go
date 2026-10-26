package js

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/v0lka/flowsh/engine"
)

// Value is a frontend-local lattice value.
// Its zero value is unknown; objects are immutable snapshots.
type Value struct {
	kind      string
	text      string
	number    float64
	boolean   bool
	object    *object
	body      *node
	module    string
	export    string
	namespace bool
	settled   *Value
	Taint     engine.Taint
}

type object struct {
	fields map[string]Value
	keys   []string
	array  bool
	length int
}

func stringValue(s string) Value       { return Value{kind: "string", text: s} }
func numberValue(n float64) Value      { return Value{kind: "number", number: n} }
func boolValue(b bool) Value           { return Value{kind: "boolean", boolean: b} }
func undefined() Value                 { return Value{kind: "undefined"} }
func unknown(taint engine.Taint) Value { return Value{Taint: taint} }

// String returns a known string and its knownness.
func (v Value) String() (string, bool) { return v.text, v.kind == "string" }

// StringValue constructs an exact bounded string for trusted models.
func StringValue(s string) Value {
	if len(s) > maxValueBytes {
		return Value{}
	}
	return stringValue(s)
}

// NumberValue constructs an exact number for trusted models.
func NumberValue(n float64) Value { return numberValue(n) }

// UndefinedValue is the exact JavaScript undefined value.
func UndefinedValue() Value { return undefined() }

// ContentValue represents opaque filesystem bytes or text.
func ContentValue() Value { return Value{kind: "content"} }

// UnknownBoolean represents either true or false.
func UnknownBoolean() Value { return Value{kind: "boolean-unknown"} }

func (v Value) imprecise() bool {
	return v.kind == "" || v.kind == "content" || v.kind == "boolean-unknown"
}

// BuiltinValue identifies a module namespace or an exported function.
func BuiltinValue(module, export string) Value {
	kind := "module"
	if export != "" {
		kind = "builtin"
	}
	return Value{kind: kind, module: module, export: export}
}

// PromiseValue wraps a trusted model's fulfillment value.
func PromiseValue(value Value) Value {
	return Value{kind: "promise", settled: &value, Taint: value.Taint}
}

// Kind returns the value category.
func (v Value) Kind() string { return v.kind }

// Boolean returns an exact boolean when available.
func (v Value) Boolean() (bool, bool) { return v.boolean, v.kind == "boolean" }

// Number returns an exact number when available.
func (v Value) Number() (float64, bool) { return v.number, v.kind == "number" }

// Property reads an own field; missing fields are undefined.
func (v Value) Property(key string) (Value, bool) {
	if v.object == nil || v.object.array {
		return Value{}, false
	}
	field, ok := v.object.fields[key]
	if !ok {
		field = undefined()
	}
	field.Taint = field.Taint.Join(v.Taint)
	return field, true
}

// Keys returns a bounded copy of a plain record's own keys.
func (v Value) Keys() ([]string, bool) {
	if v.object == nil || v.object.array {
		return nil, false
	}
	return slices.Clone(v.object.keys), true
}

// Projection returns a bounded report argument.
func (v Value) Projection() string {
	if text, ok := v.String(); ok {
		if len(text) <= 4096 {
			return text
		}
		return "<string>"
	}
	if text, ok := v.primitiveString(); ok {
		return text
	}
	if v.object != nil && !v.object.array && len(v.object.keys) <= 32 {
		fields := make(map[string]any, len(v.object.keys))
		bytes := 0
		for _, key := range v.object.keys {
			field := v.object.fields[key]
			bytes += len(key) + len(field.text) + 16
			if bytes > 4096 {
				return "<object>"
			}
			switch field.kind {
			case "string":
				fields[key] = field.text
			case "boolean":
				fields[key] = field.boolean
			case "number":
				if math.IsNaN(field.number) || math.IsInf(field.number, 0) {
					fields[key] = "<number>"
				} else {
					fields[key] = field.number
				}
			case "null":
				fields[key] = nil
			default:
				fields[key] = "<" + field.kind + ">"
			}
		}
		if encoded, err := json.Marshal(fields); err == nil && len(encoded) <= 4096 {
			return string(encoded)
		}
	}
	if v.kind == "" {
		return "<unknown>"
	}
	return "<" + v.kind + ">"
}

func joinValue(a, b Value) Value {
	t := a.Taint.Join(b.Taint)
	if !sameValue(a, b) {
		return unknown(t)
	}
	a.Taint = t
	return a
}

func sameValue(a, b Value) bool {
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case "string":
		return a.text == b.text
	case "number":
		if a.number == 0 && b.number == 0 {
			return math.Signbit(a.number) == math.Signbit(b.number)
		}
		return a.number == b.number || math.IsNaN(a.number) && math.IsNaN(b.number)
	case "boolean":
		return a.boolean == b.boolean
	case "object":
		return a.object == b.object
	case "function":
		return a.body == b.body
	case "module", "builtin":
		return a.module == b.module && a.export == b.export && a.namespace == b.namespace
	case "promise":
		return a.settled == b.settled
	default:
		return true
	}
}

func (v Value) truth() (bool, bool) {
	switch v.kind {
	case "undefined", "null":
		return false, true
	case "boolean":
		return v.boolean, true
	case "number":
		return v.number != 0 && !math.IsNaN(v.number), true
	case "string":
		return v.text != "", true
	case "object", "function", "module", "builtin", "promise", "loader":
		return true, true
	default:
		return false, false
	}
}

func (v Value) primitiveString() (string, bool) {
	switch v.kind {
	case "string":
		return v.text, true
	case "number":
		if v.number == 0 {
			return "0", true
		}
		// Avoid number formats that differ between Go and JavaScript.
		if math.IsNaN(v.number) || math.IsInf(v.number, 0) || math.Abs(v.number) > 1<<53 || math.Abs(v.number) < 1e-6 {
			return "", false
		}
		return strconv.FormatFloat(v.number, 'f', -1, 64), true
	case "boolean":
		return strconv.FormatBool(v.boolean), true
	case "null":
		return "null", true
	case "undefined":
		return "undefined", true
	default:
		return "", false
	}
}

type binding struct {
	value                 Value
	constant, initialized bool
}
type state struct {
	scopes   []map[string]binding
	poisoned bool
}

func newState() *state { return &state{scopes: []map[string]binding{{}}} }

func (s *state) lookup(name string) (binding, int) {
	for i, scope := range slices.Backward(s.scopes) {
		if v, ok := scope[name]; ok {
			return v, i
		}
	}
	return binding{}, -1
}

func (e *evaluator) joinStates(a, b *state) *state {
	if a == nil {
		return e.clone(b)
	}
	out := e.clone(a)
	out.poisoned = a.poisoned || b.poisoned
	for i, scope := range out.scopes {
		for name, av := range scope {
			e.step()
			bv, ok := b.scopes[i][name]
			if !ok {
				av.value = unknown(av.value.Taint)
				av.initialized = false
			} else {
				av.value = joinValue(av.value, bv.value)
				av.initialized = av.initialized && bv.initialized
			}
			scope[name] = av
		}
		for name, bv := range b.scopes[i] {
			e.step()
			if _, ok := scope[name]; !ok {
				bv.value = unknown(bv.value.Taint)
				bv.initialized = false
				scope[name] = bv
			}
		}
	}
	return out
}

func (e *evaluator) havoc(s *state) {
	s.poisoned = true
	for _, scope := range s.scopes {
		for name, v := range scope {
			e.step()
			if !v.constant || v.value.kind == "object" || v.value.kind == "module" || v.value.kind == "builtin" || v.value.kind == "loader" {
				v.value = unknown(v.value.Taint)
				scope[name] = v
			}
		}
	}
}

func parseNumber(text string) Value {
	if strings.HasSuffix(text, "n") {
		return Value{}
	}
	if len(text) > 2 && text[0] == '0' && strings.ContainsAny(text[1:2], "xXoObB") {
		n, err := strconv.ParseUint(text, 0, 64)
		if err == nil && n <= 1<<53 {
			return numberValue(float64(n))
		}
		return Value{}
	}
	if len(text) > 1 && text[0] == '0' && text[1] >= '0' && text[1] <= '9' {
		return Value{}
	}
	n, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return Value{}
	}
	return numberValue(n)
}
