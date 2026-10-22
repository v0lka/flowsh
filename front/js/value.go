package js

import (
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/v0lka/flowsh/engine"
)

// Value is a frontend-local lattice value.
// Its zero value is unknown; objects are immutable snapshots.
type Value struct {
	kind    string
	text    string
	number  float64
	boolean bool
	object  *object
	body    *node
	Taint   engine.Taint
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
	case "object", "function":
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
type state struct{ scopes []map[string]binding }

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
	for _, scope := range s.scopes {
		for name, v := range scope {
			e.step()
			if !v.constant || v.value.kind == "object" {
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
