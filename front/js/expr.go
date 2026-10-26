package js

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/v0lka/flowsh/engine"
)

func (e *evaluator) eval(n *node, s *state) Value {
	e.step()
	if n == nil {
		return undefined()
	}
	e.depth++
	defer func() { e.depth-- }()
	if e.depth > maxDepth {
		panic(budgetExhausted{})
	}
	switch n.kind {
	case "number":
		e.charge(len(n.text))
		value := parseNumber(n.text)
		if value.kind == "" {
			e.degrade(n, "unsupported JavaScript numeric literal")
		}
		return value
	case "string":
		e.charge(len(n.text))
		if text, ok := decodeString(n.text); ok {
			return stringValue(text)
		}
		e.degrade(n, "unsupported JavaScript string literal")
		return Value{}
	case "true":
		return boolValue(true)
	case "false":
		return boolValue(false)
	case "null":
		return Value{kind: "null"}
	case "undefined", "identifier", "shorthand_property_identifier":
		v, i := s.lookup(n.text)
		if i < 0 {
			if n.text == "undefined" {
				return undefined()
			}
			if n.text == "require" && !s.poisoned && e.resolver != nil {
				e.possibleThrow(s)
				return Value{kind: "loader"}
			}
			e.possibleThrow(s)
			return Value{}
		}
		if !v.initialized {
			e.degrade(n, "JavaScript binding read before initialization")
			e.possibleThrow(s)
			return unknown(v.value.Taint)
		}
		return v.value
	case "parenthesized_expression":
		return e.eval(n.first(), s)
	case "sequence_expression":
		v := undefined()
		for _, c := range n.namedChildren() {
			v = e.eval(c, s)
		}
		return v
	case "template_string":
		value := stringValue("")
		for _, c := range n.namedChildren() {
			var part Value
			switch c.kind {
			case "template_substitution":
				part = e.eval(c.first(), s)
			case "string_fragment":
				e.charge(len(c.text))
				part = stringValue(strings.ReplaceAll(strings.ReplaceAll(c.text, "\r\n", "\n"), "\r", "\n"))
			case "escape_sequence":
				text, ok := decodeString("\"" + c.text + "\"")
				if ok {
					part = stringValue(text)
				}
			default:
				e.degrade(c, "unsupported JavaScript template component")
			}
			switch part.kind {
			case "", "object", "function", "module", "builtin", "promise", "loader":
				e.unmodelled(c, s, "JavaScript object-to-string conversion is unmodelled")
			}
			text, ok := part.primitiveString()
			taint := value.Taint.Join(part.Taint)
			if !ok || value.kind == "" || len(value.text)+len(text) > maxValueBytes {
				value = unknown(taint)
			} else {
				e.charge(len(value.text) + len(text))
				value = stringValue(value.text + text)
				value.Taint = taint
			}
		}
		return value
	case "object", "array":
		return e.container(n, s)
	case "member_expression", "subscript_expression":
		base := e.eval(n.get("object"), s)
		keyNode := n.get("property")
		if keyNode == nil {
			keyNode = n.get("index")
		}
		key, known := e.propertyKey(keyNode, s)
		if !known {
			return unknown(base.Taint)
		}
		return e.readProperty(n, s, base, key)
	case "assignment_expression", "augmented_assignment_expression":
		left := n.get("left")
		if left != nil && left.kind == "identifier" {
			var old Value
			if n.kind == "augmented_assignment_expression" {
				old = e.eval(left, s)
			}
			value := e.eval(n.get("right"), s)
			if n.kind == "augmented_assignment_expression" {
				value = e.binary(strings.TrimSuffix(n.operator(), "="), old, value, n, s)
			}
			e.bindPattern(left, value, s, "")
			return value
		}
		// Evaluate receiver/key before the RHS; writes may invoke setters.
		if left != nil && (left.kind == "member_expression" || left.kind == "subscript_expression") {
			e.eval(left.get("object"), s)
			if key := left.get("index"); key != nil {
				e.eval(key, s)
			}
		}
		value := e.eval(n.get("right"), s)
		e.bindPattern(left, value, s, "")
		return value
	case "update_expression":
		arg := n.get("argument")
		old := e.eval(arg, s)
		value := unknown(old.Taint)
		switch old.kind {
		case "number":
			delta := 1.0
			if n.operator() == "--" {
				delta = -1
			}
			value = numberValue(old.number + delta)
			value.Taint = old.Taint
		case "", "object", "function":
			e.unmodelled(n, s, "JavaScript update coercion is unmodelled")
		default:
			e.degrade(n, "JavaScript update coercion is unmodelled")
		}
		e.bindPattern(arg, value, s, "")
		if strings.HasPrefix(strings.TrimSpace(n.text), n.operator()) {
			return value
		}
		if old.kind != "number" {
			return unknown(old.Taint)
		}
		return old
	case "binary_expression":
		left := e.eval(n.get("left"), s)
		if op := n.operator(); op == "&&" || op == "||" || op == "??" {
			return e.logical(n, s, left, op)
		}
		right := e.eval(n.get("right"), s)
		return e.binary(n.operator(), left, right, n, s)
	case "ternary_expression":
		condition := e.eval(n.get("condition"), s)
		if b, ok := condition.truth(); ok {
			if b {
				return e.eval(n.get("consequence"), s)
			}
			return e.eval(n.get("alternative"), s)
		}
		other := e.clone(s)
		a := e.eval(n.get("consequence"), s)
		b := e.eval(n.get("alternative"), other)
		*s = *e.joinStates(s, other)
		return joinValue(a, b)
	case "unary_expression":
		op := n.operator()
		argument := n.get("argument")
		value := e.eval(argument, s)
		switch op {
		case "void":
			return undefined()
		case "!":
			if b, ok := value.truth(); ok {
				v := boolValue(!b)
				v.Taint = value.Taint
				return v
			}
		case "typeof":
			if value.kind == "content" || value.kind == "loader" {
				return unknown(value.Taint)
			}
			if value.kind != "" {
				kind := value.kind
				if kind == "boolean-unknown" {
					kind = "boolean"
				}
				if kind == "module" || kind == "promise" {
					kind = "object"
				}
				if kind == "builtin" {
					kind = "function"
				}
				if kind == "null" {
					kind = "object"
				}
				v := stringValue(kind)
				v.Taint = value.Taint
				return v
			}
		case "+", "-", "~":
			if value.kind == "number" {
				number := value.number
				if op == "-" {
					number = -number
				}
				if op == "~" {
					number = float64(^toInt32(number))
				}
				v := numberValue(number)
				v.Taint = value.Taint
				return v
			}
			if value.kind == "object" || value.kind == "function" || value.kind == "" {
				e.unmodelled(n, s, "JavaScript object coercion is unmodelled")
			} else {
				e.degrade(n, "JavaScript primitive coercion is unmodelled")
			}
		default:
			e.unmodelled(n, s, "unsupported JavaScript unary operation")
		}
		return unknown(value.Taint)
	case "await_expression":
		value := e.eval(n.first(), s)
		if value.kind == "promise" && value.settled != nil {
			e.possibleThrow(s)
			return *value.settled
		}
		if value.kind == "" || value.kind == "object" || value.kind == "function" {
			e.unmodelled(n, s, "JavaScript await of an unknown thenable")
			return unknown(value.Taint)
		}
		return value
	case "arrow_function", "function_expression":
		return Value{kind: "function", body: n.get("body")}
	case "call_expression", "new_expression":
		return e.call(n, s)
	default:
		e.unmodelled(n, s, "unsupported JavaScript expression: "+n.kind)
		return Value{}
	}
}

func (e *evaluator) propertyKey(n *node, s *state) (string, bool) {
	if n == nil {
		return "", false
	}
	if n.kind == "property_identifier" || n.kind == "shorthand_property_identifier_pattern" {
		return n.text, true
	}
	if n.kind == "computed_property_name" {
		e.eval(n.first(), s)
		e.unmodelled(n, s, "computed JavaScript property keys are unsupported")
		return "", false
	}
	if n.kind != "string" && n.kind != "number" {
		e.eval(n, s)
		e.unmodelled(n, s, "computed JavaScript property keys are unsupported")
		return "", false
	}
	value := e.eval(n, s)
	text, known := value.primitiveString()
	if !known {
		e.unmodelled(n, s, "JavaScript property key is unknown")
	}
	return text, known
}

func (e *evaluator) readProperty(n *node, s *state, v Value, key string) Value {
	if v.kind == "module" && !s.poisoned && e.resolver != nil {
		r := e.resolver(Call{Kind: "property", Module: v.module, Export: key, Loc: e.location(n)})
		if r.Handled {
			return r.Value
		}
	}
	if v.object == nil {
		e.unmodelled(n, s, "JavaScript property access on an unknown or unsupported receiver")
		return unknown(v.Taint)
	}
	if v.object.array && key == "length" {
		value := numberValue(float64(v.object.length))
		value.Taint = v.Taint
		return value
	}
	if field, ok := v.object.fields[key]; ok {
		field.Taint = field.Taint.Join(v.Taint)
		return field
	}
	e.unmodelled(n, s, "JavaScript inherited property access is unmodelled")
	return unknown(v.Taint)
}

func (e *evaluator) container(n *node, s *state) Value {
	obj := &object{fields: map[string]Value{}, array: n.kind == "array"}
	result := Value{kind: "object", object: obj}
	index := 0
	valid := true
	put := func(key string, value Value) {
		e.step()
		if len(obj.keys) >= maxRecorded {
			panic(budgetExhausted{})
		}
		if _, exists := obj.fields[key]; !exists {
			obj.keys = append(obj.keys, key)
		}
		obj.fields[key] = value
		result.Taint = result.Taint.Join(value.Taint)
	}
	for _, c := range n.children {
		if obj.array && c.kind == "," {
			index++
			continue
		}
		if !c.named || c.kind == "comment" {
			continue
		}
		if obj.array {
			if c.kind == "spread_element" {
				e.eval(c.first(), s)
				valid = false
				e.unmodelled(c, s, "JavaScript spread iteration is unsupported")
			} else {
				put(strconv.Itoa(index), e.eval(c, s))
			}
			obj.length = index + 1
			continue
		}
		switch c.kind {
		case "pair":
			key, known := e.propertyKey(c.get("key"), s)
			value := e.eval(c.get("value"), s)
			if !known {
				valid = false
			} else if key == "__proto__" {
				valid = false
				e.degrade(c, "JavaScript prototype object is unsupported")
			} else {
				put(key, value)
			}
		case "shorthand_property_identifier":
			put(c.text, e.eval(c, s))
		default:
			if c.kind == "spread_element" {
				e.eval(c.first(), s)
			}
			valid = false
			e.unmodelled(c, s, "JavaScript methods, accessors, and object spread are unsupported")
		}
	}
	if obj.array {
		// Elision commas add holes; trailing commas do not.
		if index > obj.length {
			obj.length = index
		}
	}
	if !valid {
		return unknown(result.Taint)
	}
	return result
}

func (e *evaluator) call(n *node, s *state) Value {
	callee := n.get("function")
	if callee == nil {
		callee = n.get("constructor")
	}
	value := e.eval(callee, s)
	call := Call{Loc: e.location(n), Charge: e.charge}
	if value.kind == "builtin" && !s.poisoned {
		call.Module, call.Export = value.module, value.export
	}
	if callee != nil {
		e.charge(len(callee.text))
		call.Callee = callee.text
	}
	taint := value.Taint
	if args := n.get("arguments"); args != nil {
		for _, arg := range args.namedChildren() {
			if len(call.Args) >= maxRecorded {
				panic(budgetExhausted{})
			}
			v := e.eval(arg, s)
			call.Args = append(call.Args, v)
			call.ArgLocs = append(call.ArgLocs, e.location(arg))
			e.charge(modelWork(v))
			taint = taint.Join(v.Taint)
		}
	}
	if value.kind == "loader" && !s.poisoned && n.kind == "call_expression" && len(call.Args) == 1 {
		if module, ok := call.Args[0].String(); ok {
			r := e.resolver(Call{Kind: "module", Module: module, Loc: call.Loc})
			if r.Handled && r.Value.kind == "module" {
				return r.Value
			}
		}
	}
	if value.kind != "function" && n.kind == "call_expression" && e.resolver != nil {
		r := e.resolver(call)
		if r.Handled {
			for _, eff := range r.Effects {
				e.step()
				if eff.Validate() != nil {
					e.degrade(n, "invalid JavaScript resolver effect")
					e.havoc(s)
					return unknown(engine.TaintTop())
				}
				if len(e.result.Effects) >= maxRecorded {
					panic(budgetExhausted{})
				}
				e.result.Effects = append(e.result.Effects, eff)
				if eff.Kind == engine.KindCodeExec && eff.Target.IsTop() {
					e.degrade(n, "JavaScript resolver reported unknown execution")
				}
			}
			for _, d := range r.Derivations {
				e.step()
				if len(e.result.Derivations) >= maxRecorded {
					panic(budgetExhausted{})
				}
				e.result.Derivations = append(e.result.Derivations, d)
			}
			if r.MayThrow {
				e.possibleThrow(s)
			}
			if r.Reason != "" {
				e.unmodelled(n, s, r.Reason)
			}
			return r.Value
		}
	}
	reason := "JavaScript call effects are unmodelled"
	if value.kind == "function" {
		reason = "JavaScript function invocation is deferred to the function-abstraction layer"
	}
	e.unmodelled(n, s, reason)
	return unknown(taint.Join(engine.TaintTop()))
}

func (e *evaluator) logical(n *node, s *state, left Value, op string) Value {
	take, known := left.truth()
	if op == "||" {
		take = !take
	}
	if op == "??" {
		take = left.kind == "null" || left.kind == "undefined"
		known = left.kind != ""
	}
	if known {
		if take {
			return e.eval(n.get("right"), s)
		}
		return left
	}
	other := e.clone(s)
	right := e.eval(n.get("right"), other)
	*s = *e.joinStates(s, other)
	return joinValue(left, right)
}

func (e *evaluator) binary(op string, a, b Value, n *node, s *state) Value {
	taint := a.Taint.Join(b.Taint)
	result := Value{}
	if a.imprecise() || b.imprecise() {
		if op != "===" && op != "!==" {
			e.unmodelled(n, s, "JavaScript coercion of an unknown value is unmodelled")
		}
		return unknown(taint)
	}
	if op == "===" || op == "!==" {
		if a.kind == "function" || b.kind == "function" {
			return unknown(taint)
		}
		equal := strictEqual(a, b)
		if op == "!==" {
			equal = !equal
		}
		result = boolValue(equal)
	} else if a.kind == "object" || b.kind == "object" || a.kind == "function" || b.kind == "function" {
		e.unmodelled(n, s, "JavaScript coercion or object operation is unmodelled")
	} else if op == "+" && (a.kind == "string" || b.kind == "string") {
		left, lk := a.primitiveString()
		right, rk := b.primitiveString()
		if lk && rk && len(left)+len(right) <= maxValueBytes {
			e.charge(len(left) + len(right))
			result = stringValue(left + right)
		}
	} else if a.kind == "number" && b.kind == "number" {
		switch op {
		case "+":
			result = numberValue(a.number + b.number)
		case "-":
			result = numberValue(a.number - b.number)
		case "*":
			result = numberValue(a.number * b.number)
		case "/":
			result = numberValue(a.number / b.number)
		case "%":
			result = numberValue(math.Mod(a.number, b.number))
		case "**":
			result = numberValue(math.Pow(a.number, b.number))
			if math.IsNaN(b.number) || math.Abs(a.number) == 1 && math.IsInf(b.number, 0) {
				result = numberValue(math.NaN())
			}
		case "<":
			result = boolValue(a.number < b.number)
		case "<=":
			result = boolValue(a.number <= b.number)
		case ">":
			result = boolValue(a.number > b.number)
		case ">=":
			result = boolValue(a.number >= b.number)
		case "==":
			result = boolValue(a.number == b.number)
		case "!=":
			result = boolValue(a.number != b.number)
		case "&":
			result = numberValue(float64(toInt32(a.number) & toInt32(b.number)))
		case "|":
			result = numberValue(float64(toInt32(a.number) | toInt32(b.number)))
		case "^":
			result = numberValue(float64(toInt32(a.number) ^ toInt32(b.number)))
		}
	} else if op == "==" || op == "!=" {
		if a.kind == b.kind || (a.kind == "null" && b.kind == "undefined") || (a.kind == "undefined" && b.kind == "null") {
			equal := strictEqual(a, b) || (a.kind != b.kind)
			if op == "!=" {
				equal = !equal
			}
			result = boolValue(equal)
		}
	}
	if result.kind == "" {
		e.unmodelled(n, s, "unsupported JavaScript binary operation or coercion")
	}
	result.Taint = taint
	return result
}

func toInt32(n float64) int32 {
	if math.IsNaN(n) || math.IsInf(n, 0) || n == 0 {
		return 0
	}
	n = math.Mod(math.Trunc(n), 4294967296)
	if n < 0 {
		n += 4294967296
	}
	return int32(uint32(n))
}

func decodeString(raw string) (string, bool) {
	if len(raw) < 2 || len(raw) > maxValueBytes+2 {
		return "", false
	}
	var out strings.Builder
	for i := 1; i < len(raw)-1; i++ {
		c := raw[i]
		if c != '\\' {
			out.WriteByte(c)
			continue
		}
		i++
		if i >= len(raw)-1 {
			return "", false
		}
		if strings.HasPrefix(raw[i:], " ") || strings.HasPrefix(raw[i:], " ") {
			i += len(" ") - 1
			continue
		}
		switch c = raw[i]; c {
		case '\n':
			continue
		case '\r':
			if i+1 < len(raw)-1 && raw[i+1] == '\n' {
				i++
			}
			continue
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'b':
			out.WriteByte('\b')
		case 'f':
			out.WriteByte('\f')
		case 'v':
			out.WriteByte('\v')
		case '0':
			if i+1 < len(raw)-1 && raw[i+1] >= '0' && raw[i+1] <= '9' {
				return "", false
			}
			out.WriteByte(0)
		case 'x', 'u':
			count := 2
			if c == 'u' {
				count = 4
			}
			start := i + 1
			if c == 'u' && start < len(raw)-1 && raw[start] == '{' {
				end := strings.IndexByte(raw[start+1:], '}')
				if end < 0 {
					return "", false
				}
				start++
				count = end
				i = start + count
			} else {
				i += count
			}
			if count < 1 || count > 6 || start+count > len(raw)-1 {
				return "", false
			}
			number, err := strconv.ParseUint(raw[start:start+count], 16, 32)
			if err != nil {
				return "", false
			}
			r := rune(number)
			if utf16.IsSurrogate(r) {
				return "", false
			}
			if !utf8.ValidRune(r) {
				return "", false
			}
			out.WriteRune(r)
		default:
			if c >= '1' && c <= '9' {
				return "", false
			}
			out.WriteByte(c)
		}
	}
	return out.String(), true
}
