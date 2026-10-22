package js

import (
	"slices"
	"sort"
	"strconv"
)

type completion int

const (
	normal completion = iota
	breaking
	continuing
	returning
	throwing
	completionCount
)

type flow struct {
	state *state
	value Value
}
type flows [completionCount]*flow
type budgetExhausted struct{}

type evaluator struct {
	result        *Result
	name          string
	resolver      Resolver
	budget, depth int
	hasTop        bool
	throws        *state
}

func (e *evaluator) step() {
	e.charge(1)
}

func (e *evaluator) charge(work int) {
	e.budget -= work
	if e.budget < 0 {
		panic(budgetExhausted{})
	}
}

func (e *evaluator) clone(s *state) *state {
	out := &state{scopes: make([]map[string]binding, len(s.scopes))}
	for i, scope := range s.scopes {
		e.step()
		out.scopes[i] = make(map[string]binding, len(scope))
		for name, value := range scope {
			e.step()
			out.scopes[i][name] = value
		}
	}
	return out
}

func single(k completion, s *state, v Value) flows { var out flows; out[k] = &flow{s, v}; return out }

func (e *evaluator) merge(out *flows, k completion, f *flow) {
	if f == nil || f.state == nil {
		return
	}
	if out[k] == nil {
		out[k] = &flow{e.clone(f.state), f.value}
		return
	}
	out[k].state = e.joinStates(out[k].state, f.state)
	out[k].value = joinValue(out[k].value, f.value)
}

func (e *evaluator) mergeAll(out *flows, other flows) {
	for k, f := range other {
		e.merge(out, completion(k), f)
	}
}

func (e *evaluator) possibleThrow(s *state) {
	e.throws = e.joinStates(e.throws, s)
}

// unmodelled degrades and invalidates state, keeping the throw path.
func (e *evaluator) unmodelled(n *node, s *state, reason string) {
	e.degrade(n, reason)
	e.havoc(s)
	e.possibleThrow(s)
}

// popScope drops the innermost lexical scope from every flow.
func popScope(out flows) {
	for _, f := range out {
		if f != nil {
			f.state.scopes = f.state.scopes[:len(f.state.scopes)-1]
		}
	}
}

func (e *evaluator) exec(n *node, s *state) flows {
	e.step()
	if n == nil {
		return single(normal, s, undefined())
	}
	saved := e.throws
	depth := len(s.scopes)
	e.throws = nil
	out := e.statement(n, s)
	if e.throws != nil && len(e.throws.scopes) > depth {
		e.throws.scopes = e.throws.scopes[:depth]
	}
	e.merge(&out, throwing, &flow{e.throws, Value{}})
	e.throws = saved
	return out
}

func (e *evaluator) sequence(nodes []*node, s *state) flows {
	out := single(normal, s, undefined())
	for _, n := range nodes {
		if out[normal] == nil {
			break
		}
		next := e.exec(n, out[normal].state)
		out[normal] = nil
		e.mergeAll(&out, next)
	}
	return out
}

func (e *evaluator) statement(n *node, s *state) flows {
	switch n.kind {
	case "program":
		e.hoistVars(n, s)
		e.predeclare(n.namedChildren(), s)
		out := e.sequence(n.namedChildren(), s)
		if out[breaking] != nil || out[continuing] != nil || out[returning] != nil {
			e.degrade(n, "invalid JavaScript control completion at module scope")
		}
		return out
	case "statement_block":
		s.scopes = append(s.scopes, map[string]binding{})
		e.predeclare(n.namedChildren(), s)
		out := e.sequence(n.namedChildren(), s)
		popScope(out)
		return out
	case "comment", "hash_bang_line", "empty_statement", "function_declaration":
		return single(normal, s, undefined())
	case "lexical_declaration", "variable_declaration":
		kind := declarationKind(n)
		for _, decl := range n.namedChildren() {
			if decl.kind != "variable_declarator" {
				continue
			}
			value := undefined()
			if rhs := decl.get("value"); rhs != nil {
				value = e.eval(rhs, s)
			} else if kind == "var" {
				continue
			}
			e.bindPattern(decl.get("name"), value, s, kind)
		}
	case "expression_statement":
		e.eval(n.first(), s)
	case "if_statement":
		value := e.eval(n.get("condition"), s)
		b, known := value.truth()
		if known {
			if b {
				return e.exec(n.get("consequence"), s)
			}
			return e.exec(n.get("alternative"), s)
		}
		out := e.exec(n.get("consequence"), e.clone(s))
		e.mergeAll(&out, e.exec(n.get("alternative"), e.clone(s)))
		return out
	case "else_clause":
		return e.exec(n.first(), s)
	case "for_statement", "for_in_statement", "while_statement", "do_statement":
		return e.loop(n, s)
	case "switch_statement":
		return e.switchStmt(n, s)
	case "try_statement":
		return e.tryStmt(n, s)
	case "break_statement":
		if len(n.namedChildren()) > 0 {
			e.degrade(n, "labelled break is unsupported")
		}
		return single(breaking, s, undefined())
	case "continue_statement":
		if len(n.namedChildren()) > 0 {
			e.degrade(n, "labelled continue is unsupported")
		}
		return single(continuing, s, undefined())
	case "return_statement":
		return single(returning, s, e.eval(n.first(), s))
	case "throw_statement":
		return single(throwing, s, e.eval(n.first(), s))
	case "export_statement":
		if decl := n.get("declaration"); decl != nil {
			return e.exec(decl, s)
		}
		if value := n.get("value"); value != nil {
			e.eval(value, s)
		}
		if n.get("source") != nil {
			e.unmodelled(n, s, "external JavaScript module initialization is unmodelled")
		}
	case "import_statement":
		e.unmodelled(n, s, "JavaScript module initialization is unmodelled")
	case "class_declaration":
		e.unmodelled(n, s, "unsupported JavaScript statement: "+n.kind)
		e.bindName(n.get("name"), Value{}, s, "let")
	case "labeled_statement":
		// A label on an empty statement changes no control target.
		body := n.get("body")
		if body != nil && body.kind == "empty_statement" {
			return e.exec(body, s)
		}
		e.degrade(n, "JavaScript labels are unsupported")
		e.havoc(s)
	default:
		e.unmodelled(n, s, "unsupported JavaScript statement: "+n.kind)
	}
	return single(normal, s, undefined())
}

func declarationKind(n *node) string {
	if n.kind == "variable_declaration" {
		return "var"
	}
	for _, c := range n.children {
		if c.text == "let" || c.text == "const" {
			return c.text
		}
	}
	return "let"
}

func (e *evaluator) patternNames(n *node, visit func(string)) {
	if n == nil {
		return
	}
	e.step()
	switch n.kind {
	case "identifier", "shorthand_property_identifier_pattern":
		visit(n.text)
	case "pair_pattern":
		e.patternNames(n.get("value"), visit)
	case "assignment_pattern", "object_assignment_pattern":
		e.patternNames(n.get("left"), visit)
	case "object_pattern", "array_pattern", "rest_pattern":
		for _, c := range n.namedChildren() {
			e.patternNames(c, visit)
		}
	}
}

func (e *evaluator) hoistVars(n *node, s *state) {
	e.step()
	switch n.kind {
	case "function_declaration", "function_expression", "arrow_function",
		"generator_function_declaration", "generator_function",
		"method_definition", "class_declaration", "class":
		return
	}
	if n.kind == "variable_declaration" {
		for _, d := range n.namedChildren() {
			e.patternNames(d.get("name"), func(name string) {
				if _, ok := s.scopes[0][name]; !ok {
					s.scopes[0][name] = binding{value: undefined(), initialized: true}
				}
			})
		}
	}
	for _, c := range n.namedChildren() {
		e.hoistVars(c, s)
	}
}

func (e *evaluator) predeclare(nodes []*node, s *state) {
	for _, n := range nodes {
		e.step()
		if n.kind == "export_statement" && n.get("declaration") != nil {
			n = n.get("declaration")
		}
		switch n.kind {
		case "lexical_declaration":
			for _, d := range n.namedChildren() {
				e.predeclarePattern(d.get("name"), s, declarationKind(n) == "const")
			}
		case "class_declaration":
			if name := n.get("name"); name != nil {
				e.predeclarePattern(name, s, false)
			}
		case "import_statement":
			e.predeclareImport(n, s)
		case "function_declaration", "generator_function_declaration":
			if name := n.get("name"); name != nil {
				scope := s.scopes[len(s.scopes)-1]
				scope[name.text] = binding{value: Value{kind: "function", body: n.get("body")}, initialized: true}
			}
		}
	}
}

func (e *evaluator) predeclareImport(n *node, s *state) {
	e.step()
	switch n.kind {
	case "identifier":
		s.scopes[len(s.scopes)-1][n.text] = binding{
			value: Value{}, constant: true, initialized: true,
		}
	case "import_specifier":
		name := n.get("alias")
		if name == nil {
			name = n.get("name")
		}
		if name != nil {
			e.predeclareImport(name, s)
		}
	case "import_statement", "import_clause", "named_imports", "namespace_import":
		for _, child := range n.namedChildren() {
			e.predeclareImport(child, s)
		}
	}
}

func (e *evaluator) predeclarePattern(n *node, s *state, constant bool) {
	scope := s.scopes[len(s.scopes)-1]
	e.patternNames(n, func(name string) {
		if _, exists := scope[name]; exists {
			e.degrade(n, "duplicate JavaScript lexical declaration")
		}
		scope[name] = binding{constant: constant}
	})
}

func (e *evaluator) bindName(n *node, v Value, s *state, kind string) {
	e.step()
	if kind != "" {
		i := len(s.scopes) - 1
		if kind == "var" {
			// Hoisting creates the var binding; initialization resolves the
			// active name, which a catch parameter can shadow.
			_, i = s.lookup(n.text)
			if i < 0 {
				i = 0
			}
		}
		old, exists := s.scopes[i][n.text]
		if exists && old.initialized && old.constant {
			e.degrade(n, "assignment to a JavaScript constant")
			e.possibleThrow(s)
			return
		}
		s.scopes[i][n.text] = binding{value: v, constant: kind == "const", initialized: true}
		return
	}
	old, i := s.lookup(n.text)
	exists := i >= 0
	if i < 0 {
		e.degrade(n, "assignment to an unresolved JavaScript binding")
		i = 0
	}
	if exists && (old.constant || !old.initialized) {
		e.degrade(n, "invalid JavaScript assignment")
		e.possibleThrow(s)
		return
	}
	s.scopes[i][n.text] = binding{value: v, initialized: true}
}

func (e *evaluator) bindPattern(n *node, v Value, s *state, kind string) {
	if n == nil {
		return
	}
	e.step()
	switch n.kind {
	case "identifier", "shorthand_property_identifier_pattern":
		e.bindName(n, v, s, kind)
	case "assignment_pattern", "object_assignment_pattern":
		switch v.kind {
		case "undefined":
			v = e.eval(n.get("right"), s)
		case "":
			branch := e.clone(s)
			other := e.eval(n.get("right"), branch)
			joined := e.joinStates(s, branch)
			*s = *joined
			v = joinValue(v, other)
		}
		e.bindPattern(n.get("left"), v, s, kind)
	case "object_pattern":
		if v.object == nil {
			e.unmodelled(n, s, "JavaScript destructuring of an unknown receiver")
		}
		used := map[string]bool{}
		for _, c := range n.namedChildren() {
			if c.kind == "rest_pattern" {
				rest := unknown(v.Taint)
				if v.object != nil {
					obj := &object{fields: map[string]Value{}}
					for _, key := range v.object.keys {
						e.step()
						if !used[key] {
							obj.keys = append(obj.keys, key)
							obj.fields[key] = v.object.fields[key]
						}
					}
					rest = Value{kind: "object", object: obj, Taint: v.Taint}
				}
				e.bindPattern(c.first(), rest, s, kind)
				continue
			}
			target := c
			key := c.text
			known := true
			if c.kind == "pair_pattern" {
				key, known = e.propertyKey(c.get("key"), s)
				target = c.get("value")
			}
			if c.kind == "object_assignment_pattern" {
				key = c.get("left").text
			}
			if !known {
				v = unknown(v.Taint)
				e.bindPattern(target, v, s, kind)
				continue
			}
			used[key] = true
			value := e.readProperty(c, s, v, key)
			e.bindPattern(target, value, s, kind)
		}
	case "array_pattern":
		if v.object == nil || !v.object.array {
			e.unmodelled(n, s, "JavaScript destructuring of an unknown iterable")
		}
		index := 0
		for _, c := range n.children {
			if c.kind == "," {
				index++
				continue
			}
			if !c.named || c.kind == "comment" {
				continue
			}
			if c.kind == "rest_pattern" {
				rest := unknown(v.Taint)
				if v.object != nil && v.object.array {
					obj := &object{fields: map[string]Value{}, array: true, length: max(0, v.object.length-index)}
					for j := index; j < v.object.length; j++ {
						e.step()
						key := strconv.Itoa(j - index)
						obj.keys = append(obj.keys, key)
						obj.fields[key] = e.readProperty(c, s, v, strconv.Itoa(j))
					}
					rest = Value{kind: "object", object: obj, Taint: v.Taint}
				}
				e.bindPattern(c.first(), rest, s, kind)
			} else {
				e.bindPattern(c, e.readProperty(c, s, v, strconv.Itoa(index)), s, kind)
			}
		}
	default:
		e.unmodelled(n, s, "unsupported JavaScript assignment target")
	}
}

// absorbBody merges loop exits and returns the next iteration's flow.
func (e *evaluator) absorbBody(out *flows, body flows) *flow {
	e.merge(out, normal, body[breaking])
	e.merge(out, returning, body[returning])
	e.merge(out, throwing, body[throwing])
	next := body[normal]
	if body[continuing] != nil {
		if next == nil {
			next = body[continuing]
		} else {
			next = &flow{e.joinStates(next.state, body[continuing].state), undefined()}
		}
	}
	return next
}

func (e *evaluator) loop(n *node, s *state) flows {
	s.scopes = append(s.scopes, map[string]binding{})
	finish := func(out flows) flows {
		popScope(out)
		return out
	}
	if n.kind == "for_in_statement" {
		return finish(e.forEach(n, s))
	}
	var out flows
	// A missing initializer is an empty_statement placeholder node.
	if init := n.get("initializer"); init != nil && init.kind != "empty_statement" {
		if init.kind == "lexical_declaration" {
			e.predeclare([]*node{init}, s)
		}
		var initOut flows
		if init.kind == "lexical_declaration" || init.kind == "variable_declaration" {
			initOut = e.exec(init, s)
		} else {
			e.eval(init, s)
			initOut = single(normal, s, undefined())
		}
		s = initOut[normal].state
		initOut[normal] = nil
		e.mergeAll(&out, initOut)
	}
	first := true
	for {
		e.step()
		condition := n.get("condition")
		known, b := true, true
		if n.kind != "do_statement" || !first {
			if condition != nil && condition.kind != "empty_statement" {
				value := e.eval(condition, s)
				b, known = value.truth()
			}
			if known && !b {
				e.merge(&out, normal, &flow{s, undefined()})
				return finish(out)
			}
			if !known {
				e.merge(&out, normal, &flow{s, undefined()})
				e.degrade(n, "JavaScript loop bound is unknown")
				e.havoc(s)
			}
		}
		body := e.exec(n.get("body"), s)
		next := e.absorbBody(&out, body)
		if next == nil {
			return finish(out)
		}
		s = next.state
		if inc := n.get("increment"); inc != nil {
			e.eval(inc, s)
		}
		if !known {
			e.havoc(s)
			e.merge(&out, normal, &flow{s, undefined()})
			return finish(out)
		}
		first = false
	}
}

func (e *evaluator) forEach(n *node, s *state) flows {
	kind := ""
	if k := n.get("kind"); k != nil {
		kind = k.text
	}
	if kind == "let" || kind == "const" {
		e.predeclarePattern(n.get("left"), s, kind == "const")
	}
	value := e.eval(n.get("right"), s)
	var values []Value
	op := n.operator()
	if value.object != nil {
		if op == "of" && value.object.array {
			for i := range value.object.length {
				e.step()
				values = append(values, e.readProperty(n, s, value, strconv.Itoa(i)))
			}
		} else if op == "in" {
			keys := slices.Clone(value.object.keys)
			sort.SliceStable(keys, func(i, j int) bool {
				a, ae := strconv.ParseUint(keys[i], 10, 32)
				b, be := strconv.ParseUint(keys[j], 10, 32)
				ai := ae == nil && a < 1<<32-1 && strconv.FormatUint(a, 10) == keys[i]
				bi := be == nil && b < 1<<32-1 && strconv.FormatUint(b, 10) == keys[j]
				if ai && bi {
					return a < b
				}
				return ai && !bi
			})
			for _, key := range keys {
				values = append(values, stringValue(key))
			}
		}
	}
	async := slices.ContainsFunc(n.children, func(c *node) bool { return c.text == "await" })
	precise := !async && value.object != nil && (op == "in" || value.object.array)
	if !precise {
		reason := "JavaScript iterable is unknown or unsupported"
		if async {
			reason = "JavaScript async iteration is unsupported"
		}
		// Iterating a non-iterable throws, so the catch path stays live.
		e.unmodelled(n, s, reason)
		values = []Value{unknown(value.Taint)}
	}
	out := flows{}
	if !precise {
		e.merge(&out, normal, &flow{e.clone(s), undefined()})
	}
	for _, v := range values {
		e.step()
		if kind != "" {
			e.patternNames(n.get("left"), func(name string) { delete(s.scopes[len(s.scopes)-1], name) })
			if kind == "let" || kind == "const" {
				e.predeclarePattern(n.get("left"), s, kind == "const")
			}
		}
		e.bindPattern(n.get("left"), v, s, kind)
		body := e.exec(n.get("body"), s)
		next := e.absorbBody(&out, body)
		if next == nil {
			return out
		}
		s = next.state
	}
	if !precise {
		e.havoc(s)
	}
	e.merge(&out, normal, &flow{s, undefined()})
	return out
}

func (e *evaluator) switchStmt(n *node, s *state) flows {
	value := e.eval(n.get("value"), s)
	s.scopes = append(s.scopes, map[string]binding{})
	cases := n.get("body").namedChildren()
	var declarations []*node
	for _, c := range cases {
		for _, child := range c.children {
			if child.field == "body" {
				declarations = append(declarations, child)
			}
		}
	}
	e.predeclare(declarations, s)
	type entry struct {
		index int
		state *state
	}
	var entries []entry
	defaultIndex := -1
	matched := false
	for i, c := range cases {
		if c.kind == "switch_default" {
			defaultIndex = i
			continue
		}
		test := e.eval(c.get("value"), s)
		known := value.kind != "" && test.kind != "" && value.kind != "function" && test.kind != "function"
		eq := strictEqual(value, test)
		if !known || eq {
			entries = append(entries, entry{i, e.clone(s)})
		}
		if known && eq {
			matched = true
			break
		}
	}
	var out flows
	if !matched {
		if defaultIndex >= 0 {
			entries = append(entries, entry{defaultIndex, e.clone(s)})
		} else {
			e.merge(&out, normal, &flow{s, undefined()})
		}
	}
	for _, start := range entries {
		running := single(normal, start.state, undefined())
		for _, c := range cases[start.index:] {
			if running[normal] == nil {
				break
			}
			var body []*node
			for _, child := range c.children {
				if child.field == "body" {
					body = append(body, child)
				}
			}
			next := e.sequence(body, running[normal].state)
			running[normal] = nil
			e.mergeAll(&running, next)
		}
		e.merge(&running, normal, running[breaking])
		running[breaking] = nil
		e.mergeAll(&out, running)
	}
	popScope(out)
	return out
}

func (e *evaluator) tryStmt(n *node, s *state) flows {
	out := e.exec(n.get("body"), s)
	if handler := n.get("handler"); handler != nil && out[throwing] != nil {
		caught := out[throwing]
		out[throwing] = nil
		caught.state.scopes = append(caught.state.scopes, map[string]binding{})
		saved := e.throws
		e.throws = nil
		e.predeclarePattern(handler.get("parameter"), caught.state, false)
		e.bindPattern(handler.get("parameter"), caught.value, caught.state, "let")
		parameterThrows := e.throws
		e.throws = saved
		handled := e.exec(handler.get("body"), caught.state)
		e.merge(&handled, throwing, &flow{parameterThrows, Value{}})
		popScope(handled)
		e.mergeAll(&out, handled)
	}
	if finalizer := n.get("finalizer"); finalizer != nil {
		var finished flows
		for k, f := range out {
			if f == nil {
				continue
			}
			after := e.exec(finalizer.get("body"), f.state)
			if after[normal] != nil {
				e.merge(&finished, completion(k), &flow{after[normal].state, f.value})
				after[normal] = nil
			}
			e.mergeAll(&finished, after)
		}
		return finished
	}
	return out
}

func strictEqual(a, b Value) bool {
	if a.kind == "" || b.kind == "" || a.kind != b.kind {
		return false
	}
	if a.kind == "number" {
		return a.number == b.number
	}
	return sameValue(a, b)
}
