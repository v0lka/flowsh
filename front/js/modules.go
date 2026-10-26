package js

func (e *evaluator) importValue(n *node, s *state) Value {
	if s.poisoned || e.resolver == nil {
		return Value{}
	}
	source := n.get("source")
	if source == nil {
		return Value{}
	}
	module, ok := decodeString(source.text)
	if !ok {
		return Value{}
	}
	e.charge(len(module))
	r := e.resolver(Call{Kind: "module", Module: module, Loc: e.location(n)})
	if r.Handled && r.Value.kind == "module" {
		return r.Value
	}
	return Value{}
}

func (e *evaluator) bindImport(n *node, module Value, s *state) {
	e.step()
	if n.kind == "namespace_import" {
		module.namespace = true
	}
	switch n.kind {
	case "identifier":
		s.scopes[len(s.scopes)-1][n.text] = binding{value: module, constant: true, initialized: true}
	case "import_specifier":
		target := n.get("alias")
		if target == nil {
			target = n.get("name")
		}
		imported := n.get("name")
		value := Value{}
		if module.kind == "module" && imported != nil {
			value = module
			if imported.text != "default" {
				value = e.readProperty(n, s, module, imported.text)
			}
		}
		if target != nil {
			e.bindImport(target, value, s)
		}
	case "import_statement", "import_clause", "named_imports", "namespace_import":
		for _, child := range n.namedChildren() {
			e.bindImport(child, module, s)
		}
	}
}

// modelWork counts reused strings and options before binding.
func modelWork(v Value) int {
	work := 1 + len(v.text)
	if v.object != nil {
		for _, key := range v.object.keys {
			work += 1 + len(key) + len(v.object.fields[key].text)
		}
	}
	return work
}
