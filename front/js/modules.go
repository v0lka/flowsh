package js

import (
	"cmp"

	"github.com/v0lka/flowsh/engine"
)

// importValue resolves a static import source, or ⊤.
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
	v, _ := e.resolveModule(module, e.location(n))
	return v
}

// resolveModule returns a reviewed module identity, or ⊤.
func (e *evaluator) resolveModule(module string, loc engine.SourceLoc) (Value, bool) {
	r := e.resolver(Call{Kind: "module", Module: module, Loc: loc})
	if r.Handled && r.Value.kind == "module" {
		return r.Value, true
	}
	return Value{}, false
}

// bindImport binds every local name an import declares.
func (e *evaluator) bindImport(n *node, module Value, s *state) {
	e.step()
	if n.kind == "namespace_import" {
		module.namespace = true
	}
	switch n.kind {
	case "identifier":
		s.scopes[len(s.scopes)-1][n.text] = binding{value: module, constant: true, initialized: true}
	case "import_specifier":
		imported := n.get("name")
		target := cmp.Or(n.get("alias"), imported)
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
