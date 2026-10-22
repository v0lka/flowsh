// Package js implements bounded abstract evaluation of JavaScript
// source.
package js

import "github.com/v0lka/flowsh/engine"

const (
	defaultBudget  = 50000
	maxDepth       = 256
	maxRecorded    = 1024
	maxValueBytes  = 65536
	maxSourceBytes = 1 << 20
)

// Call is a reached call site with abstract arguments.
type Call struct {
	Callee string
	Args   []Value
	Loc    engine.SourceLoc
}

// Resolution supplies trusted effects and an abstract return value.
// Handled distinguishes a pure call from an unresolved call.
type Resolution struct {
	Handled     bool
	Value       Value
	Effects     []engine.Effect
	Derivations []engine.Derivation
}

// Resolver models calls without importing bind or the KB.
type Resolver func(Call) Resolution

// Result holds effects, provenance, and analysis status.
type Result struct {
	Effects      []engine.Effect
	Derivations  []engine.Derivation
	Top          bool
	Conservative bool
	Reason       string
}

// Analyze evaluates source with conservative unresolved calls.
func Analyze(src string) *Result { return AnalyzeWith("", src, nil) }

// AnalyzeWith evaluates source with an optional resolver.
// name labels source; it never names a file to read.
// A nil resolver leaves every call unknown.
func AnalyzeWith(name, src string, resolver Resolver) *Result {
	r, _ := analyze(name, src, resolver)
	return r
}

func analyze(name, src string, resolver Resolver) (result *Result, final *state) {
	e := &evaluator{result: &Result{Effects: []engine.Effect{}}, name: name, resolver: resolver, budget: defaultBudget}
	defer func() {
		if p := recover(); p != nil {
			reason := "JavaScript evaluation failed"
			if _, ok := p.(budgetExhausted); ok {
				reason = "JavaScript analysis budget exhausted"
			}
			e.result.Top = true
			e.result.Reason = reason
			e.degrade(nil, reason)
			result = e.result
			final = nil
		}
	}()
	root, reason := parse(src)
	if root == nil {
		e.result.Top = true
		e.degrade(nil, reason)
		return e.result, nil
	}
	out := e.exec(root, newState())
	if out[normal] != nil {
		final = out[normal].state
	}
	return e.result, final
}

func (e *evaluator) degrade(n *node, reason string) {
	if e.result.Reason == "" {
		e.result.Reason = reason
	}
	e.result.Conservative = true
	eff := engine.Effect{Kind: engine.KindCodeExec, Target: engine.ScopeTop(), Mode: engine.ModeDirect, Certainty: engine.CertaintyCertain}
	if !e.hasTop {
		e.result.Effects = append(e.result.Effects, eff)
		e.hasTop = true
	}
	if len(e.result.Derivations) < maxRecorded {
		atom := engine.Atom{Kind: engine.AtomLiteral, Text: "js-opaque"}
		if n != nil {
			atom.Text = reason
			loc := e.location(n)
			atom.Loc = &loc
		}
		e.result.Derivations = append(e.result.Derivations, engine.Derivation{Effect: eff, Atoms: []engine.Atom{atom}, Rules: []string{"js.degrade"}})
	}
}

func (e *evaluator) location(n *node) engine.SourceLoc {
	return engine.SourceLoc{File: e.name, Line: n.line, Col: n.col}
}
