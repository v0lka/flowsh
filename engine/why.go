package engine

import (
	"fmt"
	"sort"
	"strings"
)

// AtomKind classifies the source-level fact an Atom denotes. It is the
// node/flag vocabulary a why-trace speaks: what a justification points at.
type AtomKind string

const (
	// AtomCommand is the invoked program name.
	AtomCommand AtomKind = "command"
	// AtomFlag is a matched flag or option (e.g. -d, --output).
	AtomFlag AtomKind = "flag"
	// AtomOperand is a positional operand.
	AtomOperand AtomKind = "operand"
	// AtomRedirect is a redirection target.
	AtomRedirect AtomKind = "redirect"
	// AtomSource is a taint source.
	AtomSource AtomKind = "source"
	// AtomSink is a taint sink.
	AtomSink AtomKind = "sink"
	// AtomLiteral is a literal token.
	AtomLiteral AtomKind = "literal"
)

// AtomKinds lists every valid atom kind, in canonical order.
var AtomKinds = []AtomKind{AtomCommand, AtomFlag, AtomOperand, AtomRedirect, AtomSource, AtomSink, AtomLiteral}

// Valid reports whether k is a defined atom kind.
func (k AtomKind) Valid() bool {
	for _, x := range AtomKinds {
		if k == x {
			return true
		}
	}
	return false
}

// String returns the atom kind as its stable identifier.
func (k AtomKind) String() string { return string(k) }

// Atom is a concrete source-level node or token that contributed to deriving an
// effect: the node/flag a why-trace cites. Text is the token text; Loc pins it to
// the source (file/line/column) when the frontend knows it.
type Atom struct {
	Kind AtomKind   `json:"kind"`
	Text string     `json:"text"`
	Loc  *SourceLoc `json:"loc,omitempty"`
}

// Premise renders the atom as the stable premise token used inside WhyStep. The
// "kind:text" shape keeps premises self-describing and matches the convention
// the frontends already use (call:…, arg:…).
func (a Atom) Premise() string { return string(a.Kind) + ":" + a.Text }

// Derivation records how one effect follows from source-level atoms: the rules
// that fired and the concrete nodes/flags (Atoms) they consumed. It is exactly
// the AST/token → effect mapping the analysis builds before the core turns it
// into a why-trace.
type Derivation struct {
	// Effect is the effect being justified.
	Effect Effect `json:"effect"`
	// Atoms are the concrete nodes/flags the effect rests on.
	Atoms []Atom `json:"atoms,omitempty"`
	// Rules are the rule identifiers that fired, applied to Atoms in order.
	Rules []string `json:"rules,omitempty"`
}

// BuildWhy turns derivations into canonical, deduplicated why-traces: one trace
// per distinct effect, each step citing a concrete atom (node/flag) so that
// every non-empty effect has something specific to point at. An effect derived
// without atoms still gets a trace — carrying the effect key as a synthetic
// premise — so that WhyGaps can still report it as unexplained.
func BuildWhy(ds []Derivation) []WhyTrace {
	order := make([]string, 0, len(ds))
	byKey := make(map[string]*WhyTrace, len(ds))
	for _, d := range ds {
		key := d.Effect.Key()
		w, ok := byKey[key]
		if !ok {
			w = &WhyTrace{Effect: key}
			byKey[key] = w
			order = append(order, key)
		}
		w.Because = append(w.Because, stepsFor(d)...)
	}
	out := make([]WhyTrace, 0, len(order))
	for _, k := range order {
		w := byKey[k]
		w.Because = dedupSteps(w.Because)
		out = append(out, *w)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Effect < out[j].Effect })
	return out
}

// stepsFor lowers one derivation into why-steps. Rules are applied to atoms in
// order; the last rule repeats when there are more atoms than rules.
func stepsFor(d Derivation) []WhyStep {
	rules := d.Rules
	if len(rules) == 0 {
		rules = []string{"effect.derive"}
	}
	if len(d.Atoms) == 0 {
		return []WhyStep{{Rule: rules[0], Premises: []string{"effect:" + d.Effect.Key()}}}
	}
	steps := make([]WhyStep, 0, len(d.Atoms))
	for i, a := range d.Atoms {
		rule := rules[min(i, len(rules)-1)]
		steps = append(steps, WhyStep{
			Rule:     rule,
			Premises: []string{a.Premise()},
			Note:     "derived from " + string(a.Kind),
			Loc:      a.Loc,
		})
	}
	return steps
}

func dedupSteps(steps []WhyStep) []WhyStep {
	seen := make(map[string]bool, len(steps))
	out := make([]WhyStep, 0, len(steps))
	for _, s := range steps {
		k := s.Rule + "\x00" + strings.Join(s.Premises, ",")
		if s.Loc != nil {
			k += fmt.Sprintf("@%s:%d:%d", s.Loc.File, s.Loc.Line, s.Loc.Col)
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

// WhyStepsFor returns the steps of the trace explaining key, or nil if the key
// has no trace.
func WhyStepsFor(why []WhyTrace, key string) []WhyStep {
	for _, w := range why {
		if w.Effect == key {
			return w.Because
		}
	}
	return nil
}

// isConcretePremise reports whether a premise names a concrete node/flag (an Atom
// premise, "kind:text") rather than the synthetic "effect:key" fallback.
func isConcretePremise(p string) bool {
	i := strings.IndexByte(p, ':')
	if i < 0 {
		return false
	}
	return p[:i] != "effect"
}

// WhyGaps returns, sorted, the keys of the effects that no why-trace explains
// with a concrete premise (a cited node/flag). An empty result is the invariant
// "every non-empty effect has a why-trace pointing at a node/flag".
func WhyGaps(effects []Effect, why []WhyTrace) []string {
	index := make(map[string]WhyTrace, len(why))
	for _, w := range why {
		index[w.Effect] = w
	}
	var gaps []string
	for _, e := range effects {
		w, ok := index[e.Key()]
		if !ok {
			gaps = append(gaps, e.Key())
			continue
		}
		concrete := false
		for _, s := range w.Because {
			for _, p := range s.Premises {
				if isConcretePremise(p) {
					concrete = true
				}
			}
		}
		if !concrete {
			gaps = append(gaps, e.Key())
		}
	}
	sort.Strings(gaps)
	return gaps
}
