package engine

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ===========================================================================
// Breadth: the extent of what an effect touches
// ===========================================================================

// Breadth classifies how wide an effect's target scope is, in the order the spec
// fixes: exact < glob < $HOME (a home subtree) < / (the whole host).
type Breadth int

const (
	// BreadthNone is ⊥: no target at all.
	BreadthNone Breadth = iota
	// BreadthExact is a single concrete target.
	BreadthExact
	// BreadthGlob is a wildcard pattern (contains *, ? or [).
	BreadthGlob
	// BreadthHome is the user's home directory or a home subtree ($HOME, ~).
	BreadthHome
	// BreadthRoot is / or ⊤: the whole host.
	BreadthRoot
)

var breadthNames = [...]string{"None", "Exact", "Glob", "Home", "Root"}

// Valid reports whether b is a defined breadth level.
func (b Breadth) Valid() bool { return b >= BreadthNone && b <= BreadthRoot }

// String returns the canonical name of the breadth level.
func (b Breadth) String() string {
	if !b.Valid() {
		return fmt.Sprintf("Breadth(%d)", int(b))
	}
	return breadthNames[b]
}

// Join returns the least upper bound (⊔), i.e. the wider of b and o.
func (b Breadth) Join(o Breadth) Breadth {
	if o > b {
		return o
	}
	return b
}

// Severity maps breadth onto the shared severity scale: exact targets are Low,
// globs Medium, home subtrees High, and the whole host Critical.
func (b Breadth) Severity() Destructiveness {
	switch b {
	case BreadthExact:
		return DestructLow
	case BreadthGlob:
		return DestructMedium
	case BreadthHome:
		return DestructHigh
	case BreadthRoot:
		return DestructCritical
	default:
		return DestructNone
	}
}

// isHomeRoot reports whether t is a home-directory root written in one of the
// spellings the frontends emit.
func isHomeRoot(t string) bool {
	switch t {
	case "$HOME", "${HOME}", "~", "%USERPROFILE%", "$env:USERPROFILE", "$env:HOME",
		"$env:USERPROFILE\\", "%USERPROFILE%\\", "$HOME/", "~/":
		return true
	}
	return false
}

// breadthOfTarget classifies a single target token.
func breadthOfTarget(t string) Breadth {
	if t == "" {
		return BreadthNone
	}
	trimmed := strings.TrimRight(t, "/")
	if trimmed == "" || trimmed == "/" {
		return BreadthRoot
	}
	if isHomeRoot(trimmed) {
		return BreadthHome
	}
	if i := strings.IndexAny(t, "*?["); i >= 0 {
		base := strings.TrimRight(t[:i], "/")
		switch {
		case base == "":
			return BreadthRoot
		case isHomeRoot(base):
			return BreadthHome
		default:
			return BreadthGlob
		}
	}
	return BreadthExact
}

// BreadthOf returns the widest breadth among a scope's targets: Root for ⊤ and
// None for ⊥.
func BreadthOf(s Scope) Breadth {
	switch {
	case s.IsTop():
		return BreadthRoot
	case s.IsBottom():
		return BreadthNone
	}
	b := BreadthNone
	for _, t := range s.Targets() {
		b = b.Join(breadthOfTarget(t))
	}
	return b
}

// escalate raises a severity by one step, saturating at Critical.
func escalate(d Destructiveness) Destructiveness {
	if d < DestructTop() {
		return d + 1
	}
	return d
}

// BreadthSeverity returns the severity of a scope's extent, raised one step when
// the scope touches a well-known secret path (secret paths ↑).
func BreadthSeverity(s Scope) Destructiveness {
	d := BreadthOf(s).Severity()
	if anySecretTarget(s) {
		d = escalate(d)
	}
	return d
}

// ===========================================================================
// Irreversibility
// ===========================================================================

// Irreversibility grades how hard an operation is to undo, from trivially
// recoverable reads to irrecoverable data destruction.
type Irreversibility int

const (
	// IrrevReversible can be undone trivially (reads, copies).
	IrrevReversible Irreversibility = iota
	// IrrevRecoverable is recoverable with effort.
	IrrevRecoverable
	// IrrevPermanent is data loss that resists recovery.
	IrrevPermanent
	// IrrevDestructive is data destruction, effectively irreversible.
	IrrevDestructive
)

var irreversibilityNames = [...]string{"Reversible", "Recoverable", "Permanent", "Destructive"}

// Valid reports whether r is a defined irreversibility level.
func (r Irreversibility) Valid() bool { return r >= IrrevReversible && r <= IrrevDestructive }

// String returns the canonical name of the irreversibility level.
func (r Irreversibility) String() string {
	if !r.Valid() {
		return fmt.Sprintf("Irreversibility(%d)", int(r))
	}
	return irreversibilityNames[r]
}

// Join returns the least upper bound (⊔), i.e. the more irreversible of r and o.
func (r Irreversibility) Join(o Irreversibility) Irreversibility {
	if o > r {
		return o
	}
	return r
}

// Severity maps irreversibility onto the shared severity scale.
func (r Irreversibility) Severity() Destructiveness {
	switch r {
	case IrrevRecoverable:
		return DestructMedium
	case IrrevPermanent:
		return DestructHigh
	case IrrevDestructive:
		return DestructCritical
	default:
		return DestructNone
	}
}

// irreversibleTokens classifies the command tokens that destroy state: the
// commands whose effect is (or can be) irrecoverable regardless of how a single
// invocation is spelled.
var irreversibleTokens = map[string]Irreversibility{
	"rm": IrrevPermanent, "unlink": IrrevPermanent, "rmdir": IrrevPermanent,
	"truncate": IrrevPermanent,
	"shred":    IrrevDestructive, "wipefs": IrrevDestructive, "mkswap": IrrevDestructive,
	"sgdisk": IrrevDestructive, "fdisk": IrrevDestructive, "blkdiscard": IrrevDestructive,
	"dd": IrrevDestructive,
}

// IrreversibilityOfCommand classifies a command token by its base name. Unknown
// commands are reversible: the analysis then falls back to the effect's own
// reversibility.
func IrreversibilityOfCommand(tok string) Irreversibility {
	if tok == "" {
		return IrrevReversible
	}
	base := tok
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if r, ok := irreversibleTokens[base]; ok {
		return r
	}
	if strings.HasPrefix(base, "mkfs") {
		return IrrevDestructive
	}
	return IrrevReversible
}

// irreversibleKind reports whether an effect kind, when it is not reversible,
// destroys state (as opposed to reading or merely altering metadata).
func irreversibleKind(k EffectKind) bool {
	switch k {
	case KindFSWrite, KindCodeExec, KindProcSignal:
		return true
	}
	return false
}

// IrreversibilityOf returns the irreversibility of an effect given the command
// tokens that produced it. It combines the command's class with the effect's own
// Reversible flag: a non-reversible write of a destructive kind is at least
// Permanent. Breadth escalation is applied by ScoreEffects.
func IrreversibilityOf(e Effect, tokens ...string) Irreversibility {
	r := IrrevReversible
	for _, t := range tokens {
		r = r.Join(IrreversibilityOfCommand(t))
	}
	if !e.Reversible && irreversibleKind(e.Kind) {
		r = r.Join(IrrevPermanent)
	}
	return r
}

// ===========================================================================
// Confidence
// ===========================================================================

// ConfidenceOf returns a 0..100 confidence in an effect, from its certainty and
// the precision of its target: an effect over ⊤ or ⊥ is inherently less certain
// about what it concretely affects.
func ConfidenceOf(e Effect) int {
	base := 0
	if e.Certainty.Valid() {
		base = int(e.Certainty) * 25
	}
	if e.Target.IsTop() || e.Target.IsBottom() {
		base = base * 3 / 5
	}
	return base
}

// ===========================================================================
// Composite score
// ===========================================================================

// Score is the composite risk assessment of a set of effects. Every risk field
// is a severity on the shared destructiveness scale, so the whole score is
// comparable, orderable and serialisable.
type Score struct {
	// Destructiveness is the worst-case severity of the effects themselves.
	Destructiveness Destructiveness `json:"destructiveness"`
	// Irreversibility is how hard the worst effect is to undo.
	Irreversibility Destructiveness `json:"irreversibility"`
	// Breadth is the extent of what is affected (secret paths raise it).
	Breadth Destructiveness `json:"breadth"`
	// Influence is the attacker control over the data.
	Influence Destructiveness `json:"influence"`
	// Exfil is the credential/data exfiltration risk.
	Exfil Destructiveness `json:"exfil"`
	// Confidence is the weakest-link confidence across effects, in [0,100].
	Confidence int `json:"confidence"`
	// Reversible is true iff every effect is reversible.
	Reversible bool `json:"reversible"`
	// Grade is the join of the risk dimensions above.
	Grade Destructiveness `json:"grade"`
	// ExfilPairs lists the detected credential-egress pairings, if any.
	ExfilPairs []Exfil `json:"exfilPairs,omitempty"`
}

// exfilSeverity grades the exfiltration risk of a set of pairings. A secret
// source reaching a tainted egress is trust-breaking (Critical); any other
// source-to-egress pairing is High.
func exfilSeverity(pairs []Exfil) Destructiveness {
	sev := DestructNone
	for _, p := range pairs {
		s := DestructHigh
		if IsSecretRead(p.Source) && (p.Sink.Taint.IsTop() || p.Sink.Taint.Contains(TaintSecret)) {
			s = DestructCritical
		}
		sev = sev.Join(s)
	}
	return sev
}

// ScoreEffects composes a set of effects into a Score. tokens are the command
// tokens (program names) that produced the effects; they let the irreversibility
// dimension recognise destructive commands (rm, mkfs, dd, truncate) that a
// single effect does not name. Passing none is valid.
func ScoreEffects(effects []Effect, tokens ...string) Score {
	sc := Score{Reversible: true, Confidence: 0, ExfilPairs: DetectExfil(effects)}
	if len(effects) == 0 {
		return sc
	}

	sc.Destructiveness = ComputeDestructiveness(effects)

	// Irreversibility: the more irreversible of the tokens and the effects,
	// escalated to Critical when a permanent destruction also applies broadly.
	irr := IrrevReversible
	for _, e := range effects {
		irr = irr.Join(IrreversibilityOf(e, tokens...))
	}
	irrSev := irr.Severity()

	// Breadth: the widest target among the effects.
	scope := ScopeBottom()
	for _, e := range effects {
		scope = scope.Join(e.Target)
	}
	breadthSev := BreadthSeverity(scope)
	if irrSev >= DestructHigh && breadthSev >= DestructHigh {
		irrSev = DestructCritical
	}
	sc.Irreversibility = irrSev
	sc.Breadth = breadthSev

	sc.Influence = MaxInfluence(effects).Severity()
	sc.Exfil = exfilSeverity(sc.ExfilPairs)

	conf := 100
	rev := true
	for _, e := range effects {
		if c := ConfidenceOf(e); c < conf {
			conf = c
		}
		if !e.Reversible {
			rev = false
		}
	}
	sc.Confidence = conf
	sc.Reversible = rev

	sc.Grade = sc.Destructiveness.
		Join(sc.Irreversibility).
		Join(sc.Breadth).
		Join(sc.Influence).
		Join(sc.Exfil)
	return sc
}

// Encode returns the canonical indented JSON of the score.
func (s Score) Encode() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}
