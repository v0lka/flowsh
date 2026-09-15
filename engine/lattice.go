package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ===========================================================================
// Certainty lattice
// ===========================================================================

// Certainty is an element of the certainty lattice: a bounded chain modelling
// how strongly the analysis believes that an effect occurs.
//
//	⊥ = CertaintyUnknown ⊑ Unlikely ⊑ Possible ⊑ Likely ⊑ Certain = ⊤
//
// Join (⊔) is the least upper bound (max) and meet (⊓) is the greatest lower
// bound (min). Being a chain, the lattice satisfies idempotence, commutativity,
// associativity, absorption and the ⊥/⊤ identities for both operations.
type Certainty int

const (
	CertaintyUnknown  Certainty = iota // ⊥ — no supporting evidence
	CertaintyUnlikely                  // weak evidence
	CertaintyPossible                  // plausible
	CertaintyLikely                    // strong evidence
	CertaintyCertain                   // ⊤ — definitely occurs
)

var certaintyNames = [...]string{"Unknown", "Unlikely", "Possible", "Likely", "Certain"}

// CertaintyBottom is the least element (⊥).
func CertaintyBottom() Certainty { return CertaintyUnknown }

// CertaintyTop is the greatest element (⊤).
func CertaintyTop() Certainty { return CertaintyCertain }

// Valid reports whether c is a defined certainty level.
func (c Certainty) Valid() bool { return c >= CertaintyUnknown && c <= CertaintyCertain }

// String returns the canonical name of the certainty level.
func (c Certainty) String() string {
	if !c.Valid() {
		return fmt.Sprintf("Certainty(%d)", int(c))
	}
	return certaintyNames[c]
}

// Join returns the least upper bound (⊔) of c and o.
func (c Certainty) Join(o Certainty) Certainty {
	if o > c {
		return o
	}
	return c
}

// Meet returns the greatest lower bound (⊓) of c and o.
func (c Certainty) Meet(o Certainty) Certainty {
	if o < c {
		return o
	}
	return c
}

// LessOrEqual reports whether c ⊑ o.
func (c Certainty) LessOrEqual(o Certainty) bool { return c <= o }

// MarshalJSON encodes the level as its canonical name.
func (c Certainty) MarshalJSON() ([]byte, error) {
	if !c.Valid() {
		return nil, fmt.Errorf("engine: cannot marshal invalid certainty %d", int(c))
	}
	return json.Marshal(c.String())
}

// UnmarshalJSON accepts the canonical name ("Certain") or the numeric ordinal.
func (c *Certainty) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err == nil {
		for i, n := range certaintyNames {
			if n == name {
				*c = Certainty(i)
				return nil
			}
		}
		return fmt.Errorf("engine: unknown certainty %q", name)
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("engine: cannot decode certainty from %s", strings.TrimSpace(string(b)))
	}
	if n < 0 || n >= len(certaintyNames) {
		return fmt.Errorf("engine: certainty ordinal out of range: %d", n)
	}
	*c = Certainty(n)
	return nil
}

// ===========================================================================
// Destructiveness lattice
// ===========================================================================

// Destructiveness is an element of the destructiveness lattice: an ordinal
// severity of how hard an effect is to undo.
//
//	⊥ = None ⊑ Low ⊑ Medium ⊑ High ⊑ Critical = ⊤
//
// Join is max, meet is min.
type Destructiveness int

const (
	DestructNone     Destructiveness = iota // no lasting impact
	DestructLow                             // reversible or read-only
	DestructMedium                          // recoverable with effort
	DestructHigh                            // hard to reverse
	DestructCritical                        // irreversible / trust-breaking
)

var destructivenessNames = [...]string{"None", "Low", "Medium", "High", "Critical"}

// DestructBottom is the least element (⊥).
func DestructBottom() Destructiveness { return DestructNone }

// DestructTop is the greatest element (⊤).
func DestructTop() Destructiveness { return DestructCritical }

// Valid reports whether d is a defined level.
func (d Destructiveness) Valid() bool { return d >= DestructNone && d <= DestructCritical }

// String returns the canonical name of the level.
func (d Destructiveness) String() string {
	if !d.Valid() {
		return fmt.Sprintf("Destructiveness(%d)", int(d))
	}
	return destructivenessNames[d]
}

// Join returns the least upper bound (⊔), i.e. max.
func (d Destructiveness) Join(o Destructiveness) Destructiveness {
	if o > d {
		return o
	}
	return d
}

// Meet returns the greatest lower bound (⊓), i.e. min.
func (d Destructiveness) Meet(o Destructiveness) Destructiveness {
	if o < d {
		return o
	}
	return d
}

// LessOrEqual reports whether d ⊑ o.
func (d Destructiveness) LessOrEqual(o Destructiveness) bool { return d <= o }

// MarshalJSON encodes the level as its canonical name.
func (d Destructiveness) MarshalJSON() ([]byte, error) {
	if !d.Valid() {
		return nil, fmt.Errorf("engine: cannot marshal invalid destructiveness %d", int(d))
	}
	return json.Marshal(d.String())
}

// UnmarshalJSON accepts the canonical name ("Critical") or the numeric ordinal.
func (d *Destructiveness) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err == nil {
		for i, n := range destructivenessNames {
			if n == name {
				*d = Destructiveness(i)
				return nil
			}
		}
		return fmt.Errorf("engine: unknown destructiveness %q", name)
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("engine: cannot decode destructiveness from %s", strings.TrimSpace(string(b)))
	}
	if n < 0 || n >= len(destructivenessNames) {
		return fmt.Errorf("engine: destructiveness ordinal out of range: %d", n)
	}
	*d = Destructiveness(n)
	return nil
}

// ===========================================================================
// Flat set lattice (shared shape of Scope and Taint)
// ===========================================================================

// flatSet is a flat (powerset) lattice over an open universe of strings with a
// single added maximal element, "arbitrary" (⊤):
//
//	⊥        = ∅
//	⊤        = {arbitrary}
//	⊔ (join) = set union, ⊤ absorbing
//	⊓ (meet) = set intersection, ⊤ as identity
//
// Elements are kept sorted and unique so that every representation — and hence
// every JSON encoding — is canonical.
type flatSet struct {
	arbitrary bool
	elems     []string
}

func newFlatSet(vals ...string) flatSet { return flatSet{elems: sortedUnique(vals)} }

func (s flatSet) join(o flatSet) flatSet {
	if s.arbitrary || o.arbitrary {
		return flatSet{arbitrary: true}
	}
	return flatSet{elems: sortedUnique(concat(s.elems, o.elems))}
}

func (s flatSet) meet(o flatSet) flatSet {
	switch {
	case s.arbitrary && o.arbitrary:
		return flatSet{arbitrary: true}
	case s.arbitrary:
		return flatSet{elems: cloneStrings(o.elems)}
	case o.arbitrary:
		return flatSet{elems: cloneStrings(s.elems)}
	default:
		return flatSet{elems: intersectSorted(s.elems, o.elems)}
	}
}

func (s flatSet) isBottom() bool { return !s.arbitrary && len(s.elems) == 0 }
func (s flatSet) isTop() bool    { return s.arbitrary }

func (s flatSet) equal(o flatSet) bool {
	if s.arbitrary != o.arbitrary {
		return false
	}
	if s.arbitrary {
		return true
	}
	return stringsEqual(s.elems, o.elems)
}

func (s flatSet) lessOrEqual(o flatSet) bool {
	if o.arbitrary {
		return true
	}
	if s.arbitrary {
		return false
	}
	return subsetSorted(s.elems, o.elems)
}

func (s flatSet) contains(v string) bool {
	if s.arbitrary {
		return true
	}
	i := sort.SearchStrings(s.elems, v)
	return i < len(s.elems) && s.elems[i] == v
}

func (s flatSet) display() string {
	switch {
	case s.arbitrary:
		return "⊤"
	case len(s.elems) == 0:
		return "∅"
	default:
		return "{" + strings.Join(s.elems, ",") + "}"
	}
}

// parseFlatSet decodes a flat set from JSON. The canonical form is
// {"<key>":[...],"arbitrary":bool}, but a bare string or array is accepted too,
// which keeps hand-written fixtures and frontend emitters terse.
func parseFlatSet(b []byte) (flatSet, error) {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		return flatSet{}, nil
	}
	switch trimmed[0] {
	case '"':
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return flatSet{}, err
		}
		return newFlatSet(v), nil
	case '[':
		var vs []string
		if err := json.Unmarshal(b, &vs); err != nil {
			return flatSet{}, err
		}
		return newFlatSet(vs...), nil
	case '{':
		var aux struct {
			Targets   []string `json:"targets"`
			Labels    []string `json:"labels"`
			Elems     []string `json:"elems"`
			Arbitrary bool     `json:"arbitrary"`
		}
		if err := json.Unmarshal(b, &aux); err != nil {
			return flatSet{}, err
		}
		if aux.Arbitrary {
			return flatSet{arbitrary: true}, nil
		}
		vals := aux.Targets
		if vals == nil {
			vals = aux.Labels
		}
		if vals == nil {
			vals = aux.Elems
		}
		return newFlatSet(vals...), nil
	default:
		return flatSet{}, fmt.Errorf("engine: cannot decode set from %s", trimmed)
	}
}

// ===========================================================================
// Scope
// ===========================================================================

// Scope is the target-set lattice: it describes the set of resources an effect
// may apply to. It is the flatSet lattice specialised to targets.
//
//	⊥        = ∅            (no target)
//	⊤        = {arbitrary}  (any target)
//	⊔        = set union
//	⊓        = set intersection
type Scope struct{ s flatSet }

// ScopeBottom returns ⊥ (the empty target set).
func ScopeBottom() Scope { return Scope{} }

// ScopeTop returns ⊤ (any target).
func ScopeTop() Scope { return Scope{s: flatSet{arbitrary: true}} }

// ScopeOf returns a scope holding the given concrete targets (empty strings are
// dropped; duplicates and ordering are normalised away).
func ScopeOf(targets ...string) Scope { return Scope{s: newFlatSet(targets...)} }

// Join returns the least upper bound (⊔) of x and y.
func (x Scope) Join(y Scope) Scope { return Scope{s: x.s.join(y.s)} }

// Meet returns the greatest lower bound (⊓) of x and y.
func (x Scope) Meet(y Scope) Scope { return Scope{s: x.s.meet(y.s)} }

// IsBottom reports whether x is ⊥.
func (x Scope) IsBottom() bool { return x.s.isBottom() }

// IsTop reports whether x is ⊤.
func (x Scope) IsTop() bool { return x.s.isTop() }

// Equal reports whether x and y are the same lattice element.
func (x Scope) Equal(y Scope) bool { return x.s.equal(y.s) }

// LessOrEqual reports whether x ⊑ y.
func (x Scope) LessOrEqual(y Scope) bool { return x.s.lessOrEqual(y.s) }

// Contains reports whether target is in x (always true for ⊤).
func (x Scope) Contains(target string) bool { return x.s.contains(target) }

// Targets returns the concrete targets of x in sorted order (nil for ⊥ and ⊤).
func (x Scope) Targets() []string { return cloneStrings(x.s.elems) }

func (x Scope) canonical() string {
	switch {
	case x.s.arbitrary:
		return "*"
	case len(x.s.elems) == 0:
		return "[]"
	default:
		return "[" + strings.Join(x.s.elems, ",") + "]"
	}
}

func (x Scope) String() string { return x.s.display() }

// MarshalJSON encodes the scope canonically as {"targets":[...],"arbitrary":bool}.
func (x Scope) MarshalJSON() ([]byte, error) {
	elems := x.s.elems
	if elems == nil {
		elems = []string{}
	}
	return json.Marshal(struct {
		Targets   []string `json:"targets"`
		Arbitrary bool     `json:"arbitrary"`
	}{elems, x.s.arbitrary})
}

// UnmarshalJSON decodes the canonical object form, or a bare string/array.
func (x *Scope) UnmarshalJSON(b []byte) error {
	s, err := parseFlatSet(b)
	if err != nil {
		return err
	}
	x.s = s
	return nil
}

// ===========================================================================
// Taint
// ===========================================================================

// Canonical taint labels. Labels are open-ended strings; these are the ones the
// core recognises and that frontends are expected to use.
const (
	TaintUntrusted  = "untrusted"
	TaintUserInput  = "userInput"
	TaintEnv        = "env"
	TaintNetwork    = "network"
	TaintSecret     = "secret"
	TaintFileSystem = "fileSystem"
	TaintProcess    = "process"
)

// Taint is the taint-label lattice: the set of provenance labels carried by an
// effect's data. It shares the flatSet shape with Scope.
//
//	⊥        = ∅            (untainted)
//	⊤        = {arbitrary}  (any taint)
//	⊔        = set union
//	⊓        = set intersection
type Taint struct{ s flatSet }

// TaintBottom returns ⊥ (untainted).
func TaintBottom() Taint { return Taint{} }

// TaintTop returns ⊤ (any taint).
func TaintTop() Taint { return Taint{s: flatSet{arbitrary: true}} }

// TaintOf returns a taint set holding the given labels.
func TaintOf(labels ...string) Taint { return Taint{s: newFlatSet(labels...)} }

// Join returns the least upper bound (⊔) of x and y.
func (x Taint) Join(y Taint) Taint { return Taint{s: x.s.join(y.s)} }

// Meet returns the greatest lower bound (⊓) of x and y.
func (x Taint) Meet(y Taint) Taint { return Taint{s: x.s.meet(y.s)} }

// IsBottom reports whether x is ⊥.
func (x Taint) IsBottom() bool { return x.s.isBottom() }

// IsTop reports whether x is ⊤.
func (x Taint) IsTop() bool { return x.s.isTop() }

// Equal reports whether x and y are the same lattice element.
func (x Taint) Equal(y Taint) bool { return x.s.equal(y.s) }

// LessOrEqual reports whether x ⊑ y.
func (x Taint) LessOrEqual(y Taint) bool { return x.s.lessOrEqual(y.s) }

// Contains reports whether label is in x (always true for ⊤).
func (x Taint) Contains(label string) bool { return x.s.contains(label) }

// Labels returns the labels of x in sorted order (nil for ⊥ and ⊤).
func (x Taint) Labels() []string { return cloneStrings(x.s.elems) }

func (x Taint) String() string { return x.s.display() }

// MarshalJSON encodes the taint canonically as {"labels":[...],"arbitrary":bool}.
func (x Taint) MarshalJSON() ([]byte, error) {
	elems := x.s.elems
	if elems == nil {
		elems = []string{}
	}
	return json.Marshal(struct {
		Labels    []string `json:"labels"`
		Arbitrary bool     `json:"arbitrary"`
	}{elems, x.s.arbitrary})
}

// UnmarshalJSON decodes the canonical object form, or a bare string/array.
func (x *Taint) UnmarshalJSON(b []byte) error {
	s, err := parseFlatSet(b)
	if err != nil {
		return err
	}
	x.s = s
	return nil
}

// ===========================================================================
// String-set helpers
// ===========================================================================

func concat(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

func cloneStrings(a []string) []string {
	if len(a) == 0 {
		return nil
	}
	out := make([]string, len(a))
	copy(out, a)
	return out
}

// sortedUnique returns a sorted, duplicate-free copy of vals with empty strings
// removed. It returns nil for an empty result.
func sortedUnique(vals []string) []string {
	if len(vals) == 0 {
		return nil
	}
	tmp := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			tmp = append(tmp, v)
		}
	}
	if len(tmp) == 0 {
		return nil
	}
	sort.Strings(tmp)
	w := 1
	for i := 1; i < len(tmp); i++ {
		if tmp[i] != tmp[w-1] {
			tmp[w] = tmp[i]
			w++
		}
	}
	return tmp[:w]
}

func intersectSorted(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	var out []string
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return out
}

func subsetSorted(a, b []string) bool {
	i, j := 0, 0
	for i < len(a) {
		if j >= len(b) {
			return false
		}
		switch {
		case a[i] == b[j]:
			i++
			j++
		case a[i] > b[j]:
			j++
		default:
			return false
		}
	}
	return true
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
