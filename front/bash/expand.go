package bash

import (
	"io"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// Σ — the abstract state of the transfer functions
// ===========================================================================
//
// Σ is the abstract state threaded through the abstract execution of a shell
// program:
//
//	Σ = ⟨ vars↑taint, PWD, umask, funcs, aliases ⟩
//
//   - Vars    is the variable store; every value carries a taint label so that
//     data provenance can flow from where a value was produced to the effects
//     it drives. A variable also records whether its value is statically known
//     (Known) — an unknown value makes every word that reads it dynamically
//     unknown, which the binding layer then treats as ⊤.
//   - PWD     is the abstract current working directory.
//   - Umask   is the abstract file-creation mask.
//   - Funcs   are the shell functions declared by the program.
//   - Aliases are the shell aliases declared by the program.

// Var is one shell variable in the abstract state. When Known is false the
// value is not statically determined (it was assigned from an unknown source);
// consumers must then treat reads of the variable as dynamic.
type Var struct {
	Value    string       `json:"value"`
	Taint    engine.Taint `json:"taint"`
	Set      bool         `json:"set"`
	Known    bool         `json:"known"`
	Export   bool         `json:"export,omitempty"`
	Readonly bool         `json:"readonly,omitempty"`
	// Int records the integer attribute (declare -i): later assignments are
	// arithmetic, which is not evaluated, so they must not be trusted as
	// literal strings.
	Int bool `json:"int,omitempty"`
}

// State is Σ. The zero value is not usable; build one with NewState.
type State struct {
	Vars    map[string]*Var   `json:"vars"`
	PWD     string            `json:"pwd"`
	Umask   string            `json:"umask"`
	Funcs   map[string]*Func  `json:"funcs,omitempty"`
	Aliases map[string]string `json:"aliases,omitempty"`
}

// defaultVars seeds Σ with the variables the expansion engine needs to know
// about statically. IFS drives field splitting; HOME and PATH are the other two
// variables shell expansion consults by default.
var defaultVars = map[string]string{
	"IFS":   " \t\n",
	"HOME":  "/root",
	"PATH":  "/usr/bin:/bin",
	"PWD":   "/",
	"SHELL": "/bin/sh",
	"USER":  "root",
}

// defaultUmask is the file-creation mask assumed unless the program sets one.
const defaultUmask = "0022"

// NewState returns the initial abstract state: the well-known defaults, an empty
// function table and an empty alias table.
func NewState() *State {
	s := &State{
		Vars:    make(map[string]*Var, len(defaultVars)),
		PWD:     defaultVars["PWD"],
		Umask:   defaultUmask,
		Funcs:   map[string]*Func{},
		Aliases: map[string]string{},
	}
	for k, v := range defaultVars {
		s.Vars[k] = &Var{Value: v, Set: true, Known: true, Taint: engine.TaintBottom()}
	}
	return s
}

// Clone returns a deep copy of s. It is used to give subshells, function calls
// and un-decidable branches their own copy of Σ.
func (s *State) Clone() *State {
	if s == nil {
		return NewState()
	}
	out := &State{
		Vars:    make(map[string]*Var, len(s.Vars)),
		PWD:     s.PWD,
		Umask:   s.Umask,
		Funcs:   make(map[string]*Func, len(s.Funcs)),
		Aliases: make(map[string]string, len(s.Aliases)),
	}
	for k, v := range s.Vars {
		if v == nil {
			continue
		}
		cp := *v
		out.Vars[k] = &cp
	}
	for k, v := range s.Funcs {
		out.Funcs[k] = v
	}
	for k, v := range s.Aliases {
		out.Aliases[k] = v
	}
	return out
}

// Get returns the variable named name, or nil when it is unset.
func (s *State) Get(name string) *Var {
	if s == nil || name == "" {
		return nil
	}
	return s.Vars[name]
}

// IsKnown reports whether name holds a statically-known value.
func (s *State) IsKnown(name string) bool {
	v := s.Get(name)
	return v != nil && v.Set && v.Known
}

// SetKnown assigns a statically-known value with the given taint.
func (s *State) SetKnown(name, value string, taint engine.Taint) {
	if s == nil || name == "" {
		return
	}
	v := s.Vars[name]
	if v == nil {
		v = &Var{}
		s.Vars[name] = v
	}
	if v.Readonly {
		return
	}
	v.Value, v.Set, v.Known, v.Taint = value, true, true, taint
}

// SetUnknown assigns a value whose content is not statically known: reads of it
// are dynamic.
func (s *State) SetUnknown(name string, taint engine.Taint) {
	if s == nil || name == "" {
		return
	}
	v := s.Vars[name]
	if v == nil {
		v = &Var{}
		s.Vars[name] = v
	}
	if v.Readonly {
		return
	}
	v.Value, v.Set, v.Known, v.Taint = "", true, false, taint
}

// MarkInteger records that name carries the integer attribute (declare -i).
func (s *State) MarkInteger(name string) {
	if s == nil || name == "" {
		return
	}
	v := s.Vars[name]
	if v == nil {
		v = &Var{}
		s.Vars[name] = v
	}
	v.Int = true
}

// Unset removes a variable from Σ.
func (s *State) Unset(name string) {
	if s == nil {
		return
	}
	if v := s.Vars[name]; v != nil && v.Readonly {
		return
	}
	delete(s.Vars, name)
}

// envGet is the lookup function handed to the expansion engine. An empty string
// means "unset", which is exactly how expand.FuncEnviron interprets it.
func (s *State) envGet(name string) string {
	if v := s.Get(name); v != nil && v.Set {
		return v.Value
	}
	return ""
}

// stateEnviron adapts the abstract state Σ to the expansion engine. It is a
// WriteEnviron, so assignment-expanding parameter operators (${x:=w}, ${x=w})
// and arithmetic side effects ($((x=1)), $((x++))) succeed instead of erroring —
// an error aborts the whole word expansion and silently drops every later
// substitution. A set-but-unknown variable is reported as set (with an empty
// value), so ${x:-w} does not substitute the default for it.
type stateEnviron struct{ s *State }

func (e stateEnviron) Get(name string) expand.Variable {
	v := e.s.Get(name)
	if v == nil || !v.Set {
		return expand.Variable{}
	}
	str := v.Value
	if !v.Known {
		str = ""
	}
	return expand.Variable{Exported: true, ReadOnly: v.Readonly, Kind: expand.String, Str: str}
}

func (e stateEnviron) Each(f func(string, expand.Variable) bool) {
	for name, v := range e.s.Vars {
		if v == nil || !v.Set || !v.Export {
			continue
		}
		if !f(name, e.Get(name)) {
			return
		}
	}
}

func (e stateEnviron) Set(name string, vr expand.Variable) error {
	if e.s == nil || name == "" {
		return nil
	}
	if !vr.IsSet() {
		e.s.Unset(name)
		return nil
	}
	if v := e.s.Get(name); v != nil && v.Readonly {
		// A read-only variable is not silently overwritten; do not error, since
		// an error would abort the whole word expansion.
		return nil
	}
	e.s.SetKnown(name, vr.String(), engine.TaintBottom())
	if vr.Exported {
		if v := e.s.Get(name); v != nil {
			v.Export = true
		}
	}
	return nil
}

// joinStates returns the least upper bound of two states reached by the two
// branches of an un-decidable control-flow split: a variable keeps its value
// only when both branches agree, and otherwise becomes unknown.
func joinStates(a, b *State) *State {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := a.Clone()
	names := map[string]bool{}
	for n := range a.Vars {
		names[n] = true
	}
	for n := range b.Vars {
		names[n] = true
	}
	for n := range names {
		av, bv := a.Vars[n], b.Vars[n]
		switch {
		case av == nil || bv == nil:
			delete(out.Vars, n) // defined on only one path → not surely set
		case !av.Set || !bv.Set || !av.Known || !bv.Known || av.Value != bv.Value:
			out.Vars[n] = &Var{Set: true, Known: false, Taint: av.Taint.Join(bv.Taint)}
		default:
			out.Vars[n] = &Var{Set: true, Known: true, Value: av.Value,
				Taint: av.Taint.Join(bv.Taint), Export: av.Export, Readonly: av.Readonly}
		}
	}
	if a.PWD != b.PWD {
		out.PWD = ""
	}
	if a.Umask != b.Umask {
		out.Umask = ""
	}
	return out
}

// ===========================================================================
// Expansion
// ===========================================================================

// substInfo records what the interpreter learned while expanding one command
// (or process) substitution: the stdout it folded to, whether that stdout was
// statically determined, and the provenance of that stdout.
type substInfo struct {
	out   string
	known bool
	taint engine.Taint
}

// newCfg builds a fresh expansion configuration bound to the current state.
//
// The environment is a expand.FuncEnviron over Σ, so IFS, HOME and PATH (and
// every other variable) are resolved from the abstract state, and field
// splitting follows the abstract IFS. The CmdSubst hook is the recursion point:
// it executes the substitution body in the interpreter and folds its standard
// output, recording whether that output was statically known. Globbing is
// deliberately disabled (ReadDir2 stays nil) so that analysis never touches the
// filesystem; a word containing glob metacharacters is instead reported as
// dynamic.
func (it *interp) newCfg() *expand.Config {
	return &expand.Config{
		Env: stateEnviron{it.state},
		CmdSubst: func(w io.Writer, cs *syntax.CmdSubst) error {
			if info, ok := it.substMemo[cs]; ok {
				// The substitution was already executed while expanding this
				// statement; reuse its folded stdout instead of running it again.
				_, _ = io.WriteString(w, info.out)
				return nil
			}
			out, known, taint := it.captureSubst(cs)
			info := substInfo{out: out, known: known, taint: taint}
			it.subst[cs] = info
			if it.substMemo != nil {
				it.substMemo[cs] = info
			}
			_, _ = io.WriteString(w, out)
			return nil
		},
		ProcSubst: func(ps *syntax.ProcSubst) (string, error) {
			if it.procMemo[ps] {
				return "/dev/fd/63", nil
			}
			it.execProcSubst(ps)
			it.subst[ps] = substInfo{known: false, taint: engine.TaintOf(engine.TaintUntrusted)}
			if it.procMemo != nil {
				it.procMemo[ps] = true
			}
			return "/dev/fd/63", nil
		},
	}
}

// expandedWord is the result of expanding a single shell word.
type expandedWord struct {
	fields []string
	known  bool
	taint  engine.Taint
}

// maxExpandedFields caps the number of fields a single word may expand to.
// Brace expansion ({1..1000000}) produces one word per element with no bound
// tied to the input length, so a short adversarial input could otherwise drive
// unbounded memory/CPU (ADR-0006); over the cap the word degrades to ⊤.
const maxExpandedFields = 4096

// expandFields expands one word into its fields (field splitting and — were it
// enabled — pathname expansion applied), together with whether the result is
// statically known and the taint the word carries. Expansion never panics: a
// failure degrades to "unknown".
func (it *interp) expandFields(w *syntax.Word) expandedWord {
	ew := expandedWord{taint: engine.TaintBottom()}
	if w == nil {
		return ew
	}
	// Bound brace expansion before materialising it: a word such as {1..1000000}
	// would otherwise allocate gigabytes for a few bytes of input.
	if braceExpansionOverflow(wordLiteralText(w)) {
		ew.fields, ew.known = nil, false
		it.markTop("brace expansion too large")
		ew.taint = it.wordTaint(w)
		return ew
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				ew.fields, ew.known = nil, false
			}
		}()
		fields, err := expand.Fields(it.newCfg(), w)
		if err != nil {
			ew.fields, ew.known = nil, false
			return
		}
		if len(fields) > maxExpandedFields {
			ew.fields, ew.known = nil, false
			it.markTop("word expansion produced too many fields")
			return
		}
		ew.fields = fields
		ew.known = it.wordKnown(w)
	}()
	ew.taint = it.wordTaint(w)
	return ew
}

// wordLiteralText returns the concatenated literal text of a word's unquoted
// literal parts (the only place brace expansion applies).
func wordLiteralText(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	for _, p := range w.Parts {
		if lit, ok := p.(*syntax.Lit); ok {
			b.WriteString(lit.Value)
		}
	}
	return b.String()
}

// braceExpansionOverflow reports whether expanding the brace forms in s would
// exceed maxExpandedFields. It is a conservative upper-bound estimator: it walks
// the brace groups and multiplies their alternative counts (an over-estimate is
// harmless — it only degrades to ⊤ a little sooner).
//
// An estimate that cannot be computed (nesting deeper than the cap, where
// braceCount reports false) is treated as a POSSIBLE overflow: the word must
// degrade to ⊤ rather than be materialised unbounded.
func braceExpansionOverflow(s string) bool {
	n, ok := braceCount(s, 0)
	return !ok || n > maxExpandedFields
}

// braceCount estimates the number of fields a brace expression expands to, as an
// over-approximation. The boolean is false when the estimate cannot be computed
// (nesting beyond the cap); callers must then treat the expansion as a possible
// overflow. A string with no brace groups returns (1, true).
func braceCount(s string, depth int) (int, bool) {
	if depth > maxBraceDepth {
		return 1, false
	}
	total := 1
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			continue
		}
		end := matchBrace(s, i)
		if end < 0 {
			continue
		}
		inner := s[i+1 : end]
		alt := 0
		for _, part := range splitTopComma(inner) {
			if lo, hi, isRange := braceRange(part); isRange && hi >= lo {
				if hi-lo >= maxExpandedFields {
					// A single range already blows the cap; cap the arithmetic
					// so a huge bound cannot overflow the int multiplication.
					return maxExpandedFields + 1, true
				}
				alt += hi - lo + 1
				continue
			}
			c, ok := braceCount(part, depth+1)
			if !ok {
				// A nested group whose size cannot be computed makes the whole
				// estimate uncomputable, so the caller degrades to ⊤.
				return 1, false
			}
			alt += c
		}
		if alt < 1 {
			alt = 1
		}
		total *= alt
		if total > maxExpandedFields {
			return total, true
		}
		i = end
	}
	return total, true
}

// maxBraceDepth bounds the brace-group nesting the estimator recurses into.
// Beyond it the count is treated as uncomputable (a possible overflow) rather
// than underestimated.
const maxBraceDepth = 16

// matchBrace returns the index of the '}' matching the '{' at open, or -1.
func matchBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitTopComma splits s on commas that are not nested inside braces.
func splitTopComma(s string) []string {
	var out []string
	depth, last := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[last:i])
				last = i + 1
			}
		}
	}
	out = append(out, s[last:])
	return out
}

// braceRange parses a {lo..hi} range body (lo/hi decimal integers), returning
// the bounds and whether it is a valid numeric range.
func braceRange(s string) (lo, hi int, ok bool) {
	i := strings.Index(s, "..")
	if i < 0 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(strings.TrimSpace(s[:i]))
	b, err2 := strconv.Atoi(strings.TrimSpace(s[i+2:]))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return a, b, true
}

// expandLiteral expands one word as a single literal string (no field
// splitting), returning the value, whether it is statically known, and its
// taint.
func (it *interp) expandLiteral(w *syntax.Word) (string, bool, engine.Taint) {
	if w == nil {
		return "", true, engine.TaintBottom()
	}
	var out string
	known := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				out, known = "", false
			}
		}()
		s, err := expand.Literal(it.newCfg(), w)
		if err != nil {
			return
		}
		out, known = s, it.wordKnown(w)
	}()
	return out, known, it.wordTaint(w)
}

// ===========================================================================
// Static knownness
// ===========================================================================

// wordKnown reports whether w expands to a value the analysis can pin down.
func (it *interp) wordKnown(w *syntax.Word) bool {
	if w == nil {
		return true
	}
	for _, p := range w.Parts {
		if !it.partKnown(p, false) {
			return false
		}
	}
	return true
}

// partKnown reports whether one word part is statically known. quoted says
// whether the part sits inside double quotes (which neutralises globbing).
func (it *interp) partKnown(p syntax.WordPart, quoted bool) bool {
	switch p := p.(type) {
	case *syntax.Lit:
		if !quoted && hasGlobMeta(p.Value) {
			return false
		}
		return true
	case *syntax.SglQuoted:
		return true
	case *syntax.DblQuoted:
		for _, ip := range p.Parts {
			if !it.partKnown(ip, true) {
				return false
			}
		}
		return true
	case *syntax.ParamExp:
		return it.paramKnown(p)
	case *syntax.CmdSubst:
		return it.subst[p].known
	case *syntax.ArithmExp:
		return it.arithKnown(p)
	case *syntax.ProcSubst:
		return false
	case *syntax.ExtGlob:
		return false
	default:
		return false
	}
}

// paramKnown reports whether a parameter expansion is statically known: either
// the variable holds a known value, or the expansion supplies a default whose
// word is itself known.
func (it *interp) paramKnown(p *syntax.ParamExp) bool {
	if p == nil || p.Param == nil {
		return false
	}
	name := p.Param.Value
	if it.state.IsKnown(name) {
		return true
	}
	// A set-but-unknown variable is NOT the same as an unset one: the operator's
	// alternate word is not used for it, so treating that word as the value
	// would be a confidently-wrong concrete target.
	if v := it.state.Get(name); v != nil && v.Set {
		return false
	}
	// ${x:-word}, ${x:=word}, ${x:+word} with a known alternate word.
	if p.Exp != nil && p.Exp.Word != nil && !p.Excl {
		return it.wordKnown(p.Exp.Word)
	}
	return false
}

// arithKnown reports whether an arithmetic expansion evaluates to a value.
func (it *interp) arithKnown(p *syntax.ArithmExp) bool {
	if p == nil || p.X == nil {
		return false
	}
	ok := false
	func() {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		_, err := expand.Arithm(it.newCfg(), p.X)
		ok = err == nil
	}()
	return ok
}

// ===========================================================================
// Taint
// ===========================================================================

// wordTaint returns the taint labels a word's value carries.
func (it *interp) wordTaint(w *syntax.Word) engine.Taint {
	if w == nil {
		return engine.TaintBottom()
	}
	t := engine.TaintBottom()
	for _, p := range w.Parts {
		t = t.Join(it.partTaint(p))
	}
	return t
}

func (it *interp) partTaint(p syntax.WordPart) engine.Taint {
	switch p := p.(type) {
	case *syntax.ParamExp:
		if p.Param != nil {
			if v := it.state.Get(p.Param.Value); v != nil {
				return v.Taint
			}
		}
		return engine.TaintBottom()
	case *syntax.CmdSubst, *syntax.ProcSubst:
		// The output of an executed command is attacker-influenceable at least
		// insofar as any code's output is (untrusted); it additionally carries
		// whatever provenance dataflow tracked for it.
		t := engine.TaintOf(engine.TaintUntrusted)
		if si, ok := it.subst[p]; ok {
			t = t.Join(si.taint)
		}
		return t
	case *syntax.DblQuoted:
		t := engine.TaintBottom()
		for _, ip := range p.Parts {
			t = t.Join(it.partTaint(ip))
		}
		return t
	default:
		return engine.TaintBottom()
	}
}

// hasGlobMeta reports whether s contains an unquoted glob metacharacter.
func hasGlobMeta(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '*', '?', '[':
			return true
		}
	}
	return false
}
