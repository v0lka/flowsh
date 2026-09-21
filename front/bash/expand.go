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
	// Numeric records the numeric class: the value is an unknown but bounded
	// integer (an exit status, a pid, a line number, …) or a join of such
	// integers. The exact digits stay unknowable, so a word reading the
	// variable is still dynamic — but its expansion can only ever be digits,
	// which cannot introduce a path separator, a ".." segment or any other
	// path-structural byte. The interpreter uses that invariant to confine a
	// path-shaped word such as out-$?.log to its literal directory instead of
	// degrading the target to ⊤ (see numericConfinedDir). An assignment
	// replaces the value wholesale and clears the class.
	Numeric bool `json:"numeric,omitempty"`
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

// numericVars are the shell's status and identity parameters whose values are
// integers bounded by construction: an exit status ($?, ${PIPESTATUS[*]}) is
// 0–255, and the pid/uid/line-number family is likewise a plain integer. The
// analysis never knows the exact digits, so the variables are seeded as
// set-but-unknown with the Numeric class: reads stay dynamic, but a
// path-shaped word containing them is confined to its literal directory
// (numericConfinedDir) instead of degrading to ⊤. Assignment replaces the
// value and clears the class; the readonly names cannot be assigned at all,
// matching bash.
var numericVars = map[string]bool{
	"?":          true, // last exit status (readonly)
	"PIPESTATUS": true, // per-pipeline-stage exit statuses (readonly)
	"#":          true, // positional parameter count (readonly)
	"RANDOM":     true, // 0–32767 pseudo-random (assignable, then ordinary)
	"LINENO":     true, // current line number
	"SECONDS":    true, // seconds since shell start
	"UID":        true, // real uid (readonly)
	"EUID":       true, // effective uid (readonly)
	"PPID":       true, // parent pid (readonly)
	"BASHPID":    true, // current bash process id
}

// NewState returns the initial abstract state: the well-known defaults, an empty
// function table and an empty alias table.
func NewState() *State {
	s := &State{
		Vars:    make(map[string]*Var, len(defaultVars)+len(numericVars)),
		PWD:     defaultVars["PWD"],
		Umask:   defaultUmask,
		Funcs:   map[string]*Func{},
		Aliases: map[string]string{},
	}
	for k, v := range defaultVars {
		s.Vars[k] = &Var{Value: v, Set: true, Known: true, Taint: engine.TaintBottom()}
	}
	for name := range numericVars {
		readonly := name == "?" || name == "PIPESTATUS" || name == "#" || name == "UID" || name == "EUID" || name == "PPID"
		s.Vars[name] = &Var{Set: true, Known: false, Numeric: true, Readonly: readonly, Taint: engine.TaintBottom()}
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
	v.Value, v.Set, v.Known, v.Taint, v.Numeric = value, true, true, taint, false
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
	v.Value, v.Set, v.Known, v.Taint, v.Numeric = "", true, false, taint, false
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
			out.Vars[n] = &Var{Set: true, Known: false, Numeric: av.Numeric && bv.Numeric, Taint: av.Taint.Join(bv.Taint)}
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
	// net records that the substitution's body itself performed a network
	// effect, so its output is content that arrived over the network. It is what
	// distinguishes a value fetched over the network from the merely-untrusted
	// output of any command (see partTaint and taintIsNetwork).
	net bool
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
			out, known, taint, net := it.captureSubst(cs)
			info := substInfo{out: out, known: known, taint: taint, net: net}
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
			net := it.execProcSubst(ps)
			it.subst[ps] = substInfo{known: false, taint: engine.TaintOf(engine.TaintUntrusted), net: net}
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
// Numeric-class expansions
// ===========================================================================
//
// A numeric-class expansion is one whose every possible value is a plain
// integer (a bounded status, pid, count or arithmetic result): it can vary the
// digits of a word but never its path structure. A word whose dynamic parts are
// all numeric-class is therefore confined to the directory named by its literal
// prefix — `out-$?.log` stays in the working directory, `/tmp/x-$?.log` stays
// in /tmp — which is strictly more precise than the ⊤ target a fully dynamic
// word degrades to, and just as sound: digits cannot introduce "/", ".." or an
// absolute prefix.

// numericParam reports whether the parameter expansion p is numeric-class: it
// reads a numeric-class variable, takes a length (${#x}), or evaluates to
// digits. Operators that could splice non-numeric text into the value (an
// alternate word or a replacement carrying a path separator or a path
// structure) or that could expand to nothing (a slice, an indirect reference)
// disqualify it.
func (it *interp) numericParam(p *syntax.ParamExp) bool {
	if p == nil || p.Param == nil {
		return false
	}
	// ${!x} is indirection: the value is another variable's NAME, which is not
	// bounded to digits.
	if p.Excl {
		return false
	}
	// ${#x} is a length: always a non-negative integer.
	if p.Length {
		return true
	}
	// A slice (${x:off:len}, possibly zero-length) expands to nothing, which
	// would let the literal text that follows start a fresh — possibly
	// absolute — path component. An array subscript is kept (the whole-array
	// [*]/[@] forms and a numeric index both name bounded digit elements); a
	// subscript that could be out of range is handled by the empty-expansion
	// check in numericConfinedDir.
	if p.Slice != nil {
		return false
	}
	v := it.state.Get(p.Param.Value)
	if v == nil || !v.Set || !v.Numeric {
		return false
	}
	// The value itself is numeric, but an alternate/replacement operator
	// substitutes its own word into the value. Accept it only when that word is
	// itself numeric-class (every part is a numeric expansion or a path-free
	// literal): a dynamic or path-bearing word could move the expansion out of
	// the confined directory.
	if p.Exp != nil && p.Exp.Word != nil && !it.numericParts(p.Exp.Word.Parts) {
		return false
	}
	if p.Repl != nil && p.Repl.With != nil && !it.numericParts(p.Repl.With.Parts) {
		return false
	}
	return true
}

// wholeArrayIndex reports whether idx is the whole-array subscript [*] or [@],
// which for a numeric-class array expands to its digit elements (never empty
// for a non-empty array).
func wholeArrayIndex(idx syntax.ArithmExpr) bool {
	w, ok := idx.(*syntax.Word)
	if !ok || len(w.Parts) != 1 {
		return false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	return ok && (lit.Value == "*" || lit.Value == "@")
}

// numericParamEmpty reports whether a numeric-class expansion may expand to
// nothing, which would let the literal text that follows it start a fresh —
// possibly absolute — path component. An array subscript can be out of range;
// an alternate/replacement is dropped above unless its word is numeric-safe; a
// length or a bare status/identity read is always at least one digit.
func numericParamEmpty(p *syntax.ParamExp) bool {
	if p == nil {
		return true
	}
	return p.Index != nil && !wholeArrayIndex(p.Index)
}

// numericParts reports whether every part of a word is numeric-class: a
// numeric expansion or a literal that carries no path structure (no separator
// and no "."/".." segment, no backslash escape). Such a word can only
// contribute digits when spliced, so it cannot move an expansion out of its
// directory.
func (it *interp) numericParts(parts []syntax.WordPart) bool {
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if unsafeLiteral(p.Value) {
				return false
			}
		case *syntax.SglQuoted:
			if unsafeLiteral(p.Value) {
				return false
			}
		case *syntax.DblQuoted:
			if !it.numericParts(p.Parts) {
				return false
			}
		case *syntax.ParamExp:
			if !it.numericParam(p) {
				return false
			}
		case *syntax.ArithmExp:
			if !it.arithKnown(p) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// unsafeLiteral reports whether a literal word part could introduce path
// structure — a separator, a "."/".." segment or a backslash escape — and so
// must not be folded into a numeric-class expansion.
func unsafeLiteral(v string) bool {
	return strings.ContainsAny(v, `/\`) || hasDotDotSegment(v)
}

// knownParamText returns the exact value a bare parameter read resolves to when
// the variable holds a statically-known value — the same text a literal written
// in its place would contribute. Anything but a plain read (an operator, an
// index, indirection, a declared-integer variable whose assignments are
// arithmetic) reports false: its value is not the stored string.
func (it *interp) knownParamText(p *syntax.ParamExp) (string, bool) {
	if p == nil || p.Param == nil || p.Excl || p.Length || p.Exp != nil || p.Index != nil || p.Slice != nil || p.Repl != nil {
		return "", false
	}
	v := it.state.Get(p.Param.Value)
	if v == nil || !v.Set || !v.Known || v.Int {
		return "", false
	}
	return v.Value, true
}

// numericConfinedDir reports the directory every expansion of w is confined to
// when each of w's dynamic parts is numeric-class, and false when w has any
// non-numeric dynamic part (an unknown variable, a command or process
// substitution, a glob extension, …) or its literal text contains a ".." path
// segment, either of which could escape the directory.
//
// The directory is the literal text preceding the FIRST numeric part truncated
// at its last separator: digits may only lengthen the final component written
// so far, and every component after the prefix is checked free of ".." so no
// expansion can climb out of the directory it lands in.
func (it *interp) numericConfinedDir(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var (
		prefix     strings.Builder // literal text before the first numeric part
		full       strings.Builder // all literal text, for the ".." check
		sawNumeric bool
		prevEmpty  bool // the previous part was a possibly-empty numeric expansion
		escaped    bool // a literal after a numeric part starts a fresh component
	)
	// walk folds one run of word parts; it returns false as soon as a
	// non-numeric dynamic part disqualifies the word.
	var walk func(parts []syntax.WordPart) bool
	walk = func(parts []syntax.WordPart) bool {
		for _, p := range parts {
			switch p := p.(type) {
			case *syntax.Lit:
				// A backslash escape hides the decoded text from the checks
				// below (\.\. is a real ".." in shell), so it disqualifies.
				if strings.Contains(p.Value, `\`) {
					return false
				}
				if prevEmpty && startsNewComponent(p.Value) {
					escaped = true
				}
				full.WriteString(p.Value)
				if !sawNumeric {
					prefix.WriteString(p.Value)
				}
				prevEmpty = false
			case *syntax.SglQuoted:
				if strings.Contains(p.Value, `\`) {
					return false
				}
				if prevEmpty && startsNewComponent(p.Value) {
					escaped = true
				}
				full.WriteString(p.Value)
				if !sawNumeric {
					prefix.WriteString(p.Value)
				}
				prevEmpty = false
			case *syntax.DblQuoted:
				if !walk(p.Parts) {
					return false
				}
			case *syntax.ParamExp:
				if it.numericParam(p) {
					sawNumeric = true
					prevEmpty = numericParamEmpty(p)
					continue
				}
				// A plain read of a statically-known variable (a host binding,
				// a literal in-script assignment, a literal for-loop item)
				// contributes its exact value: it is as literal as the text
				// around it. Only bare reads fold — an operator would change
				// the value.
				if s, ok := it.knownParamText(p); ok {
					if prevEmpty && startsNewComponent(s) {
						escaped = true
					}
					full.WriteString(s)
					if !sawNumeric {
						prefix.WriteString(s)
					}
					prevEmpty = false
					continue
				}
				return false
			case *syntax.ArithmExp:
				if !it.arithKnown(p) {
					return false
				}
				sawNumeric = true
				prevEmpty = false
			default:
				return false
			}
		}
		return true
	}
	if !walk(w.Parts) || !sawNumeric {
		return "", false
	}
	// A ".." anywhere in the literal text, or a literal that starts a fresh
	// component right after a possibly-empty numeric part (which would splice
	// an absolute path), both escape the directory: refuse confinement.
	if escaped || hasDotDotSegment(full.String()) {
		return "", false
	}
	return dirPrefix(prefix.String()), true
}

// startsNewComponent reports whether a literal begins a fresh path component:
// an absolute/root prefix ("/" or "\") starts one outright, and so does a ".."
// (already covered by the ".." scan) or "." segment.
func startsNewComponent(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, `\`)
}

// dirPrefix truncates a literal path prefix at its last separator, yielding the
// deepest directory that certainly contains it: "a/b/c" → "a/b", "/x" → "/",
// "name" → "." (the working directory).
func dirPrefix(s string) string {
	if i := strings.LastIndexByte(s, '/'); i > 0 {
		return s[:i]
	} else if i == 0 {
		return "/"
	}
	return "."
}

// hasDotDotSegment reports whether the path s contains a ".." component: such a
// component climbs out of the directory that would otherwise confine the word,
// so a word whose literal text has one is never treated as confined.
func hasDotDotSegment(s string) bool {
	for _, seg := range strings.Split(s, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
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
		// whatever provenance dataflow tracked for it. The network label is
		// added only when the substitution's body actually performed a network
		// effect — the value then genuinely arrived over the network, which is
		// what a download-cradle sink is keyed on (see taintIsNetwork). A
		// substitution that merely reads a local file is untrusted, not network
		// content.
		t := engine.TaintOf(engine.TaintUntrusted)
		if si, ok := it.subst[p]; ok {
			t = t.Join(si.taint)
			if si.net {
				t = t.Join(engine.TaintOf(engine.TaintNetwork))
			}
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
