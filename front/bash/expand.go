package bash

import (
	"io"

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
		Env: expand.FuncEnviron(it.state.envGet),
		CmdSubst: func(w io.Writer, cs *syntax.CmdSubst) error {
			out, known, taint := it.captureSubst(cs)
			it.subst[cs] = substInfo{out: out, known: known, taint: taint}
			_, _ = io.WriteString(w, out)
			return nil
		},
		ProcSubst: func(ps *syntax.ProcSubst) (string, error) {
			it.execProcSubst(ps)
			it.subst[ps] = substInfo{known: false, taint: engine.TaintOf(engine.TaintUntrusted)}
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

// expandFields expands one word into its fields (field splitting and — were it
// enabled — pathname expansion applied), together with whether the result is
// statically known and the taint the word carries. Expansion never panics: a
// failure degrades to "unknown".
func (it *interp) expandFields(w *syntax.Word) expandedWord {
	ew := expandedWord{taint: engine.TaintBottom()}
	if w == nil {
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
		ew.fields = fields
		ew.known = it.wordKnown(w)
	}()
	ew.taint = it.wordTaint(w)
	return ew
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
