package bash

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// The abstract-execution layer
// ===========================================================================
//
// This file implements the transfer functions of the shell frontend: it walks
// the syntax tree with an abstract state Σ (see expand.go), expanding words,
// interpreting redirections, pipelines, control-flow and subshells, and folds
// the effects it discovers into a single aggregate.
//
// Two design points are worth stating up front.
//
//   - Effects of ordinary commands are obtained through the Resolver seam. The
//     binding layer (package bind) already knows how to turn a normalized
//     command invocation into effects, but it imports this package, so this
//     package cannot import it back. The seam inverts that dependency: the
//     caller injects the binder. Everything the shell itself contributes —
//     redirections, code-execution sinks, environment writes — is emitted here
//     directly.
//
//   - The analysis is bounded. Whenever it cannot finish (a loop whose
//     condition never becomes false, an undecidable branch taken to its limit)
//     it degrades to ⊤ rather than diverge, and it does so within a fixed
//     step budget so the wall-clock cost is bounded.

// Resolution is the outcome of resolving one command invocation through the
// Resolver seam: the effects the command contributes together with the
// derivations that justify each of them (the concrete flag/operand/source atoms
// the effect rests on). Threading both lets the composition layer build a
// why-trace that reaches all the way down to the knowledge base.
type Resolution struct {
	Effects     []engine.Effect
	Derivations []engine.Derivation
}

// Resolver is the seam through which the effect knowledge base is injected: it
// maps one normalized, fully-expanded command invocation to the effects it
// implies and to the derivations that justify them. Passing nil disables command
// binding — only the shell's own intrinsic effects are then reported.
type Resolver func(cmd *Command, prog *Program) Resolution

// ExecResult is the outcome of abstractly executing a shell program: the
// aggregate effect set, the final abstract state, the resolved invocations, and
// the ⊤ flags.
type ExecResult struct {
	Variant Variant `json:"variant"`
	File    string  `json:"file,omitempty"`
	Source  string  `json:"source"`

	// Top is true when the whole analysis degraded to ⊤ (a parse failure or an
	// exhausted budget); Reason explains why.
	Top    bool   `json:"top"`
	Reason string `json:"reason,omitempty"`

	// Conservative is true when the aggregate includes a ⊤ effect (CodeExec
	// over the any-target scope) even though the program as a whole was
	// analysed — e.g. because it feeds data to a code-execution sink.
	Conservative bool `json:"conservative"`

	Effects         []engine.Effect        `json:"effects"`
	Destructiveness engine.Destructiveness `json:"destructiveness"`

	// Derivations justifies every reported effect with the concrete source atoms
	// (flags, operands, redirections, sinks) it rests on, for the composition
	// layer's why-trace. It is analysis metadata, not part of the effect IR.
	Derivations []engine.Derivation `json:"-"`

	State *State     `json:"state,omitempty"`
	Cmds  []*Command `json:"cmds,omitempty"`
	Notes []string   `json:"notes,omitempty"`
}

// HasTop reports whether the aggregate effects include the ⊤ effect (CodeExec
// acting on the any-target scope).
func (r *ExecResult) HasTop() bool {
	if r == nil {
		return false
	}
	for _, e := range r.Effects {
		if isTopEffect(e) {
			return true
		}
	}
	return false
}

// ===========================================================================
// Bounds
// ===========================================================================

const (
	// defaultBudget bounds the number of interpreted steps: redirections,
	// statements, loop iterations and function calls all draw on it. When it is
	// exhausted the analysis yields ⊤, which is what makes "while true" cheap.
	defaultBudget = 50000
	// maxFuncDepth bounds function-call recursion.
	maxFuncDepth = 64
	// maxAliasDepth bounds alias-chain expansion.
	maxAliasDepth = 32
	// maxRecorded bounds the resolved-invocation and note lists so that a
	// non-terminating loop cannot grow them without limit before the budget
	// stops it.
	maxRecorded = 1024
)

// Control-flow signals, propagated by execStmts until a loop or function
// consumes them.
const (
	ctlNone = iota
	ctlBreak
	ctlContinue
	ctlReturn
	ctlExit
)

// budgetError unwinds the interpreter when the step budget runs out.
type budgetError struct{ detail string }

// ===========================================================================
// Interpreter
// ===========================================================================

// interp is one abstract execution of a program.
type interp struct {
	src  string
	prog *Program
	norm *normalizer
	res  Resolver

	state  *State
	effs   []engine.Effect
	ders   []engine.Derivation
	cmds   []*Command
	notes  []string
	top    bool
	reason string

	budget int
	depth  int

	// stdout/stdin fold the value flowing out of, and into, the command
	// currently being interpreted; they are what threads a pipeline. The
	// matching *Taint fields thread its provenance through the same channel.
	stdout      string
	stdoutKnown bool
	stdoutTaint engine.Taint
	stdin       string
	stdinKnown  bool
	stdinTaint  engine.Taint

	// status/statusKnown record the exit status of the last command, when the
	// analysis can pin it down; they decide && / || / if / while branches.
	status      int
	statusKnown bool

	// ctl is the pending control-flow signal.
	ctl int

	// subst records the stdout (and its knownness) captured for every command
	// and process substitution node encountered during expansion.
	subst map[syntax.Node]substInfo

	// funcRaw holds the raw bodies of the program's functions, so the
	// interpreter can execute them.
	funcRaw map[string]*syntax.FuncDecl
}

func newInterp(src string, prog *Program, r Resolver, f *syntax.File) *interp {
	it := &interp{
		src:     src,
		prog:    prog,
		norm:    newNormalizer(src),
		res:     r,
		state:   NewState(),
		budget:  defaultBudget,
		subst:   map[syntax.Node]substInfo{},
		funcRaw: collectFuncsRaw(f),
	}
	if prog != nil {
		for n, fn := range prog.Funcs {
			it.state.Funcs[n] = fn
		}
		for n, a := range prog.Aliases {
			if a != nil {
				it.state.Aliases[n] = a.Value
			}
		}
	}
	return it
}

// collectFuncsRaw indexes every function definition in the raw syntax tree.
func collectFuncsRaw(f *syntax.File) map[string]*syntax.FuncDecl {
	out := map[string]*syntax.FuncDecl{}
	if f == nil {
		return out
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		if fd, ok := n.(*syntax.FuncDecl); ok && fd.Name != nil {
			out[fd.Name.Value] = fd
		}
		return true
	})
	return out
}

// step charges one unit against the budget and unwinds with budgetError when it
// is exhausted.
func (it *interp) step() {
	it.budget--
	if it.budget <= 0 {
		panic(budgetError{"step budget exhausted"})
	}
}

// ===========================================================================
// Entry point
// ===========================================================================

// Exec parses src as variant v and abstractly executes it, returning the
// aggregate effect set and the final state. r is the effect resolver (nil means
// no command binding). Exec never panics: a parse failure, an internal error, or
// an exhausted budget all degrade to a ⊤ result.
func Exec(v Variant, name, src string, r Resolver) (res *ExecResult) {
	var it *interp
	defer func() {
		if rec := recover(); rec != nil {
			if it != nil {
				res = it.finish(rec)
				return
			}
			res = topResult(v, name, src, fmt.Sprintf("internal failure: %v", rec))
		}
	}()

	lang, ok := v.langVariant()
	if !ok {
		return topResult(v, name, src, "unknown shell variant "+strconv.Quote(string(v)))
	}
	parser := syntax.NewParser(syntax.Variant(lang))
	f, err := parser.Parse(strings.NewReader(src), name)
	if err != nil {
		return topResult(v, name, src, err.Error())
	}
	syntax.Simplify(f)

	prog := &Program{Variant: v, File: name, Source: src, Stmts: []*Stmt{}}
	newNormalizer(src).fill(f, prog)

	it = newInterp(src, prog, r, f)
	it.execStmts(f.Stmts)
	return it.result()
}

// ExecBash is Exec for the bash dialect.
func ExecBash(src string, r Resolver) *ExecResult { return Exec(Bash, "script", src, r) }

// topResult builds a fully-⊤ result.
func topResult(v Variant, name, src, reason string) *ExecResult {
	rep := engine.NewReport()
	rep.Effects = []engine.Effect{topEffect(engine.ModeDirect)}
	rep.Normalize()
	return &ExecResult{
		Variant:         v,
		File:            name,
		Source:          src,
		Top:             true,
		Reason:          reason,
		Conservative:    true,
		Effects:         rep.Effects,
		Destructiveness: rep.Destructiveness,
		State:           NewState(),
		Notes:           []string{reason},
	}
}

// finish turns a recovered panic into a ⊤ result, preserving whatever effects
// were discovered before the unwinding.
func (it *interp) finish(rec interface{}) *ExecResult {
	if b, ok := rec.(budgetError); ok {
		it.markTop("analysis budget exhausted: " + b.detail)
	} else {
		it.markTop(fmt.Sprintf("internal failure: %v", rec))
	}
	return it.result()
}

// result folds the accumulated effects into their canonical form.
func (it *interp) result() *ExecResult {
	rep := engine.NewReport()
	rep.Effects = it.effs
	rep.Normalize()

	cons := it.top
	for _, e := range rep.Effects {
		if isTopEffect(e) {
			cons = true
		}
	}
	return &ExecResult{
		Variant:         it.prog.Variant,
		File:            it.prog.File,
		Source:          it.prog.Source,
		Top:             it.top,
		Reason:          it.reason,
		Conservative:    cons,
		Effects:         rep.Effects,
		Destructiveness: rep.Destructiveness,
		Derivations:     it.ders,
		State:           it.state,
		Cmds:            it.cmds,
		Notes:           dedupStrings(it.notes),
	}
}

// markTop flags the whole analysis as ⊤ and records a ⊤ effect.
func (it *interp) markTop(reason string) {
	if !it.top {
		it.top, it.reason = true, reason
	}
	it.addNote(reason)
	it.effs = append(it.effs, topEffect(engine.ModeDirect))
}

// markTopEffect records a ⊤ effect for one sub-computation (a sink) without
// claiming the whole program is unanalysable. It returns the effect so the
// caller can attach a derivation citing the construct that produced it.
func (it *interp) markTopEffect(reason string) engine.Effect {
	it.addNote(reason)
	e := topEffect(engine.ModeDirect)
	it.effs = append(it.effs, e)
	return e
}

// ===========================================================================
// Effects
// ===========================================================================

func topEffect(mode engine.EffectMode) engine.Effect {
	return engine.Effect{
		Kind:       engine.KindCodeExec,
		Target:     engine.ScopeTop(),
		Mode:       mode,
		Certainty:  engine.CertaintyCertain,
		Taint:      engine.TaintBottom(),
		Reversible: false,
	}
}

func isTopEffect(e engine.Effect) bool {
	return e.Kind == engine.KindCodeExec && e.Target.IsTop()
}

func envWriteEffect(name string, taint engine.Taint) engine.Effect {
	return engine.Effect{
		Kind:       engine.KindEnvWrite,
		Target:     engine.ScopeOf(name),
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      taint,
		Reversible: false,
	}
}

func (it *interp) emit(kind engine.EffectKind, target engine.Scope, mode engine.EffectMode, cert engine.Certainty, taint engine.Taint, atom engine.Atom) {
	e := engine.Effect{
		Kind:       kind,
		Target:     target,
		Mode:       mode,
		Certainty:  cert,
		Taint:      taint,
		Reversible: defaultReversible(kind),
	}
	it.effs = append(it.effs, e)
	it.derive(e, atom)
}

// derive records why one effect follows from the given source atoms. It is the
// interpreter's counterpart of the binder's derivations: the shell's intrinsic
// effects (redirections, stdio, sinks, environment writes) each cite a redirect,
// literal or command atom, so that every effect has a concrete justification.
func (it *interp) derive(e engine.Effect, atoms ...engine.Atom) {
	if len(atoms) == 0 {
		return
	}
	it.ders = append(it.ders, engine.Derivation{
		Effect: e,
		Atoms:  atoms,
		Rules:  []string{intrinsicRule(e.Kind)},
	})
}

// intrinsicRule names the rule the shell itself fires for an intrinsic effect
// kind; it mirrors the binder's rule vocabulary so the two read alike.
func intrinsicRule(k engine.EffectKind) string {
	switch k {
	case engine.KindFSRead:
		return "fs.read"
	case engine.KindFSWrite:
		return "fs.write"
	case engine.KindFSMeta:
		return "fs.meta"
	case engine.KindEnvWrite:
		return "env.write"
	case engine.KindNetEgress:
		return "net.egress"
	case engine.KindNetIngress:
		return "net.ingress"
	case engine.KindIPC:
		return "ipc"
	case engine.KindStdio:
		return "stdio"
	case engine.KindCodeExec:
		return "code.exec"
	default:
		return "effect.derive"
	}
}

// sourceLoc converts a frontend position into the core's source location,
// returning nil when the position carries no information.
func sourceLoc(p Pos, file string) *engine.SourceLoc {
	if p.IsZero() && file == "" {
		return nil
	}
	return &engine.SourceLoc{File: file, Line: p.Line, Col: p.Col}
}

// redirectAtom builds the redirect atom a redirection effect cites.
func (it *interp) redirectAtom(p Pos, text string) engine.Atom {
	return engine.Atom{Kind: engine.AtomRedirect, Text: text, Loc: sourceLoc(p, it.prog.File)}
}

// defaultReversible mirrors the core's default reversibility per kind.
func defaultReversible(k engine.EffectKind) bool {
	switch k {
	case engine.KindFSRead, engine.KindEnvRead, engine.KindNetIngress,
		engine.KindNetEgress, engine.KindStdio, engine.KindCredAccess:
		return true
	default:
		return false
	}
}

// ===========================================================================
// Statement execution
// ===========================================================================

func (it *interp) execStmts(ss []*syntax.Stmt) {
	for _, s := range ss {
		if it.ctl != ctlNone {
			return
		}
		it.execStmt(s)
	}
}

func (it *interp) execStmt(s *syntax.Stmt) {
	if s == nil {
		return
	}
	it.step()
	// An input redirection contributes the provenance of the file it reads to
	// this statement's standard input; the contribution is scoped to the
	// statement so it cannot leak into a following one.
	savedInTaint := it.stdinTaint
	defer func() { it.stdinTaint = savedInTaint }()
	for _, r := range s.Redirs {
		it.redir(r)
	}
	if s.Cmd == nil {
		return
	}
	if s.Background || s.Coprocess {
		saved := it.state
		it.state = it.state.Clone()
		it.execCommand(s.Cmd)
		it.state = saved
		return
	}
	it.execCommand(s.Cmd)
}

func (it *interp) execCommand(c syntax.Command) {
	switch c := c.(type) {
	case nil:
		// bare redirection
	case *syntax.CallExpr:
		it.execCall(c)
	case *syntax.BinaryCmd:
		it.execBinary(c)
	case *syntax.Block:
		it.execStmts(c.Stmts)
	case *syntax.Subshell:
		saved := it.state
		it.state = it.state.Clone()
		it.execStmts(c.Stmts)
		it.state = saved
	case *syntax.IfClause:
		it.execIf(c)
	case *syntax.WhileClause:
		it.execWhile(c)
	case *syntax.ForClause:
		it.execFor(c)
	case *syntax.CaseClause:
		it.execCase(c)
	case *syntax.FuncDecl:
		it.execFuncDecl(c)
	case *syntax.DeclClause:
		it.execDecl(c)
	case *syntax.TimeClause:
		if c.Stmt != nil {
			it.execStmt(c.Stmt)
		}
	case *syntax.CoprocClause:
		saved := it.state
		it.state = it.state.Clone()
		if c.Stmt != nil {
			it.execStmt(c.Stmt)
		}
		it.state = saved
	case *syntax.ArithmCmd, *syntax.TestClause, *syntax.LetClause:
		it.status, it.statusKnown = 0, false
	default:
		it.addNote("unsupported construct at " + fromMvdanPos(c.Pos()).String())
	}
}

// ===========================================================================
// Pipelines and AND/OR lists
// ===========================================================================

func (it *interp) execBinary(b *syntax.BinaryCmd) {
	switch b.Op {
	case syntax.Pipe, syntax.PipeAll:
		it.execPipeline(b)
	case syntax.AndStmt, syntax.OrStmt:
		it.execAndOr(b)
	}
}

// execPipeline runs every stage of a pipeline in its own subshell copy of Σ,
// threading the (folded) standard output of each stage into the next — this is
// the pipeline's value flow. A stage that is a code-execution sink turns the
// flowing value into executed code, which the sink itself reports as ⊤ when it
// is dispatched.
func (it *interp) execPipeline(b *syntax.BinaryCmd) {
	stages := it.flattenPipeline(b)

	savedIn, savedKnown, savedTaint := it.stdin, it.stdinKnown, it.stdinTaint
	in, inKnown, inTaint := it.stdin, it.stdinKnown, it.stdinTaint
	for _, st := range stages {
		it.stdin, it.stdinKnown, it.stdinTaint = in, inKnown, inTaint
		savedState := it.state
		it.state = it.state.Clone()
		it.stdout, it.stdoutKnown, it.stdoutTaint = "", false, engine.TaintBottom()
		it.execStmt(st)
		out, ok, outTaint := it.stdout, it.stdoutKnown, it.stdoutTaint
		it.state = savedState
		in, inKnown, inTaint = out, ok, outTaint
	}
	it.stdin, it.stdinKnown, it.stdinTaint = savedIn, savedKnown, savedTaint
	it.status, it.statusKnown = 0, false
}

func (it *interp) flattenPipeline(b *syntax.BinaryCmd) []*syntax.Stmt {
	var out []*syntax.Stmt
	var walk func(x *syntax.Stmt)
	walk = func(x *syntax.Stmt) {
		if x == nil {
			return
		}
		if bc, ok := x.Cmd.(*syntax.BinaryCmd); ok && (bc.Op == syntax.Pipe || bc.Op == syntax.PipeAll) {
			walk(bc.X)
			walk(bc.Y)
			return
		}
		out = append(out, x)
	}
	walk(b.X)
	walk(b.Y)
	return out
}

// execAndOr runs the right-hand side only when the left-hand side's exit status
// makes it reachable; an unknown status conservatively runs it.
func (it *interp) execAndOr(b *syntax.BinaryCmd) {
	it.execStmt(b.X)
	val, known := it.status, it.statusKnown
	run := true
	if known {
		if b.Op == syntax.AndStmt {
			run = val == 0
		} else {
			run = val != 0
		}
	}
	if run {
		it.execStmt(b.Y)
	}
}

// ===========================================================================
// Control flow
// ===========================================================================

func (it *interp) execIf(c *syntax.IfClause) {
	it.execStmts(c.Cond)
	val, known := it.status, it.statusKnown
	if known {
		if val == 0 {
			it.execStmts(c.Then)
		} else {
			it.execElse(c.Else)
		}
		return
	}
	// Undecidable condition: execute both branches and join both the effects
	// (already accumulated) and the two resulting states.
	base := it.state.Clone()
	it.execStmts(c.Then)
	a := it.state
	it.state = base
	it.execElse(c.Else)
	b := it.state
	it.state = joinStates(a, b)
	it.status, it.statusKnown = 0, false
}

func (it *interp) execElse(e *syntax.IfClause) {
	if e == nil {
		return
	}
	if len(e.Cond) > 0 { // elif
		it.execIf(e)
		return
	}
	it.execStmts(e.Then)
}

func (it *interp) execWhile(c *syntax.WhileClause) {
	for {
		it.step()
		it.execStmts(c.Cond)
		val, known := it.status, it.statusKnown
		ok := val == 0
		if c.Until {
			ok = !ok
		}
		if !known {
			it.execStmts(c.Do)
			it.markTop("loop condition is not statically decidable")
			it.handleLoopCtl()
			return
		}
		if !ok {
			return
		}
		it.execStmts(c.Do)
		if it.handleLoopCtl() {
			return
		}
	}
}

func (it *interp) execFor(c *syntax.ForClause) {
	switch loop := c.Loop.(type) {
	case *syntax.WordIter:
		name := ""
		if loop.Name != nil {
			name = loop.Name.Value
		}
		if !loop.InPos.IsValid() && len(loop.Items) == 0 {
			it.state.SetUnknown(name, engine.TaintBottom())
			it.execStmts(c.Do)
			it.markTop("for-loop over positional parameters")
			it.handleLoopCtl()
			return
		}
		var vals []string
		known := true
		for _, w := range loop.Items {
			ew := it.expandFields(w)
			if !ew.known {
				known = false
			}
			vals = append(vals, ew.fields...)
		}
		if !known {
			it.state.SetUnknown(name, engine.TaintBottom())
			it.execStmts(c.Do)
			it.markTop("for-loop over a dynamically-known word list")
			it.handleLoopCtl()
			return
		}
		for _, v := range vals {
			it.step()
			if name != "" {
				it.state.SetKnown(name, v, engine.TaintBottom())
			}
			it.execStmts(c.Do)
			if it.handleLoopCtl() {
				return
			}
		}

	case *syntax.CStyleLoop:
		// Without modelling the arithmetic, a C-style loop is treated like a
		// loop with an unknown bound: iterate until the budget stops it.
		for {
			it.step()
			it.execStmts(c.Do)
			if it.handleLoopCtl() {
				return
			}
		}
	}
}

// handleLoopCtl consumes a break/continue issued by a loop body, returning true
// when the loop must stop (break, or an enclosing return/exit).
func (it *interp) handleLoopCtl() (stop bool) {
	switch it.ctl {
	case ctlBreak:
		it.ctl = ctlNone
		return true
	case ctlContinue:
		it.ctl = ctlNone
		return false
	case ctlReturn, ctlExit:
		return true
	}
	return false
}

func (it *interp) execCase(c *syntax.CaseClause) {
	subj := ""
	known := true
	if c.Word != nil {
		subj, known, _ = it.expandLiteral(c.Word)
	}
	if !known {
		for _, item := range c.Items {
			it.execStmts(item.Stmts)
		}
		it.markTop("case subject is not statically decidable")
		return
	}
	var def []*syntax.Stmt
	for _, item := range c.Items {
		if len(item.Patterns) == 0 {
			def = item.Stmts
			continue
		}
		if it.caseMatch(subj, item.Patterns) {
			it.execStmts(item.Stmts)
			return
		}
	}
	if def != nil {
		it.execStmts(def)
	}
}

func (it *interp) caseMatch(subj string, pats []*syntax.Word) bool {
	for _, p := range pats {
		pat, known, _ := it.expandLiteral(p)
		if !known {
			return false
		}
		if ok, err := path.Match(pat, subj); err == nil && ok {
			return true
		}
	}
	return false
}

func (it *interp) execFuncDecl(c *syntax.FuncDecl) {
	if c.Name == nil {
		return
	}
	name := c.Name.Value
	it.funcRaw[name] = c
	if it.state.Funcs == nil {
		it.state.Funcs = map[string]*Func{}
	}
	it.state.Funcs[name] = &Func{Pos: fromMvdanPos(c.Name.Pos()), Name: name}
}

// execDecl applies the state component of declare/local/export/readonly and asks
// the resolver for the effects the declaration itself contributes.
func (it *interp) execDecl(c *syntax.DeclClause) {
	variant := ""
	if c.Variant != nil {
		variant = c.Variant.Value
	}
	var args []string
	for _, a := range c.Args {
		if a == nil || a.Name == nil {
			continue
		}
		name := a.Name.Value
		if name == "" || strings.HasPrefix(name, "-") {
			continue
		}
		val, known := "", true
		taint := engine.TaintBottom()
		if a.Value != nil {
			val, known, taint = it.expandLiteral(a.Value)
		}
		if known {
			it.state.SetKnown(name, val, taint)
		} else {
			it.state.SetUnknown(name, taint)
		}
		if v := it.state.Get(name); v != nil {
			switch variant {
			case "export":
				v.Export = true
			case "readonly":
				v.Readonly = true
			}
		}
		args = append(args, name+"="+val)
	}
	if variant == "" || it.res == nil {
		return
	}
	cmd := &Command{Pos: fromMvdanPos(c.Pos()), Name: variant, NameWord: &Word{Value: variant, Literal: true}}
	for _, a := range args {
		cmd.Args = append(cmd.Args, &Word{Value: a, Literal: true})
	}
	it.addCmd(cmd)
	declRes := it.res(cmd, it.prog)
	it.effs = append(it.effs, declRes.Effects...)
	it.ders = append(it.ders, declRes.Derivations...)
}

// ===========================================================================
// Simple commands
// ===========================================================================

// argWord is one expanded argument together with whether it is statically known
// and the provenance of its value. pos is the source position of the word it
// came from, so the normalized invocation keeps a location for the binding
// layer's why-trace atoms.
type argWord struct {
	val   string
	lit   bool
	taint engine.Taint
	pos   Pos
}

func (it *interp) execCall(c *syntax.CallExpr) {
	// Effects from the start of this command — including the filesystem reads a
	// command substitution performs while the command's words are expanded — are
	// what determine the provenance of its stdout, so note where they begin.
	effStart := len(it.effs)
	it.stdout, it.stdoutKnown, it.stdoutTaint = "", false, engine.TaintBottom()

	// 1. Environment assignments. A bare assignment persists in Σ; an
	// assignment prefixing a command only applies to that command.
	var assigns []*Assign
	for _, a := range c.Assigns {
		if a == nil || a.Name == nil {
			continue
		}
		name := a.Name.Value
		val, known := "", true
		taint := engine.TaintBottom()
		if a.Value != nil {
			val, known, taint = it.expandLiteral(a.Value)
		}
		as := &Assign{Pos: fromMvdanPos(a.Pos()), Name: name, Append: a.Append}
		as.Value = &Word{Value: val, Literal: known, Taint: taint}
		assigns = append(assigns, as)
		ew := envWriteEffect(name, taint)
		it.effs = append(it.effs, ew)
		it.derive(ew, engine.Atom{Kind: engine.AtomLiteral, Text: name, Loc: sourceLoc(as.Pos, it.prog.File)})
		if len(c.Args) == 0 {
			if known {
				it.state.SetKnown(name, val, taint)
			} else {
				it.state.SetUnknown(name, taint)
			}
		}
	}

	// 2. Peel recognized wrappers (sudo, env, …) and pick up the environment
	// they donate, reusing the normalizer's unwrapping.
	wrappers, wEnv, start := it.norm.unwrap(c.Args)
	for _, we := range wEnv {
		assigns = append(assigns, we)
		ew := envWriteEffect(we.Name, engine.TaintBottom())
		it.effs = append(it.effs, ew)
		it.derive(ew, engine.Atom{Kind: engine.AtomLiteral, Text: we.Name, Loc: sourceLoc(we.Pos, it.prog.File)})
	}
	rest := c.Args[start:]

	// 3. Expand the effective command words.
	var (
		name   string
		nameOK bool
		argvW  []argWord
	)
	if len(rest) > 0 {
		ew0 := it.expandFields(rest[0])
		if ew0.known && len(ew0.fields) > 0 {
			name, nameOK = ew0.fields[0], true
		}
		for _, f := range ew0.fields[min(1, len(ew0.fields)):] {
			argvW = append(argvW, argWord{val: f, lit: ew0.known, taint: ew0.taint, pos: fromMvdanPos(rest[0].Pos())})
		}
		for _, w := range rest[1:] {
			ew := it.expandFields(w)
			for _, f := range ew.fields {
				argvW = append(argvW, argWord{val: f, lit: ew.known, taint: ew.taint, pos: fromMvdanPos(w.Pos())})
			}
		}
	}

	// 4. Build the normalized invocation handed to the binding layer.
	pos := fromMvdanPos(c.Pos())
	var nameWord *Word
	if nameOK {
		nameWord = &Word{Value: name, Literal: true}
	} else if len(rest) > 0 {
		nameWord = &Word{Value: "", Literal: false}
	}
	cmd := &Command{Pos: pos, Name: name, NameWord: nameWord, Wrappers: wrappers, Assigns: assigns, StdinTaint: it.stdinTaint}
	argv := make([]string, 0, len(argvW))
	for _, a := range argvW {
		cmd.Args = append(cmd.Args, &Word{Value: a.val, Literal: a.lit, Taint: a.taint, Pos: a.pos})
		argv = append(argv, a.val)
	}
	it.addCmd(cmd)

	// 5. No command word: a bare assignment / redirection.
	if len(rest) == 0 {
		it.stdout, it.stdoutKnown = "", true
		return
	}

	// 6. Fold stdout, then dispatch. The effects this command contributed —
	// its own, plus those its argument expansions performed — also determine
	// the provenance of what it writes to stdout, which a following pipeline
	// stage reads as its stdin.
	if nameOK {
		it.stdout, it.stdoutKnown = it.stdoutOf(name, argv)
	} else {
		it.stdout, it.stdoutKnown = "", false
	}
	it.dispatch(name, nameOK, argv, cmd)
	it.stdoutTaint = outTaintOf(it.effs[effStart:], it.stdinTaint)
}

// dispatch applies the name-resolution chain with the interpreter's own state:
// aliases are expanded, functions are executed, code-execution sinks and
// code-executing builtins yield ⊤, and every other command's effects come from
// the resolver.
func (it *interp) dispatch(name string, nameOK bool, argv []string, cmd *Command) []engine.Effect {
	if !nameOK {
		e := it.markTopEffect("dynamically-named command")
		it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: cmd.Name, Loc: sourceLoc(cmd.Pos, it.prog.File)})
		it.statusKnown = false
		return nil
	}

	// alias expansion (bounded, then handed to the interpreter proper)
	for depth := 0; depth < maxAliasDepth; depth++ {
		body, ok := it.state.Aliases[name]
		if !ok {
			break
		}
		nn, nargs, ok2 := it.expandAliasValue(body)
		if !ok2 {
			break
		}
		argv = append(append([]string{}, nargs...), argv...)
		name = nn
	}

	// shell functions declared by the program
	if fd := it.funcRaw[name]; fd != nil {
		it.callFunc(fd, argv)
		it.setStatus(name)
		return nil
	}

	// code-execution sinks: data flowing in is data executed
	if isSink(name) {
		e := it.markTopEffect("code-execution sink " + strconv.Quote(name))
		it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: name, Loc: sourceLoc(cmd.Pos, it.prog.File)})
		it.setStatus(name)
		return nil
	}

	// builtins that mutate Σ
	it.builtinState(name, argv)

	// builtins that execute code supplied at run time
	if isCodeExecBuiltin(name) {
		e := it.markTopEffect("code-executing builtin " + strconv.Quote(name))
		it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: name, Loc: sourceLoc(cmd.Pos, it.prog.File)})
		it.setStatus(name)
		return nil
	}

	// builtins that are pure shell state: they have no external effect, so
	// asking the knowledge base about them would only produce a spurious ⊤.
	if isShellOnlyBuiltin(name) {
		switch name {
		case "break":
			it.ctl = ctlBreak
		case "continue":
			it.ctl = ctlContinue
		case "return":
			it.ctl = ctlReturn
		case "exit":
			it.ctl = ctlExit
		}
		it.setStatus(name)
		return nil
	}

	// declared effects, from the binding layer
	if it.res == nil {
		it.addNote("no effect resolver bound for " + strconv.Quote(name))
		it.setStatus(name)
		return nil
	}
	bound := it.res(cmd, it.prog)
	it.effs = append(it.effs, bound.Effects...)
	it.ders = append(it.ders, bound.Derivations...)
	it.setStatus(name)
	return bound.Effects
}

// outTaintOf returns the provenance of the data a command writes to its standard
// output, given the effects it contributes and the provenance of what it reads
// on standard input. It is deliberately a per-command over-approximation: a
// command may echo to stdout anything it read (filesystem reads, credential
// access) or was fed on stdin, and network responses it received are
// attacker-influenced. Keeping the join per-command — and not per-script — is
// what makes an egress pairing a real data flow rather than mere co-occurrence.
func outTaintOf(effs []engine.Effect, stdinTaint engine.Taint) engine.Taint {
	t := stdinTaint
	for _, e := range effs {
		switch e.Kind {
		case engine.KindFSRead:
			t = t.Join(e.Taint)
			for _, tg := range e.Target.Targets() {
				if engine.SecretPath(tg) {
					t = t.Join(engine.TaintOf(engine.TaintSecret))
				}
			}
		case engine.KindCredAccess:
			t = t.Join(e.Taint).Join(engine.TaintOf(engine.TaintSecret))
		case engine.KindNetIngress:
			t = t.Join(engine.TaintOf(engine.TaintUntrusted))
		}
	}
	return t
}

// setStatus records the exit status of a command when it is statically known.
func (it *interp) setStatus(name string) {
	switch name {
	case "true", ":":
		it.status, it.statusKnown = 0, true
	case "false":
		it.status, it.statusKnown = 1, true
	default:
		it.statusKnown = false
	}
}

// expandAliasValue parses an alias body into the command name and leading
// arguments it stands for.
func (it *interp) expandAliasValue(body string) (string, []string, bool) {
	p := Parse(Bash, "<alias>", body)
	if p.Top || len(p.Stmts) != 1 {
		return "", nil, false
	}
	s := p.Stmts[0]
	if s == nil || s.Kind != KindSimple || s.Cmd == nil || s.Cmd.Name == "" {
		return "", nil, false
	}
	args := make([]string, 0, len(s.Cmd.Args))
	for _, w := range s.Cmd.Args {
		args = append(args, w.Value)
	}
	return s.Cmd.Name, args, true
}

// callFunc executes a function body with positional parameters bound in a fresh
// copy of Σ.
func (it *interp) callFunc(fd *syntax.FuncDecl, argv []string) {
	if fd == nil || fd.Name == nil {
		return
	}
	name := fd.Name.Value
	if it.depth >= maxFuncDepth {
		it.markTopEffect("function recursion limit reached at " + strconv.Quote(name))
		return
	}
	saved := it.state
	it.state = it.state.Clone()
	it.depth++
	it.state.SetKnown("0", name, engine.TaintBottom())
	it.state.SetKnown("#", strconv.Itoa(len(argv)), engine.TaintBottom())
	it.state.SetKnown("@", strings.Join(argv, " "), engine.TaintBottom())
	it.state.SetKnown("*", strings.Join(argv, " "), engine.TaintBottom())
	for i, a := range argv {
		it.state.SetKnown(strconv.Itoa(i+1), a, engine.TaintBottom())
	}
	if fd.Body != nil {
		it.execStmt(fd.Body)
	}
	it.depth--
	it.state = saved
	if it.ctl == ctlReturn {
		it.ctl = ctlNone
	}
}

// ===========================================================================
// Redirections
// ===========================================================================

func (it *interp) redir(r *syntax.Redirect) {
	if r == nil {
		return
	}
	it.step()
	switch r.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		it.redirectTarget(r.Word, false)
	case syntax.RdrIn:
		it.redirectTarget(r.Word, true)
	case syntax.RdrInOut:
		it.redirectTarget(r.Word, true)
		it.redirectTarget(r.Word, false)
	case syntax.DplOut, syntax.DplIn:
		it.emit(engine.KindStdio, engine.ScopeBottom(), engine.ModeDirect, engine.CertaintyCertain, engine.TaintBottom(), it.redirectAtom(fromMvdanPos(r.Pos()), r.Op.String()))
	case syntax.Hdoc, syntax.DashHdoc:
		it.heredoc(r.Hdoc)
	case syntax.WordHdoc:
		it.expandLiteral(r.Word)
		it.emit(engine.KindStdio, engine.ScopeBottom(), engine.ModeDirect, engine.CertaintyCertain, engine.TaintBottom(), it.redirectAtom(fromMvdanPos(r.Pos()), r.Op.String()))
	default:
		it.emit(engine.KindStdio, engine.ScopeBottom(), engine.ModeDirect, engine.CertaintyCertain, engine.TaintBottom(), it.redirectAtom(fromMvdanPos(r.Pos()), r.Op.String()))
	}
}

// redirectTarget emits the effect of a file redirection, recognizing the bash
// /dev/tcp and /dev/udp pseudo-files as network effects.
func (it *interp) redirectTarget(w *syntax.Word, reading bool) {
	val, known, taint := it.expandLiteral(w)
	if host, port, isTCP, ok := devNet(val); ok {
		kind := engine.KindNetEgress
		if reading {
			kind = engine.KindNetIngress
		}
		target := engine.ScopeTop()
		if known {
			target = engine.ScopeOf(host + ":" + port)
		}
		it.emit(kind, target, engine.ModeDirect, engine.CertaintyCertain, taint, it.redirectAtom(fromMvdanPos(w.Pos()), host+":"+port))
		_ = isTCP
		it.emit(engine.KindIPC, engine.ScopeBottom(), engine.ModeAmbient, engine.CertaintyLikely, taint, it.redirectAtom(fromMvdanPos(w.Pos()), host+":"+port))
		return
	}
	kind := engine.KindFSWrite
	if reading {
		kind = engine.KindFSRead
	}
	target := engine.ScopeBottom()
	switch {
	case !known:
		target = engine.ScopeTop()
	case val != "":
		target = engine.ScopeOf(val)
	}
	if reading {
		// `cmd < file` feeds the file's content to the command's standard
		// input: record its provenance so an egress fed only by the
		// redirection is still seen to carry the data out.
		content := taint
		if engine.SecretPath(val) {
			content = content.Join(engine.TaintOf(engine.TaintSecret))
		}
		it.stdinTaint = it.stdinTaint.Join(content)
	}
	it.emit(kind, target, engine.ModeDirect, engine.CertaintyCertain, taint, it.redirectAtom(fromMvdanPos(w.Pos()), val))
}

// devNet parses a /dev/tcp or /dev/udp pseudo-path into its host and port.
func devNet(s string) (host, port string, isTCP, ok bool) {
	const tcp, udp = "/dev/tcp/", "/dev/udp/"
	var rest string
	switch {
	case strings.HasPrefix(s, tcp):
		rest, isTCP = s[len(tcp):], true
	case strings.HasPrefix(s, udp):
		rest = s[len(udp):]
	default:
		return "", "", false, false
	}
	h, p, _ := strings.Cut(rest, "/")
	return h, p, isTCP, true
}

func (it *interp) heredoc(w *syntax.Word) {
	it.expandLiteral(w)
	pos := Pos{}
	if w != nil {
		pos = fromMvdanPos(w.Pos())
	}
	it.emit(engine.KindStdio, engine.ScopeBottom(), engine.ModeDirect, engine.CertaintyCertain, engine.TaintBottom(), it.redirectAtom(pos, "<<"))
}

// ===========================================================================
// Command and process substitution
// ===========================================================================

// captureSubst executes a command-substitution body in a subshell and returns
// the stdout it folded to, together with whether that stdout is statically
// known and its provenance.
func (it *interp) captureSubst(cs *syntax.CmdSubst) (string, bool, engine.Taint) {
	if cs == nil {
		return "", true, engine.TaintBottom()
	}
	savedState := it.state
	savedOut, savedKnown := it.stdout, it.stdoutKnown
	savedTaint := it.stdoutTaint
	savedCtl := it.ctl
	it.state = it.state.Clone()
	it.stdout, it.stdoutKnown, it.stdoutTaint = "", false, engine.TaintBottom()
	it.ctl = ctlNone
	it.execStmts(cs.Stmts)
	out, known, taint := it.stdout, it.stdoutKnown, it.stdoutTaint
	it.state = savedState
	it.stdout, it.stdoutKnown, it.stdoutTaint = savedOut, savedKnown, savedTaint
	it.ctl = savedCtl
	return out, known, taint
}

func (it *interp) execProcSubst(ps *syntax.ProcSubst) {
	if ps == nil {
		return
	}
	savedState := it.state
	savedCtl := it.ctl
	it.state = it.state.Clone()
	it.ctl = ctlNone
	it.execStmts(ps.Stmts)
	it.state = savedState
	it.ctl = savedCtl
}

// ===========================================================================
// Helpers
// ===========================================================================

// addNote records an explanatory note, bounded so a runaway loop cannot grow
// the list without limit.
func (it *interp) addNote(s string) {
	if len(it.notes) < maxRecorded {
		it.notes = append(it.notes, s)
	}
}

// addCmd records one resolved invocation, with the same bound as addNote.
func (it *interp) addCmd(c *Command) {
	if len(it.cmds) < maxRecorded {
		it.cmds = append(it.cmds, c)
	}
}

func dedupStrings(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(xs))
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
