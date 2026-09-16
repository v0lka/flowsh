package bash

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/expand"
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
	// loopDepth counts the enclosing loops; a break/continue is only consumed
	// when it is > 0, so an unconsumed loop-control builtin is ignored (as bash
	// does) instead of silently abandoning the rest of the statement list.
	loopDepth int

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

	// substMemo/procMemo memoise the substitution side effects already performed
	// within the statement currently being interpreted, so that a word whose
	// substitutions are expanded twice — a `[[ … ]]` clause is walked once by
	// expandSubstsIn and again by testFileReads — runs each substitution only
	// once. They are non-nil only while such a clause is being executed.
	substMemo map[*syntax.CmdSubst]substInfo
	procMemo  map[*syntax.ProcSubst]bool

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
		// Aliases are intentionally NOT preloaded: bash applies an alias only
		// from the point it is declared, so they are installed by the `alias`
		// builtin as the program executes (see builtinState). Preloading them
		// would let a later declaration rewrite an earlier use.
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

// resolutionProgram returns the program handed to the resolver, restricted to
// the aliases declared so far. bash applies an alias only from the point it is
// declared, so a declaration that runs after a use (or never runs) must not
// rewrite that use; the interpreter installs aliases as the `alias` builtin
// executes, and this view keeps the binder's own alias resolution in step.
func (it *interp) resolutionProgram() *Program {
	if it.prog == nil || len(it.prog.Aliases) == 0 {
		return it.prog
	}
	p := *it.prog
	p.Aliases = make(map[string]*Alias, len(it.state.Aliases))
	for n, v := range it.state.Aliases {
		p.Aliases[n] = &Alias{Name: n, Value: v}
	}
	return &p
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
	if nestingTooDeep(src) {
		return topResult(v, name, src, "input nesting too deep")
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
	// The JSON contract requires `reason` whenever `conservative` or `top` is
	// set: a result made conservative by an ordinary ⊤ effect (rather than by
	// markTop) still needs an explanation.
	reason := it.reason
	if cons && reason == "" {
		reason = "analysis includes an unbounded (⊤) effect"
	}
	return &ExecResult{
		Variant:         it.prog.Variant,
		File:            it.prog.File,
		Source:          it.prog.Source,
		Top:             it.top,
		Reason:          reason,
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
			// A control-flow signal that no enclosing construct can consume is a
			// no-op in bash (only `exit` is terminal everywhere): reset it and
			// keep executing, so a stray break/continue/return cannot suppress
			// the rest of the statement list.
			switch it.ctl {
			case ctlExit:
				return
			case ctlReturn:
				if it.depth == 0 {
					it.addNote("return outside a function; ignored")
					it.ctl = ctlNone
					break
				}
				return
			default: // ctlBreak, ctlContinue
				if it.loopDepth == 0 {
					it.addNote("loop-control builtin outside a loop; ignored")
					it.ctl = ctlNone
					break
				}
				return
			}
		}
		it.execStmt(s)
	}
}

func (it *interp) execStmt(s *syntax.Stmt) {
	if s == nil {
		return
	}
	it.step()
	// Reset the exit status so a stale value from an earlier statement can never
	// leak into a condition or an && / || operand of this one. Statements that
	// compute no status (a bare assignment, a declaration, a function
	// definition) leave it unknown, so both branches of a dependent operator are
	// explored — conservative, never a miss.
	it.status, it.statusKnown = 0, false
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
		savedCtl := it.ctl
		it.state = it.state.Clone()
		// A background job (or coprocess) runs in its own subshell: a
		// control-flow signal it raises must not escape to the enclosing
		// statement list.
		it.ctl = ctlNone
		it.execCommand(s.Cmd)
		it.state = saved
		it.ctl = savedCtl
		// Launching a job succeeds regardless of the job's own exit status.
		it.status, it.statusKnown = 0, true
		return
	}
	it.execCommand(s.Cmd)
	// `! cmd` inverts the command's exit status (bash semantics), which decides
	// the reachable branch of a following if / && / || / while.
	if s.Negated && it.statusKnown {
		if it.status == 0 {
			it.status = 1
		} else {
			it.status = 0
		}
	}
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
		savedCtl := it.ctl
		it.state = it.state.Clone()
		// A subshell runs in its own shell: a control-flow signal it raises must
		// be confined to it, never abort the enclosing statement list.
		it.ctl = ctlNone
		it.execStmts(c.Stmts)
		it.state = saved
		it.ctl = savedCtl
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
		savedCtl := it.ctl
		it.state = it.state.Clone()
		it.ctl = ctlNone
		if c.Stmt != nil {
			it.execStmt(c.Stmt)
		}
		it.state = saved
		it.ctl = savedCtl
	case *syntax.ArithmCmd:
		// Walk the expression so any command/process substitution inside it is
		// executed (its effects recorded); the command's own status is unknown.
		it.expandSubstsIn(c)
		it.status, it.statusKnown = 0, false
	case *syntax.TestClause:
		// A `[[ … ]]` clause expands each of its words twice — once by
		// expandSubstsIn (to run any command/process substitution) and again by
		// testFileReads (to resolve the file-test operand). Memoise within this
		// clause so each substitution's effects run exactly once.
		substMemo, procMemo := it.substMemo, it.procMemo
		it.substMemo = make(map[*syntax.CmdSubst]substInfo)
		it.procMemo = make(map[*syntax.ProcSubst]bool)
		it.expandSubstsIn(c)
		it.testFileReads(c)
		it.substMemo, it.procMemo = substMemo, procMemo
		it.status, it.statusKnown = 0, false
	case *syntax.LetClause:
		it.expandSubstsIn(c)
		it.status, it.statusKnown = 0, false
	default:
		// An unhandled construct must not silently drop its effects: record a ⊤
		// effect and a note rather than only a note.
		e := it.markTopEffect("unsupported construct at " + fromMvdanPos(c.Pos()).String())
		it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: it.src, Loc: sourceLoc(fromMvdanPos(c.Pos()), it.prog.File)})
		it.status, it.statusKnown = 0, false
	}
}

// testFileReads reports the filesystem read implied by a file-test operator in a
// `[[ … ]]` conditional ([[ -f /etc/passwd ]]), which the generic expansion does
// not model.
func (it *interp) testFileReads(c *syntax.TestClause) {
	if c == nil || c.X == nil {
		return
	}
	syntax.Walk(c.X, func(n syntax.Node) bool {
		ut, ok := n.(*syntax.UnaryTest)
		if !ok {
			return true
		}
		w, ok := ut.X.(*syntax.Word)
		if !ok {
			return true
		}
		switch ut.Op.String() {
		case "-e", "-f", "-d", "-r", "-w", "-x", "-s", "-L", "-h", "-b", "-c", "-p", "-S", "-g", "-u", "-k", "-N":
			val, known, taint := it.expandLiteral(w)
			if !known {
				it.emit(engine.KindFSRead, engine.ScopeTop(), engine.ModeDirect, engine.CertaintyCertain, taint, it.redirectAtom(fromMvdanPos(w.Pos()), "-test"))
				return true
			}
			if val != "" {
				it.emit(engine.KindFSRead, engine.ScopeOf(val), engine.ModeDirect, engine.CertaintyCertain, taint, it.redirectAtom(fromMvdanPos(w.Pos()), "-test"))
			}
		}
		return true
	})
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
		savedCtl := it.ctl
		it.state = it.state.Clone()
		// Each pipeline stage runs in its own subshell; confine any control-flow
		// signal it raises so it cannot abort the enclosing statement list.
		it.ctl = ctlNone
		it.stdout, it.stdoutKnown, it.stdoutTaint = "", false, engine.TaintBottom()
		it.execStmt(st)
		out, ok, outTaint := it.stdout, it.stdoutKnown, it.stdoutTaint
		it.state = savedState
		it.ctl = savedCtl
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
		if !known {
			// The RHS is executed only speculatively (the LHS status is
			// unknown): a terminal control-flow signal it raises must not escape
			// and abort the enclosing statement list.
			savedCtl := it.ctl
			it.ctl = ctlNone
			it.execStmt(b.Y)
			it.ctl = savedCtl
			it.statusKnown = false
			return
		}
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
		switch {
		case val == 0:
			if len(c.Then) == 0 {
				it.status, it.statusKnown = 0, true
			} else {
				it.execStmts(c.Then)
			}
		case c.Else == nil || (len(c.Else.Cond) == 0 && len(c.Else.Then) == 0):
			// No branch taken: an `if` that runs nothing exits 0.
			it.status, it.statusKnown = 0, true
		default:
			it.execElse(c.Else)
		}
		return
	}
	// Undecidable condition: execute both branches and join both the effects
	// (already accumulated) and the two resulting states. A control-flow signal
	// raised inside a speculatively executed branch must not escape it.
	savedCtl := it.ctl
	it.ctl = ctlNone
	base := it.state.Clone()
	it.execStmts(c.Then)
	a := it.state
	it.state = base
	it.ctl = ctlNone
	it.execElse(c.Else)
	b := it.state
	it.state = joinStates(a, b)
	it.ctl = savedCtl
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
	it.loopDepth++
	defer func() { it.loopDepth-- }()
	ran := false
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
			if !ran {
				// The loop never ran: its exit status is 0.
				it.status, it.statusKnown = 0, true
			} else {
				it.statusKnown = false
			}
			return
		}
		ran = true
		it.execStmts(c.Do)
		if it.handleLoopCtl() {
			return
		}
	}
}

func (it *interp) execFor(c *syntax.ForClause) {
	it.loopDepth++
	defer func() { it.loopDepth-- }()
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
		if len(vals) == 0 {
			// The loop ran no iterations: its exit status is 0.
			it.status, it.statusKnown = 0, true
		}

	case *syntax.CStyleLoop:
		// Walk the arithmetic clauses so any command/process substitution in the
		// init/cond/post expressions is executed (its effects recorded).
		if loop.Init != nil {
			it.expandSubstsIn(loop.Init)
		}
		if loop.Cond != nil {
			it.expandSubstsIn(loop.Cond)
		}
		if loop.Post != nil {
			it.expandSubstsIn(loop.Post)
		}
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
	defIdx := -1
	for i, item := range c.Items {
		if len(item.Patterns) == 0 {
			if defIdx < 0 {
				defIdx = i
			}
			continue
		}
		matched, unknown := it.caseMatch(subj, item.Patterns)
		if unknown {
			// A pattern that cannot be decided (a dynamic word) might match:
			// run its arm and degrade to ⊤ rather than silently drop it.
			it.execStmts(item.Stmts)
			it.markTop("case pattern is not statically decidable")
			return
		}
		if !matched {
			continue
		}
		it.execStmts(item.Stmts)
		switch item.Op.String() {
		case ";&":
			// Fall through: run every following arm's body until one ends in
			// ";;" (a ";"-terminated arm does not continue the fall-through).
			for j := i + 1; j < len(c.Items); j++ {
				it.execStmts(c.Items[j].Stmts)
				if c.Items[j].Op.String() != ";&" {
					break
				}
			}
		case ";;&":
			// Resume matching: keep testing the remaining arms.
			for j := i + 1; j < len(c.Items); j++ {
				m2, unk2 := it.caseMatch(subj, c.Items[j].Patterns)
				if unk2 {
					it.execStmts(c.Items[j].Stmts)
					it.markTop("case pattern is not statically decidable")
					return
				}
				if m2 {
					it.execStmts(c.Items[j].Stmts)
					if c.Items[j].Op.String() != ";;&" {
						break
					}
				}
			}
		}
		return
	}
	if defIdx >= 0 {
		it.execStmts(c.Items[defIdx].Stmts)
		return
	}
	// No arm matched and there is no default: the case exits 0.
	it.status, it.statusKnown = 0, true
}

// caseMatch reports whether any of pats matches subj. The second result is true
// when a pattern cannot be decided statically (it must then be treated as
// possibly matching, never as a non-match).
func (it *interp) caseMatch(subj string, pats []*syntax.Word) (matched, unknown bool) {
	for _, p := range pats {
		pat, ok := it.casePattern(p)
		if !ok {
			return false, true
		}
		m, ok := globMatch(pat, subj)
		if !ok {
			// The pattern uses a construct the matcher cannot faithfully
			// evaluate: it must be treated as possibly matching, never as a
			// non-match, so the arm is not silently dropped.
			return false, true
		}
		if m {
			return true, false
		}
	}
	return false, false
}

// casePattern expands a case pattern word to its pattern text. A pattern word is
// "known" even when it contains shell glob syntax (a legitimate part of a case
// pattern), so only a genuinely dynamic word yields ok=false.
func (it *interp) casePattern(p *syntax.Word) (string, bool) {
	if p == nil {
		return "", true
	}
	if !it.patternKnown(p) {
		return "", false
	}
	var out string
	bad := false
	func() {
		defer func() {
			if recover() != nil {
				bad = true
			}
		}()
		s, err := expand.Literal(it.newCfg(), p)
		if err != nil {
			bad = true
			return
		}
		out = s
	}()
	if bad {
		return "", false
	}
	return out, true
}

// patternKnown reports whether a case-pattern word's text is statically
// determinable; unlike wordKnown, unquoted glob metacharacters are treated as
// known pattern syntax rather than as unknown content.
func (it *interp) patternKnown(w *syntax.Word) bool {
	if w == nil {
		return true
	}
	for _, p := range w.Parts {
		if !it.patternPartKnown(p) {
			return false
		}
	}
	return true
}

func (it *interp) patternPartKnown(p syntax.WordPart) bool {
	switch p := p.(type) {
	case *syntax.Lit:
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
	case *syntax.ExtGlob:
		return true
	default:
		return it.partKnown(p, false)
	}
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
// the resolver for the effects the declaration itself contributes. Option flags
// are forwarded to the binder (so a KB flag such as `export -p` matches), and
// the operand is the variable NAME (not NAME=value).
func (it *interp) execDecl(c *syntax.DeclClause) {
	variant := ""
	if c.Variant != nil {
		variant = c.Variant.Value
	}
	var (
		flags     []string
		opNames   []string
		nameref   bool
		integer   bool
		unmodeled bool
	)
	for _, a := range c.Args {
		if a == nil {
			continue
		}
		if a.Name == nil {
			// A flag (or a name-only operand): both carry their text in Value.
			if a.Value == nil {
				continue
			}
			v, ok := literalOf(a.Value)
			if !ok {
				continue
			}
			flags = append(flags, v)
			switch v {
			case "-n":
				nameref = true
			case "-i":
				integer = true
			case "-l", "-u":
				unmodeled = true
			}
			continue
		}
		name := a.Name.Value
		if name == "" {
			continue
		}
		val, known := "", true
		taint := engine.TaintBottom()
		if a.Value != nil {
			val, known, taint = it.expandLiteral(a.Value)
		}
		switch {
		case nameref:
			// A nameref aliases another variable; it is not resolved, so reads of
			// it must degrade to ⊤ rather than yield the target's name.
			it.state.SetUnknown(name, taint)
		case unmodeled:
			// -l/-u (case folding) are not modelled: invalidate the value.
			it.state.SetUnknown(name, taint)
		case integer:
			// -i makes later assignments arithmetic; the value is not evaluated,
			// so mark the variable integer and leave it unknown until assigned.
			it.state.SetUnknown(name, taint)
			it.state.MarkInteger(name)
		case known:
			it.state.SetKnown(name, val, taint)
		default:
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
		opNames = append(opNames, name)
	}
	if variant == "" || it.res == nil {
		return
	}
	cmd := &Command{Pos: fromMvdanPos(c.Pos()), Name: variant, NameWord: &Word{Value: variant, Literal: true}}
	for _, f := range flags {
		cmd.Args = append(cmd.Args, &Word{Value: f, Literal: true})
	}
	for _, n := range opNames {
		cmd.Args = append(cmd.Args, &Word{Value: n, Literal: true})
	}
	it.addCmd(cmd)
	declRes := it.res(cmd, it.resolutionProgram())
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
		switch {
		case a.Index != nil:
			// A subscripted assignment a[expr]=v: execute any substitutions in
			// the subscript, then treat the value as unknown (the subscript's
			// value is not modelled).
			it.expandSubstsIn(a.Index)
			if a.Value != nil {
				val, _, taint = it.expandLiteral(a.Value)
			}
			known = false
		case a.Array != nil:
			// a=( … ): expand every element so nested command/process
			// substitutions run, and record the result as unknown.
			for _, el := range a.Array.Elems {
				if el == nil {
					continue
				}
				_, _, tel := it.expandLiteral(el.Value)
				taint = taint.Join(tel)
			}
			known = false
		case a.Value != nil:
			val, known, taint = it.expandLiteral(a.Value)
		}
		as := &Assign{Pos: fromMvdanPos(a.Pos()), Name: name, Append: a.Append}
		as.Value = &Word{Value: val, Literal: known, Taint: taint}
		assigns = append(assigns, as)
		ew := envWriteEffect(name, taint)
		it.effs = append(it.effs, ew)
		it.derive(ew, engine.Atom{Kind: engine.AtomLiteral, Text: name, Loc: sourceLoc(as.Pos, it.prog.File)})
		if len(c.Args) == 0 {
			switch {
			case a.Array != nil || a.Index != nil:
				it.state.SetUnknown(name, taint)
			case a.Append:
				// name+=value appends to the existing value.
				if prev := it.state.Get(name); prev != nil && prev.Set && prev.Known {
					it.state.SetKnown(name, prev.Value+val, taint.Join(prev.Taint))
				} else if prev := it.state.Get(name); prev != nil && prev.Set {
					it.state.SetUnknown(name, taint)
				} else {
					it.state.SetKnown(name, val, taint)
				}
			case known:
				if prev := it.state.Get(name); prev != nil && prev.Int {
					// `declare -i x; x=1+1` — the assignment is arithmetic.
					it.state.SetUnknown(name, taint)
				} else {
					it.state.SetKnown(name, val, taint)
				}
			default:
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

	// The wrapper machinery drops the tokens it consumes (option values, fixed
	// positionals). Expand them anyway so any command/process substitution there
	// still runs and its effects are recorded.
	for _, w := range c.Args[:start] {
		it.expandFields(w)
	}

	// 3. Expand the effective command words.
	var (
		name   string
		nameOK bool
		argvW  []argWord
	)
	if len(rest) > 0 {
		if v, ok := literalOf(rest[0]); ok && (v == "[" || v == "test") {
			// `[` is the `test` builtin; as an unquoted word its `[` would be
			// read as a glob metacharacter and the whole invocation degraded to
			// ⊤ (or, quoted, dropped). Map it to `test` so its file-test operand
			// is reported.
			it.expandFields(rest[0])
			name, nameOK = v, true
		} else {
			ew0 := it.expandFields(rest[0])
			if ew0.known && len(ew0.fields) > 0 {
				name, nameOK = ew0.fields[0], true
			}
			if !ew0.known && len(ew0.fields) == 0 {
				// A command-name word whose expansion is unknown contributes a
				// dynamic placeholder so the invocation still degrades to ⊤.
				argvW = append(argvW, argWord{val: "", lit: false, taint: ew0.taint, pos: fromMvdanPos(rest[0].Pos())})
			} else {
				for _, f := range ew0.fields[min(1, len(ew0.fields)):] {
					argvW = append(argvW, argWord{val: f, lit: ew0.known, taint: ew0.taint, pos: fromMvdanPos(rest[0].Pos())})
				}
			}
		}
		for _, w := range rest[1:] {
			ew := it.expandFields(w)
			if !ew.known && len(ew.fields) == 0 {
				// An unquoted, wholly-unknown expansion yields no field: keep a
				// dynamic operand so the target degrades to ⊤, not to ⊥.
				argvW = append(argvW, argWord{val: "", lit: false, taint: ew.taint, pos: fromMvdanPos(w.Pos())})
				continue
			}
			for _, f := range ew.fields {
				argvW = append(argvW, argWord{val: f, lit: ew.known, taint: ew.taint, pos: fromMvdanPos(w.Pos())})
			}
		}
	}

	// `test`/`[` — drop the trailing `]` operand that `[` requires.
	if name == "[" {
		name = "test"
		if n := len(argvW); n > 0 && argvW[n-1].lit && argvW[n-1].val == "]" {
			argvW = argvW[:n-1]
		}
	}

	// An xargs -I/-i/--replace placeholder stands for the (unknown) input, so
	// an operand equal to it must widen the target to ⊤ rather than be taken as
	// a concrete path.
	if repl, ok := xargsPlaceholder(wrappers); ok && repl != "" {
		for i := range argvW {
			if argvW[i].val == repl {
				argvW[i].val, argvW[i].lit = "", false
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

	// 5. No command word.
	if len(rest) == 0 {
		if len(wrappers) > 0 {
			// The wrapper consumed its whole argument list (env -S '<cmd>',
			// sudo -i, timeout 5, bare env/xargs, …), leaving no effective
			// command. Degrade to ⊤ rather than fail open to an empty report.
			e := it.markTopEffect("wrapper consumed the whole command line")
			it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: wrapperText(wrappers), Loc: sourceLoc(pos, it.prog.File)})
		}
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

	// An external-exec wrapper (command/env/sudo/nohup/timeout/xargs/setsid)
	// looks the operand up in PATH and execs it in a new process, so shell
	// aliases and functions are bypassed; `command` additionally suppresses
	// alias expansion.
	external := len(cmd.Wrappers) > 0

	// alias expansion (bounded, then handed to the interpreter proper)
	if !external {
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
	}

	// shell functions declared by the program
	if fd := it.funcRaw[name]; fd != nil && !external {
		it.callFunc(fd, argv)
		// A user function's exit status is the body's last status; keying it on
		// the (possibly builtin-matching) name would be wrong, so leave whatever
		// the body computed (unknown for a body that computes none).
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

	// builtins that execute code supplied at run time. `trap` executes its
	// ACTION only when one is registered; the bare listing/query forms
	// (`trap`, `trap -p`, `trap - SIG`) carry no action and execute nothing.
	if isCodeExecBuiltin(name) && (name != "trap" || trapHasAction(argv)) {
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
	bound := it.res(cmd, it.resolutionProgram())
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
	// An alias body carrying redirections or embedded command/process
	// substitutions cannot be reduced to a name plus argument words without
	// dropping the effects those parts execute. Reject it so the invocation
	// falls through to the binder, whose tokenizeAlias applies the same rule and
	// degrades the body to ⊤ rather than silently under-reporting (no-silent-miss).
	if len(s.Redirs) > 0 || aliasArgsHaveSubst(s.Cmd) {
		return "", nil, false
	}
	args := make([]string, 0, len(s.Cmd.Args))
	for _, w := range s.Cmd.Args {
		args = append(args, w.Value)
	}
	return s.Cmd.Name, args, true
}

// aliasArgsHaveSubst reports whether an alias body's command carries a command
// or process substitution in any of its argument words (directly or inside
// double quotes).
func aliasArgsHaveSubst(c *Command) bool {
	if c == nil {
		return false
	}
	for _, w := range c.Args {
		if wordHasSubst(w) {
			return true
		}
	}
	return false
}

// wordHasSubst reports whether a word contains a command or process substitution.
func wordHasSubst(w *Word) bool {
	if w == nil {
		return false
	}
	for _, p := range w.Parts {
		switch p.Kind {
		case PartCmdSubst, PartProcSubst:
			return true
		case PartDblQuoted:
			for _, ip := range p.Parts {
				if ip.Kind == PartCmdSubst || ip.Kind == PartProcSubst {
					return true
				}
			}
		}
	}
	return false
}

// callFunc executes a function body. bash functions share the caller's variable
// scope — only the positional parameters are local to the call — so the body is
// executed against the caller's Σ and the state changes it performs persist.
func (it *interp) callFunc(fd *syntax.FuncDecl, argv []string) {
	if fd == nil || fd.Name == nil {
		return
	}
	name := fd.Name.Value
	if it.depth >= maxFuncDepth {
		it.markTopEffect("function recursion limit reached at " + strconv.Quote(name))
		return
	}
	positional := []string{"0", "#", "@", "*", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	savedPos := make(map[string]*Var, len(positional))
	for _, n := range positional {
		savedPos[n] = it.state.Vars[n]
	}
	it.depth++
	it.state.SetKnown("0", name, engine.TaintBottom())
	it.state.SetKnown("#", strconv.Itoa(len(argv)), engine.TaintBottom())
	if len(argv) > 1 {
		// "$@"/"$*" expand to N separate words; joining them into one field
		// would mis-target the arguments, so keep them unknown.
		it.state.SetUnknown("@", engine.TaintBottom())
		it.state.SetUnknown("*", engine.TaintBottom())
	} else {
		it.state.SetKnown("@", strings.Join(argv, " "), engine.TaintBottom())
		it.state.SetKnown("*", strings.Join(argv, " "), engine.TaintBottom())
	}
	for i, a := range argv {
		it.state.SetKnown(strconv.Itoa(i+1), a, engine.TaintBottom())
	}
	// A body containing shift / set -- rebinds the positional parameters; that
	// is not modelled, so invalidate them so reads degrade to ⊤ instead of
	// keeping a stale argument.
	if funcRebindsPositional(fd) {
		for i := 1; i <= 9; i++ {
			it.state.Unset(strconv.Itoa(i))
		}
		it.state.SetUnknown("@", engine.TaintBottom())
		it.state.SetUnknown("*", engine.TaintBottom())
	}
	if fd.Body != nil {
		it.execStmt(fd.Body)
	}
	it.depth--
	for _, n := range positional {
		if v := savedPos[n]; v != nil {
			it.state.Vars[n] = v
		} else {
			delete(it.state.Vars, n)
		}
	}
	if it.ctl == ctlReturn {
		it.ctl = ctlNone
	}
}

// funcRebindsPositional reports whether a function body contains a shift or a
// `set --` that rebinds the positional parameters.
func funcRebindsPositional(fd *syntax.FuncDecl) bool {
	if fd == nil || fd.Body == nil {
		return false
	}
	found := false
	syntax.Walk(fd.Body, func(n syntax.Node) bool {
		if found {
			return false
		}
		ce, ok := n.(*syntax.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}
		lit, ok := firstLit(ce.Args[0])
		if !ok {
			return true
		}
		switch lit {
		case "shift":
			found = true
			return false
		case "set":
			// `set -- a b` rebinds; `set -e` does not.
			for _, w := range ce.Args[1:] {
				if v, ok := firstLit(w); ok && v == "--" {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// firstLit returns the literal text of a word made up of a single unquoted
// literal part.
func firstLit(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) != 1 {
		return "", false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok {
		return "", false
	}
	return lit.Value, true
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
		// `>&word` / `<&word` with a non-numeric operand is bash's synonym for
		// `&>word` / `&<word`: a file redirection, not a stream dupe, so its
		// filesystem effect must be reported.
		if r.Word != nil && !isFdWord(r.Word) {
			it.redirectTarget(r.Word, r.Op == syntax.DplIn)
		}
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
	it.ctl = ctlNone

	// A command substitution's stdout is the concatenation of every inner
	// statement's output, so fold them all rather than only the last.
	var sb strings.Builder
	known := len(cs.Stmts) > 0
	taint := engine.TaintBottom()
	for _, s := range cs.Stmts {
		if it.ctl != ctlNone {
			break
		}
		it.stdout, it.stdoutKnown, it.stdoutTaint = "", false, engine.TaintBottom()
		it.execStmt(s)
		sb.WriteString(it.stdout)
		if !it.stdoutKnown {
			known = false
		}
		taint = taint.Join(it.stdoutTaint)
	}
	out := sb.String()

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

// expandSubstsIn walks a syntax subtree and expands every word it contains, so
// that any command or process substitution inside a construct the interpreter
// does not otherwise execute (an arithmetic or conditional command, a C-style
// for clause) is still executed and its effects are recorded.
func (it *interp) expandSubstsIn(n syntax.Node) {
	if n == nil {
		return
	}
	syntax.Walk(n, func(x syntax.Node) bool {
		if w, ok := x.(*syntax.Word); ok {
			it.expandFields(w)
			return false
		}
		return true
	})
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

// isFdWord reports whether a redirect word names a file descriptor (all digits,
// or "-" for a closed/duplicated stream), as opposed to a file path.
func isFdWord(w *syntax.Word) bool {
	v, ok := literalOf(w)
	if !ok {
		return false
	}
	if v == "-" {
		return true
	}
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// wrapperText renders a wrapper chain (outermost first) for a derivation atom.
func wrapperText(ws []*Wrapper) string {
	names := make([]string, 0, len(ws))
	for _, w := range ws {
		if w != nil {
			names = append(names, w.Name)
		}
	}
	return strings.Join(names, " ")
}

// xargsPlaceholder returns the -I/-i/--replace replacement string declared by an
// xargs wrapper, if any. The placeholder is a stand-in for the (unknown) input
// items, so an operand equal to it must widen the target to ⊤ rather than be
// taken as a concrete path.
func xargsPlaceholder(wrappers []*Wrapper) (string, bool) {
	for _, w := range wrappers {
		if w == nil || w.Name != WrapXargs {
			continue
		}
		for i := 0; i < len(w.Options); i++ {
			opt := w.Options[i]
			switch {
			case opt == "-I" || opt == "-i" || opt == "--replace":
				if i+1 < len(w.Options) {
					return w.Options[i+1], true
				}
			case strings.HasPrefix(opt, "-I") && len(opt) > 2:
				return opt[2:], true
			case strings.HasPrefix(opt, "--replace="):
				return strings.TrimPrefix(opt, "--replace="), true
			}
		}
	}
	return "", false
}
