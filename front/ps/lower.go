package ps

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/v0lka/flowsh/engine"
)

// StylePS names the dialect the result was lowered from. It is the value the
// composition layer uses to tell a PowerShell result from a bash one.
const StylePS = "ps"

// Options tunes lowering. The zero value is a valid, non-Windows configuration;
// use Lower for the host-default behaviour.
type Options struct {
	// Windows enables the Registry provider. On non-Windows hosts the provider
	// does not exist, so registry paths contribute no effect (the task scopes
	// Registry to Windows). Lower defaults it to runtime.GOOS == "windows".
	Windows bool
}

// Result is the outcome of lowering one normalized PowerShell program into the
// effect IR. It mirrors the binder's Result so the two compose uniformly.
type Result struct {
	Style           string                 `json:"style"`
	Effects         []engine.Effect        `json:"effects"`
	Destructiveness engine.Destructiveness `json:"destructiveness"`
	// Derivations justifies every reported effect with the concrete source atoms
	// (command, operand, redirect, source, sink) it rests on. It is analysis
	// metadata for the why-trace, not part of the serialized result.
	Derivations []engine.Derivation `json:"-"`
	// Conservative is true when the outcome includes a ⊤ (CodeExec) effect
	// because a construct could not be bounded.
	Conservative bool     `json:"conservative"`
	Notes        []string `json:"notes,omitempty"`
}

// Encode returns the canonical indented JSON of the result.
func (r *Result) Encode() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// cmdletIndex maps a lower-cased cmdlet name onto its canonical spelling so
// lookups are case-insensitive, as PowerShell's are.
var cmdletIndex = func() map[string]string {
	m := make(map[string]string, len(Cmdlets))
	for k := range Cmdlets {
		m[strings.ToLower(k)] = k
	}
	return m
}()

// Lower lowers a parsed program into the effect IR, using the host's provider
// configuration.
func Lower(p *Program) *Result {
	return LowerWith(p, Options{Windows: runtime.GOOS == "windows"})
}

// LowerWith is Lower with explicit options.
func LowerWith(p *Program, opts Options) (res *Result) {
	l := &lowerer{
		prog:       p,
		windows:    opts.Windows,
		aliases:    map[string]string{},
		state:      NewState(),
		budget:     defaultBudget,
		envEmitted: map[string]bool{},
		pipeNet:    map[int]bool{},
	}
	// Lowering never panics (SECURITY.md): an exhausted analysis budget or an
	// internal error is converted into a ⊤ conclusion that preserves every
	// effect discovered so far, mirroring the bash frontend's Exec recovery.
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		if _, ok := rec.(budgetError); !ok {
			l.top("internal error during lowering")
		} else {
			l.top("analysis budget exhausted")
		}
		res = &Result{Style: StylePS}
		l.finish(res)
	}()
	r := &Result{Style: StylePS}
	if p == nil {
		l.top("nil program")
		l.finish(r)
		return r
	}
	if p.Top {
		reason := p.Reason
		if reason == "" {
			reason = "unparseable program"
		}
		l.top(reason)
		l.finish(r)
		return r
	}
	for _, s := range p.Stmts {
		if s == nil {
			continue
		}
		l.step()
		l.stmt(s)
	}
	l.finish(r)
	return r
}

// stmt lowers one normalized statement; it is the single dispatch point used
// for the program's top-level statements and for an assignment's right-hand
// side alike.
func (l *lowerer) stmt(s *Stmt) {
	prevPipe := l.curPipe
	l.curPipe = s.Pipe
	defer func() { l.curPipe = prevPipe }()
	switch s.Kind {
	case KindCommand:
		// Record a declared alias only after it has been lowered, so it
		// affects the statements that follow it and nothing before.
		if name, value, ok := aliasDecl(s.Cmd); ok {
			l.aliases[strings.ToLower(name)] = value
		}
		l.command(s)
	case KindAssignment:
		// The right-hand side runs first: its effects justify the value's
		// provenance at the moment the assignment binds it.
		rhsMark := len(l.effects)
		if a := s.Assign; a != nil {
			for _, rs := range a.RHS {
				if rs == nil {
					continue
				}
				l.step()
				l.stmt(rs)
			}
		}
		l.assignment(s.Assign, l.effects[rhsMark:])
	case KindTop:
		l.top(s.Reason)
	case KindIf:
		l.ifStmt(s.If)
	case KindLoop:
		l.loopStmt(s.Loop)
	case KindTry:
		l.tryStmt(s.Try)
	}
}

// stmtsExec lowers a structured body (a branch, loop or handler body),
// charging the budget per statement.
func (l *lowerer) stmtsExec(ss []*Stmt) {
	for _, s := range ss {
		if s == nil {
			continue
		}
		l.step()
		l.stmt(s)
	}
}

// condTruthy decides a condition only when the condition word is a *literal
// constant*: $true, $false, $null, a numeric literal, or a whole quoted string
// literal. PowerShell truthiness for those is: $false/$null, the number 0 and
// the empty string are false, every other literal is true — in particular a
// non-empty *string* is true whatever it spells, so the strings "0" and "false"
// are truthy (unlike the boolean/number constants of the same spelling).
//
// Any other condition — a cmdlet call (Get-Item x), an operator expression
// ($a -eq $b, $n -lt 3), a variable — is not decidable from the text, so it is
// reported unresolved: the caller then keeps every arm that is not
// known-false, exactly as ADR-0014 requires. Deciding such a condition as
// "certainly true" would drop the sibling arms and bind a value from a branch
// that may never run.
func condTruthy(w *Word) (truth, known bool) {
	if w == nil {
		return false, false
	}
	t := strings.TrimSpace(w.Text)
	switch strings.ToLower(t) {
	case "$true":
		return true, true
	case "$false", "$null":
		return false, true
	}
	if v, ok := numericLiteral(t); ok {
		return v != 0, true
	}
	// A double-quoted literal that interpolates is not a constant.
	if inner, ok := wholeQuoted(t); ok {
		if t[0] == '"' && strings.ContainsAny(inner, "$`") {
			return false, false
		}
		return inner != "", true
	}
	return false, false
}

// ifStmt lowers an if/elseif…/else statement: every arm whose condition is not
// known-false runs in a forked Σ; the results join to a least upper bound. A
// known-true arm reached without a preceding unresolved arm decides the whole
// conditional. Each arm's condition pipeline (its Head) is lowered first,
// because PowerShell evaluates the condition before deciding the branch — an
// `if (Remove-Item -Force C:\x) { }` deletes the file.
func (l *lowerer) ifStmt(is *IfStmt) {
	if is == nil {
		return
	}
	l.step()
	base := l.state
	var reached []*State // final states of executable arms
	decided := false
	for i := range is.Arms {
		br := &is.Arms[i]
		l.stmtsExec(br.Head)
		ev := l.evalWord(br.Cond)
		l.emitEnvReads("if", br.Pos, ev.EnvReads)
		truth, known := condTruthy(br.Cond)
		switch {
		case known && truth:
			// This arm certainly runs — but only if no earlier unresolved arm
			// could have short-circuited it.
			if len(reached) == 0 {
				l.state = base.Clone()
				l.stmtsExec(br.Body)
				reached = append(reached, l.state)
				l.state = base
				decided = true
			} else {
				// An earlier unresolved arm might be false, so this arm may
				// still run: fork it too.
				l.state = base.Clone()
				l.stmtsExec(br.Body)
				reached = append(reached, l.state)
				l.state = base
			}
		case known:
			// known-false: the arm cannot run.
		default:
			l.state = base.Clone()
			l.stmtsExec(br.Body)
			reached = append(reached, l.state)
			l.state = base
		}
		if decided {
			break
		}
	}
	if !decided {
		// The else body runs when no arm certainly matched: certainly (all
		// false) or possibly (some condition unresolved).
		if len(is.Else) > 0 {
			l.state = base.Clone()
			l.stmtsExec(is.Else)
			reached = append(reached, l.state)
			l.state = base
		}
		if len(reached) == 0 {
			// Every condition is known-false and there is no else: the whole
			// conditional is dead code, Σ untouched.
			return
		}
		if len(is.Else) == 0 {
			// Without an else the fall-through (no arm matched) is itself a
			// reachable path carrying the pre-branch state.
			reached = append(reached, base)
		}
	}
	// A decided conditional leaves exactly the deciding arm's final state.
	l.state = joinAll(reached)
}

// joinAll folds a set of branch-final states into their least upper bound.
func joinAll(states []*State) *State {
	var out *State
	for _, s := range states {
		out = JoinStates(out, s)
	}
	return out
}

// loopStmt lowers a foreach/for/while/do loop. A foreach over a statically
// known literal list or literal range iterates exactly; every other loop runs
// its body once (the sound single-iteration convention the bash frontend uses
// for undecidable loops) under the step budget. The loop's header clauses are
// lowered first: a foreach iterable, a while/do condition and a for header are
// all evaluated by PowerShell, so the commands in them run.
func (l *lowerer) loopStmt(lp *LoopStmt) {
	if lp == nil {
		return
	}
	l.step()
	l.stmtsExec(lp.Head)
	switch lp.Text {
	case "foreach":
		var ev evaluatedWord
		if lp.Iter != nil {
			ev = l.evalWord(lp.Iter)
			l.emitEnvReads(lp.Text, lp.Pos, ev.EnvReads)
		}
		if lp.Var != nil && lp.Var.VarName != "" {
			if elems, ok := l.foreachElems(lp, ev); ok {
				for _, e := range elems {
					l.step()
					l.state.Set(lp.Var.VarName, e, ev.Taint)
					l.stmtsExec(lp.Body)
				}
				return
			}
		}
		// An unresolved iterable: one iteration with the loop variable
		// set-but-unknown, carrying the iterable's provenance.
		if lp.Var != nil && lp.Var.VarName != "" {
			l.state.SetUnknown(lp.Var.VarName, ev.Taint)
		}
		l.stmtsExec(lp.Body)
		l.note("foreach: unresolved iterable %s → one iteration", quoteTarget(iterText(lp)))
	case "while", "do":
		truth, known := false, false
		if lp.Cond != nil {
			l.emitEnvReads(lp.Text, lp.Pos, l.evalWord(lp.Cond).EnvReads)
			truth, known = condTruthy(lp.Cond)
		}
		if known && !truth && lp.Text == "while" {
			l.note("while: known-false condition → body skipped")
			return
		}
		l.stmtsExec(lp.Body)
		l.note("%s: undecidable iteration count → run once", lp.Text)
	default: // "for"
		l.stmtsExec(lp.Body)
		l.note("for: undecidable iteration count → run once")
	}
}

func iterText(lp *LoopStmt) string {
	if lp.Iter != nil {
		return lp.Iter.Text
	}
	return ""
}

// foreachElems returns the exact values a foreach iterates, when the analysis
// can determine them: the elements of a literal range (1..3 → 1, 2, 3) or of a
// literal comma list ('a.txt','b.txt'). It reports ok=false for anything else —
// in particular for an iterable that carries a command, whose *output* is
// run-time data: its source text is not a value and must never be bound as one
// (the iterable itself is lowered through Head instead).
func (l *lowerer) foreachElems(lp *LoopStmt, ev evaluatedWord) ([]string, bool) {
	if len(lp.Head) != 0 {
		return nil, false
	}
	// A literal range iterates exactly, whether it is written literally (1..3)
	// or evaluates to one (1..$n with $n known).
	if lo, hi, ok := literalRange(iterText(lp)); ok {
		return rangeElems(lo, hi), true
	}
	if ev.Known {
		if lo, hi, ok := literalRange(ev.Text); ok {
			return rangeElems(lo, hi), true
		}
		if hasRangeOp(ev.Text) {
			// A range the analysis cannot expand exactly (a dynamic bound, or
			// one wider than maxRangeIterations): its elements are unknown.
			return nil, false
		}
	}
	// A literal list iterates exactly, each element evaluated on its own
	// (quotes stripped per element); a single literal value is a one-element
	// list.
	return l.literalElements(splitTopLevelCommas(iterText(lp)))
}

// rangeElems expands an inclusive integer range into its elements. The
// PowerShell range operator counts in either direction (3..1 yields 3, 2, 1),
// so a descending range is expanded descending rather than as an empty list —
// an empty list would silently drop the loop body's effects.
func rangeElems(lo, hi int) []string {
	step := 1
	if hi < lo {
		step = -1
	}
	out := make([]string, 0, abs(hi-lo)+1)
	for v := lo; ; v += step {
		out = append(out, strconv.Itoa(v))
		if v == hi {
			break
		}
	}
	return out
}

// abs returns the absolute value of n.
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// literalElements evaluates each comma-separated element of a literal list
// and reports whether every one is statically known.
func (l *lowerer) literalElements(parts []string) ([]string, bool) {
	if len(parts) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		e := l.evalWordTextStr(p)
		if !e.Known {
			return nil, false
		}
		out = append(out, e.Text)
	}
	return out, true
}

// tryStmt lowers a try/catch…/finally statement: the body and the handlers
// both run, a deliberate conservative superset of the runtime's either/or.
func (l *lowerer) tryStmt(ts *TryStmt) {
	if ts == nil {
		return
	}
	l.step()
	l.stmtsExec(ts.Body)
	l.stmtsExec(ts.Catch)
	l.stmtsExec(ts.Finally)
	l.note("try: body and handler both lowered (conservative superset)")
}

// ===========================================================================
// Session-state cmdlets
// ===========================================================================

// mutateState applies the session-state transfer of the state-mutating
// cmdlets: Set-Location moves $pwd, Set-Variable/New-Variable and Set-Item
// Variable: write variables, Clear-Variable and Remove-Item Variable: unset
// them. Every effect the cmdlet itself reports is unchanged — this only
// updates Σ so later reads resolve.
func (l *lowerer) mutateState(c *Command, canonical string) {
	switch strings.ToLower(canonical) {
	case "set-location":
		// cd /tmp — the target is the first path parameter or operand.
		for _, b := range c.Bindings {
			if b.Param != nil && pathParam(b.Param.Bare()) && b.Value != nil {
				t := l.resolveTarget(b.Value)
				l.applyLocation(t)
				return
			}
		}
		for _, a := range c.Args {
			if a != nil {
				l.applyLocation(l.resolveTarget(a))
				return
			}
		}
		l.state.SetUnknown("pwd", engine.TaintBottom())
	case "pop-location":
		// The popped location is whatever Push-Location saved — unknowable.
		l.state.SetUnknown("pwd", engine.TaintBottom())
	case "set-variable", "new-variable":
		name, value := l.namedValueBinding(c, "name", "value")
		if name == "" {
			return
		}
		l.bindVar(name, value, "=")
		l.note("$%s := (Set-Variable)", name)
	case "clear-variable", "remove-variable", "rv":
		// Clear-Variable / Remove-Variable / rv unset the named variables,
		// whether the name is named (-Name x) or positional (rv x).
		for _, n := range l.variableNameTargets(c) {
			l.state.Unset(n)
			l.note("$%s unset (%s)", n, cmdLabel(c, canonical))
		}
	case "set-item", "remove-item":
		// Variable:\x targets mutate session state; every other target is
		// reported by the spec path above.
		for _, b := range c.Bindings {
			if b.Param != nil && pathParam(b.Param.Bare()) && b.Value != nil {
				l.applyVariablePath(c, b.Value, canonical)
			}
		}
		for _, a := range c.Args {
			if a != nil {
				l.applyVariablePath(c, a, canonical)
			}
		}
	}
}

// applyLocation moves $pwd to a known location, or marks it unknown.
func (l *lowerer) applyLocation(t resolvedTarget) {
	if t.eval.Known && t.eval.Text != "" {
		l.state.Set("pwd", t.eval.Text, t.eval.Taint)
		l.note("$pwd := %s", t.eval.Text)
		return
	}
	l.state.SetUnknown("pwd", engine.TaintBottom())
}

// applyVariablePath recognises a Variable:\x target of Set-Item /
// Remove-Item and writes or unsets that session variable. The provider
// separator after `Variable:` is not part of the variable name, so
// `Variable:\x` names $x.
func (l *lowerer) applyVariablePath(c *Command, w *Word, canonical string) {
	raw := unbrace(w.Text)
	if !strings.HasPrefix(strings.ToLower(raw), "variable:") {
		return
	}
	name := strings.TrimLeft(raw[len("variable:"):], `\/`)
	if name == "" || strings.ContainsAny(name, `\/`) {
		return
	}
	if strings.EqualFold(canonical, "set-item") {
		_, value := l.namedValueBinding(c, "", "value")
		l.bindVar(name, value, "=")
		l.note("$%s := (Set-Item Variable:)", name)
		return
	}
	l.state.Unset(name)
	l.note("$%s unset (Remove-Item Variable:)", name)
}

// variableNameTargets collects the session-variable names a state-mutating
// cmdlet acts on: the -Name parameter's value (quoted or not) and, when no
// -Name is given, the first positional operand (Clear-Variable x,
// `rv x`).
func (l *lowerer) variableNameTargets(c *Command) []string {
	var out []string
	add := func(text string) {
		if n, ok := plainVarName(unbrace(unquoteWord(text))); ok {
			out = append(out, n)
		}
	}
	for _, b := range c.Bindings {
		if b.Param != nil && b.Value != nil && strings.EqualFold(b.Param.Bare(), "name") {
			add(b.Value.Text)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, a := range c.Args {
		if a != nil {
			// The first operand is the variable name of the positional form.
			add(a.Text)
			break
		}
	}
	return out
}

// namedValueBinding extracts a named parameter's name and evaluated value.
// Parameter matching is case-insensitive, as PowerShell's is; the name is
// unquoted, so `-Name 'h'` names $h. When no -Name parameter is present, the
// positional form Set-Variable x 'v' supplies the name and the value from the
// operands.
func (l *lowerer) namedValueBinding(c *Command, nameParamName, valueParamName string) (string, evaluatedWord) {
	var name string
	var value evaluatedWord
	for _, b := range c.Bindings {
		if b.Param == nil {
			continue
		}
		switch {
		case strings.EqualFold(b.Param.Bare(), nameParamName):
			if b.Value != nil {
				if n, ok := plainVarName(unbrace(unquoteWord(b.Value.Text))); ok {
					name = n
				}
			}
		case strings.EqualFold(b.Param.Bare(), valueParamName):
			if b.Value != nil {
				l.step()
				value = evalWordText(b.Value, l.state)
			}
		}
	}
	if name == "" {
		// The positional form: the first operand is the variable name and the
		// second its value (Set-Variable x 'v.txt').
		if len(c.Args) >= 1 && c.Args[0] != nil {
			if n, ok := plainVarName(unbrace(unquoteWord(c.Args[0].Text))); ok {
				name = n
				if len(c.Args) >= 2 && c.Args[1] != nil {
					l.step()
					value = evalWordText(c.Args[1], l.state)
				}
			}
		}
	}
	return name, value
}

// ===========================================================================
// Analysis budget
// ===========================================================================

// defaultBudget bounds the abstract-lowering work: statements, loop
// iterations and word evaluations draw on it. It is a deterministic step
// counter, not a wall-clock budget, so a result never depends on host load and
// the race detector needs no special case (unlike the parse budget,
// ADR-0012/0013). The order matches the bash frontend's step budget
// (ADR-0006).
const defaultBudget = 50000

// budgetError panics out of the lowering loop when the budget is exhausted;
// LowerWith recovers it and records the ⊤ conclusion.
type budgetError struct{}

// step charges one unit of lowering work and panics with budgetError when the
// budget is exhausted.
func (l *lowerer) step() {
	if l.budget <= 0 {
		panic(budgetError{})
	}
	l.budget--
}

// ===========================================================================
// Lowering
// ===========================================================================

type lowerer struct {
	prog         *Program
	windows      bool
	effects      []engine.Effect
	ders         []engine.Derivation
	notes        []string
	conservative bool
	bump         engine.Destructiveness
	// aliases holds the aliases declared by the source *before* the statement
	// currently being lowered, keyed by folded name. Resolution is therefore
	// order-aware: an alias only rewrites the calls that follow its declaration,
	// as in PowerShell (a later Set-Alias must not rewrite an earlier call).
	aliases map[string]string
	// state is the abstract variable environment Σ: values the script
	// assigns, consulted when a word references a variable so statically-known
	// values can lower to concrete targets.
	state *State
	// budget bounds the lowering work; see defaultBudget.
	budget int
	// envEmitted deduplicates the EnvRead effects word evaluations request, so
	// a value referenced ten times reports one read.
	envEmitted map[string]bool
	// gatedEgress records that the egress gate dropped a literal target during
	// the command currently being lowered, so the intrinsic ProcSpawn fallback
	// knows the command would otherwise contribute no effect.
	gatedEgress bool
	// pipeNet records, per pipeline group, whether a network egress was emitted
	// in an earlier stage of the pipeline, so a later code-execution sink in the
	// same pipeline can be marked as the cradle sink (fetched content reaching a
	// shell/interpreter — the download cradle).
	pipeNet map[int]bool
	// curPipe is the pipeline group of the statement being lowered (0 when it
	// is not part of a pipeline).
	curPipe int
}

// emitEff records one effect together with the derivation that justifies it,
// citing the concrete source atoms (command, operand, redirect, source, sink).
func (l *lowerer) emitEff(e engine.Effect, atoms ...engine.Atom) {
	if e.Kind == engine.KindNetEgress && l.curPipe != 0 {
		l.pipeNet[l.curPipe] = true
	}
	l.effects = append(l.effects, e)
	l.ders = append(l.ders, engine.Derivation{Effect: e, Atoms: atoms, Rules: []string{ruleForKind(e.Kind)}})
}

func (l *lowerer) note(format string, args ...any) {
	l.notes = append(l.notes, fmt.Sprintf(format, args...))
}

// top records a ⊤ conclusion: a CodeExec effect over the any-target scope,
// flagged conservative, with the reason in the notes. Every path that cannot
// bound its input funnels through here.
func (l *lowerer) top(reason string) {
	l.emitEff(topEffect(engine.ModeDirect), atom(engine.AtomLiteral, reason, Pos{}))
	l.conservative = true
	l.note("⊤ %s → CodeExec(⊤)", reason)
}

// emitTopCodeExec records a ⊤ CodeExec, marking it as the sink of a network
// data flow when an earlier stage of the same pipeline carried a network egress
// — the download cradle (fetched content reaching a code-execution sink). The
// flow is established from the pipeline's value flow, never from the mere
// co-occurrence of an egress and a sink, so a canonical cradle verdict is
// always backed by the flow it ships.
func (l *lowerer) emitTopCodeExec(mode engine.EffectMode, atoms ...engine.Atom) {
	e := topEffect(mode)
	if l.curPipe != 0 && l.pipeNet[l.curPipe] {
		e.NetFlow = engine.FlowCradle
	}
	l.emitEff(e, atoms...)
}

// canonicalCmdlet returns the canonical spelling of name if it is a known
// cmdlet (case-insensitively).
func canonicalCmdlet(name string) (string, bool) {
	c, ok := cmdletIndex[strings.ToLower(name)]
	return c, ok
}

// resolve maps a command name to its canonical cmdlet spelling, following the
// script's own aliases and then the built-in alias table. viaAlias reports
// whether an alias was expanded.
//
// Resolution follows PowerShell's precedence alias > function > cmdlet: a
// script-declared alias shadows a built-in alias and a cmdlet of the same name.
// Only aliases declared *before* the current statement are consulted, so
// resolution follows source order.
func (l *lowerer) resolve(name string) (canonical string, viaAlias bool) {
	if l.aliases != nil {
		if target, ok := l.aliases[strings.ToLower(name)]; ok {
			if c, ok := canonicalCmdlet(target); ok {
				return c, true
			}
			return target, true
		}
	}
	if target, ok := LookupAlias(name, nil); ok {
		if c, ok := canonicalCmdlet(target); ok {
			return c, true
		}
		return target, true
	}
	if c, ok := canonicalCmdlet(name); ok {
		return c, false
	}
	return name, false
}

func (l *lowerer) command(s *Stmt) {
	c := s.Cmd
	if c == nil {
		return
	}
	// before records the effect count so the intrinsic ProcSpawn fallback can
	// tell whether this command (or its specs) contributed any effect at all.
	before := len(l.effects)
	l.gatedEgress = false
	if c.ArrayComma {
		// A comma-separated argument list (`Remove-Item x,y`) is not modelled:
		// the operand set cannot be bounded, so degrade to ⊤ rather than bind a
		// garbled target.
		l.emitEff(topEffect(engine.ModeDirect), atom(engine.AtomCommand, c.Name, c.Pos))
		l.conservative = true
		l.note("⊤ %s: comma-separated argument list is not modelled → CodeExec(⊤)", cmdLabel(c, c.Name))
		l.redirs(c)
		return
	}
	canonical, viaAlias := l.resolve(c.Name)

	// A splatted argument whose variable holds a fully-known hashtable
	// expands into the parameter bindings it denotes; an unknown splat keeps
	// its ⊤ trigger in topReason.
	l.expandSplat(c)

	// Control-flow keywords are not commands: they have no external effect of
	// their own (an uncaught throw terminates with an error, not a mutation).
	switch strings.ToLower(canonical) {
	case "break", "continue", "return", "exit", "throw":
		l.note("%s: control-flow keyword → no external effect", canonical)
		l.redirs(c)
		return
	}

	if reason, ok := l.topReason(c, canonical); ok {
		l.emitTopCodeExec(engine.ModeDirect, atom(engine.AtomCommand, canonical, c.Pos))
		l.conservative = true
		l.note("⊤ %s → CodeExec(⊤): %s", cmdLabel(c, canonical), reason)
		l.redirs(c)
		return
	}
	if l.prog != nil && l.prog.Funcs[strings.ToLower(canonical)] {
		l.emitEff(topEffect(engine.ModeTransitive), atom(engine.AtomCommand, canonical, c.Pos))
		l.conservative = true
		l.note("⊤ shell function %s → CodeExec(⊤, transitively): body is opaque", canonical)
		l.redirs(c)
		return
	}
	specs, known := Cmdlets[canonical]
	if !known {
		l.emitEff(topEffect(engine.ModeDirect), atom(engine.AtomCommand, canonical, c.Pos))
		l.conservative = true
		l.note("⊤ unknown command %q → CodeExec(⊤)", canonical)
		l.redirs(c)
		return
	}
	if viaAlias {
		l.note("alias %s → %s", c.Name, canonical)
	}
	if len(specs) == 0 {
		l.note("%s: no external effect", canonical)
		// A no-effect cmdlet can still mutate session state
		// (Set-Variable, Clear-Variable, …), which later reads resolve through.
		l.mutateState(c, canonical)
		l.redirs(c)
		return
	}
	for _, sp := range specs {
		l.emitSpec(c, canonical, sp)
	}
	l.dataFiles(c, canonical)
	l.bumpFor(c, canonical)
	l.mutateState(c, canonical)
	// A command whose only effect was a gated-out egress target (a literal that
	// names no network address) must not leave the report empty: emit the
	// command's intrinsic "it ran" effect, as the bash binder does, so the
	// no-silent-miss invariant holds on this path too. Pure cmdlets that
	// contribute no external effect are intentionally left effect-free.
	l.ensureGatedEgressFallback(c, canonical, before)
	l.redirs(c)
}

// ensureGatedEgressFallback emits the command's intrinsic "it ran" effect when
// the egress gate dropped the command's only effect and nothing else replaced
// it. It is the PowerShell counterpart of the bash binder's intrinsicProcSpawn,
// closing the fail-open hole the gate would otherwise create for a command like
// Invoke-WebRequest -Uri ./local.html (a literal that names no network address).
func (l *lowerer) ensureGatedEgressFallback(c *Command, canonical string, before int) {
	if len(l.effects) != before || !l.gatedEgress || l.conservative {
		return
	}
	e := effectOf(engine.KindProcSpawn, scopeOf(canonical), engine.ModeDirect, false)
	l.emitEff(e, atom(engine.AtomCommand, canonical, c.Pos))
	l.note("%s: egress target gated out → ProcSpawn", cmdLabel(c, canonical))
}

// topReason reports whether a command must be lowered to ⊤ and why. It covers
// the constructs the task pins: Invoke-Expression, dot-sourcing, Add-Type,
// New-Object, [ScriptBlock]::Create (handled as a static invocation upstream),
// the call operator & with a computed name, and splatting.
func (l *lowerer) topReason(c *Command, canonical string) (string, bool) {
	switch strings.ToLower(canonical) {
	case "invoke-expression":
		return "Invoke-Expression evaluates data as code", true
	case "add-type":
		return "Add-Type compiles and loads arbitrary code", true
	case "new-object":
		return "New-Object instantiates an arbitrary .NET type", true
	case "invoke-history":
		return "Invoke-History re-executes a previous command (arbitrary code)", true
	case "trace-command":
		return "Trace-Command evaluates an arbitrary expression string", true
	}
	if c.DotSource {
		return "dot-sourcing runs an external script in the caller's scope", true
	}
	if c.CallOperator && (c.ComputedName || c.Name == "") {
		return "call operator & with a computed name", true
	}
	for _, a := range c.Args {
		if a.Splat {
			return "splatting " + a.Text + " hides the parameter set", true
		}
	}
	if c.ComputedName {
		return "computed command name", true
	}
	return "", false
}

// resolvedTarget is one cmdlet target: the raw source spelling (for why-trace
// atoms) together with the word's evaluation against Σ (for the effect scope).
// A statically-known evaluation yields the concrete target; an unresolved one
// degrades the scope to ⊤ — never to a fabricated literal (ADR-0003).
type resolvedTarget struct {
	raw  string
	pos  Pos
	eval evaluatedWord
}

// resolveTarget evaluates one source word as a target.
func (l *lowerer) resolveTarget(w *Word) resolvedTarget {
	l.step()
	t := resolvedTarget{raw: cleanTarget(w)}
	if w != nil {
		t.pos = w.Pos
		t.eval = evalWordText(w, l.state)
	}
	return t
}

// scopeForTarget maps a resolved target onto an effect scope: a known value →
// its concrete scope; a present-but-unresolved word → ⊤ (the sound stand-in);
// no textual target → ⊥ (the spec contributes no operand).
func scopeForTarget(t resolvedTarget) engine.Scope {
	switch {
	case t.raw == "":
		return engine.ScopeBottom()
	case t.eval.Known && t.eval.Text != "":
		return scopeOf(t.eval.Text)
	default:
		return engine.ScopeTop()
	}
}

// egressHostOf extracts a literal network host from an unresolved egress
// target whose host part is literal and only the tail is dynamic
// ("http://evil.example/$lines" → "evil.example"). A host that fails the
// host grammar yields no host: the egress then stays wholly unresolved (⊤).
func egressHostOf(s string) (string, bool) {
	rest := ""
	if i := strings.Index(s, "://"); i > 0 {
		if strings.ContainsAny(s[:i], "/@$ \\") {
			return "", false
		}
		rest = s[i+3:]
	} else if strings.HasPrefix(s, "//") {
		rest = s[2:] // UNC/SMB authority
	} else {
		return "", false
	}
	if end := strings.IndexAny(rest, "/?#\\"); end >= 0 {
		rest = rest[:end]
	}
	host := rest
	if j := strings.LastIndex(host, "@"); j >= 0 {
		host = host[j+1:]
	}
	if strings.HasPrefix(host, "[") { // [IPv6]:port
		if j := strings.Index(host, "]"); j >= 0 {
			host = host[1:j]
		}
	} else if j := strings.LastIndex(host, ":"); j >= 0 {
		host = host[:j] // host:port
	}
	if host == "" || !engine.HostShapedLenient(host) {
		return "", false
	}
	return host, true
}

// emitEnvReads reports the environment variables word evaluations referenced:
// each becomes one EnvRead effect, deduplicated per lowering. The analysis
// itself never reads the host environment (SECURITY.md, Data Protection).
func (l *lowerer) emitEnvReads(label string, pos Pos, names []string) {
	for _, n := range names {
		if n == "" || l.envEmitted[n] {
			continue
		}
		l.envEmitted[n] = true
		l.emitEff(effectOf(engine.KindEnvRead, scopeOf(n), engine.ModeDirect, false),
			atom(engine.AtomCommand, label, pos), atom(engine.AtomOperand, n, pos))
		l.note("$env:%s → EnvRead", n)
	}
}

// emitSpec lowers one cmdlet spec: it resolves the target set and emits the
// corresponding effect(s), handling the Env/Variable/Registry providers and
// credential-material detection for reads.
func (l *lowerer) emitSpec(c *Command, cmd string, sp Spec) {
	base := atom(engine.AtomCommand, cmd, c.Pos)
	targets := l.targetWords(c, sp.Target)
	for _, t := range targets {
		l.emitEnvReads(cmd, c.Pos, t.eval.EnvReads)
	}
	cred := sp.Kind == engine.KindFSRead && isCredentialText(c.Text)
	if len(targets) == 0 {
		// A path/name/url effect with no operand is fed from the pipeline or a
		// default location: the target is unknown, so widen to ⊤ rather than
		// claim ⊥ (no target).
		switch sp.Target {
		case TargetPath, TargetURL, TargetName:
			e := effectOf(sp.Kind, engine.ScopeTop(), sp.Mode, sp.Reversible)
			l.emitEff(e, withSink([]engine.Atom{base}, e)...)
			// Note: the effect's *target* is ⊤, but the effect is not the ⊤
			// shape (CodeExec over any), so the conservative flag is deliberately
			// NOT set here: the result contract ties Conservative to a genuine
			// CodeExec/⊤ effect, and a read/write with an unknown target is still
			// a bounded kind.
			l.note("%s: %s ⊤ (pipelines/default) → %s", cmd, sp.Op, sp.Kind)
			if cred {
				l.emitEff(effectOf(engine.KindCredAccess, engine.ScopeTop(), engine.ModeDirect, false),
					base, atom(engine.AtomSource, "credential", c.Pos))
				l.note("%s: credential material ⊤ → CredAccess", cmd)
			}
			return
		}
		l.emitOne(c, cmd, sp, resolvedTarget{}, cred)
		return
	}
	for _, t := range targets {
		l.emitOne(c, cmd, sp, t, cred)
	}
}

func (l *lowerer) emitOne(c *Command, cmd string, sp Spec, t resolvedTarget, cred bool) {
	base := []engine.Atom{atom(engine.AtomCommand, cmd, c.Pos)}
	if t.raw != "" {
		base = append(base, atom(engine.AtomOperand, t.raw, l.targetPos(c, t.raw)))
	}
	switch driveOf(t.raw) {
	case DriveEnv:
		en := envNameOf(t.raw)
		kind := engine.KindEnvRead
		if sp.Kind == engine.KindFSWrite || sp.Kind == engine.KindFSMeta {
			kind = engine.KindEnvWrite
		}
		l.emitEff(effectOf(kind, scopeOf(en), sp.Mode, sp.Reversible), base...)
		l.note("%s: %s Env:%s → %s", cmd, sp.Op, en, kind)
		return

	case DriveVariable:
		l.note("%s: %s Variable: provider is session-local → no external effect", cmd, sp.Op)
		return

	case DriveRegistry:
		if !l.windows {
			l.note("%s: %s Registry: provider is Windows-only → skipped on this host", cmd, sp.Op)
			return
		}
		kind := sp.Kind
		if sp.Kind == engine.KindFSWrite || sp.Kind == engine.KindFSMeta || sp.Kind == engine.KindFSRead {
			kind = engine.KindPersist
		}
		l.emitEff(effectOf(kind, scopeOf(t.raw), sp.Mode, sp.Reversible), base...)
		l.note("%s: %s %s → %s", cmd, sp.Op, t.raw, kind)
		return

	case DriveFunction, DriveAlias:
		// Function:/Alias: name in-memory session state, which is not durable
		// off-process state: a write there has no external effect.
		l.note("%s: %s %s → %s: session-local provider, no external effect", cmd, sp.Op, t.raw, driveOf(t.raw))
		return

	case DriveWSMan:
		// WSMan: is durable host configuration (like the registry), so a write
		// lowers to Persist.
		l.emitEff(effectOf(engine.KindPersist, scopeOf(t.raw), sp.Mode, sp.Reversible), base...)
		l.note("%s: %s %s → Persist (WSMan configuration)", cmd, sp.Op, t.raw)
		return

	case DriveCert:
		// Cert: is the certificate store: reading it is credential access, while
		// installing/removing a certificate mutates persisted host state.
		kind := engine.KindCredAccess
		if sp.Kind == engine.KindFSWrite || sp.Kind == engine.KindFSMeta {
			kind = engine.KindPersist
		}
		l.emitEff(effectOf(kind, scopeOf(t.raw), sp.Mode, sp.Reversible), base...)
		l.note("%s: %s %s → %s (certificate store)", cmd, sp.Op, t.raw, kind)
		return
	}

	// Egress target gate: a NetEgress target must pass the host/URL grammar.
	// A statically-known target is judged literally. An unresolved target
	// keeps its egress: scoped to the literal host when one prefixes the
	// dynamic tail, else widened to ⊤ (the unresolved egress keeps
	// participating in the network controls). A literal that names no network
	// address creates no egress effect at all. Destination parameters
	// (-Uri, -ComputerName) name hosts by declaration, so the lenient grammar
	// accepts single-label computer names.
	scope := scopeForTarget(t)
	if t.raw != "" && !t.eval.Known {
		l.note("%s: target %s is unresolved → ⊤", cmd, quoteTarget(t.raw))
	}
	if sp.Kind == engine.KindNetEgress {
		switch {
		case t.raw == "":
			// No target text (TargetNone/TargetSelf specs): the effect keeps
			// the ⊥ target it always had.
		case t.eval.Known && t.eval.Text == "":
			l.note("%s: %s evaluates to an empty target → no egress", cmd, sp.Op)
			l.gatedEgress = true
			return
		case t.eval.Known:
			if !engine.HostShapedLenient(t.eval.Text) {
				l.note("%s: %s %s names no network address → no egress", cmd, sp.Op, quoteTarget(t.eval.Text))
				l.gatedEgress = true
				return
			}
			scope = scopeOf(t.eval.Text)
		default:
			if host, ok := egressHostOf(t.raw); ok {
				// The endpoint is literal even though the tail is dynamic:
				// scope the egress to the host it would contact.
				scope = scopeOf(host)
				l.note("%s: endpoint host %s (unresolved tail) → host-scoped egress", cmd, quoteTarget(host))
			} else {
				scope = engine.ScopeTop()
				l.note("%s: unresolved egress target %s → ⊤", cmd, quoteTarget(t.raw))
			}
		}
	}
	e := effectOf(sp.Kind, scope, sp.Mode, sp.Reversible)
	if sp.Kind == engine.KindNetEgress {
		// The word's provenance (a secret-bearing variable interpolated into
		// the request) flows onto the egress effect.
		e.Taint = e.Taint.Join(t.eval.Taint)
	}
	l.emitEff(e, withSink(base, e)...)
	l.note("%s: %s %s → %s", cmd, sp.Op, quoteTarget(t.eval.Text), sp.Kind)
	if cred {
		l.emitEff(effectOf(engine.KindCredAccess, scope, engine.ModeDirect, false),
			append(base, atom(engine.AtomSource, "credential", c.Pos))...)
		l.note("%s: credential material %s → CredAccess", cmd, quoteTarget(t.eval.Text))
	}
}

// targetWords resolves the target words a spec applies to, evaluated against Σ.
func (l *lowerer) targetWords(c *Command, k TargetKind) []resolvedTarget {
	switch k {
	case TargetNone:
		return nil
	case TargetSelf:
		if c.Name != "" {
			return []resolvedTarget{{raw: c.Name, pos: c.Pos, eval: evaluatedWord{Text: c.Name, Known: true}}}
		}
		return nil
	case TargetCwd:
		return []resolvedTarget{{raw: ".", pos: c.Pos, eval: evaluatedWord{Text: ".", Known: true}}}
	}
	var vals []resolvedTarget
	add := func(w *Word) {
		if w != nil {
			vals = append(vals, l.resolveTarget(w))
		}
	}
	switch k {
	case TargetPath:
		for _, b := range c.Bindings {
			if b.Param != nil && pathParam(b.Param.Bare()) && b.Value != nil {
				add(b.Value)
			}
		}
		// A positional operand names the item the cmdlet acts on, so it is
		// combined with the named path parameters rather than being dropped when
		// one is present (`Move-Item C:\a -Destination C:\b` acts on both).
		for _, a := range c.Args {
			add(a)
		}
		// A filesystem-selection parameter (-Include/-Exclude/-Filter) is not a
		// path and must not be recorded as the target: it only filters a query.
		// When no path parameter or operand names the location, no target is
		// contributed, so emitSpec widens it to ⊤ (a bounded effect kind over an
		// unknown target) rather than fabricating a path from the pattern.
	case TargetURL:
		// A network target is carried by a URL-ish parameter (-Uri/-Url/
		// -ConnectionUri/-Proxy/-SmtpServer); a probe cmdlet may instead name its
		// peer with a host-style parameter (-ComputerName/-Name), so those are
		// consulted next. Only when neither is present is the URL the operand, as
		// in `Invoke-WebRequest https://…`. An explicit parameter deliberately
		// wins over any stray operand, so the egress is reported at the
		// parameter's endpoint rather than at a decoy operand.
		for _, b := range c.Bindings {
			if b.Param != nil && urlParam(b.Param.Bare()) && b.Value != nil {
				add(b.Value)
			}
		}
		if len(vals) == 0 {
			for _, b := range c.Bindings {
				if b.Param != nil && nameParam(b.Param.Bare()) && b.Value != nil {
					add(b.Value)
				}
			}
		}
		if len(vals) == 0 {
			for _, a := range c.Args {
				add(a)
			}
		}
	case TargetName:
		for _, b := range c.Bindings {
			if b.Param != nil && nameParam(b.Param.Bare()) && b.Value != nil {
				add(b.Value)
			}
		}
		if len(vals) == 0 {
			for _, a := range c.Args {
				add(a)
			}
		}
	}
	return vals
}

// cleanTarget returns a word's target text with one matching pair of surrounding
// quotes stripped, so a quoted operand records the real path (`'C:\a'` →
// `C:\a`) rather than the quoted source spelling.
func cleanTarget(w *Word) string {
	if w == nil {
		return ""
	}
	return unquoteWord(w.Text)
}

// downloadOutputCmdlets are the download clients whose output-file parameter
// receives the fetched body: the write of that file is the ingest sink of the
// fetch (curl -o f URL's PowerShell counterpart), so the report can pair the
// egress with the file it wrote.
var downloadOutputCmdlets = map[string]bool{
	"invoke-webrequest": true,
	"invoke-restmethod": true,
}

// dataFiles lowers the data-file parameters of a cmdlet that is otherwise about
// something else (a network request, a mail message): -InFile and -Attachments
// name a file that is read, -OutFile names a file that is written, and the
// catalog output path is written by New-FileCatalog. Without this the file
// read/write would be lost.
func (l *lowerer) dataFiles(c *Command, cmd string) {
	for _, b := range c.Bindings {
		if b.Param == nil || b.Value == nil {
			continue
		}
		kind, ok := dataFileKind(cmd, b.Param.Bare())
		if !ok {
			continue
		}
		t := l.resolveTarget(b.Value)
		if t.raw == "" {
			continue
		}
		l.emitEnvReads(cmd, c.Pos, t.eval.EnvReads)
		e := effectOf(kind, scopeForTarget(t), engine.ModeDirect, kind == engine.KindFSRead)
		if kind == engine.KindFSWrite && downloadOutputCmdlets[strings.ToLower(cmd)] {
			// The file a download client writes holds the body it fetched:
			// that write is the ingest sink of the fetch (NetFlow == ingest).
			e.NetFlow = engine.FlowIngest
		}
		base := []engine.Atom{atom(engine.AtomCommand, cmd, c.Pos), atom(engine.AtomOperand, t.raw, b.Value.Pos)}
		l.emitEff(e, withSink(base, e)...)
		if !t.eval.Known {
			l.note("%s: %s %s is unresolved → ⊤", cmd, b.Param.Name, quoteTarget(t.raw))
		} else {
			l.note("%s: %s %s → %s", cmd, b.Param.Name, quoteTarget(t.eval.Text), kind)
		}
		if kind == engine.KindFSRead && isCredentialText(t.raw) {
			l.emitEff(effectOf(engine.KindCredAccess, scopeForTarget(t), engine.ModeDirect, false),
				atom(engine.AtomCommand, cmd, c.Pos), atom(engine.AtomSource, "credential", b.Value.Pos))
			l.note("%s: credential material %s → CredAccess", cmd, quoteTarget(t.raw))
		}
	}
}

// dataFileKind classifies a parameter that names a data file read from or
// written to by a cmdlet: -InFile/-Attachments are reads; -OutFile is a write.
// The catalog output path is a write only for New-FileCatalog — Test-FileCatalog
// accepts the same parameter names but merely reads the catalog it verifies, so
// the classification is cmdlet-aware rather than global.
func dataFileKind(cmd, bare string) (engine.EffectKind, bool) {
	b := bareParam(bare)
	if inNames(readDataNames, b) {
		return engine.KindFSRead, true
	}
	if inNames(writeDataNames, b) {
		return engine.KindFSWrite, true
	}
	if strings.EqualFold(cmd, "New-FileCatalog") && inNames(catalogOutputNames, b) {
		return engine.KindFSWrite, true
	}
	return "", false
}

// targetPos returns the source position of the word that carries target: the
// binding value or positional argument it was read from. It falls back to the
// command's own position when the target is synthetic (".", the command name)
// or cannot be located, so the operand atom a why-trace cites points at the
// operand rather than the whole command.
func (l *lowerer) targetPos(c *Command, target string) Pos {
	if c == nil {
		return Pos{}
	}
	for _, b := range c.Bindings {
		if b != nil && b.Value != nil && b.Value.Text == target {
			return b.Value.Pos
		}
	}
	for _, a := range c.Args {
		if a != nil && a.Text == target {
			return a.Pos
		}
	}
	return c.Pos
}

// redirectKind maps a redirection operator onto the effect it has on its
// target file: `>`/`>>` (optionally stream-qualified, `2>`, `*>>`) write it,
// while `<` reads it. ok is false for an operator that names no file — in
// particular a stream merge (2>&1, *>&1), whose target is a file descriptor.
func redirectKind(op string) (engine.EffectKind, bool) {
	if strings.Contains(op, "&") {
		return "", false
	}
	s := strings.TrimSpace(op)
	i := 0
	for i < len(s) && (s[i] == '*' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	if i >= len(s) {
		return "", false
	}
	switch s[i] {
	case '>':
		return engine.KindFSWrite, true
	case '<':
		return engine.KindFSRead, true
	}
	return "", false
}

// redirs lowers a command's redirections: > and >> write their target file and
// < reads it. A redirection word evaluated against Σ resolves to its concrete
// path; an unresolved one degrades the effect's target to ⊤.
func (l *lowerer) redirs(c *Command) {
	for _, r := range c.Redirs {
		kind, ok := redirectKind(r.Op)
		if !ok {
			// A stream merge (2>&1, *>&1): the target is a file descriptor, not
			// a path, so no file is read or written.
			l.note("redirection %s → no file target", r.Op)
			continue
		}
		read := kind == engine.KindFSRead
		if r.Word == nil || r.Word.Text == "" {
			l.emitEff(effectOf(kind, engine.ScopeTop(), engine.ModeDirect, read),
				atom(engine.AtomRedirect, r.Op, r.Pos))
			l.note("redirection %s → %s(⊤)", r.Op, kind)
			continue
		}
		t := l.resolveTarget(r.Word)
		l.emitEnvReads(c.Name, c.Pos, t.eval.EnvReads)
		e := effectOf(kind, scopeForTarget(t), engine.ModeDirect, read)
		if !t.eval.Known {
			l.note("redirection %s %s is unresolved → %s(⊤)", r.Op, r.Word.Text, kind)
		} else {
			l.note("redirection %s %s → %s", r.Op, t.eval.Text, kind)
		}
		l.emitEff(e,
			atom(engine.AtomCommand, c.Name, c.Pos), atom(engine.AtomRedirect, r.Word.Text, r.Word.Pos))
	}
}

// bumpFor raises the destructiveness for confirmed destructive invocations.
func (l *lowerer) bumpFor(c *Command, cmd string) {
	if strings.EqualFold(cmd, "Remove-Item") {
		if c.HasParam("Recurse") || c.HasParam("Force") || hasSwitchCanon(c, "recurse") || hasSwitchCanon(c, "force") {
			l.bump = l.bump.Join(engine.DestructCritical)
			l.note("Remove-Item with -Recurse/-Force: recursive/forced delete → Critical")
		}
		return
	}
	// Disk-wiping Storage cmdlets destroy data irreversibly; escalate them to
	// Critical like the equivalent util-linux/fdisk operations.
	switch {
	case strings.EqualFold(cmd, "Clear-Disk"),
		strings.EqualFold(cmd, "Format-Volume"),
		strings.EqualFold(cmd, "Remove-Partition"):
		l.bump = l.bump.Join(engine.DestructCritical)
		l.note("%s: disk/volume destruction → Critical", cmd)
	}
}

// hasSwitchCanon reports whether the command carries a switch whose canonical
// name is canon, accepting PowerShell's parameter-name abbreviation (`-Rec` →
// recurse).
func hasSwitchCanon(c *Command, canon string) bool {
	if c == nil {
		return false
	}
	for _, p := range c.Params {
		if p == nil {
			continue
		}
		if got, ok := switchCanon(p.Bare()); ok && got == canon {
			return true
		}
	}
	return false
}

// assignment lowers a variable/environment assignment and binds the assigned
// value in Σ. A statically-known literal value makes later reads concrete; a
// value produced by commands stays unknown and carries the provenance of the
// right-hand side's effects. A member/index target ($o.Prop = v) binds nothing:
// its base variable is invalidated instead, so a later read of the base
// degrades to ⊤ rather than to the member's value.
func (l *lowerer) assignment(a *Assign, rhs []engine.Effect) {
	if a == nil {
		return
	}
	// Classify every target: $a,$env:X = … mixes drives.
	type bindTarget struct {
		drive, name string
	}
	var binds []bindTarget
	for _, w := range a.Targets {
		if w == nil {
			continue
		}
		d, n := classifyVar(w.Text)
		binds = append(binds, bindTarget{d, n})
	}
	if len(binds) == 0 && len(a.Invalidate) == 0 {
		l.top("assignment with an unknown target")
		return
	}

	// The value: a pure literal/expression right-hand side is evaluated
	// against Σ; a command right-hand side yields an unknown value carrying
	// the RHS effects' provenance — and untrusted, since any command's output
	// is run-time data (the bash frontend's rule for command substitutions).
	valueKnown := len(a.RHS) == 0
	var value evaluatedWord
	if valueKnown {
		value = l.evalWord(a.Value)
	} else {
		value = evaluatedWord{Taint: rhsTaintOf(rhs).Join(engine.TaintOf(engine.TaintUntrusted))}
	}

	// A known hashtable literal binds entry-wise, so a later splat of the
	// variable can expand into parameter bindings.
	if valueKnown && a.Hash != nil {
		kvs, allKnown, taint := l.evalHashEntries(a.Hash)
		if allKnown && len(binds) == 1 && binds[0].drive == DriveVariable {
			l.state.SetHash(binds[0].name, kvs, taint)
			l.note("$%s := hashtable literal (%d entries)", binds[0].name, len(kvs))
			l.note("session variable assignment %s: no external effect", a.TargetWord.Text)
			return
		}
		value = evaluatedWord{Taint: taint}
		valueKnown = false
	}

	// A comma list is a PowerShell array and an operator expression (`1 + 2`,
	// `'a' + $b`) is a computed value: neither is one literal, so binding the
	// raw text would fabricate a target no PowerShell expression could name
	// (ADR-0003/ADR-0014). The documented multi-target form $a,$b = 'p1','p2'
	// is bound element-wise by the loop below instead.
	elementwise := false
	if valueKnown && len(binds) > 1 {
		_, elementwise = multiAssignParts(a.Value, len(binds))
	}
	if valueKnown && !elementwise {
		raw := ""
		if a.Value != nil {
			raw = a.Value.Text
		}
		if !isSingleExpression(raw) || len(splitTopLevelCommas(raw)) > 1 {
			value = evaluatedWord{Taint: value.Taint}
			valueKnown = false
		}
	}

	// A write through a member or an index does not give the base variable the
	// member's value: invalidate it, so a later read of the base degrades to ⊤
	// instead of resolving to a value the script never stored there.
	for _, w := range a.Invalidate {
		if w == nil {
			continue
		}
		if _, name := classifyVar(w.Text); name != "" {
			l.state.SetUnknown(name, value.Taint)
			l.note("$%s invalidated (member/index assignment)", name)
		}
	}
	if len(binds) == 0 {
		if a.TargetWord != nil {
			l.note("session variable assignment %s: no external effect", a.TargetWord.Text)
		}
		return
	}

	for i, b := range binds {
		switch b.drive {
		case DriveEnv:
			if b.name == "" {
				l.top("environment assignment with an unknown variable name")
				continue
			}
			l.emitEff(effectOf(engine.KindEnvWrite, scopeOf(b.name), engine.ModeDirect, false),
				atom(engine.AtomLiteral, b.name, a.Pos))
			l.note("$env:%s = … → EnvWrite", b.name)
			// The script itself determined the value: later $env:name reads
			// resolve through Σ (no second EnvRead is owed).
			l.bindVar("env:"+strings.ToLower(b.name), value, a.Op)
		case DriveRegistry:
			if !l.windows {
				l.note("registry assignment %s: Windows-only → skipped", b.name)
				continue
			}
			l.emitEff(effectOf(engine.KindPersist, scopeOf(b.name), engine.ModeDirect, false),
				atom(engine.AtomLiteral, b.name, a.Pos))
			l.note("registry assignment %s → Persist", b.name)
		default:
			// A session-variable assignment has no external effect, but the
			// value must bind: later reads of the variable resolve through Σ.
			if valueKnown && len(binds) > 1 {
				// $a,$b = 1,2: element-wise binding only when the literal
				// element count matches the target count.
				if parts, ok := multiAssignParts(a.Value, len(binds)); ok {
					l.bindVar(b.name, l.evalWordTextStr(parts[i]), a.Op)
					continue
				}
			}
			l.bindVar(b.name, value, a.Op)
		}
	}
	l.note("session variable assignment %s: no external effect", a.TargetWord.Text)
}

// evalWord evaluates one word against Σ, charging the budget.
func (l *lowerer) evalWord(w *Word) evaluatedWord {
	l.step()
	return evalWordText(w, l.state)
}

// evalWordTextStr evaluates a raw text fragment (a multi-assign element) as an
// interpolated word, charging the budget.
func (l *lowerer) evalWordTextStr(text string) evaluatedWord {
	l.step()
	return evalWordText(&Word{Text: text}, l.state)
}

// bindVar writes one assignment into Σ. "=" stores a known value when the
// right-hand side is known; "+=" adds onto a known previous value when both
// operands are numeric and concatenates them otherwise; every other operator
// (or an unknown operand) degrades to set-but-unknown.
func (l *lowerer) bindVar(name string, v evaluatedWord, op string) {
	if name == "" {
		return
	}
	switch op {
	case "=", "":
		if v.Known {
			l.state.Set(name, v.Text, v.Taint)
		} else {
			l.state.SetUnknown(name, v.Taint)
		}
	case "+=":
		if prev := l.state.Get(name); prev != nil && prev.Set && prev.Known && v.Known {
			l.state.Set(name, plusValue(prev.Value, v.Text), prev.Taint.Join(v.Taint))
		} else {
			t := engine.TaintBottom()
			if prev != nil {
				t = prev.Taint
			}
			l.state.SetUnknown(name, t.Join(v.Taint))
		}
	default:
		t := v.Taint
		if prev := l.state.Get(name); prev != nil {
			t = t.Join(prev.Taint)
		}
		l.state.SetUnknown(name, t)
	}
}

// plusValue evaluates PowerShell's `+` on two known values: the sum when both
// are numeric (0 + 1 is 1, not "01"), a string concatenation otherwise.
// PowerShell's operand-typed `+` is richer than this (a string left operand
// concatenates even when the right one is numeric), so the numeric case is an
// approximation — but it is the one that keeps `$i += 1` from producing a
// fabricated numeric-looking target.
func plusValue(a, b string) string {
	av, aNum := numericLiteral(a)
	bv, bNum := numericLiteral(b)
	if !aNum || !bNum {
		return a + b
	}
	if ai, aInt := intLiteral(a); aInt {
		if bi, bInt := intLiteral(b); bInt {
			return strconv.Itoa(ai + bi)
		}
	}
	return strconv.FormatFloat(av+bv, 'g', -1, 64)
}

// evalHashEntries evaluates a hashtable literal's entries against Σ; the table
// is known only when every entry is. It returns the entries, that knownness,
// and the joined provenance of the entry values.
func (l *lowerer) evalHashEntries(ht *Hashtable) ([]KV, bool, engine.Taint) {
	taint := engine.TaintBottom()
	allKnown := true
	kvs := make([]KV, 0, len(ht.Entries))
	for _, e := range ht.Entries {
		l.step()
		ev := evalWordText(e.Value, l.state)
		taint = taint.Join(ev.Taint)
		if !ev.Known {
			allKnown = false
		}
		kvs = append(kvs, KV{Key: e.Name, Value: ev.Text, Known: ev.Known, Taint: ev.Taint})
	}
	return kvs, allKnown, taint
}

// expandSplat replaces a splatted operand or parameter value whose variable
// holds a fully-known hashtable with the parameter bindings it denotes; an
// unknown splat keeps its ⊤ trigger. An expanded operand is removed from the
// argument list: a splat denotes parameters, never an operand of its own, so
// leaving the raw `@p` text behind would let it be evaluated as a literal
// target (ADR-0014).
func (l *lowerer) expandSplat(c *Command) {
	var args []*Word
	expanded := false
	for _, a := range c.Args {
		if b, ok := l.splatBindings(c, a); ok {
			c.Bindings = append(c.Bindings, b...)
			expanded = true
			continue
		}
		args = append(args, a)
	}
	if expanded {
		c.Args = args
	}

	// A splat in a parameter-value position (-Path @p) is expanded the same
	// way: the entries denote the parameters, so the splat binding is replaced
	// by the bindings it stands for.
	orig := c.Bindings
	var binds []*Binding
	for _, b := range orig {
		if b != nil && b.Value != nil {
			if kv, ok := l.splatBindings(c, b.Value); ok {
				binds = append(binds, kv...)
				continue
			}
		}
		binds = append(binds, b)
	}
	c.Bindings = binds
}

// splatBindings expands one splatted word into the bindings its hashtable
// denotes, and reports ok=false when the word is not a splat, its variable is
// unknown, or any entry value is not statically known (the splat then keeps
// its ⊤ trigger). A switch entry registers its parameter on the command, so
// the escalations a switch carries (-Recurse → Critical) survive the splat.
func (l *lowerer) splatBindings(c *Command, a *Word) ([]*Binding, bool) {
	if a == nil || !a.Splat || a.VarName == "" {
		return nil, false
	}
	v := l.state.Get(a.VarName)
	if v == nil || !v.Known || len(v.Hash) == 0 {
		return nil, false
	}
	var bindings []*Binding
	for _, kv := range v.Hash {
		if !kv.Known {
			return nil, false
		}
		p := &Param{Pos: a.Pos, Name: "-" + kv.Key}
		switch {
		case isSwitchPrefix(kv.Key):
			// A switch entry: `$true` binds it, `$false` omits it.
			switch strings.ToLower(kv.Value) {
			case "true", "1":
				if c != nil {
					c.Params = append(c.Params, p)
				}
			case "false", "0", "":
				// omit
			default:
				bindings = append(bindings, &Binding{Param: p,
					Value: &Word{Pos: a.Pos, Text: kv.Value, Literal: true}})
			}
		default:
			bindings = append(bindings, &Binding{Param: p,
				Value: &Word{Pos: a.Pos, Text: kv.Value, Literal: true}})
		}
	}
	a.Splat = false // expanded: no longer a ⊤ trigger
	l.note("splatting $%s expanded (%d known entries)", a.VarName, len(v.Hash))
	return bindings, true
}

// multiAssignParts splits a literal right-hand side on top-level commas and
// reports whether the element count matches the target count, so
// $a,$b = 1,2 can bind element-wise.
func multiAssignParts(v *Word, want int) ([]string, bool) {
	if v == nil || v.Text == "" || want < 2 {
		return nil, false
	}
	parts := splitTopLevelCommas(v.Text)
	if len(parts) != want {
		return nil, false
	}
	for _, p := range parts {
		if p == "" {
			return nil, false
		}
	}
	return parts, true
}

// rhsTaintOf folds the provenance a right-hand side's effects contribute to
// the assigned value: credential reads taint secret, filesystem reads
// filesystem, network ingress network+untrusted, environment reads env. It is
// the per-assignment counterpart of the bash frontend's outTaintOf.
func rhsTaintOf(rhs []engine.Effect) engine.Taint {
	t := engine.TaintBottom()
	for _, e := range rhs {
		switch {
		case e.Kind == engine.KindCredAccess || engine.IsSecretRead(e):
			t = t.Join(engine.TaintOf(engine.TaintSecret))
		case e.Kind == engine.KindFSRead:
			t = t.Join(engine.TaintOf(engine.TaintFileSystem))
		case e.Kind == engine.KindNetIngress:
			t = t.Join(engine.TaintOf(engine.TaintNetwork, engine.TaintUntrusted))
		case e.Kind == engine.KindEnvRead:
			t = t.Join(engine.TaintOf(engine.TaintEnv))
		}
	}
	return t
}

// splitTopLevelCommas splits s on commas that sit outside any brackets, braces,
// parentheses or quoted section: "1, 2" → ["1", " 2"], "@{a=1,b}, 2" stays
// two parts.
func splitTopLevelCommas(s string) []string {
	var parts []string
	depth := 0
	last := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '\'', '"':
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '`' {
					i++
				}
				i++
			}
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(s[last:i]))
				last = i + 1
			}
		}
	}
	return append(parts, strings.TrimSpace(s[last:]))
}

// finish normalises the collected effects into canonical order, folds the
// destructiveness, de-duplicates the notes and fills the result.
func (l *lowerer) finish(r *Result) {
	rep := engine.NewReport()
	rep.Effects = l.effects
	rep.Normalize()
	r.Effects = rep.Effects
	r.Destructiveness = rep.Destructiveness.Join(l.bump)
	l.stampFile()
	l.markEgressTaint(r.Effects)
	r.Derivations = l.ders
	r.Conservative = l.conservative
	r.Notes = dedupSorted(l.notes)
}

// markEgressTaint pairs a secret read with an egress sink at the program level.
//
// The frontend tracks dataflow through Σ (ADR-0014): a value a credential read
// produced carries the secret label into the request that carries it, and the
// egress effect it feeds is tainted directly. That per-command provenance only
// covers the flows the word evaluator follows, so this program-level pass
// remains as a backstop: when the analysed program reads credential material
// and also reaches an egress sink, the sink is marked secret-bearing so
// DetectExfil can pair them. It over-approximates (the read need not feed the
// request), but it cannot miss an exfiltration the way a provenance-only path
// would.
func (l *lowerer) markEgressTaint(effs []engine.Effect) {
	secret := false
	for _, e := range effs {
		if engine.IsSecretRead(e) {
			secret = true
			break
		}
	}
	if !secret {
		return
	}
	for i := range effs {
		if effs[i].Kind == engine.KindNetEgress {
			effs[i].Taint = effs[i].Taint.Join(engine.TaintOf(engine.TaintSecret))
		}
	}
}

// stampFile fills in the source file of every why-trace atom from the program's
// file, so a position recorded with line/column alone still names its source.
func (l *lowerer) stampFile() {
	file := ""
	if l.prog != nil {
		file = l.prog.File
	}
	if file == "" {
		return
	}
	for i := range l.ders {
		for j := range l.ders[i].Atoms {
			a := &l.ders[i].Atoms[j]
			if a.Loc != nil && a.Loc.File == "" {
				a.Loc.File = file
			}
		}
	}
}

// ===========================================================================
// Why-trace atoms
// ===========================================================================

// atom builds a source atom for a why-trace, carrying the frontend position
// when one is known.
func atom(kind engine.AtomKind, text string, p Pos) engine.Atom {
	var loc *engine.SourceLoc
	if p.Line > 0 || p.Col > 0 {
		loc = &engine.SourceLoc{Line: p.Line, Col: p.Col}
	}
	return engine.Atom{Kind: kind, Text: text, Loc: loc}
}

// withSink appends the sink atom an egress effect must cite, so a data-carrying
// outbound request is explained by the network sink it reaches.
func withSink(atoms []engine.Atom, e engine.Effect) []engine.Atom {
	if e.Kind != engine.KindNetEgress {
		return atoms
	}
	return append(append([]engine.Atom{}, atoms...), engine.Atom{Kind: engine.AtomSink, Text: "NetEgress"})
}

// ruleForKind names the rule the lowerer fires for an effect kind; the names
// mirror the why-trace vocabulary (fs.read, net.egress, cred.access…).
func ruleForKind(k engine.EffectKind) string {
	switch k {
	case engine.KindFSRead:
		return "fs.read"
	case engine.KindFSWrite:
		return "fs.write"
	case engine.KindFSMeta:
		return "fs.meta"
	case engine.KindEnvRead:
		return "env.read"
	case engine.KindEnvWrite:
		return "env.write"
	case engine.KindNetEgress:
		return "net.egress"
	case engine.KindNetIngress:
		return "net.ingress"
	case engine.KindProcSpawn:
		return "proc.spawn"
	case engine.KindProcSignal:
		return "proc.signal"
	case engine.KindIPC:
		return "ipc"
	case engine.KindStdio:
		return "stdio"
	case engine.KindPrivEsc:
		return "priv.escalate"
	case engine.KindPersist:
		return "persist"
	case engine.KindCredAccess:
		return "cred.access"
	case engine.KindCodeExec:
		return "code.exec"
	default:
		return "effect.derive"
	}
}

// ===========================================================================
// Credential-material detection
// ===========================================================================

// credentialMarkers are substrings that, when present in a command's text,
// indicate it touches credential or secret material.
var credentialMarkers = []string{
	".ssh", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts",
	"authorized_keys", ".aws", "credentials", ".netrc", ".git-credentials",
	".pem", ".pfx", ".p12", ".pgpass", ".npmrc", ".htpasswd",
	"password", "passwd", "secret", "token", "apikey", "api_key",
	"kubeconfig", ".kube", ".azure", ".docker/config.json",
	"shadow", "ntds.dit", "sam.json",
}

// isCredentialText reports whether text mentions credential material.
func isCredentialText(text string) bool {
	if text == "" {
		return false
	}
	lower := strings.ToLower(text)
	for _, m := range credentialMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// ===========================================================================
// Small helpers
// ===========================================================================

// cmdLabel renders a command for a note: the raw name, and its canonical form
// when that differs.
func cmdLabel(c *Command, canonical string) string {
	if c == nil {
		return canonical
	}
	name := c.Name
	if name == "" && c.NameWord != nil {
		name = c.NameWord.Text
	}
	if name == "" {
		return canonical
	}
	if canonical != "" && !strings.EqualFold(name, canonical) {
		return name + "→" + canonical
	}
	return name
}

// quoteTarget renders a target for a note.
func quoteTarget(t string) string {
	if t == "" {
		return "∅"
	}
	return "\"" + t + "\""
}

// dedupSorted returns a sorted, duplicate-free copy of xs.
func dedupSorted(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	sort.Strings(xs)
	out := xs[:1]
	for _, x := range xs[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}
