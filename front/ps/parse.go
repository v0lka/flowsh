// Package ps is the PowerShell frontend of the effect IR.
//
// It has exactly two responsibilities:
//
//   - Parse turns PowerShell source text into a faithful, position-preserving
//     normalized AST, using the pure-Go tree-sitter runtime gotreesitter and
//     its embedded PowerShell grammar, under a hard wall-clock budget; and
//   - Lower (see lower.go) folds that AST into the frontend-agnostic effect IR
//     (github.com/v0lka/flowsh/engine), consulting the PowerShell alias and
//     cmdlet tables (see aliases.go) — not the bash knowledge base.
//
// A frontend may fail to understand its input. Where it cannot — an unknown
// construct, a parser timeout, an internal panic — it must degrade to the top
// element ⊤ rather than guess or crash. Parse therefore never panics and never
// returns a Go error: every failure is folded into the returned Program as
// Top=true with a human-readable Reason, so that Lower emits ⊤ (CodeExec) and
// nothing else.
//
// Dependency direction is one-way: this package is a frontend and may import
// the frontend-agnostic core (github.com/v0lka/flowsh/engine), never the other
// way around. It does not import the bash frontend or the binder: PowerShell
// resolution has its own alias table and its own cmdlet→effect mapping.
package ps

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"

	"github.com/v0lka/flowsh/engine"
)

// DefaultTimeoutMicros bounds a single parse in an ordinary build. The task
// budgets hundreds of milliseconds for the whole analysis, so 250 ms per source
// is generous while still stopping a pathological input at the top element ⊤.
//
// Parse applies this budget in ordinary builds only: under the race detector a
// wall-clock budget is not meaningful and would make the result depend on host
// load, so Parse disables it there (see budget_race.go). ParseTimeout takes an
// explicit budget in every build, so callers that want to pin one still can.
const DefaultTimeoutMicros uint64 = 250_000

// ===========================================================================
// Positions
// ===========================================================================

// Pos is a source position within a parsed program: a 1-based line and column
// (counted in bytes) plus a 0-based byte offset. The zero Pos means "no
// position".
type Pos struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

// IsZero reports whether p is the zero position.
func (p Pos) IsZero() bool { return p == Pos{} }

// String renders the position as "line:col".
func (p Pos) String() string {
	if p.IsZero() {
		return "-"
	}
	return fmt.Sprintf("%d:%d", p.Line, p.Col)
}

// ===========================================================================
// The normalized AST
// ===========================================================================

// Word is a normalized PowerShell argument or name word. Text is the raw source
// text; Literal is true when the text is fully known at analysis time (no
// variable reference or escape). EnvName/VarName are set when the word is
// exactly an environment reference ($env:NAME) or a plain variable ($NAME);
// Splat marks @NAME splatting.
type Word struct {
	Pos     Pos    `json:"pos"`
	Text    string `json:"text"`
	Literal bool   `json:"literal"`
	EnvName string `json:"envName,omitempty"`
	VarName string `json:"varName,omitempty"`
	Splat   bool   `json:"splat,omitempty"`
}

// Param is a named parameter such as -Recurse (Name keeps the leading dash).
type Param struct {
	Pos  Pos    `json:"pos"`
	Name string `json:"name"`
}

// Bare returns the parameter name without its leading dash.
func (p *Param) Bare() string {
	if p == nil {
		return ""
	}
	return strings.TrimPrefix(p.Name, "-")
}

// Binding is a named parameter together with the value token that followed it.
type Binding struct {
	Param *Param `json:"param"`
	Value *Word  `json:"value"`
}

// Redirect is an I/O redirection (> file, >> file). Op is the operator text.
type Redirect struct {
	Pos  Pos    `json:"pos"`
	Op   string `json:"op"`
	Word *Word  `json:"word,omitempty"`
}

// Command is a normalized simple command: its name, its named parameters, its
// positional operands, the bindings that pair a parameter with its value, and
// its redirections. ComputedName marks a name that is not statically known
// (& $cmd); CallOperator/DotSource mark the invocation operators & and .
type Command struct {
	Pos          Pos         `json:"pos"`
	Text         string      `json:"text"`
	Name         string      `json:"name"`
	NameWord     *Word       `json:"nameWord,omitempty"`
	ComputedName bool        `json:"computedName,omitempty"`
	CallOperator bool        `json:"callOperator,omitempty"`
	DotSource    bool        `json:"dotSource,omitempty"`
	Params       []*Param    `json:"params,omitempty"`
	Args         []*Word     `json:"args,omitempty"`
	Bindings     []*Binding  `json:"bindings,omitempty"`
	Redirs       []*Redirect `json:"redirs,omitempty"`
	// ArrayComma marks a command whose argument list uses PowerShell's
	// comma-separated array syntax (a,b). The grammar cannot split such a list
	// into elements, so the operands cannot be bounded and the command lowers
	// to ⊤ rather than to a garbled target set.
	ArrayComma bool `json:"arrayComma,omitempty"`
}

// HasParam reports whether the command carries the named parameter (bare, no
// dash, case-insensitive).
func (c *Command) HasParam(bare string) bool {
	if c == nil {
		return false
	}
	for _, p := range c.Params {
		if strings.EqualFold(p.Bare(), bare) {
			return true
		}
	}
	return false
}

// ParamValue returns the value bound to the named parameter, or nil.
func (c *Command) ParamValue(bare string) *Word {
	if c == nil {
		return nil
	}
	for _, b := range c.Bindings {
		if b.Param != nil && strings.EqualFold(b.Param.Bare(), bare) {
			return b.Value
		}
	}
	return nil
}

// Assign is a normalized assignment. Drive/Name describe the assignment target:
// "$env:FOO" → (Env, "FOO"), "$x" → (Variable, "x").
type Assign struct {
	Pos        Pos    `json:"pos"`
	TargetWord *Word  `json:"targetWord,omitempty"`
	Drive      string `json:"drive,omitempty"`
	Name       string `json:"name,omitempty"`
	Op         string `json:"op,omitempty"`
	Value      *Word  `json:"value,omitempty"`
	// Targets lists every variable the assignment writes ($a,$b = 1,2 has
	// two); the first entry mirrors TargetWord.
	Targets []*Word `json:"targets,omitempty"`
	// RHS holds the statements of a command-bearing right-hand side
	// ($x = Get-Content f, $x = "a$(cmd)b"): they are lowered in place, before
	// the assignment binds its value, so their effects and provenance are
	// known at the moment $x is written. A nil RHS is a pure expression whose
	// knownness Value's text alone determines.
	RHS []*Stmt `json:"rhs,omitempty"`
	// Hash holds the parsed entries of a @{…} literal right-hand side
	// ($p = @{Path='x'; Force=$true}), so a later splat of the variable can
	// expand into parameter bindings.
	Hash *Hashtable `json:"hash,omitempty"`
}

// HEntry is one Name=Value entry of a hashtable literal.
type HEntry struct {
	Name  string `json:"name"`
	Value *Word  `json:"value,omitempty"`
}

// Hashtable is a parsed @{…} literal.
type Hashtable struct {
	Pos     Pos      `json:"pos"`
	Entries []HEntry `json:"entries,omitempty"`
}

// Kind classifies a normalized statement.
type Kind string

const (
	// KindCommand is a simple command invocation.
	KindCommand Kind = "command"
	// KindAssignment is a variable/environment assignment.
	KindAssignment Kind = "assignment"
	// KindTop is a construct that must be analysed as ⊤ (opaque code execution).
	KindTop Kind = "top"
	// KindIf is an if/elseif…else conditional.
	KindIf Kind = "if"
	// KindLoop is a foreach/for/while/do loop.
	KindLoop Kind = "loop"
	// KindTry is a try/catch…/finally statement.
	KindTry Kind = "try"
)

// Branch is one conditional arm of an if statement.
type Branch struct {
	Pos  Pos     `json:"pos"`
	Cond *Word   `json:"cond,omitempty"`
	Body []*Stmt `json:"body"`
}

// IfStmt is an if/elseif…/else conditional. Arms holds the if and elseif arms
// in source order; Else is the else body.
type IfStmt struct {
	Pos  Pos      `json:"pos"`
	Arms []Branch `json:"arms,omitempty"`
	Else []*Stmt  `json:"else,omitempty"`
}

// LoopStmt is a foreach/for/while/do loop. Var/Iter describe a foreach header
// (the loop variable and the iterable source text); Cond is a while/do
// condition. The analysis runs the body once unless the iterable is a literal
// list or the condition is known-false.
type LoopStmt struct {
	Pos  Pos     `json:"pos"`
	Text string  `json:"text"` // "foreach" | "for" | "while" | "do"
	Var  *Word   `json:"var,omitempty"`
	Iter *Word   `json:"iter,omitempty"`
	Cond *Word   `json:"cond,omitempty"`
	Body []*Stmt `json:"body"`
}

// TryStmt is a try/catch…/finally statement: the analysis lowers the body and
// the handlers as one conservative superset.
type TryStmt struct {
	Pos     Pos     `json:"pos"`
	Body    []*Stmt `json:"body"`
	Catch   []*Stmt `json:"catch,omitempty"`
	Finally []*Stmt `json:"finally,omitempty"`
}

// Stmt is a normalized statement.
type Stmt struct {
	Kind   Kind      `json:"kind"`
	Pos    Pos       `json:"pos"`
	Cmd    *Command  `json:"cmd,omitempty"`
	Assign *Assign   `json:"assign,omitempty"`
	If     *IfStmt   `json:"if,omitempty"`
	Loop   *LoopStmt `json:"loop,omitempty"`
	Try    *TryStmt  `json:"try,omitempty"`
	Reason string    `json:"reason,omitempty"` // KindTop only
	// Pipe is the pipeline group id shared by the stages of one PowerShell
	// pipeline (0 when the statement is not part of a pipeline). The lowerer
	// uses it to establish the value flow between stages — a network fetch
	// piped into a code-execution sink is the download cradle.
	Pipe int `json:"pipe,omitempty"`
}

// Program is the normalized AST of a PowerShell source: its statements, plus
// the aliases and functions the source declares itself.
//
// When Top is true the source could not be parsed (timeout, internal error) and
// the analysis must assume the top element ⊤; statements are then empty and
// Reason explains why. Errors records that the tree contained ERROR/MISSING
// nodes but was still lowered best-effort.
type Program struct {
	File    string            `json:"file,omitempty"`
	Source  string            `json:"source"`
	Top     bool              `json:"top"`
	Reason  string            `json:"reason,omitempty"`
	ErrPos  *Pos              `json:"errPos,omitempty"`
	Errors  bool              `json:"errors,omitempty"`
	Stmts   []*Stmt           `json:"stmts"`
	Aliases map[string]string `json:"aliases,omitempty"`
	Funcs   map[string]bool   `json:"funcs,omitempty"`
}

// Validate reports whether the program is well-formed.
func (p *Program) Validate() error {
	if p == nil {
		return fmt.Errorf("ps: nil program")
	}
	if p.Top {
		if p.Reason == "" {
			return fmt.Errorf("ps: top program without a reason")
		}
		if len(p.Stmts) != 0 {
			return fmt.Errorf("ps: top program carries %d statements", len(p.Stmts))
		}
		return nil
	}
	for i, s := range p.Stmts {
		if s == nil {
			return fmt.Errorf("ps: stmts[%d]: nil statement", i)
		}
		if s.Kind == "" {
			return fmt.Errorf("ps: stmts[%d]: empty kind", i)
		}
		if s.Kind == KindCommand && s.Cmd == nil {
			return fmt.Errorf("ps: stmts[%d]: command without a command node", i)
		}
		if s.Kind == KindAssignment && s.Assign == nil {
			return fmt.Errorf("ps: stmts[%d]: assignment without an assignment node", i)
		}
	}
	return nil
}

// Encode validates the program and returns its canonical indented JSON.
func (p *Program) Encode() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(p, "", "  ")
}

// ===========================================================================
// Parsing
// ===========================================================================

// Parse parses src under the default budget. name is used for diagnostics.
//
// Parse never panics and never returns a Go error: an unrecoverable failure is
// represented as the top element ⊤ (Program.Top with a Reason). Callers that
// must tell "parsed" from "unparseable" inspect Program.Top.
//
// The default budget is DefaultTimeoutMicros in an ordinary build; under the
// race detector it is disabled (parseBudgetMicros is 0), because a wall-clock
// budget is not a meaningful bound for a race-instrumented binary and letting
// it fire would make the result depend on host load rather than on the source.
// See budget_race.go / budget_norace.go.
func Parse(name, src string) *Program { return ParseTimeout(name, src, parseBudgetMicros) }

// ParseTimeout is Parse with an explicit per-parse budget in microseconds. A
// timeoutMicros of 0 disables the timeout (not recommended for untrusted
// input).
func ParseTimeout(name, src string, timeoutMicros uint64) (prog *Program) {
	defer func() {
		if r := recover(); r != nil {
			prog = topProgram(name, src, Pos{}, fmt.Sprintf("internal parser panic: %v", r))
		}
	}()

	lang := grammars.PowershellLanguage()
	if lang == nil {
		return topProgram(name, src, Pos{}, "powershell grammar unavailable")
	}
	parser := gotreesitter.NewParser(lang)
	parser.SetTimeoutMicros(timeoutMicros)

	tree, err := parser.Parse([]byte(src))
	if err != nil {
		return topProgram(name, src, Pos{}, err.Error())
	}
	if tree == nil || tree.RootNode() == nil {
		return topProgram(name, src, Pos{}, "parser returned no tree")
	}
	if tree.ParseStoppedEarly() {
		return topProgram(name, src, Pos{}, fmt.Sprintf("parse stopped early (%s): treating source as ⊤", tree.ParseStopReason()))
	}

	root := tree.RootNode()
	prog = &Program{
		File:    name,
		Source:  src,
		Stmts:   []*Stmt{},
		Aliases: map[string]string{},
		Funcs:   map[string]bool{},
		Errors:  root.HasError() || root.HasErrorOrMissing(),
	}
	w := &walker{lang: lang, src: []byte(src), prog: prog}
	w.walk(root)
	if len(prog.Aliases) == 0 {
		prog.Aliases = nil
	}
	if len(prog.Funcs) == 0 {
		prog.Funcs = nil
	}
	// An ERROR/MISSING node that sits *outside* every command is a fragment the
	// grammar could not attach to one: it means a command was truncated or a
	// pipeline stage dropped (a `$var\…` operand suffix, a swallowed stage).
	// Lowering the salvaged statements would report a silently narrower effect
	// set, so when the source recognised a command at all it degrades to ⊤. An
	// ERROR nested *inside* a command — its operand expression, or its element
	// list (the latter is repaired by the comma-array path) — is instead handled
	// best-effort, and a source with no command at all is not a miss and stays
	// an empty program.
	if e := statementLevelError(root, lang); e != nil && hasDescendantType(root, lang, "command_name") {
		return topProgram(name, src, w.pos(e), "a command could not be parsed from the source")
	}
	return prog
}

// statementLevelError returns the first ERROR (or MISSING) node that is not
// inside any command, or nil. Such a node is a fragment the grammar could not
// attach to a command — a truncated operand suffix or a dropped pipeline stage —
// so the source it belongs to must degrade to ⊤ rather than be lowered from its
// salvaged prefix. Descent stops at a command node: an ERROR inside one is
// repaired best-effort (in its operand) or by the comma-array path (in its
// element list), and must not escalate the whole source to ⊤.
func statementLevelError(n *gotreesitter.Node, lang *gotreesitter.Language) *gotreesitter.Node {
	if n == nil || n.Type(lang) == "command" {
		return nil
	}
	for i := 0; i < n.ChildCount(); i++ {
		if ch := n.Child(i); ch.Type(lang) == "ERROR" || ch.IsMissing() {
			return ch
		}
	}
	for i := 0; i < n.ChildCount(); i++ {
		if e := statementLevelError(n.Child(i), lang); e != nil {
			return e
		}
	}
	return nil
}

// hasDescendantType reports whether n or any of its descendants has the given
// node type.
func hasDescendantType(n *gotreesitter.Node, lang *gotreesitter.Language, typ string) bool {
	if n == nil {
		return false
	}
	if n.Type(lang) == typ {
		return true
	}
	for i := 0; i < n.ChildCount(); i++ {
		if hasDescendantType(n.Child(i), lang, typ) {
			return true
		}
	}
	return false
}

// topProgram builds the ⊤ program: no statements, Top set, and a reason.
func topProgram(name, src string, errPos Pos, reason string) *Program {
	p := &Program{File: name, Source: src, Top: true, Reason: reason, Stmts: []*Stmt{}}
	if !errPos.IsZero() {
		ep := errPos
		p.ErrPos = &ep
	}
	return p
}

// ===========================================================================
// CST → normalized AST
// ===========================================================================

// walker lowers a gotreesitter CST into the normalized AST. The traversal is a
// full pre-order visit that recognises command, assignment, function and static
// .NET invocation nodes; anything else is descended into transparently.
type walker struct {
	lang *gotreesitter.Language
	src  []byte
	prog *Program
	// pipeSeq numbers the pipelines seen; pipeGroup is the group id stamped
	// onto the command statements currently being emitted (0 outside a
	// pipeline).
	pipeSeq   int
	pipeGroup int
	// stmts redirects statement emission while a sub-tree is walked into a
	// side list (an assignment's right-hand side) instead of the program's
	// top-level statement list. nil means top-level.
	stmts *[]*Stmt
}

// emit appends a statement to the current collection target.
func (w *walker) emit(s *Stmt) {
	if s.Kind == KindCommand && s.Pipe == 0 {
		s.Pipe = w.pipeGroup
	}
	if w.stmts != nil {
		*w.stmts = append(*w.stmts, s)
		return
	}
	w.prog.Stmts = append(w.prog.Stmts, s)
}

// walkInto walks n with statement emission redirected into a fresh list and
// returns the collected statements.
func (w *walker) walkInto(n *gotreesitter.Node) []*Stmt {
	if n == nil {
		return nil
	}
	outer := w.stmts
	list := []*Stmt{}
	w.stmts = &list
	w.walk(n)
	w.stmts = outer
	if len(list) == 0 {
		return nil
	}
	return list
}

func (w *walker) walk(n *gotreesitter.Node) {
	if n == nil {
		return
	}
	switch n.Type(w.lang) {
	case "function_statement":
		// A function body is opaque at the binding layer: record the name and
		// do NOT descend, so its body is not mistaken for executed code.
		w.function(n)
		return
	case "class_statement", "trap_statement", "param_block":
		// A class definition, a trap handler and a parameter default are each a
		// definition (or a deferred handler), not code executed at the point it
		// appears. Like a function body they must not be mistaken for executed
		// code, so the walker does not descend into them.
		return
	case "switch_statement":
		// A switch is not modelled: it can read a file (-File), evaluate a
		// condition and run any of its clauses, so it degrades to ⊤ rather than
		// producing nothing. The clauses are not descended into, so their
		// (conditionally executed) bodies are not reported as if unconditional.
		w.emit(&Stmt{Kind: KindTop, Pos: w.pos(n), Reason: w.switchReason(n)})
		return
	case "pipeline_chain":
		// A pipeline's stages share a group id so the lowerer can establish
		// the value flow between them — a network fetch piped into a
		// code-execution sink is the download cradle. A pipeline with fewer
		// than two stages carries no flow and is walked transparently.
		w.pipelineNode(n)
		return
	case "command":
		c := w.command(n)
		w.emit(&Stmt{Kind: KindCommand, Pos: c.Pos, Cmd: c})
		w.maybeDeclareAlias(c)
		// Fall through to the transparent descent: an argument may itself
		// carry an assignable expression — Remove-Item ($x = Get-Content f) —
		// whose inner statements must still be recognised.
	case "assignment_expression":
		// The assignment owns its right-hand side: the RHS is walked into
		// Assign.RHS (not the enclosing statement list), so the lowerer runs it
		// before the assignment binds its value. This case RETURNS — a
		// transparent descent would lower the RHS commands twice.
		if a := w.assignment(n); a != nil {
			w.emit(&Stmt{Kind: KindAssignment, Pos: a.Pos, Assign: a})
		}
		return
	case "invokation_expression":
		// A static .NET invocation [Type]::Method(...) is opaque: it can do
		// anything, so it lowers to ⊤. This covers [ScriptBlock]::Create.
		w.emit(&Stmt{Kind: KindTop, Pos: w.pos(n), Reason: w.staticInvocation(n)})
		// Fall through: arguments may carry inner statements; the ⊤ effect
		// above already covers them soundly.
	case "if_statement":
		// The conditional owns its bodies: they are walked into structured
		// arms so the lowerer can fork Σ per branch. No transparent descent —
		// the bodies must not be lowered twice.
		if s := w.ifStatement(n); s != nil {
			w.emit(s)
		}
		return
	case "foreach_statement", "for_statement", "while_statement", "do_statement":
		if s := w.loopStatement(n); s != nil {
			w.emit(s)
		}
		return
	case "try_statement":
		if s := w.tryStatement(n); s != nil {
			w.emit(s)
		}
		return
	}
	for i := 0; i < n.ChildCount(); i++ {
		w.walk(n.Child(i))
	}
}

// pipelineNode walks a pipeline's stages under a shared group id (stamped onto
// the command statements by emit) so the lowerer can establish the value flow
// between stages. A pipeline with fewer than two direct command stages carries
// no flow and is walked transparently.
func (w *walker) pipelineNode(n *gotreesitter.Node) {
	if len(directChildren(n, "command", w.lang)) < 2 {
		for i := 0; i < n.ChildCount(); i++ {
			w.walk(n.Child(i))
		}
		return
	}
	w.pipeSeq++
	prev := w.pipeGroup
	w.pipeGroup = w.pipeSeq
	for i := 0; i < n.ChildCount(); i++ {
		w.walk(n.Child(i))
	}
	w.pipeGroup = prev
}

// function records a function definition's name without descending into its
// body. The name is keyed case-insensitively, because PowerShell command and
// function names are case-insensitive: `function get-content { … }` must shadow
// a later `Get-Content` call exactly as the canonical spelling would.
func (w *walker) function(n *gotreesitter.Node) {
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		if ch.Type(w.lang) == "function_name" {
			w.prog.Funcs[strings.ToLower(ch.Text(w.src))] = true
		}
	}
}

// switchReason renders a reason for a switch_statement, noting the file it reads
// when it is the -File form.
func (w *walker) switchReason(n *gotreesitter.Node) string {
	if f := findType(n, "switch_filename", w.lang); f != nil {
		return "switch -File " + f.Text(w.src) + " is not modelled"
	}
	return "switch construct is not modelled"
}

// staticInvocation renders a human-readable reason for a [Type]::Method node.
func (w *walker) staticInvocation(n *gotreesitter.Node) string {
	for i := 0; i < n.ChildCount(); i++ {
		if ch := n.Child(i); ch.Type(w.lang) == "type_literal" {
			return "static .NET invocation " + ch.Text(w.src)
		}
	}
	return "static .NET invocation"
}

// aliasDecl extracts a literal (name, value) pair from a Set-Alias/New-Alias
// command, unquoting each side. It reports ok=false when the command is not an
// alias declaration or either side is not statically known.
func aliasDecl(c *Command) (name, value string, ok bool) {
	if c == nil {
		return "", "", false
	}
	switch strings.ToLower(strings.TrimSpace(c.Name)) {
	case "set-alias", "new-alias", "sal", "nal":
	default:
		return "", "", false
	}
	nameWord := c.ParamValue("name")
	valueWord := c.ParamValue("value")
	if nameWord == nil && len(c.Args) >= 1 {
		nameWord = c.Args[0]
	}
	if valueWord == nil && len(c.Args) >= 2 {
		valueWord = c.Args[1]
	}
	if nameWord == nil || valueWord == nil || !nameWord.Literal || !valueWord.Literal {
		return "", "", false
	}
	name = unquoteWord(nameWord.Text)
	value = unquoteWord(valueWord.Text)
	if name == "" || value == "" {
		return "", "", false
	}
	return name, value, true
}

// maybeDeclareAlias records an alias declared by Set-Alias/New-Alias with a
// literal name and value, so subsequent calls can resolve it. Aliases are keyed
// by their folded name, because PowerShell alias names are case-insensitive and
// a later declaration of the same name (in any case) replaces the earlier one.
func (w *walker) maybeDeclareAlias(c *Command) {
	name, value, ok := aliasDecl(c)
	if !ok {
		return
	}
	w.prog.Aliases[strings.ToLower(name)] = value
}

// unquoteWord strips one matching pair of surrounding single or double quotes,
// so `'Remove-Item'` (a quoted alias target or operand) resolves to its real
// text rather than a quoted, unknown spelling.
func unquoteWord(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// command builds a Command from a `command` node.
func (w *walker) command(n *gotreesitter.Node) *Command {
	c := &Command{Pos: w.pos(n), Text: n.Text(w.src)}
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		switch ch.Type(w.lang) {
		case "command_invokation_operator":
			switch strings.TrimSpace(ch.Text(w.src)) {
			case ".":
				c.DotSource = true
			case "&":
				c.CallOperator = true
			}
		case "command_name":
			c.Name = ch.Text(w.src)
			c.NameWord = w.word(ch)
		case "command_name_expr":
			// A name derived from a sub-expression — `& (Get-Command x)`,
			// `& $cmd`, `& $env:ComSpec` — is not statically known. The inner
			// command's name must not be mistaken for the invoked name, so the
			// invocation is flagged computed and lowers to ⊤.
			w.nameExpr(c, ch)
			c.ComputedName = true
		case "command_elements":
			w.elements(c, ch)
		}
	}
	return c
}

// nameExpr extracts the command name from a command_name_expr, flagging a
// computed (non-literal) name such as the variable in `& $cmd`.
func (w *walker) nameExpr(c *Command, n *gotreesitter.Node) {
	var visit func(*gotreesitter.Node)
	visit = func(x *gotreesitter.Node) {
		switch x.Type(w.lang) {
		case "command_name":
			if c.Name == "" {
				c.Name = x.Text(w.src)
				c.NameWord = w.word(x)
			}
		case "variable":
			c.ComputedName = true
			if c.NameWord == nil {
				c.NameWord = w.word(x)
			}
		}
		for i := 0; i < x.ChildCount(); i++ {
			visit(x.Child(i))
		}
	}
	visit(n)
}

// elements walks command_elements, splitting it into named parameters,
// parameter→value bindings, positional operands and redirections.
func (w *walker) elements(c *Command, n *gotreesitter.Node) {
	var (
		pending *Param
		// colonValue is set after a switch parameter is followed by a colon
		// separator (`-Confirm:`): the next token is that switch's inline value
		// and must not leak into the operand list as a spurious target.
		colonValue bool
	)
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		switch ch.Type(w.lang) {
		case "command_argument_sep":
			if strings.TrimSpace(ch.Text(w.src)) == ":" && pending != nil && isSwitchPrefix(pending.Bare()) {
				colonValue = true
			}
			continue
		case "command_parameter":
			p := &Param{Pos: w.pos(ch), Name: ch.Text(w.src)}
			c.Params = append(c.Params, p)
			pending = p
			colonValue = false
			continue
		case "redirection":
			c.Redirs = append(c.Redirs, w.redirect(ch))
			continue
		case "ERROR":
			// The grammar cannot split a PowerShell comma-separated argument
			// list (a,b) into elements: it swallows the separator and the tail
			// into an ERROR node. Rather than bind a garbled operand set, mark
			// the whole command for ⊤.
			if strings.Contains(ch.Text(w.src), ",") {
				c.ArrayComma = true
			}
			continue
		}
		if colonValue {
			// The token belongs to the preceding switch (`-Confirm:$false`).
			colonValue, pending = false, nil
			continue
		}
		// A redirection written without a separating space (`>file`, `2>file`,
		// `>>file`) is emitted as a single operand token, not a redirection
		// node; recognise it before treating it as an operand.
		if r, ok := inlineRedirect(w.pos(ch), ch.Text(w.src)); ok {
			c.Redirs = append(c.Redirs, r)
			continue
		}
		wd := w.word(ch)
		if pending != nil && !isSwitchPrefix(pending.Bare()) {
			c.Bindings = append(c.Bindings, &Binding{Param: pending, Value: wd})
		} else {
			c.Args = append(c.Args, wd)
		}
		pending = nil
	}
}

// inlineRedirect recognises a redirection written without a separating space
// (`>file`, `>>file`, `2>file`, `*>file`), which the PowerShell grammar emits as
// a single operand token rather than a redirection node. It returns the
// operator and the target file name. A bare operator or a stream merge
// (`2>&1`, whose target is a file descriptor, not a path) is not a file write
// and reports ok=false.
func inlineRedirect(p Pos, text string) (*Redirect, bool) {
	s := strings.TrimSpace(text)
	if s == "" {
		return nil, false
	}
	i := 0
	for i < len(s) && (s[i] == '*' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	if i >= len(s) || s[i] != '>' {
		return nil, false
	}
	j := i + 1
	if j < len(s) && s[j] == '>' {
		j++
	}
	file := s[j:]
	if file == "" || strings.HasPrefix(file, "&") {
		return nil, false
	}
	return &Redirect{
		Pos:  p,
		Op:   s[:j],
		Word: &Word{Pos: p, Text: file, Literal: !strings.ContainsAny(file, "$`")},
	}, true
}

// redirect builds a Redirect from a `redirection` node.
func (w *walker) redirect(n *gotreesitter.Node) *Redirect {
	r := &Redirect{Pos: w.pos(n)}
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		switch ch.Type(w.lang) {
		case "file_redirection_operator":
			r.Op = strings.TrimSpace(ch.Text(w.src))
		case "merging_redirection_operator":
			// A stream merge (2>&1, *>&1) duplicates a file descriptor; it does
			// not name a file. The op text (which contains '&') tells the
			// lowerer to skip it.
			r.Op = strings.TrimSpace(ch.Text(w.src))
		case "redirected_file_name":
			r.Word = w.firstWord(ch)
		}
	}
	return r
}

// firstWord returns the first named leaf-ish child of n as a Word.
func (w *walker) firstWord(n *gotreesitter.Node) *Word {
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		if ch.Type(w.lang) == "command_argument_sep" {
			continue
		}
		if ch.IsNamed() {
			return w.word(ch)
		}
	}
	return nil
}

// assignment builds an Assign from an assignment_expression node. Every
// variable on the left becomes a target ($a,$b = 1,2), and the right-hand side
// is walked into Assign.RHS so the lowerer runs its commands before the
// assignment binds its value; a pure-expression RHS leaves RHS nil.
func (w *walker) assignment(n *gotreesitter.Node) *Assign {
	a := &Assign{Pos: w.pos(n)}
	var valueNode *gotreesitter.Node
	opSeen := false
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		switch ch.Type(w.lang) {
		case "left_assignment_expression":
			for _, v := range findAll(ch, "variable", w.lang) {
				a.Targets = append(a.Targets, w.word(v))
			}
		case "assignement_operator":
			a.Op = ch.Text(w.src)
			opSeen = true
		default:
			// The value is whatever follows the operator (a pipeline, a
			// literal, a parenthesised expression, an array…).
			if opSeen && valueNode == nil {
				valueNode = ch
			}
		}
	}
	if len(a.Targets) > 0 {
		a.TargetWord = a.Targets[0]
	}
	if a.TargetWord == nil {
		return nil
	}
	if valueNode != nil {
		text := valueNode.Text(w.src)
		a.Value = &Word{Pos: w.pos(valueNode), Text: text, Literal: !strings.ContainsAny(text, "$`")}
		a.RHS = w.walkInto(valueNode)
		if ht := parseHashtable(text, w.pos(valueNode)); ht != nil {
			a.Hash = ht
		}
	}
	a.Drive, a.Name = classifyVar(a.TargetWord.Text)
	return a
}

// findAll returns every descendant of n whose type is typ, in source order.
func findAll(n *gotreesitter.Node, typ string, lang *gotreesitter.Language) []*gotreesitter.Node {
	if n == nil {
		return nil
	}
	var out []*gotreesitter.Node
	if n.Type(lang) == typ {
		out = append(out, n)
	}
	for i := 0; i < n.ChildCount(); i++ {
		out = append(out, findAll(n.Child(i), typ, lang)...)
	}
	return out
}

// condWord builds the raw condition word of a control-flow header.
func (w *walker) condWord(n *gotreesitter.Node) *Word {
	text := n.Text(w.src)
	return &Word{Pos: w.pos(n), Text: text, Literal: !strings.ContainsAny(text, "$`")}
}

// ifStatement builds an if/elseif…/else statement. The if arm's condition is
// the statement's own pipeline; each elseif_clause contributes another arm;
// the else_clause's block becomes Else.
func (w *walker) ifStatement(n *gotreesitter.Node) *Stmt {
	is := &IfStmt{Pos: w.pos(n)}
	armIdx := -1 // index of the arm awaiting its body
	closeArm := func(block *gotreesitter.Node) {
		if armIdx >= 0 {
			is.Arms[armIdx].Body = w.walkInto(block)
			armIdx = -1
		}
	}
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		switch ch.Type(w.lang) {
		case "pipeline":
			is.Arms = append(is.Arms, Branch{Pos: w.pos(ch), Cond: w.condWord(ch)})
			armIdx = len(is.Arms) - 1
		case "statement_block":
			closeArm(ch)
		case "elseif_clauses":
			for _, ec := range directChildren(ch, "elseif_clause", w.lang) {
				for _, c := range directChildren(ec, "pipeline", w.lang) {
					is.Arms = append(is.Arms, Branch{Pos: w.pos(c), Cond: w.condWord(c)})
					armIdx = len(is.Arms) - 1
				}
				for _, b := range directChildren(ec, "statement_block", w.lang) {
					closeArm(b)
				}
			}
		case "else_clause":
			for _, b := range directChildren(ch, "statement_block", w.lang) {
				is.Else = append(is.Else, w.walkInto(b)...)
			}
		}
	}
	if len(is.Arms) == 0 {
		return nil
	}
	return &Stmt{Kind: KindIf, Pos: is.Pos, If: is}
}

// loopStatement builds a foreach/for/while/do statement.
func (w *walker) loopStatement(n *gotreesitter.Node) *Stmt {
	lp := &LoopStmt{Pos: w.pos(n)}
	switch n.Type(w.lang) {
	case "foreach_statement":
		lp.Text = "foreach"
		for _, ch := range directChildren(n, "variable", w.lang) {
			lp.Var = w.word(ch)
			break
		}
		for _, ch := range directChildren(n, "pipeline", w.lang) {
			text := ch.Text(w.src)
			lp.Iter = &Word{Pos: w.pos(ch), Text: text, Literal: !strings.ContainsAny(text, "$`")}
			break
		}
	case "while_statement":
		lp.Text = "while"
		for _, ch := range directChildren(n, "while_condition", w.lang) {
			lp.Cond = w.condWord(ch)
			break
		}
	case "do_statement":
		lp.Text = "do"
		for _, ch := range directChildren(n, "while_condition", w.lang) {
			lp.Cond = w.condWord(ch)
			break
		}
	case "for_statement":
		lp.Text = "for"
	}
	for _, b := range directChildren(n, "statement_block", w.lang) {
		lp.Body = w.walkInto(b)
		break
	}
	if len(lp.Body) == 0 && lp.Var == nil && lp.Cond == nil {
		return nil
	}
	return &Stmt{Kind: KindLoop, Pos: lp.Pos, Loop: lp}
}

// tryStatement builds a try/catch…/finally statement: the body, every catch
// handler and the finally block are lowered as one conservative superset.
func (w *walker) tryStatement(n *gotreesitter.Node) *Stmt {
	ts := &TryStmt{Pos: w.pos(n)}
	for _, b := range directChildren(n, "statement_block", w.lang) {
		ts.Body = append(ts.Body, w.walkInto(b)...)
		break
	}
	for _, cc := range directChildren(n, "catch_clauses", w.lang) {
		for _, c := range directChildren(cc, "catch_clause", w.lang) {
			for _, b := range directChildren(c, "statement_block", w.lang) {
				ts.Catch = append(ts.Catch, w.walkInto(b)...)
			}
		}
	}
	for _, fc := range directChildren(n, "finally_clause", w.lang) {
		for _, b := range directChildren(fc, "statement_block", w.lang) {
			ts.Finally = append(ts.Finally, w.walkInto(b)...)
		}
	}
	if len(ts.Body) == 0 && len(ts.Catch) == 0 && len(ts.Finally) == 0 {
		return nil
	}
	return &Stmt{Kind: KindTry, Pos: ts.Pos, Try: ts}
}

// parseHashtable parses a @{…} literal's Name=Value entries (separated by `;`
// or newlines); the first `=` or `:` outside quotes separates an entry's name
// from its value. Anything else (nested hashtables, expressions) yields nil —
// the literal then stays a raw word.
func parseHashtable(text string, pos Pos) *Hashtable {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "@{") || !strings.HasSuffix(t, "}") {
		return nil
	}
	inner := t[2 : len(t)-1]
	ht := &Hashtable{Pos: pos}
	for _, part := range splitTopLevelEntries(inner) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		i := indexEntrySep(part)
		if i <= 0 {
			return nil // an unrecognised entry poisons the whole literal
		}
		name := strings.TrimSpace(part[:i])
		value := strings.TrimSpace(part[i+1:])
		if name == "" || value == "" || !isVarNameLike(name) {
			return nil
		}
		ht.Entries = append(ht.Entries, HEntry{
			Name:  name,
			Value: &Word{Text: value, Literal: !strings.ContainsAny(value, "$`")},
		})
	}
	if len(ht.Entries) == 0 {
		return nil
	}
	return ht
}

// splitTopLevelEntries splits s on `;` and newlines outside quotes.
func splitTopLevelEntries(s string) []string {
	var parts []string
	last := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"':
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '`' {
					i++
				}
				i++
			}
		case ';', '\n':
			parts = append(parts, s[last:i])
			last = i + 1
		}
	}
	return append(parts, s[last:])
}

// indexEntrySep returns the index of the entry separator (the first `=` or
// `:` outside quotes), or -1.
func indexEntrySep(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"':
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '`' {
					i++
				}
				i++
			}
		case '=', ':':
			return i
		}
	}
	return -1
}

// isVarNameLike reports whether s is a plausible parameter name (letters,
// digits, underscores).
func isVarNameLike(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isNameChar(c) {
			return false
		}
	}
	return len(s) > 0
}

// directChildren returns the node's immediate children of the given type.
func directChildren(n *gotreesitter.Node, typ string, lang *gotreesitter.Language) []*gotreesitter.Node {
	if n == nil {
		return nil
	}
	var out []*gotreesitter.Node
	for i := 0; i < n.ChildCount(); i++ {
		if ch := n.Child(i); ch != nil && ch.Type(lang) == typ {
			out = append(out, ch)
		}
	}
	return out
}

// findType returns the first descendant of n whose type is typ.
func findType(n *gotreesitter.Node, typ string, lang *gotreesitter.Language) *gotreesitter.Node {
	if n == nil {
		return nil
	}
	if n.Type(lang) == typ {
		return n
	}
	for i := 0; i < n.ChildCount(); i++ {
		if got := findType(n.Child(i), typ, lang); got != nil {
			return got
		}
	}
	return nil
}

// word builds a Word from a node, classifying environment/variable references
// and splatting.
func (w *walker) word(n *gotreesitter.Node) *Word {
	text := n.Text(w.src)
	wd := &Word{Pos: w.pos(n), Text: text, Literal: !strings.ContainsAny(text, "$`")}
	if name, ok := envRef(text); ok {
		wd.EnvName = name
	} else if name, ok := varRef(text); ok {
		wd.VarName = name
	}
	if name, ok := splatRef(text); ok {
		wd.Splat = true
		wd.VarName = name
	}
	return wd
}

// splatRef reports whether s is a splatting reference (@name, @{name}) and
// returns the splatted variable name. Hashtable/array literals such as @{} and
// @() are not splatting and are rejected.
func splatRef(s string) (string, bool) {
	if !strings.HasPrefix(s, "@") {
		return "", false
	}
	body := s[1:]
	if body == "" {
		return "", false
	}
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		inner := body[1 : len(body)-1]
		if isVarName(inner) {
			return inner, true
		}
		return "", false
	}
	if isVarName(body) {
		return body, true
	}
	return "", false
}

// isVarName reports whether s is a non-empty bare identifier ([A-Za-z_][A-Za-z0-9_]*).
func isVarName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// pos converts a node's start into a Pos.
func (w *walker) pos(n *gotreesitter.Node) Pos {
	p := n.StartPoint()
	return Pos{Line: int(p.Row) + 1, Col: int(p.Column) + 1, Offset: int(n.StartByte())}
}

// ===========================================================================
// Variable reference helpers
// ===========================================================================

// unbrace strips a ${...} wrapper, leaving the $-prefixed body.
func unbrace(s string) string {
	if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") && len(s) >= 3 {
		return "$" + s[2:len(s)-1]
	}
	return s
}

// envRef reports whether s is exactly an environment reference and returns the
// variable name. "$env:FOO" and "${env:FOO}" → ("FOO", true).
func envRef(s string) (string, bool) {
	b := unbrace(strings.TrimSpace(s))
	if len(b) >= 5 && strings.EqualFold(b[:5], "$env:") {
		if name := b[5:]; name != "" {
			return name, true
		}
	}
	return "", false
}

// varRef reports whether s is exactly a plain variable reference and returns
// its name. "$x" and "${x}" → ("x", true). Names containing path or member
// punctuation are rejected, so "$env:USERPROFILE\\.ssh" is not a plain variable.
func varRef(s string) (string, bool) {
	b := unbrace(strings.TrimSpace(s))
	if !strings.HasPrefix(b, "$") {
		return "", false
	}
	name := b[1:]
	if name == "" || strings.ContainsAny(name, ":.\\/ ") {
		return "", false
	}
	return name, true
}

// ===========================================================================
// Effect constructors shared with lower.go
// ===========================================================================

// effectOf builds a fully-specified effect with the certainty implied by its
// mode, mirroring the binder's convention.
func effectOf(kind engine.EffectKind, target engine.Scope, mode engine.EffectMode, reversible bool) engine.Effect {
	return engine.Effect{
		Kind:       kind,
		Target:     target,
		Mode:       mode,
		Certainty:  certaintyOf(mode),
		Taint:      engine.TaintBottom(),
		Reversible: reversible,
	}
}

// certaintyOf maps an effect mode onto the certainty the frontend assigns when
// the corresponding construct is present.
func certaintyOf(m engine.EffectMode) engine.Certainty {
	switch m {
	case engine.ModeConditional:
		return engine.CertaintyPossible
	case engine.ModeTransitive, engine.ModeAmbient:
		return engine.CertaintyLikely
	default:
		return engine.CertaintyCertain
	}
}

// topEffect is the conservative ⊤ effect: code execution over the any-target
// scope. Executing arbitrary code can do anything, so this is the sound
// stand-in for "the effects are unknown".
func topEffect(mode engine.EffectMode) engine.Effect {
	return effectOf(engine.KindCodeExec, engine.ScopeTop(), mode, false)
}

// scopeOf returns ScopeOf(targets) or ⊥ when there are none.
func scopeOf(targets ...string) engine.Scope {
	nonEmpty := targets[:0:0]
	for _, t := range targets {
		if t != "" {
			nonEmpty = append(nonEmpty, t)
		}
	}
	if len(nonEmpty) == 0 {
		return engine.ScopeBottom()
	}
	return engine.ScopeOf(nonEmpty...)
}
