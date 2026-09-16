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
)

// Stmt is a normalized statement.
type Stmt struct {
	Kind   Kind     `json:"kind"`
	Pos    Pos      `json:"pos"`
	Cmd    *Command `json:"cmd,omitempty"`
	Assign *Assign  `json:"assign,omitempty"`
	Reason string   `json:"reason,omitempty"` // KindTop only
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
		w.prog.Stmts = append(w.prog.Stmts, &Stmt{Kind: KindTop, Pos: w.pos(n), Reason: w.switchReason(n)})
		return
	case "command":
		c := w.command(n)
		w.prog.Stmts = append(w.prog.Stmts, &Stmt{Kind: KindCommand, Pos: c.Pos, Cmd: c})
		w.maybeDeclareAlias(c)
	case "assignment_expression":
		if a := w.assignment(n); a != nil {
			w.prog.Stmts = append(w.prog.Stmts, &Stmt{Kind: KindAssignment, Pos: a.Pos, Assign: a})
		}
	case "invokation_expression":
		// A static .NET invocation [Type]::Method(...) is opaque: it can do
		// anything, so it lowers to ⊤. This covers [ScriptBlock]::Create.
		w.prog.Stmts = append(w.prog.Stmts, &Stmt{Kind: KindTop, Pos: w.pos(n), Reason: w.staticInvocation(n)})
	}
	for i := 0; i < n.ChildCount(); i++ {
		w.walk(n.Child(i))
	}
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

// assignment builds an Assign from an assignment_expression node.
func (w *walker) assignment(n *gotreesitter.Node) *Assign {
	a := &Assign{Pos: w.pos(n)}
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		switch ch.Type(w.lang) {
		case "left_assignment_expression":
			if v := findType(ch, "variable", w.lang); v != nil {
				a.TargetWord = w.word(v)
			}
		case "assignement_operator":
			a.Op = ch.Text(w.src)
		case "pipeline":
			text := ch.Text(w.src)
			a.Value = &Word{Pos: w.pos(ch), Text: text, Literal: !strings.ContainsAny(text, "$`")}
		}
	}
	if a.TargetWord == nil {
		return nil
	}
	a.Drive, a.Name = classifyVar(a.TargetWord.Text)
	return a
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
