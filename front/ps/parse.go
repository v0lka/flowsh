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

// DefaultTimeoutMicros bounds a single parse. The task budgets hundreds of
// milliseconds for the whole analysis, so 250 ms per source is generous while
// still stopping a pathological input at the top element ⊤.
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

// Parse parses src under the default timeout. name is used for diagnostics.
//
// Parse never panics and never returns a Go error: an unrecoverable failure is
// represented as the top element ⊤ (Program.Top with a Reason). Callers that
// must tell "parsed" from "unparseable" inspect Program.Top.
func Parse(name, src string) *Program { return ParseTimeout(name, src, DefaultTimeoutMicros) }

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
	return prog
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
// body.
func (w *walker) function(n *gotreesitter.Node) {
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		if ch.Type(w.lang) == "function_name" {
			w.prog.Funcs[ch.Text(w.src)] = true
		}
	}
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

// maybeDeclareAlias records an alias declared by Set-Alias/New-Alias with a
// literal name and value, so subsequent calls can resolve it.
func (w *walker) maybeDeclareAlias(c *Command) {
	switch strings.ToLower(c.Name) {
	case "set-alias", "new-alias", "sal", "nal":
	default:
		return
	}
	name := c.ParamValue("name")
	value := c.ParamValue("value")
	if name == nil && len(c.Args) >= 1 {
		name = c.Args[0]
	}
	if value == nil && len(c.Args) >= 2 {
		value = c.Args[1]
	}
	if name != nil && value != nil && name.Literal && value.Literal && name.Text != "" {
		w.prog.Aliases[name.Text] = value.Text
	}
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
			w.nameExpr(c, ch)
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
	var pending *Param
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		switch ch.Type(w.lang) {
		case "command_argument_sep":
			continue
		case "command_parameter":
			p := &Param{Pos: w.pos(ch), Name: ch.Text(w.src)}
			c.Params = append(c.Params, p)
			pending = p
			continue
		case "redirection":
			c.Redirs = append(c.Redirs, w.redirect(ch))
			continue
		}
		wd := w.word(ch)
		if pending != nil && !isSwitch(pending.Bare()) {
			c.Bindings = append(c.Bindings, &Binding{Param: pending, Value: wd})
		} else {
			c.Args = append(c.Args, wd)
		}
		pending = nil
	}
}

// redirect builds a Redirect from a `redirection` node.
func (w *walker) redirect(n *gotreesitter.Node) *Redirect {
	r := &Redirect{Pos: w.pos(n)}
	for i := 0; i < n.ChildCount(); i++ {
		ch := n.Child(i)
		switch ch.Type(w.lang) {
		case "file_redirection_operator":
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
