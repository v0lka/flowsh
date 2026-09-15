package bash

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// The normalized AST
// ===========================================================================

// Kind classifies a normalized statement.
type Kind string

const (
	KindSimple   Kind = "simple"   // a simple command (program invocation or assignment)
	KindPipeline Kind = "pipeline" // a | b, a |& b
	KindAndOr    Kind = "andor"    // a && b, a || b
	KindBlock    Kind = "block"    // { ...; }
	KindSubshell Kind = "subshell" // ( ... )
	KindIf       Kind = "if"
	KindWhile    Kind = "while" // while/until
	KindFor      Kind = "for"
	KindCase     Kind = "case"
	KindFunc     Kind = "func" // function definition
	KindArithm   Kind = "arithm"
	KindTest     Kind = "test" // [[ ... ]]
	KindDecl     Kind = "decl" // declare/local/export/readonly/typeset/nameref
	KindLet      Kind = "let"
	KindTime     Kind = "time"
	KindCoproc   Kind = "coproc"
	KindOther    Kind = "other"
)

// Known wrapper command names.
const (
	WrapSudo    = "sudo"
	WrapEnv     = "env"
	WrapNohup   = "nohup"
	WrapCommand = "command"
	WrapNice    = "nice"
	WrapTimeout = "timeout"
	WrapXargs   = "xargs"
	WrapSetsid  = "setsid"
)

// Program is the normalized AST of a shell source: a sequence of statements
// with positions, plus the aliases and functions the source declares.
//
// When Top is true the source could not be parsed (or the variant was unknown)
// and the analysis must assume the top effect ⊤; the statements are then empty
// and Reason explains why.
type Program struct {
	Variant Variant `json:"variant"`
	File    string  `json:"file,omitempty"`
	Source  string  `json:"source"`
	Top     bool    `json:"top"`
	Reason  string  `json:"reason,omitempty"`
	ErrPos  *Pos    `json:"errPos,omitempty"`

	Stmts []*Stmt `json:"stmts"`

	// Aliases and Funcs are keyed by name. Go's encoding/json sorts map keys,
	// so the encoding is deterministic.
	Aliases map[string]*Alias `json:"aliases,omitempty"`
	Funcs   map[string]*Func  `json:"funcs,omitempty"`
}

// Stmt is a normalized statement. It is a tagged union: Kind selects which of
// the optional fields are meaningful. Positions are always preserved.
type Stmt struct {
	Kind Kind `json:"kind"`
	Pos  Pos  `json:"pos"`
	End  Pos  `json:"end"`

	Negated    bool `json:"negated,omitempty"`
	Background bool `json:"background,omitempty"`
	Coprocess  bool `json:"coprocess,omitempty"`
	Until      bool `json:"until,omitempty"`
	Select     bool `json:"select,omitempty"`

	Redirs []*Redirect `json:"redirs,omitempty"`

	// KindSimple.
	Cmd *Command `json:"cmd,omitempty"`
	// KindFunc.
	Func *Func `json:"func,omitempty"`

	// KindPipeline / KindAndOr.
	Op    string `json:"op,omitempty"`
	Left  *Stmt  `json:"left,omitempty"`
	Right *Stmt  `json:"right,omitempty"`

	// Control structures.
	Cond    []*Stmt     `json:"cond,omitempty"` // if/while condition
	Body    []*Stmt     `json:"body,omitempty"` // block/subshell/loop body/then-branch/time+coproc payload
	Else    []*Stmt     `json:"else,omitempty"` // if else-branch
	Name    string      `json:"name,omitempty"` // for-loop variable / iterator name
	Words   []*Word     `json:"words,omitempty"`
	Items   []*CaseItem `json:"items,omitempty"`
	Subject *Word       `json:"subject,omitempty"` // case subject
	Text    string      `json:"text,omitempty"`    // raw text for arithm/test/let/other
	Decl    string      `json:"decl,omitempty"`    // decl variant
}

// CaseItem is one arm of a case statement.
type CaseItem struct {
	Pos      Pos     `json:"pos"`
	Patterns []*Word `json:"patterns,omitempty"`
	Body     []*Stmt `json:"body,omitempty"`
}

// Command is a normalized simple command. Wrappers lists the command wrappers
// (outermost first) that were peeled off the front; the command's own Name and
// Args are what remain. Assigns is every environment assignment that applies to
// the command, in source order, each tagged with the wrapper (if any) that
// introduced it.
type Command struct {
	Pos  Pos    `json:"pos"`
	Name string `json:"name"`
	// NameWord is the raw word for the program name — present even when the
	// name is not statically known (then Name is empty and Literal is false).
	NameWord *Word      `json:"nameWord,omitempty"`
	Args     []*Word    `json:"args,omitempty"`
	Assigns  []*Assign  `json:"assigns,omitempty"`
	Wrappers []*Wrapper `json:"wrappers,omitempty"`

	// ResolveKind is "", "func" or "alias" when Name names a shell function or
	// alias declared by the same program; ResolvesTo is that symbol's name.
	ResolveKind string `json:"resolveKind,omitempty"`
	ResolvesTo  string `json:"resolvesTo,omitempty"`

	// StdinTaint is the provenance of the data the command reads from standard
	// input (a pipeline's upstream output, or an input redirection). It is
	// analysis metadata produced by abstract execution and is deliberately not
	// part of the serialized normalized AST.
	StdinTaint engine.Taint `json:"-"`
}

// Wrapper is one command wrapper that normalization unwrapped (sudo, env,
// nohup, command, nice, timeout, xargs). Pos is the position of the wrapper's
// own name; Options are its option words verbatim; Args are its non-option
// positional arguments (e.g. timeout's duration).
type Wrapper struct {
	Name    string   `json:"name"`
	Pos     Pos      `json:"pos"`
	Options []string `json:"options,omitempty"`
	Args    []*Word  `json:"args,omitempty"`
}

// Assign is an environment (or array) assignment. Via is empty for an
// assignment written directly on the command and otherwise names the wrapper
// that introduced it (e.g. "env" for "env FOO=1 cmd").
type Assign struct {
	Pos    Pos    `json:"pos"`
	Name   string `json:"name"`
	Value  *Word  `json:"value,omitempty"`
	Append bool   `json:"append,omitempty"`
	Via    string `json:"via,omitempty"`
}

// Redirect is an I/O redirection.
type Redirect struct {
	Pos  Pos    `json:"pos"`
	Op   string `json:"op"`
	N    string `json:"n,omitempty"` // file descriptor, if given
	Word *Word  `json:"word,omitempty"`
	Hdoc *Word  `json:"hdoc,omitempty"`
}

// Word is a shell word: its source position, the literal text when it is fully
// literal, and the structural parts that make it up.
type Word struct {
	Pos     Pos    `json:"pos"`
	Value   string `json:"value,omitempty"`
	Literal bool   `json:"literal"`
	Parts   []Part `json:"parts,omitempty"`

	// Taint is the provenance of the word's value, as computed by abstract
	// execution (variable reads, command substitutions, …). It is analysis
	// metadata consumed by the binding layer and is deliberately not part of
	// the serialized normalized AST.
	Taint engine.Taint `json:"-"`
}

// PartKind enumerates the kinds of word part the frontend models.
type PartKind string

const (
	PartLit       PartKind = "lit"
	PartSglQuoted PartKind = "sglQuoted"
	PartDblQuoted PartKind = "dblQuoted"
	PartParamExp  PartKind = "paramExp"
	PartCmdSubst  PartKind = "cmdSubst"
	PartArithmExp PartKind = "arithmExp"
	PartProcSubst PartKind = "procSubst"
	PartExtGlob   PartKind = "extGlob"
	PartUnknown   PartKind = "unknown"
)

// Part is one component of a Word.
type Part struct {
	Kind   PartKind `json:"kind"`
	Pos    Pos      `json:"pos"`
	Value  string   `json:"value,omitempty"`
	Param  string   `json:"param,omitempty"`
	Op     string   `json:"op,omitempty"`
	Dollar bool     `json:"dollar,omitempty"`
	Stmts  []*Stmt  `json:"stmts,omitempty"` // cmdSubst / procSubst body
	Parts  []Part   `json:"parts,omitempty"` // dblQuoted inner parts
}

// Alias is a shell alias declaration (alias Name=Value).
type Alias struct {
	Pos   Pos    `json:"pos"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Func is a shell function definition.
type Func struct {
	Pos   Pos     `json:"pos"`
	Name  string  `json:"name"`
	Style string  `json:"style,omitempty"` // posix | function | function-parens
	Body  []*Stmt `json:"body,omitempty"`
}

// ===========================================================================
// Program helpers
// ===========================================================================

// Validate reports whether the program is well-formed: it has a known variant,
// a ⊤ program carries a reason and no statements, and every statement is valid.
func (p *Program) Validate() error {
	if !p.Variant.Valid() {
		return fmt.Errorf("bash: unknown variant %q", string(p.Variant))
	}
	if p.Top {
		if p.Reason == "" {
			return fmt.Errorf("bash: top program without a reason")
		}
		if len(p.Stmts) != 0 {
			return fmt.Errorf("bash: top program carries %d statements", len(p.Stmts))
		}
		return nil
	}
	for i, s := range p.Stmts {
		if err := s.validate(); err != nil {
			return fmt.Errorf("bash: stmts[%d]: %w", i, err)
		}
	}
	return nil
}

func (s *Stmt) validate() error {
	if s == nil {
		return fmt.Errorf("nil statement")
	}
	if s.Kind == "" {
		return fmt.Errorf("statement with empty kind")
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
// Normalization
// ===========================================================================

type normalizer struct {
	src     string
	aliases map[string]*Alias
	funcs   map[string]*Func
}

func newNormalizer(src string) *normalizer {
	return &normalizer{
		src:     src,
		aliases: map[string]*Alias{},
		funcs:   map[string]*Func{},
	}
}

// fill lowers the parsed file into prog and annotates command resolution.
func (n *normalizer) fill(f *syntax.File, prog *Program) {
	prog.Stmts = n.stmts(f.Stmts)
	prog.Aliases = n.aliases
	prog.Funcs = n.funcs
	annotate(prog.Stmts, n.funcs, n.aliases)
}

func (n *normalizer) stmts(ss []*syntax.Stmt) []*Stmt {
	if len(ss) == 0 {
		return nil
	}
	out := make([]*Stmt, 0, len(ss))
	for _, s := range ss {
		if s != nil {
			out = append(out, n.stmt(s))
		}
	}
	return out
}

func (n *normalizer) stmt(s *syntax.Stmt) *Stmt {
	out := &Stmt{
		Pos:        fromMvdanPos(s.Pos()),
		End:        fromMvdanPos(s.End()),
		Negated:    s.Negated,
		Background: s.Background,
		Coprocess:  s.Coprocess,
	}
	for _, r := range s.Redirs {
		out.Redirs = append(out.Redirs, n.redirect(r))
	}
	n.command(s.Cmd, out)
	if out.Kind == "" {
		out.Kind = KindSimple
	}
	return out
}

// command lowers a syntax.Command into out, dispatching on its concrete type.
func (n *normalizer) command(c syntax.Command, out *Stmt) {
	switch c := c.(type) {
	case nil:
		// A statement may have no command at all (e.g. a bare redirection
		// "> file"). Model it as an empty simple command so consumers can
		// rely on Stmt.Cmd being non-nil for simple statements.
		out.Kind = KindSimple
		out.Cmd = &Command{}

	case *syntax.CallExpr:
		n.call(c, out)

	case *syntax.BinaryCmd:
		if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
			out.Kind = KindPipeline
		} else {
			out.Kind = KindAndOr
		}
		out.Op = c.Op.String()
		out.Left = n.stmt(c.X)
		out.Right = n.stmt(c.Y)

	case *syntax.Block:
		out.Kind = KindBlock
		out.Body = n.stmts(c.Stmts)

	case *syntax.Subshell:
		out.Kind = KindSubshell
		out.Body = n.stmts(c.Stmts)

	case *syntax.IfClause:
		n.ifClause(c, out)

	case *syntax.WhileClause:
		out.Kind = KindWhile
		out.Until = c.Until
		out.Cond = n.stmts(c.Cond)
		out.Body = n.stmts(c.Do)

	case *syntax.ForClause:
		out.Kind = KindFor
		out.Select = c.Select
		switch loop := c.Loop.(type) {
		case *syntax.WordIter:
			if loop.Name != nil {
				out.Name = loop.Name.Value
			}
			out.Words = n.words(loop.Items)
		case *syntax.CStyleLoop:
			out.Text = n.slice(loop.Lparen, loop.Rparen)
		}
		out.Body = n.stmts(c.Do)

	case *syntax.CaseClause:
		out.Kind = KindCase
		if c.Word != nil {
			out.Subject = n.word(c.Word)
		}
		for _, it := range c.Items {
			out.Items = append(out.Items, n.caseItem(it))
		}

	case *syntax.FuncDecl:
		n.funcDecl(c, out)

	case *syntax.ArithmCmd:
		out.Kind = KindArithm
		if c.X != nil {
			out.Text = n.slice(c.X.Pos(), c.X.End())
		}

	case *syntax.TestClause:
		out.Kind = KindTest
		out.Text = n.slice(c.Pos(), c.End())

	case *syntax.DeclClause:
		out.Kind = KindDecl
		if c.Variant != nil {
			out.Decl = c.Variant.Value
		}
		for _, a := range c.Args {
			out.Words = append(out.Words, n.rawWord(a.Pos(), a.End()))
		}

	case *syntax.LetClause:
		out.Kind = KindLet
		exprs := make([]string, 0, len(c.Exprs))
		for _, e := range c.Exprs {
			exprs = append(exprs, n.slice(e.Pos(), e.End()))
		}
		out.Text = strings.Join(exprs, " ")

	case *syntax.TimeClause:
		out.Kind = KindTime
		if c.Stmt != nil {
			out.Body = []*Stmt{n.stmt(c.Stmt)}
		}

	case *syntax.CoprocClause:
		out.Kind = KindCoproc
		if c.Name != nil {
			out.Words = []*Word{n.word(c.Name)}
		}
		if c.Stmt != nil {
			out.Body = []*Stmt{n.stmt(c.Stmt)}
		}

	default:
		out.Kind = KindOther
		out.Text = n.slice(c.Pos(), c.End())
	}
}

func (n *normalizer) ifClause(c *syntax.IfClause, out *Stmt) {
	out.Kind = KindIf
	out.Cond = n.stmts(c.Cond)
	out.Body = n.stmts(c.Then)
	if c.Else == nil {
		return
	}
	if len(c.Else.Cond) > 0 {
		// "elif": model it as a nested if in the else branch.
		out.Else = []*Stmt{n.elifStmt(c.Else)}
		return
	}
	out.Else = n.stmts(c.Else.Then)
}

func (n *normalizer) elifStmt(c *syntax.IfClause) *Stmt {
	out := &Stmt{
		Pos: fromMvdanPos(c.Pos()),
		End: fromMvdanPos(c.End()),
	}
	n.ifClause(c, out)
	return out
}

func (n *normalizer) caseItem(it *syntax.CaseItem) *CaseItem {
	out := &CaseItem{Pos: fromMvdanPos(it.Pos())}
	out.Patterns = n.words(it.Patterns)
	out.Body = n.stmts(it.Stmts)
	return out
}

func (n *normalizer) funcDecl(c *syntax.FuncDecl, out *Stmt) {
	out.Kind = KindFunc
	f := &Func{Pos: fromMvdanPos(c.Name.Pos())}
	if c.Name != nil {
		f.Name = c.Name.Value
	}
	switch {
	case c.RsrvWord && c.Parens:
		f.Style = "function-parens"
	case c.RsrvWord:
		f.Style = "function"
	default:
		f.Style = "posix"
	}
	if c.Body != nil {
		f.Body = []*Stmt{n.stmt(c.Body)}
	}
	out.Func = f
	if f.Name != "" {
		n.funcs[f.Name] = f
	}
}

// call lowers a simple command, unwrapping its wrappers.
func (n *normalizer) call(c *syntax.CallExpr, out *Stmt) {
	out.Kind = KindSimple

	wrappers, wEnv, start := n.unwrap(c.Args)

	cmd := &Command{Wrappers: wrappers}
	for _, a := range c.Assigns {
		cmd.Assigns = append(cmd.Assigns, n.assign(a, ""))
	}

	rest := c.Args[start:]
	if len(rest) > 0 {
		nameWord := n.word(rest[0])
		cmd.NameWord = nameWord
		cmd.Pos = nameWord.Pos
		if nameWord.Literal {
			cmd.Name = nameWord.Value
		}
		for _, w := range rest[1:] {
			cmd.Args = append(cmd.Args, n.word(w))
		}
	} else if len(wrappers) > 0 {
		if spec := wrapperSpecs[wrappers[len(wrappers)-1].Name]; spec != nil && spec.defaultCmd != "" {
			cmd.Name = spec.defaultCmd
		}
		cmd.Pos = wrappers[len(wrappers)-1].Pos
	} else if len(cmd.Assigns) > 0 {
		cmd.Pos = cmd.Assigns[0].Pos
	}

	// Environment assignments contributed by wrappers apply to the command
	// too, interleaved with the command's own in source order.
	cmd.Assigns = append(cmd.Assigns, wEnv...)
	sortAssigns(cmd.Assigns)

	out.Cmd = cmd
	n.maybeAlias(cmd, out)
}

func sortAssigns(as []*Assign) {
	sort.SliceStable(as, func(i, j int) bool {
		a, b := as[i].Pos, as[j].Pos
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		return a.Offset < b.Offset
	})
}

// maybeAlias records an "alias name=value" declaration. Aliases are not
// expanded (that is a runtime, order-sensitive behaviour), only collected.
func (n *normalizer) maybeAlias(cmd *Command, s *Stmt) {
	if cmd.Name != WrapAliasBuiltin || s.Negated || s.Background {
		return
	}
	for _, w := range cmd.Args {
		if !w.Literal {
			continue
		}
		name, value, ok := splitEq(w.Value)
		if !ok {
			continue
		}
		n.aliases[name] = &Alias{Pos: w.Pos, Name: name, Value: value}
	}
}

// WrapAliasBuiltin is the shell builtin that declares aliases.
const WrapAliasBuiltin = "alias"

func (n *normalizer) assign(a *syntax.Assign, via string) *Assign {
	out := &Assign{
		Pos:    fromMvdanPos(a.Pos()),
		Via:    via,
		Append: a.Append,
	}
	if a.Name != nil {
		out.Name = a.Name.Value
	}
	if a.Value != nil {
		out.Value = n.word(a.Value)
	}
	return out
}

func (n *normalizer) redirect(r *syntax.Redirect) *Redirect {
	out := &Redirect{
		Pos: fromMvdanPos(r.Pos()),
		Op:  r.Op.String(),
	}
	if r.N != nil {
		out.N = r.N.Value
	}
	if r.Word != nil {
		out.Word = n.word(r.Word)
	}
	if r.Hdoc != nil {
		out.Hdoc = n.word(r.Hdoc)
	}
	return out
}

func (n *normalizer) words(ws []*syntax.Word) []*Word {
	if len(ws) == 0 {
		return nil
	}
	out := make([]*Word, 0, len(ws))
	for _, w := range ws {
		out = append(out, n.word(w))
	}
	return out
}

func (n *normalizer) word(w *syntax.Word) *Word {
	if w == nil {
		return nil
	}
	out := &Word{Pos: fromMvdanPos(w.Pos())}
	for _, p := range w.Parts {
		out.Parts = append(out.Parts, n.part(p))
	}
	if v, ok := literalOf(w); ok {
		out.Value, out.Literal = v, true
	}
	return out
}

// rawWord builds a literal Word from a byte range of the source.
func (n *normalizer) rawWord(a, b syntax.Pos) *Word {
	return &Word{Pos: fromMvdanPos(a), Value: n.slice(a, b), Literal: true}
}

func (n *normalizer) part(pt syntax.WordPart) Part {
	switch p := pt.(type) {
	case *syntax.Lit:
		return Part{Kind: PartLit, Pos: fromMvdanPos(p.Pos()), Value: p.Value}
	case *syntax.SglQuoted:
		return Part{Kind: PartSglQuoted, Pos: fromMvdanPos(p.Pos()), Value: p.Value, Dollar: p.Dollar}
	case *syntax.DblQuoted:
		out := Part{Kind: PartDblQuoted, Pos: fromMvdanPos(p.Pos()), Dollar: p.Dollar}
		for _, ip := range p.Parts {
			out.Parts = append(out.Parts, n.part(ip))
		}
		return out
	case *syntax.ParamExp:
		out := Part{Kind: PartParamExp, Pos: fromMvdanPos(p.Pos()), Op: paramOp(p)}
		if p.Param != nil {
			out.Param = p.Param.Value
		}
		return out
	case *syntax.CmdSubst:
		return Part{Kind: PartCmdSubst, Pos: fromMvdanPos(p.Pos()), Stmts: n.stmts(p.Stmts)}
	case *syntax.ArithmExp:
		return Part{Kind: PartArithmExp, Pos: fromMvdanPos(p.Pos()), Value: n.slice(p.X.Pos(), p.X.End())}
	case *syntax.ProcSubst:
		return Part{Kind: PartProcSubst, Pos: fromMvdanPos(p.Pos()), Op: p.Op.String(), Stmts: n.stmts(p.Stmts)}
	case *syntax.ExtGlob:
		return Part{Kind: PartExtGlob, Pos: fromMvdanPos(p.Pos()), Op: p.Op.String(), Value: p.Pattern.Value}
	default:
		return Part{Kind: PartUnknown, Pos: fromMvdanPos(pt.Pos()), Value: n.slice(pt.Pos(), pt.End())}
	}
}

// slice returns the source text spanned by [a, b), clamped to the source.
func (n *normalizer) slice(a, b syntax.Pos) string {
	if !a.IsValid() || !b.IsValid() {
		return ""
	}
	lo, hi := int(a.Offset()), int(b.Offset())
	if lo < 0 {
		lo = 0
	}
	if hi > len(n.src) {
		hi = len(n.src)
	}
	if lo > hi {
		return ""
	}
	return n.src[lo:hi]
}

// ===========================================================================
// Wrapper unwrapping
// ===========================================================================

// wrapperSpec describes how a wrapper command consumes its own arguments.
type wrapperSpec struct {
	// valueOpts are option tokens that consume the following word as their
	// value when written separately (e.g. "-u", "--user").
	valueOpts map[string]bool
	// envAssigns, when set, makes NAME=value words that follow the options be
	// lifted onto the wrapped command as environment assignments.
	envAssigns bool
	// fixedArgs is how many positional words the wrapper consumes after its
	// options (e.g. timeout's required duration).
	fixedArgs int
	// defaultCmd is the command implied when nothing follows (xargs -> echo).
	defaultCmd string
}

func optSet(opts ...string) map[string]bool {
	m := make(map[string]bool, len(opts))
	for _, o := range opts {
		m[o] = true
	}
	return m
}

// wrapperSpecs is the closed set of recognized wrappers.
var wrapperSpecs = map[string]*wrapperSpec{
	WrapSudo: {
		valueOpts: optSet("-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
			"-C", "--close-from", "-T", "--command-timeout", "-r", "--role", "-t", "--type", "-U", "--other-user"),
		envAssigns: true,
	},
	WrapEnv: {
		valueOpts:  optSet("-u", "--unset", "-C", "--chdir", "-S", "--split-string"),
		envAssigns: true,
	},
	WrapNohup:   {},
	WrapCommand: {},
	WrapNice: {
		valueOpts: optSet("-n", "--adjustment"),
	},
	WrapTimeout: {
		valueOpts: optSet("-k", "--kill-after", "-s", "--signal"),
		fixedArgs: 1,
	},
	WrapXargs: {
		valueOpts: optSet("-n", "-I", "-i", "-d", "-P", "-s", "-E", "-L", "-a",
			"--arg-file", "--delimiter", "--max-args", "--replace", "--max-chars",
			"--max-lines", "--eof", "--max-procs", "--max-replace-args"),
		defaultCmd: "echo",
	},
	// setsid runs a program in a new session; like nohup it takes only flag
	// options, so the program that follows is the effective command.
	WrapSetsid: {},
}

// takesValue reports whether opt consumes the following word as its value.
func (s *wrapperSpec) takesValue(opt string) bool {
	if !strings.HasPrefix(opt, "-") || opt == "-" || opt == "--" {
		return false
	}
	if strings.HasPrefix(opt, "--") {
		if strings.IndexByte(opt, '=') >= 0 {
			return false // value attached: --user=root
		}
		return s.valueOpts[opt]
	}
	if len(opt) > 2 {
		return false // value attached: -uroot
	}
	return s.valueOpts[opt]
}

// unwrap peels recognized wrappers off the front of a simple command's words.
// It returns the wrapper chain (outermost first), the environment assignments
// the wrappers contributed, and the index of the first word that is part of the
// effective command (== len(words) when nothing remains).
func (n *normalizer) unwrap(words []*syntax.Word) ([]*Wrapper, []*Assign, int) {
	var (
		wrappers []*Wrapper
		env      []*Assign
	)
	i := 0
	for i < len(words) {
		name, ok := literalOf(words[i])
		if !ok {
			break
		}
		spec, ok := wrapperSpecs[name]
		if !ok {
			break
		}
		w := &Wrapper{Name: name, Pos: fromMvdanPos(words[i].Pos())}
		j := i + 1

		// Consume the wrapper's options.
		for j < len(words) {
			opt, ok := literalOf(words[j])
			if !ok {
				break
			}
			if opt == "--" || opt == "-" {
				j++
				break
			}
			if !strings.HasPrefix(opt, "-") {
				break
			}
			w.Options = append(w.Options, opt)
			if spec.takesValue(opt) && j+1 < len(words) {
				if v, ok := literalOf(words[j+1]); ok {
					w.Options = append(w.Options, v)
				}
				j += 2
				continue
			}
			j++
		}

		// Consume the wrapper's environment assignments.
		if spec.envAssigns {
			for j < len(words) {
				lit, ok := literalOf(words[j])
				if !ok {
					break
				}
				a, ok := n.envAssignWord(words[j], lit, name)
				if !ok {
					break
				}
				env = append(env, a)
				j++
			}
		}

		// Consume the wrapper's fixed positional arguments.
		for k := 0; k < spec.fixedArgs && j < len(words); k++ {
			w.Args = append(w.Args, n.word(words[j]))
			j++
		}

		wrappers = append(wrappers, w)
		i = j
	}

	return wrappers, env, i
}

// envAssignWord turns a literal "NAME=value" word introduced by a wrapper into
// an Assign, preserving the source position of both the name and the value.
func (n *normalizer) envAssignWord(w *syntax.Word, lit, via string) (*Assign, bool) {
	name, value, ok := splitEq(lit)
	if !ok {
		return nil, false
	}
	p := fromMvdanPos(w.Pos())
	out := &Assign{Pos: p, Name: name, Via: via}
	if value != "" {
		out.Value = &Word{
			Pos:     shiftPos(p, len(name)+1),
			Value:   value,
			Literal: true,
		}
	}
	return out, true
}

// ===========================================================================
// Word / name helpers
// ===========================================================================

// literalOf returns the literal text of a word and whether the word is fully
// literal (no parameter expansion, command substitution, arithmetic, process
// substitution, extended glob, or unquoted-nonliteral content).
func literalOf(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	for _, p := range w.Parts {
		switch p := p.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, ip := range p.Parts {
				lit, ok := ip.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// splitEq splits a literal "NAME=value" string, requiring a valid name. The
// value may be empty.
func splitEq(s string) (name, value string, ok bool) {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return "", "", false
	}
	if !validName(s[:i]) {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// validName reports whether s is a valid shell name (a variable name).
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// paramOp renders the operator of a parameter expansion, or "" for a plain $x.
func paramOp(p *syntax.ParamExp) string {
	switch {
	case p.Excl:
		return "!"
	case p.Length:
		return "#"
	case p.Width:
		return "%"
	case p.Slice != nil:
		return ":"
	case p.Repl != nil:
		return "/"
	case p.Exp != nil:
		return p.Exp.Op.String()
	default:
		return ""
	}
}

// ===========================================================================
// Symbol resolution
// ===========================================================================

// annotate marks every command whose name is a declared function or alias.
func annotate(stmts []*Stmt, funcs map[string]*Func, aliases map[string]*Alias) {
	for _, s := range stmts {
		if s == nil {
			continue
		}
		if c := s.Cmd; c != nil && c.Name != "" {
			switch {
			case funcs[c.Name] != nil:
				c.ResolveKind, c.ResolvesTo = "func", c.Name
			case aliases[c.Name] != nil:
				c.ResolveKind, c.ResolvesTo = "alias", c.Name
			}
		}
		if f := s.Func; f != nil {
			annotate(f.Body, funcs, aliases)
		}
		annotate(s.Cond, funcs, aliases)
		annotate(s.Body, funcs, aliases)
		annotate(s.Else, funcs, aliases)
		if s.Left != nil {
			annotate([]*Stmt{s.Left}, funcs, aliases)
		}
		if s.Right != nil {
			annotate([]*Stmt{s.Right}, funcs, aliases)
		}
		for _, it := range s.Items {
			annotate(it.Body, funcs, aliases)
		}
	}
}
