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
	// WrapBuiltin is the `builtin` keyword: like `command` it forces the shell
	// builtin, bypassing functions/aliases, and its members (eval, source, …)
	// execute arbitrary code — so it is unwrapped so the wrapped command is
	// analysed rather than dropped.
	WrapBuiltin = "builtin"
	// WrapStdbuf adjusts the buffering of the program it runs; that program is
	// the wrapper's payload, so leaving stdbuf unpeeled would report a spawn of
	// stdbuf instead of the destructive command it runs.
	WrapStdbuf = "stdbuf"
	// WrapWatch runs its program repeatedly, in a child process; that program
	// is the wrapper's payload.
	WrapWatch = "watch"
	// The wrappers below run the command that follows their own options
	// (Finding 2). Their knowledge-base rows declare that positional a bare
	// `ProcSpawn` of a program name, so leaving them unpeeled reports the
	// wrapper's spawn and loses everything the payload does:
	// `flock /tmp/l rm -rf /x` graded Medium while the identical `rm -rf /x`
	// graded Critical, and a policy keyed on the grade admitted it.
	//
	// The payload is the run of words that follows the wrapper's own options
	// and positionals, so each spec models exactly that arity — including the
	// options that consume a value, since consuming one word too few would bind
	// an option value as the payload command (a fabricated program name) and
	// one too many would drop the payload.
	WrapFlock      = "flock"       // flock [OPTIONS] FILE|DIR COMMAND [ARG…]
	WrapSystemdRun = "systemd-run" // systemd-run [OPTIONS] COMMAND [ARG…]
	WrapNsenter    = "nsenter"     // nsenter [OPTIONS] [PROGRAM [ARG…]]
	WrapTaskset    = "taskset"     // taskset [OPTIONS] MASK COMMAND [ARG…]
	WrapIonice     = "ionice"      // ionice [OPTIONS] [COMMAND [ARG…]]
	WrapChrt       = "chrt"        // chrt [OPTIONS] PRIORITY COMMAND [ARG…]
	WrapUnshare    = "unshare"     // unshare [OPTIONS] [PROGRAM [ARG…]]
	// The tracers, sandboxes and process-attribute launchers below are the
	// rest of the same class (Finding 2): each runs the command that follows
	// its own options, and its row models that operand as a bare ProcSpawn, so
	// leaving it unpeeled reports the spawn of the tracer and loses everything
	// the payload does (`strace -f rm -rf /x` graded Medium while `timeout 5
	// rm -rf /x` graded Critical).
	WrapSSHAgent    = "ssh-agent"   // ssh-agent [-a BIND] [-t LIFE] [CMD [ARG…]]
	WrapStrace      = "strace"      // strace [OPTIONS] COMMAND [ARG…]
	WrapLtrace      = "ltrace"      // ltrace [OPTIONS] COMMAND [ARG…]
	WrapValgrind    = "valgrind"    // valgrind [OPTIONS] PROG [ARG…]
	WrapCaffeinate  = "caffeinate"  // caffeinate [-t SEC] [-w PID] COMMAND [ARG…]
	WrapChroot      = "chroot"      // chroot [OPTION] NEWROOT [COMMAND [ARG…]]
	WrapRuncon      = "runcon"      // runcon [OPTIONS] COMMAND [ARG…]
	WrapPrlimit     = "prlimit"     // prlimit [OPTIONS] [RESOURCE[=LIMITS]…] [COMMAND [ARG…]]
	WrapSwitchRoot  = "switch_root" // switch_root [-c CONSOLE] NEW_ROOT NEW_INIT [ARG…]
	WrapSetarch     = "setarch"     // setarch [ARCH] [OPTIONS] COMMAND [ARG…]
	WrapLinux32     = "linux32"     // linux32 [OPTIONS] COMMAND [ARG…] (setarch alias)
	WrapLinux64     = "linux64"     // linux64 [OPTIONS] COMMAND [ARG…] (setarch alias)
	WrapBusybox     = "busybox"     // busybox APPLET [ARG…]
	WrapToybox      = "toybox"      // toybox APPLET [ARG…]
	WrapEnvdir      = "envdir"      // envdir DIR COMMAND [ARG…]
	WrapSoftlimit   = "softlimit"   // softlimit [OPTIONS] COMMAND [ARG…]
	WrapFaketime    = "faketime"    // faketime [OPTIONS] TIMESTAMP COMMAND [ARG…]
	WrapUnbuffer    = "unbuffer"    // unbuffer [OPTIONS] COMMAND [ARG…]
	WrapXvfbRun     = "xvfb-run"    // xvfb-run [OPTIONS] COMMAND [ARG…]
	WrapSystemdCat  = "systemd-cat" // systemd-cat [OPTIONS] [COMMAND [ARG…]]
	WrapTorsocks    = "torsocks"    // torsocks [OPTIONS] COMMAND [ARG…]
	WrapProxychains = "proxychains" // proxychains[4] [-f CONFIG] COMMAND [ARG…]
)

// commandStringWrappers are the wrappers that take their payload as a *shell
// command string* rather than as argv words (`man su`: "Pass command to the
// shell with the -c option"; `man script`, `man flock`). The normalizer's
// word-level peel cannot express that payload, so front/bash/exec.go extracts
// the string, parses it as the shell line it is, and analyses it — degrading to
// ⊤ when it cannot be bound (Finding 2). Their command-name-to-option mapping
// lives in exec.go (execWrapperPayloadOption), which keeps this package free of
// any binding decision.
var commandStringWrappers = map[string]bool{
	"su":      true, // su [-c CMD] …
	"runuser": true, // runuser [-c CMD] … (su's unprivileged sibling)
	"script":  true, // script [-c CMD] [FILE]
	WrapFlock: true, // flock [-c CMD] FILE
}

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

	// Redirs are the I/O redirections of the statement the command runs in, as
	// the abstract interpreter resolved them (operator plus expanded target
	// text). They are attached while the statement executes and feed the
	// report's per-command view; they are deliberately not part of the
	// serialized normalized AST.
	Redirs []ExecRedirect `json:"-"`
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

// ExecRedirect is one redirection of the statement a command runs in, as the
// abstract interpreter resolved it: the operator verbatim and the expanded
// target text (a file path, an fd word for stream dupes, a host:port for the
// /dev/tcp pseudo-file; empty for heredocs). Known reports whether the target
// text is statically known — an unknown target is the expanded word's
// placeholder, not a path the analysis can bound. It rides on Command.Redirs
// for the report's per-command view and is not part of the serialized AST.
type ExecRedirect struct {
	Op     string
	Target string
	Known  bool
}

// Word is a shell word: its source position, the literal text when it is fully
// literal, and the structural parts that make it up.
type Word struct {
	Pos     Pos    `json:"pos"`
	Value   string `json:"value,omitempty"`
	Literal bool   `json:"literal"`
	Parts   []Part `json:"parts,omitempty"`

	// Dir is the directory a non-literal word is confined to when every one of
	// its dynamic parts is numeric-class (an exit status, a pid, a length: see
	// the numeric-class section of expand.go). Empty for literal words and for
	// dynamic words the analysis cannot bound, which stay ⊤. It is analysis
	// metadata consumed by the binding layer and is deliberately not part of
	// the serialized normalized AST.
	Dir string `json:"-"`

	// Taint is the provenance of the word's value, as computed by abstract
	// execution (variable reads, command substitutions, …). It is analysis
	// metadata consumed by the binding layer and is deliberately not part of
	// the serialized normalized AST.
	Taint engine.Taint `json:"-"`

	// Root marks a literal relative operand that the shell's tracked working
	// directory resolves to the filesystem root ("." after `cd /`, "../../"
	// after `cd /tmp`). The value keeps its written form; the binding layer
	// resolves it to the root only where the effect's extent is graded
	// (metadata changes — Finding 70).
	Root bool `json:"-"`
	// FromXargs marks an operand whose value xargs substitutes from its input
	// items (Finding 92): the value is data, not text, so it is unknown (⊤) and
	// a parameter that reads a file reads a path the analysis cannot name.
	FromXargs bool `json:"-"`
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
	// fixedUnless names options whose presence replaces the fixed positional
	// with an option value (taskset: `-c/--cpu-list` supplies the CPU list, so
	// the MASK positional disappears and the next word is already the payload).
	// When any recorded option is in the set, fixedArgs is not consumed.
	fixedUnless map[string]bool
	// fixedIfIn consumes the fixed positional only when its literal text is a
	// member of the set. setarch's ARCH word is optional and syntactically
	// indistinguishable from the program name, so consuming it unconditionally
	// would bind `setarch -R rm -rf /x`'s `-rf` as the payload command; the
	// architecture names are a closed vocabulary, so the word is consumed only
	// when it is one of them.
	fixedIfIn map[string]bool
	// requirePayload makes the peel conditional on a payload word actually
	// following: these wrappers' command-less forms are queries or usage errors
	// (`chrt -p 1` prints a pid's policy, `ionice -p 1234` its class,
	// `flock FILE` just locks), so peeling them would leave no command and
	// widen an inert line to ⊤. With no payload the wrapper word stays the
	// command and its own row binds it.
	requirePayload bool
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

// setarchArchitectures is the closed vocabulary setarch accepts as its optional
// ARCH word (`setarch --list`). Only these words may be consumed as the fixed
// positional, so a program name is never mistaken for an architecture.
var setarchArchitectures = optSet(
	"i386", "i486", "i586", "i686", "x86_64", "amd64", "arm", "armv5l",
	"armv7l", "armv8l", "aarch64", "arm64", "ppc", "ppc64", "ppc64le",
	"s390", "s390x", "mips", "mips64", "mips64el", "mipsel", "riscv32",
	"riscv64", "sparc", "sparc64", "alpha", "hppa", "m68k", "ia64", "sh4",
	"xtensa", "loongarch64", "uname26", "linux32", "linux64",
)

// wrapperSpecs is the closed set of recognized wrappers.
var wrapperSpecs = map[string]*wrapperSpec{
	WrapSudo: {
		valueOpts: optSet("-u", "--user", "-g", "--group", "-h", "--host", "-D", "--chdir",
			"-R", "--chroot", "-p", "--prompt",
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
	// builtin forces a shell builtin; it takes no options of its own.
	WrapBuiltin: {},
	// stdbuf runs the program that follows with an adjusted buffering mode; its
	// own options are the buffering flags (-i/-o/-e and their long forms), each
	// of which takes the mode as its value.
	WrapStdbuf: {
		valueOpts: optSet("-i", "-o", "-e", "--input", "--output", "--error"),
	},
	// watch runs the command that follows every interval seconds; only the
	// interval option takes a value, the rest (--no-title, --differences, …)
	// are plain flags.
	WrapWatch: {
		valueOpts: optSet("-n", "--interval"),
	},

	// ---------------------------------------------------------------------
	// Payload wrappers (Finding 2). Each option set below is the wrapper's
	// documented value-taking set (man flock/systemd-run/nsenter/taskset/
	// ionice/chrt/unshare); every other option is a flag whose word the peel
	// skips without consuming a value.
	// ---------------------------------------------------------------------

	// flock [OPTIONS] FILE|DIR COMMAND [ARG…]: the lock file is the one fixed
	// positional; `-c`/`--command` supplies the payload as a string instead
	// (exec.go analyses it), which is why it appears as a value option here —
	// its value must never be read as the COMMAND word.
	WrapFlock: {
		valueOpts: optSet("-c", "--command", "-E", "--conflict-exit-code",
			"-w", "--wait", "--timeout", "--start", "--length"),
		fixedArgs:      1,
		requirePayload: true,
	},
	// systemd-run [OPTIONS] COMMAND [ARG…].
	WrapSystemdRun: {
		valueOpts: optSet("-u", "--unit", "-p", "--property", "-E", "--setenv",
			"--description", "--slice", "--expand-environment", "--service-type",
			"--uid", "--gid", "--nice", "--working-directory", "--root-directory",
			"--output", "--on-active", "--on-boot", "--on-startup",
			"--on-unit-active", "--on-unit-inactive", "--on-calendar",
			"--path-property", "--socket-property", "--timer-property",
			"--job-mode", "--background", "-H", "--host", "-M", "--machine",
			"-C", "--capsule", "--json"),
		requirePayload: true,
	},
	// nsenter [OPTIONS] [PROGRAM [ARG…]]. A command-less nsenter executes
	// $SHELL (`man nsenter`), so no payload is itself an unbounded execution
	// and the peel stays unconditional.
	WrapNsenter: {
		valueOpts: optSet("-t", "--target", "-N", "--net-socket", "-G", "--setgid",
			"-S", "--setuid"),
	},
	// taskset [OPTIONS] MASK COMMAND [ARG…]; the MASK positional is replaced by
	// the -c/--cpu-list value, so it is only consumed when that option is
	// absent.
	WrapTaskset: {
		valueOpts:      optSet("-c", "--cpu-list", "-p", "--pid"),
		fixedArgs:      1,
		fixedUnless:    optSet("-c", "--cpu-list"),
		requirePayload: true,
	},
	// ionice [OPTIONS] [COMMAND [ARG…]].
	WrapIonice: {
		valueOpts: optSet("-c", "--class", "-n", "--classdata", "-p", "--pid",
			"-P", "--pgid", "-u", "--uid"),
		requirePayload: true,
	},
	// chrt [OPTIONS] PRIORITY COMMAND [ARG…].
	WrapChrt: {
		valueOpts: optSet("-T", "--sched-runtime", "-P", "--sched-period",
			"-D", "--sched-deadline", "-p", "--pid"),
		fixedArgs:      1,
		requirePayload: true,
	},
	// unshare [OPTIONS] [PROGRAM [ARG…]]. The namespace options take an
	// OPTIONAL value (`-m[=file]`), so they stay flags: consuming a following
	// word would swallow the payload. The options with a mandatory value are
	// listed.
	WrapUnshare: {
		valueOpts: optSet("-R", "--root", "-w", "--wd", "-S", "--setuid",
			"-G", "--setgid", "-l", "--load-interp", "--map-user", "--map-users",
			"--map-group", "--map-groups", "--owner", "--propagation",
			"--setgroups", "--monotonic", "--boottime"),
	},

	// ---------------------------------------------------------------------
	// Process-attribute launchers and tracers (Finding 2). Each runs the
	// command after its own options; the option sets below are the documented
	// value-taking options, so the peel neither binds an option value as the
	// payload nor swallows the payload word.
	// ---------------------------------------------------------------------

	// ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]
	//           [-O option] [-P allowed_providers] [-t life] [command [arg …]]
	// A command-less ssh-agent starts a daemon and runs nothing, so the peel
	// requires a payload.
	WrapSSHAgent: {
		valueOpts:      optSet("-a", "-E", "-O", "-P", "-t"),
		requirePayload: true,
	},
	// strace [OPTIONS] PROG [ARGS]. The value-taking options are documented in
	// strace(1); every other option (-f, -c, -t, -y, …) is a flag.
	WrapStrace: {
		valueOpts: optSet("-a", "-b", "-e", "-E", "-I", "-O", "-p", "-P", "-s",
			"-S", "-u", "-X", "-o", "--output", "--expr", "--attach",
			"--columns", "--decode-fds", "--string-limit", "--syscall-limit",
			"--trace", "--signal", "--status", "--read", "--write",
			"--inject", "--fault", "--tips", "--stack-traces"),
		requirePayload: true,
	},
	// ltrace [OPTIONS] COMMAND [ARG…]; same shape as strace.
	WrapLtrace: {
		valueOpts: optSet("-a", "-A", "-b", "-e", "-l", "-n", "-o", "-p", "-s",
			"-u", "-x", "--output", "--config"),
		requirePayload: true,
	},
	// valgrind [OPTIONS] PROG [ARGS]; the tool and log destinations take
	// values, everything else is a flag or a --tool=… attached form.
	WrapValgrind: {
		valueOpts: optSet("--tool", "--log-file", "--log-file-exactly",
			"--log-file-qualifier", "--log-socket", "--xml-file",
			"--xml-socket", "--vgdb", "--vgdb-error", "--vgdb-startup",
			"--demangle", "--num-callers", "--error-limit", "--max-threads",
			"--trace-children", "--child-silent-after-fork", "--gen-suppressions",
			"--suppressions", "--trace-redir", "--input-fd", "--log-fd",
			"--xml-fd"),
		requirePayload: true,
	},
	// caffeinate [-disu] [-t timeout] [-w pid] [command [arg …]]
	WrapCaffeinate: {
		valueOpts:      optSet("-t", "-w"),
		requirePayload: true,
	},
	// chroot [OPTION] NEWROOT [COMMAND [ARG…]]; with no COMMAND it runs
	// ${SHELL} -i, so only an explicit payload is peeled.
	WrapChroot: {
		valueOpts:      optSet("--userspec", "--groups"),
		fixedArgs:      1,
		requirePayload: true,
	},
	// runcon [OPTIONS] COMMAND [ARG…]
	WrapRuncon: {
		valueOpts: optSet("-c", "--compute", "-t", "--type", "-u", "--user",
			"-r", "--role", "-l", "--range"),
		requirePayload: true,
	},
	// prlimit [OPTIONS] [RESOURCE[=LIMITS]…] [COMMAND [ARG…]]. Every resource
	// name is a value-taking long option in its separated spelling
	// (`--nofile 1024`); the `--nofile=1024` form is attached and is skipped
	// by takesValue. The short aliases documented by util-linux are listed with
	// them.
	WrapPrlimit: {
		valueOpts: optSet("-p", "--pid", "-o", "--output", "--as", "--core",
			"--cpu", "--data", "--fsize", "--locks", "--memlock", "--msgqueue",
			"--nice", "--nofile", "--nproc", "--rss", "--rtprio", "--rttime",
			"--sigpending", "--stack", "-c", "-d", "-e", "-f", "-i", "-l", "-m",
			"-n", "-q", "-r", "-s", "-t"),
		requirePayload: true,
	},
	// switch_root [-c CONSOLE] NEW_ROOT NEW_INIT [ARGS…]
	WrapSwitchRoot: {
		valueOpts:      optSet("-c", "--console"),
		fixedArgs:      2,
		requirePayload: true,
	},
	// setarch [ARCH] [OPTIONS] [PROGRAM [ARG…]]; linux32/linux64 are the same
	// binary with the architecture preset, so they take no ARCH positional.
	// The ARCH word is only consumed when it actually names an architecture:
	// consuming the program word as ARCH (`setarch -R rm -rf /x`) would bind
	// `-rf` as the payload command and fabricate the report.
	WrapSetarch: {
		fixedArgs:      1,
		fixedIfIn:      setarchArchitectures,
		requirePayload: true,
	},
	WrapLinux32: {
		requirePayload: true,
	},
	WrapLinux64: {
		requirePayload: true,
	},
	// busybox APPLET [ARG…] / toybox APPLET [ARG…]: the applet is the payload
	// command (busybox rm -rf /x runs rm).
	WrapBusybox: {
		requirePayload: true,
	},
	WrapToybox: {
		requirePayload: true,
	},
	// envdir DIR COMMAND [ARG…]
	WrapEnvdir: {
		fixedArgs:      1,
		requirePayload: true,
	},
	// softlimit [-a all] [-c core] [-d data] [-f fsize] [-l lock] [-m mem]
	//          [-o ofile] [-p nproc] [-r rss] [-s stack] [-t cpu] PROG [ARG…]
	WrapSoftlimit: {
		valueOpts: optSet("-a", "-c", "-d", "-f", "-l", "-m", "-o", "-p", "-r",
			"-s", "-t"),
		requirePayload: true,
	},
	// faketime [OPTIONS] TIMESTAMP COMMAND [ARG…]; the TIMESTAMP positional is
	// the one fixed operand.
	WrapFaketime: {
		valueOpts:      optSet("-f", "--format", "--exclude-monotonic", "-m"),
		fixedArgs:      1,
		requirePayload: true,
	},
	// unbuffer [OPTIONS] COMMAND [ARG…] (expect)
	WrapUnbuffer: {
		valueOpts:      optSet("-p"),
		requirePayload: true,
	},
	// xvfb-run [OPTIONS] COMMAND [ARG…]
	WrapXvfbRun: {
		valueOpts: optSet("-n", "-s", "-f", "-e", "-p", "--server-num",
			"--server-args", "--auth-file", "--error-file", "--auto-servernum"),
		requirePayload: true,
	},
	// systemd-cat [OPTIONS] [COMMAND [ARG…]]; with no command it reads stdin,
	// so only an explicit payload is peeled.
	WrapSystemdCat: {
		valueOpts: optSet("-t", "--identifier", "-p", "--priority", "--stderr",
			"--namespace", "-u", "--unit"),
		requirePayload: true,
	},
	// torsocks [OPTIONS] COMMAND [ARG…]
	WrapTorsocks: {
		valueOpts:      optSet("-u", "--user", "-p", "--pass", "-P", "--port", "-a", "--address", "-i", "--isolate"),
		requirePayload: true,
	},
	// proxychains / proxychains4 [-f CONFIG] [-q] COMMAND [ARG…]
	WrapProxychains: {
		valueOpts:      optSet("-f"),
		requirePayload: true,
	},
	// proxychains4 is the same program under its version-suffixed name.
	"proxychains4": {
		valueOpts:      optSet("-f"),
		requirePayload: true,
	},
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

// SudoValueOpts reports whether opt is one of sudo's value-taking options —
// the same set unwrap uses to pair option words with the values they absorb.
// Exported for the binder's wrapper elevation, which re-walks the recorded
// option words and must know which entries were consumed values rather than
// free-standing flags.
func SudoValueOpts(opt string) bool {
	return wrapperSpecs[WrapSudo].valueOpts[opt]
}

// dynamicValueOption reports whether the literal prefix of a partially-dynamic
// word names value-taking options of the wrapper, returning the option specs
// to record. The prefix may carry the attached-value long form (`--user=`);
// a short prefix is a cluster whose last element takes the expansion as its
// value (`-lu"$U"` records `-l` and an unsatisfied `-u` + `@`) — earlier cluster
// elements are plain flags. A known limitation: when an EARLIER cluster
// element is itself value-taking (`-ug"$U"` — real bash attaches `g…` to
// `-u`), the element is recorded as an unsatisfied option instead; the
// resulting unresolved-target elevation and notes are the safe over-report
// for either reading of the spelling (real bash attaches the whole tail to
// the last option). A long prefix without `=` is recorded as the bare option
// plus the `@` placeholder once its quoted tail is absorbed (`--user"$U"`
// records `--user` + `@`); the literal misspelling `--usernobody` stays a
// single unknown option. The unresolved target is the safe side of a spelling
// sudo itself would reject. The caller absorbs
// the matched word only when its dynamic tail is quoted (dynamicTailQuoted):
// an unquoted expansion field-splits, so the word stays the dynamically-named
// inner command.
func (s *wrapperSpec) dynamicValueOption(prefix string) ([]string, bool) {
	if !strings.HasPrefix(prefix, "-") || prefix == "-" || prefix == "--" {
		return nil, false
	}
	if strings.HasPrefix(prefix, "--") {
		name := prefix
		if k := strings.IndexByte(prefix, '='); k >= 0 {
			name = prefix[:k]
		}
		if !s.valueOpts[name] {
			return nil, false
		}
		return []string{name}, true
	}
	last := "-" + prefix[len(prefix)-1:]
	if !s.valueOpts[last] {
		return nil, false // attached short-option value (-uroot…) needs the full word
	}
	specs := make([]string, 0, len(prefix))
	for i := 1; i < len(prefix)-1; i++ {
		specs = append(specs, "-"+prefix[i:i+1])
	}
	return append(specs, last), true
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
		// `ip netns exec NS cmd …` is a payload wrapper whose object/command
		// pair, not the command name alone, decides whether a program runs
		// (`ip netns list` runs none). It is the one multi-word wrapper: without
		// the peel the destructive payload vanished entirely and
		// `ip netns exec ns1 rm -rf /x` graded Low.
		if name == "ip" {
			if ns, next, matched := ipNetnsExec(words, i+1); matched {
				w := &Wrapper{Name: name, Pos: fromMvdanPos(words[i].Pos())}
				w.Args = append(w.Args, n.word(ns))
				wrappers = append(wrappers, w)
				i = next
				continue
			}
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
				// A word with a dynamic part. When its literal prefix names
				// value-taking options of the wrapper, the expansion reads as
				// the last one's attached value (`sudo -u"$U" cmd`, `sudo
				// --user="$U" cmd`, `sudo -lu"$U" cmd`): record the options —
				// the value-taking one without a resolvable value (the `@`
				// placeholder when the word is absorbed), which the refined
				// -u doctrine resolves to an unresolved target. The word itself
				// is absorbed — and the peel continues with the following
				// words — only when the dynamic tail is quoted: bash
				// field-splits the expansion of an unquoted part, so `sudo
				// -u$U cmd` can expand into several argv fields (an option
				// value plus free-standing words sudo reads as its own
				// command line). Such a word ends the option run instead and
				// stays the (dynamic) inner command the analysis degrades to
				// ⊤; the recorded unsatisfied options keep the doctrine in
				// charge of the elevation verdict. Any other partially
				// dynamic word ends the option run too.
				if specs, dyn := spec.dynamicValueOption(literalPrefixOf(words[j])); dyn {
					w.Options = append(w.Options, specs...)
					if dynamicTailQuoted(words[j]) {
						// The quoted expansion is one field, absorbed as the
						// last recorded option's value — which the analysis
						// cannot resolve. Record the "@" placeholder the
						// separated spelling uses, so the binder's re-pairing
						// can never glue the following option word as this
						// option's value (`sudo -u"$U" -l cmd` must keep -l
						// free-standing, exactly like `sudo -u $U -l cmd`).
						w.Options = append(w.Options, "@")
						j++
						continue
					}
				}
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
				} else {
					// The value is dynamic: record a placeholder so the
					// binder's re-pairing can never glue the next word as
					// this option's value.
					w.Options = append(w.Options, "@")
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
		fixed := spec.fixedArgs
		for _, o := range w.Options {
			if spec.fixedUnless[o] {
				fixed = 0
				break
			}
		}
		if spec.fixedIfIn != nil {
			if j < len(words) {
				if lit, ok := literalOf(words[j]); !ok || !spec.fixedIfIn[lit] {
					fixed = 0
				}
			} else {
				fixed = 0
			}
		}
		for k := 0; k < fixed && j < len(words); k++ {
			w.Args = append(w.Args, n.word(words[j]))
			j++
		}

		// GNU option permutation: an option may follow the wrapper's fixed
		// positional (`setarch x86_64 -R cmd`, `timeout 5 -k 1 cmd`), because
		// getopt permutes the non-option words to the end. Re-process the option
		// run once the fixed positional has been consumed; a payload command
		// never starts with '-' (and `--` still terminates the run).
		if fixed > 0 {
			for j < len(words) {
				opt, ok := literalOf(words[j])
				if !ok || !strings.HasPrefix(opt, "-") || opt == "-" {
					break
				}
				if opt == "--" {
					j++
					break
				}
				w.Options = append(w.Options, opt)
				if spec.takesValue(opt) && j+1 < len(words) {
					if v, ok := literalOf(words[j+1]); ok {
						w.Options = append(w.Options, v)
					} else {
						w.Options = append(w.Options, "@")
					}
					j += 2
					continue
				}
				j++
			}
		}

		// A wrapper whose command-less form runs nothing (chrt -p PID,
		// ionice -p PID, taskset -p PID, flock FILE, systemd-run --scope) is
		// peeled only when a payload word actually follows. Peeling it with no
		// payload would leave the line without a command and widen an inert
		// query to ⊤; leaving the wrapper word alone lets its own row bind it.
		if spec.requirePayload && j >= len(words) {
			break
		}

		wrappers = append(wrappers, w)
		i = j
	}

	return wrappers, env, i
}

// ipValueOpts are ip(8)'s value-taking global options, which may sit between
// the command name and the object word (`ip -n NS netns exec …`).
var ipValueOpts = optSet("-n", "--netns", "-f", "--family", "-l", "--loops",
	"-rc", "--rcvbuf")

// ipNetnsExec matches the `ip [OPTIONS] netns exec NS COMMAND [ARG…]` shape and
// returns the namespace operand and the index of the payload's first word. Any
// other ip invocation (`ip netns list`, `ip addr`) runs no program, so the
// boolean is false and the wrapper word stays the command.
func ipNetnsExec(words []*syntax.Word, j int) (*syntax.Word, int, bool) {
	for j < len(words) {
		lit, ok := literalOf(words[j])
		if !ok {
			return nil, 0, false
		}
		switch {
		case lit == "netns":
			// netns exec NS COMMAND — the object and command words are fixed,
			// and a command-less form is a usage error that runs nothing.
			if j+3 >= len(words) {
				return nil, 0, false
			}
			if obj, ok := literalOf(words[j+1]); !ok || obj != "exec" {
				return nil, 0, false
			}
			if _, ok := literalOf(words[j+2]); !ok {
				return nil, 0, false
			}
			if _, ok := literalOf(words[j+3]); !ok {
				return nil, 0, false
			}
			return words[j+2], j + 3, true
		case strings.HasPrefix(lit, "-"):
			if lit == "--" {
				return nil, 0, false
			}
			if ipValueOpts[lit] {
				if j+1 >= len(words) {
					return nil, 0, false
				}
				j += 2
				continue
			}
			j++
		default:
			return nil, 0, false
		}
	}
	return nil, 0, false
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

// dynamicTailQuoted reports whether every dynamic part of a word sits inside
// double quotes, so the word still expands to a single field. Bash
// field-splits the expansion of an unquoted part, and the split fields become
// free-standing argv words: `sudo -u$U cmd` with U="root rm -rf /" really runs
// `rm -rf /` as root, so such a word can never be folded into the wrapper's
// option run. A quoted tail (`sudo -u"$U" cmd`) expands to one field and is
// what the attached-value reading assumes.
func dynamicTailQuoted(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, p := range w.Parts {
		switch p.(type) {
		case *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
			// Literal text and quoted runs stay one field.
		default:
			return false
		}
	}
	return true
}

// literalPrefixOf returns the literal text a word STARTS with, stopping at the
// first part that is not literal text — the prefix analogue of literalOf, so
// `-u"$U"` yields `-u`: the literal option spelling that precedes the first
// expansion.
func literalPrefixOf(w *syntax.Word) string {
	if w == nil {
		return ""
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
					return b.String()
				}
				b.WriteString(lit.Value)
			}
		default:
			return b.String()
		}
	}
	return b.String()
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

// ===========================================================================
// find(1) exec actions
// ===========================================================================

// findExecActions are the find(1) primaries that run an arbitrary command on
// the files the search matched. The words that follow one of them are not
// find's own operands: they are a command line of their own, terminated by `;`
// (one run per file) or `+` (as many files per run as fit). Binding them as
// find's positional payload reports a spawn of a program name and never the
// destructive effects the payload performs, so they are extracted here and
// analysed as the invocations they are.
var findExecActions = map[string]bool{
	"-exec":    true,
	"-execdir": true,
	"-ok":      true,
	"-okdir":   true,
}

// findPayload is one command a find(1) invocation runs through an exec action,
// reduced to the invocation it performs.
type findPayload struct {
	// Cmd is the payload invocation: its own wrappers peeled, and each `{}`
	// operand replaced by the search roots the matched files come from.
	Cmd *Command
	// Certain is false when the payload cannot be bounded statically — a
	// dynamically-named command, an expansion-bearing word, or a search root
	// that is not a literal. The caller must then degrade the payload to ⊤
	// rather than bind a fabricated, narrow effect set.
	Certain bool
}

// findPayloads extracts the commands a find(1) invocation runs through its
// -exec/-execdir/-ok/-okdir actions. words must begin with find's own name.
//
// Each `{}` operand stands for every matched file, i.e. a path under one of the
// search roots, so it is replaced by those roots: the payload then targets the
// searched subtree instead of the literal string "{}". A search root the
// analysis cannot resolve, or a payload word carrying an expansion, leaves the
// payload unbounded (Certain == false) rather than substituting a fabricated
// path — the same fail-closed rule the wrapper peel follows.
func (n *normalizer) findPayloads(words []*syntax.Word) []*findPayload {
	if len(words) < 2 {
		return nil
	}

	// The search roots are the leading operands before find's expression: the
	// literal words that do not start an expression (a `-primary`, `!`, `(`).
	var roots []string
	rootOK := true
	for _, w := range words[1:] {
		lit, ok := literalOf(w)
		if !ok {
			rootOK = false
			break
		}
		if strings.HasPrefix(lit, "-") || lit == "!" || lit == "(" || lit == ")" {
			break
		}
		roots = append(roots, lit)
	}

	var out []*findPayload
	for i := 1; i < len(words); i++ {
		lit, ok := literalOf(words[i])
		if !ok || !findExecActions[lit] {
			continue
		}
		j := i + 1
		var payload []*syntax.Word
		terminated := false
		for ; j < len(words); j++ {
			v, ok := literalOf(words[j])
			if ok && isFindActionTerminator(v) {
				terminated = true
				break
			}
			payload = append(payload, words[j])
		}
		// An unterminated action is a find usage error: find runs no payload.
		if terminated && len(payload) > 0 {
			out = append(out, n.findPayload(payload, roots, rootOK))
		}
		i = j
	}
	return out
}

// isFindActionTerminator reports whether v ends a find exec action's argv. The
// normalizer keeps backslash escapes, so the escaped spelling is matched as
// well as the plain one (a quoted `';'` is already unquoted by literalOf).
func isFindActionTerminator(v string) bool {
	switch v {
	case ";", "\\;", "+", "\\+":
		return true
	}
	return false
}

// findPayload reduces one exec action's argv to the command it runs.
func (n *normalizer) findPayload(words []*syntax.Word, roots []string, rootOK bool) *findPayload {
	certain := rootOK
	substituted := make([]*syntax.Word, 0, len(words))
	rootText := strings.Join(roots, " ")
	for _, w := range words {
		lit, ok := literalOf(w)
		if !ok {
			// A dynamically-valued word: what it expands to is not statically
			// bounded, so the payload cannot be bound either.
			substituted = append(substituted, w)
			certain = false
			continue
		}
		if !strings.Contains(lit, "{}") {
			substituted = append(substituted, w)
			continue
		}
		if !rootOK || len(roots) == 0 {
			// `{}` names a matched file whose location the analysis cannot
			// bound; the payload's operand must stay unknown.
			certain = false
			substituted = append(substituted, litWord("", w.Pos()))
			continue
		}
		if lit == "{}" && len(roots) > 1 {
			// One word per root: the payload runs once per matched file, and a
			// matched file may come from any of the roots.
			for _, r := range roots {
				substituted = append(substituted, litWord(r, w.Pos()))
			}
			continue
		}
		substituted = append(substituted, litWord(strings.ReplaceAll(lit, "{}", rootText), w.Pos()))
	}

	wrappers, wEnv, start := n.unwrap(substituted)
	cmd := &Command{Wrappers: wrappers}
	rest := substituted[start:]
	if len(rest) == 0 {
		if len(wrappers) > 0 {
			last := wrappers[len(wrappers)-1]
			if spec := wrapperSpecs[last.Name]; spec != nil && spec.defaultCmd != "" {
				cmd.Name = spec.defaultCmd
				cmd.NameWord = &Word{Pos: last.Pos, Value: spec.defaultCmd, Literal: true}
			}
			cmd.Pos = last.Pos
		}
		return &findPayload{Cmd: cmd, Certain: false}
	}
	nameWord := n.word(rest[0])
	cmd.NameWord = nameWord
	cmd.Pos = nameWord.Pos
	if !nameWord.Literal {
		certain = false
	} else {
		cmd.Name = nameWord.Value
	}
	for _, w := range rest[1:] {
		cmd.Args = append(cmd.Args, n.word(w))
	}
	cmd.Assigns = append(cmd.Assigns, wEnv...)
	return &findPayload{Cmd: cmd, Certain: certain}
}

// findPayloadsOfWords is findPayloads for an already-normalized invocation:
// its words carry the values the interpreter computed, so literal words are
// re-fabricated from those values and a word with dynamic parts becomes an
// unresolvable part — which keeps the payload unbounded instead of inventing
// one.
func (n *normalizer) findPayloadsOfWords(words []*Word) []*findPayload {
	if len(words) == 0 {
		return nil
	}
	sw := make([]*syntax.Word, 0, len(words)+1)
	sw = append(sw, litWord("find", syntax.Pos{}))
	for _, w := range words {
		switch {
		case w == nil:
			sw = append(sw, litWord("", syntax.Pos{}))
		case w.Literal:
			sw = append(sw, litWord(w.Value, syntax.Pos{}))
		default:
			// A dynamically-valued word: literalOf reports it as non-literal,
			// which is what makes the payload unbounded.
			sw = append(sw, &syntax.Word{Parts: []syntax.WordPart{&syntax.ParamExp{}}})
		}
	}
	return n.findPayloads(sw)
}

// litWord builds a single-literal shell word at pos. It is how the normalizer
// fabricates the words a `{}` substitution or a wrapper default introduces.
func litWord(value string, pos syntax.Pos) *syntax.Word {
	return &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{ValuePos: pos, ValueEnd: pos, Value: value}}}
}
