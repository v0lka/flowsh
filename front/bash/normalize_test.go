package bash

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func parseOK(t *testing.T, v Variant, src string) *Program {
	t.Helper()
	p := Parse(v, "t", src)
	if p.Top {
		t.Fatalf("Parse(%q) unexpectedly top: %s", src, p.Reason)
	}
	return p
}

// singleCommand returns the command of the sole statement of src.
func singleCommand(t *testing.T, src string) *Command {
	t.Helper()
	p := parseOK(t, Bash, src)
	if len(p.Stmts) != 1 {
		t.Fatalf("Parse(%q): got %d stmts want 1", src, len(p.Stmts))
	}
	s := p.Stmts[0]
	if s.Kind != KindSimple || s.Cmd == nil {
		t.Fatalf("Parse(%q): got kind %q cmd %v", src, s.Kind, s.Cmd)
	}
	return s.Cmd
}

func wantPos(t *testing.T, what string, got, want Pos) {
	t.Helper()
	if got != want {
		t.Errorf("%s: pos got %+v want %+v", what, got, want)
	}
}

// ---------------------------------------------------------------------------
// AC 3: wrappers (sudo env FOO=1 cmd) normalize with positions preserved.
// ---------------------------------------------------------------------------

func TestUnwrapSudoEnvPositions(t *testing.T) {
	cmd := singleCommand(t, `sudo env FOO=1 /bin/cmd -x arg`)

	if cmd.Name != "/bin/cmd" {
		t.Errorf("name: got %q want /bin/cmd", cmd.Name)
	}
	// The effective command keeps the position of its own word (col 16).
	wantPos(t, "cmd", cmd.Pos, Pos{Line: 1, Col: 16, Offset: 15})

	if len(cmd.Wrappers) != 2 {
		t.Fatalf("wrappers: got %d want 2", len(cmd.Wrappers))
	}
	if cmd.Wrappers[0].Name != WrapSudo {
		t.Errorf("wrapper0: got %q want sudo", cmd.Wrappers[0].Name)
	}
	wantPos(t, "sudo", cmd.Wrappers[0].Pos, Pos{Line: 1, Col: 1, Offset: 0})
	if cmd.Wrappers[1].Name != WrapEnv {
		t.Errorf("wrapper1: got %q want env", cmd.Wrappers[1].Name)
	}
	wantPos(t, "env", cmd.Wrappers[1].Pos, Pos{Line: 1, Col: 6, Offset: 5})

	if len(cmd.Assigns) != 1 {
		t.Fatalf("assigns: got %d want 1", len(cmd.Assigns))
	}
	a := cmd.Assigns[0]
	if a.Name != "FOO" || a.Via != WrapEnv {
		t.Errorf("assign: got name %q via %q", a.Name, a.Via)
	}
	wantPos(t, "assign", a.Pos, Pos{Line: 1, Col: 10, Offset: 9})
	if a.Value == nil || a.Value.Value != "1" {
		t.Fatalf("assign value: got %+v", a.Value)
	}
	wantPos(t, "assign value", a.Value.Pos, Pos{Line: 1, Col: 14, Offset: 13})

	if len(cmd.Args) != 2 {
		t.Fatalf("args: got %d want 2", len(cmd.Args))
	}
	if cmd.Args[0].Value != "-x" {
		t.Errorf("arg0: got %q", cmd.Args[0].Value)
	}
	wantPos(t, "arg0", cmd.Args[0].Pos, Pos{Line: 1, Col: 25, Offset: 24})
	if cmd.Args[1].Value != "arg" {
		t.Errorf("arg1: got %q", cmd.Args[1].Value)
	}
	wantPos(t, "arg1", cmd.Args[1].Pos, Pos{Line: 1, Col: 28, Offset: 27})
}

func TestUnwrapNestedChain(t *testing.T) {
	const src = `nohup timeout 30 nice -n 5 sudo env A=1 command xargs -0 rm -rf /x`
	cmd := singleCommand(t, src)

	if cmd.Name != "rm" {
		t.Fatalf("name: got %q want rm", cmd.Name)
	}
	wantPos(t, "cmd", cmd.Pos, Pos{Line: 1, Col: 58, Offset: 57})

	wantOrder := []struct {
		name string
		col  int
		off  int
	}{
		{WrapNohup, 1, 0},
		{WrapTimeout, 7, 6},
		{WrapNice, 18, 17},
		{WrapSudo, 28, 27},
		{WrapEnv, 33, 32},
		{WrapCommand, 41, 40},
		{WrapXargs, 49, 48},
	}
	if len(cmd.Wrappers) != len(wantOrder) {
		t.Fatalf("wrappers: got %d want %d", len(cmd.Wrappers), len(wantOrder))
	}
	for i, w := range wantOrder {
		if cmd.Wrappers[i].Name != w.name {
			t.Errorf("wrapper[%d]: got %q want %q", i, cmd.Wrappers[i].Name, w.name)
		}
		wantPos(t, "wrapper "+w.name, cmd.Wrappers[i].Pos, Pos{Line: 1, Col: w.col, Offset: w.off})
	}

	// timeout keeps its duration as a positional arg, with positions.
	tw := cmd.Wrappers[1]
	if len(tw.Args) != 1 || tw.Args[0].Value != "30" {
		t.Fatalf("timeout args: got %+v", tw.Args)
	}
	wantPos(t, "timeout duration", tw.Args[0].Pos, Pos{Line: 1, Col: 15, Offset: 14})

	// nice keeps "-n 5" verbatim.
	if got := cmd.Wrappers[2].Options; !reflect.DeepEqual(got, []string{"-n", "5"}) {
		t.Errorf("nice options: got %v", got)
	}
	// xargs keeps "-0".
	if got := cmd.Wrappers[6].Options; !reflect.DeepEqual(got, []string{"-0"}) {
		t.Errorf("xargs options: got %v", got)
	}
	// sudo keeps no options and contributes no assignments.
	if len(cmd.Wrappers[3].Options) != 0 {
		t.Errorf("sudo options: got %v", cmd.Wrappers[3].Options)
	}

	// The env assignment is lifted onto the command, tagged with its origin.
	if len(cmd.Assigns) != 1 || cmd.Assigns[0].Name != "A" || cmd.Assigns[0].Via != WrapEnv {
		t.Fatalf("assigns: got %+v", cmd.Assigns)
	}
	wantPos(t, "assign", cmd.Assigns[0].Pos, Pos{Line: 1, Col: 37, Offset: 36})

	if len(cmd.Args) != 2 || cmd.Args[0].Value != "-rf" || cmd.Args[1].Value != "/x" {
		t.Fatalf("args: got %+v", cmd.Args)
	}
	wantPos(t, "arg0", cmd.Args[0].Pos, Pos{Line: 1, Col: 61, Offset: 60})
	wantPos(t, "arg1", cmd.Args[1].Pos, Pos{Line: 1, Col: 65, Offset: 64})
}

func TestWrapperOptionValues(t *testing.T) {
	cases := []struct {
		src     string
		name    string
		options []string
	}{
		{`sudo -u root --other-user=x cmd`, "cmd", []string{"-u", "root", "--other-user=x"}},
		{`sudo -uroot cmd`, "cmd", []string{"-uroot"}},
		{`env -u FOO cmd`, "cmd", []string{"-u", "FOO"}},
		{`env --unset=FOO cmd`, "cmd", []string{"--unset=FOO"}},
		{`timeout -k 5 30 cmd`, "cmd", []string{"-k", "5"}},
		{`nice -n 5 cmd`, "cmd", []string{"-n", "5"}},
		{`nice -5 cmd`, "cmd", []string{"-5"}},
		{`command -p cmd`, "cmd", []string{"-p"}},
		{`xargs -I{} -n 1 cmd`, "cmd", []string{"-I{}", "-n", "1"}},
	}
	for _, tc := range cases {
		cmd := singleCommand(t, tc.src)
		if cmd.Name != tc.name {
			t.Errorf("%q: name got %q want %q", tc.src, cmd.Name, tc.name)
			continue
		}
		if len(cmd.Wrappers) != 1 {
			t.Errorf("%q: wrappers got %d want 1", tc.src, len(cmd.Wrappers))
			continue
		}
		if got := cmd.Wrappers[0].Options; !reflect.DeepEqual(got, tc.options) {
			t.Errorf("%q: options got %v want %v", tc.src, got, tc.options)
		}
	}
}

func TestWrapperDefaultsAndResets(t *testing.T) {
	// xargs with no command implies echo.
	if cmd := singleCommand(t, `xargs`); cmd.Name != "echo" {
		t.Errorf("xargs: name got %q want echo", cmd.Name)
	}
	if cmd := singleCommand(t, `xargs -0`); cmd.Name != "echo" {
		t.Errorf("xargs -0: name got %q want echo", cmd.Name)
	}
	// env -i is an option, not a command.
	cmd := singleCommand(t, `env -i cmd`)
	if cmd.Name != "cmd" {
		t.Fatalf("env -i: name got %q want cmd", cmd.Name)
	}
	if got := cmd.Wrappers[0].Options; !reflect.DeepEqual(got, []string{"-i"}) {
		t.Errorf("env -i options: got %v", got)
	}
	// A bare - also terminates env's options.
	if cmd := singleCommand(t, `env - cmd`); cmd.Name != "cmd" {
		t.Errorf("env -: name got %q want cmd", cmd.Name)
	}
	// "--" terminates option parsing and is not the command.
	if cmd := singleCommand(t, `sudo -- rm`); cmd.Name != "rm" {
		t.Errorf("sudo --: name got %q want rm", cmd.Name)
	}
}

// A non-literal head word is not a wrapper (it cannot be recognised statically).
func TestWrapperRequiresLiteralHead(t *testing.T) {
	cmd := singleCommand(t, `"$w" env FOO=1 cmd`)
	if len(cmd.Wrappers) != 0 {
		t.Errorf("wrappers: got %v want none", cmd.Wrappers)
	}
	if cmd.Name != "" || cmd.NameWord == nil || cmd.NameWord.Literal {
		t.Errorf("name: got %q nameWord %+v", cmd.Name, cmd.NameWord)
	}
	if len(cmd.Args) != 3 {
		t.Errorf("args: got %d want 3", len(cmd.Args))
	}
}

// ---------------------------------------------------------------------------
// Aliases and functions enter the model.
// ---------------------------------------------------------------------------

func TestAliasCollection(t *testing.T) {
	p := parseOK(t, Bash, "alias ll='ls -l'\nalias cp='cp -i' mv='mv -i'\nll /tmp")
	if len(p.Aliases) != 3 {
		t.Fatalf("aliases: got %d want 3 (%v)", len(p.Aliases), p.Aliases)
	}
	ll := p.Aliases["ll"]
	if ll == nil || ll.Value != "ls -l" || ll.Name != "ll" {
		t.Fatalf("alias ll: got %+v", ll)
	}
	wantPos(t, "alias ll", ll.Pos, Pos{Line: 1, Col: 7, Offset: 6})
	if p.Aliases["cp"] == nil || p.Aliases["cp"].Value != "cp -i" {
		t.Errorf("alias cp: got %+v", p.Aliases["cp"])
	}
	if p.Aliases["mv"] == nil || p.Aliases["mv"].Value != "mv -i" {
		t.Errorf("alias mv: got %+v", p.Aliases["mv"])
	}

	// Using an alias marks the command as resolving to it.
	use := p.Stmts[len(p.Stmts)-1]
	if use.Cmd == nil || use.Cmd.Name != "ll" {
		t.Fatalf("use stmt: got %+v", use.Cmd)
	}
	if use.Cmd.ResolveKind != "alias" || use.Cmd.ResolvesTo != "ll" {
		t.Errorf("resolution: got %q/%q", use.Cmd.ResolveKind, use.Cmd.ResolvesTo)
	}

	// "alias -p" declares nothing and must not crash.
	if q := parseOK(t, Bash, "alias -p"); len(q.Aliases) != 0 {
		t.Errorf("alias -p: got %v", q.Aliases)
	}
}

func TestFunctionCollection(t *testing.T) {
	p := parseOK(t, Bash, "f() { echo hi; }\nfunction g { :; }\nfunction h() { :; }")
	if len(p.Funcs) != 3 {
		t.Fatalf("funcs: got %d want 3 (%v)", len(p.Funcs), p.Funcs)
	}
	if got := p.Funcs["f"].Style; got != "posix" {
		t.Errorf("f style: got %q want posix", got)
	}
	if got := p.Funcs["g"].Style; got != "function" {
		t.Errorf("g style: got %q want function", got)
	}
	if got := p.Funcs["h"].Style; got != "function-parens" {
		t.Errorf("h style: got %q want function-parens", got)
	}
	if p.Funcs["f"].Pos.Col != 1 {
		t.Errorf("f pos: got %+v", p.Funcs["f"].Pos)
	}
	if len(p.Funcs["f"].Body) != 1 {
		t.Fatalf("f body: got %d", len(p.Funcs["f"].Body))
	}
	// The statement that declares f is a func statement.
	if p.Stmts[0].Kind != KindFunc || p.Stmts[0].Func == nil {
		t.Errorf("stmt0: got kind %q func %v", p.Stmts[0].Kind, p.Stmts[0].Func)
	}
}

func TestFunctionResolution(t *testing.T) {
	p := parseOK(t, Bash, "deploy() { :; }\ndeploy /tmp")
	use := p.Stmts[1]
	if use.Cmd == nil || use.Cmd.ResolveKind != "func" || use.Cmd.ResolvesTo != "deploy" {
		t.Fatalf("resolution: got %+v", use.Cmd)
	}
	// A name that is neither a function nor an alias is unresolved.
	q := parseOK(t, Bash, "ls")
	if q.Stmts[0].Cmd.ResolveKind != "" {
		t.Errorf("ls resolved to %q", q.Stmts[0].Cmd.ResolveKind)
	}
}

// ---------------------------------------------------------------------------
// Structure: pipelines, control flow, substitutions, redirections.
// ---------------------------------------------------------------------------

func TestPipelineAndControlFlow(t *testing.T) {
	p := parseOK(t, Bash, "cat f | grep x && echo done")
	if len(p.Stmts) != 1 {
		t.Fatalf("stmts: got %d want 1", len(p.Stmts))
	}
	top := p.Stmts[0]
	if top.Kind != KindAndOr || top.Op != "&&" {
		t.Fatalf("top: got kind %q op %q", top.Kind, top.Op)
	}
	if top.Left == nil || top.Left.Kind != KindPipeline || top.Left.Op != "|" {
		t.Fatalf("left: got %+v", top.Left)
	}
	if top.Left.Left.Cmd.Name != "cat" || top.Left.Right.Cmd.Name != "grep" {
		t.Errorf("pipeline cmds: %q | %q", top.Left.Left.Cmd.Name, top.Left.Right.Cmd.Name)
	}
	if top.Right.Cmd.Name != "echo" {
		t.Errorf("right: got %q", top.Right.Cmd.Name)
	}
}

func TestIfElseAndElif(t *testing.T) {
	p := parseOK(t, Bash, "if a; then b; elif c; then d; else e; fi")
	top := p.Stmts[0]
	if top.Kind != KindIf {
		t.Fatalf("kind: got %q", top.Kind)
	}
	if len(top.Cond) != 1 || top.Cond[0].Cmd.Name != "a" {
		t.Fatalf("cond: got %+v", top.Cond)
	}
	if len(top.Body) != 1 || top.Body[0].Cmd.Name != "b" {
		t.Fatalf("then: got %+v", top.Body)
	}
	// The elif is a nested if inside the else branch.
	if len(top.Else) != 1 || top.Else[0].Kind != KindIf {
		t.Fatalf("else: got %+v", top.Else)
	}
	elif := top.Else[0]
	if len(elif.Cond) != 1 || elif.Cond[0].Cmd.Name != "c" {
		t.Fatalf("elif cond: got %+v", elif.Cond)
	}
	if len(elif.Body) != 1 || elif.Body[0].Cmd.Name != "d" {
		t.Fatalf("elif then: got %+v", elif.Body)
	}
	if len(elif.Else) != 1 || elif.Else[0].Cmd.Name != "e" {
		t.Fatalf("elif else: got %+v", elif.Else)
	}
}

func TestLoopsAndCase(t *testing.T) {
	p := parseOK(t, Bash, "for f in a b; do cat $f; done")
	f := p.Stmts[0]
	if f.Kind != KindFor || f.Name != "f" {
		t.Fatalf("for: got kind %q name %q", f.Kind, f.Name)
	}
	if len(f.Words) != 2 || f.Words[0].Value != "a" || f.Words[1].Value != "b" {
		t.Errorf("for words: got %+v", f.Words)
	}
	if len(f.Body) != 1 || f.Body[0].Cmd.Name != "cat" {
		t.Errorf("for body: got %+v", f.Body)
	}

	w := parseOK(t, Bash, "while a; do b; done").Stmts[0]
	if w.Kind != KindWhile || len(w.Cond) != 1 || len(w.Body) != 1 {
		t.Errorf("while: got %+v", w)
	}
	u := parseOK(t, Bash, "until a; do b; done").Stmts[0]
	if !u.Until {
		t.Errorf("until flag not set")
	}

	c := parseOK(t, Bash, "case $x in a|b) one;; *) two;; esac").Stmts[0]
	if c.Kind != KindCase || c.Subject == nil || c.Subject.Literal {
		t.Fatalf("case: got %+v", c)
	}
	if len(c.Items) != 2 {
		t.Fatalf("case items: got %d", len(c.Items))
	}
	if len(c.Items[0].Patterns) != 2 || c.Items[0].Patterns[0].Value != "a" {
		t.Errorf("case patterns: got %+v", c.Items[0].Patterns)
	}
	if len(c.Items[0].Body) != 1 || c.Items[0].Body[0].Cmd.Name != "one" {
		t.Errorf("case body: got %+v", c.Items[0].Body)
	}
}

func TestCommandSubstitutionAndParam(t *testing.T) {
	p := parseOK(t, Bash, `echo $(git rev-parse HEAD) "${x:-def}" ${y//a/b}`)
	cmd := p.Stmts[0].Cmd
	if len(cmd.Args) != 3 {
		t.Fatalf("args: got %d want 3", len(cmd.Args))
	}
	// $() command substitution, with the nested command lowered.
	sub := cmd.Args[0]
	if len(sub.Parts) != 1 || sub.Parts[0].Kind != PartCmdSubst {
		t.Fatalf("arg0 parts: got %+v", sub.Parts)
	}
	if len(sub.Parts[0].Stmts) != 1 || sub.Parts[0].Stmts[0].Cmd.Name != "git" {
		t.Fatalf("cmdsubst: got %+v", sub.Parts[0].Stmts)
	}
	if got := sub.Parts[0].Stmts[0].Cmd.Args; len(got) != 2 || got[0].Value != "rev-parse" || got[1].Value != "HEAD" {
		t.Errorf("nested args: got %+v", got)
	}
	// "..." with a parameter expansion inside.
	dq := cmd.Args[1]
	if len(dq.Parts) != 1 || dq.Parts[0].Kind != PartDblQuoted {
		t.Fatalf("arg1 parts: got %+v", dq.Parts)
	}
	inner := dq.Parts[0].Parts
	if len(inner) != 1 || inner[0].Kind != PartParamExp || inner[0].Param != "x" || inner[0].Op != ":-" {
		t.Fatalf("dblquoted param: got %+v", inner)
	}
	// ${y//a/b} replacement.
	rep := cmd.Args[2]
	if len(rep.Parts) != 1 || rep.Parts[0].Kind != PartParamExp || rep.Parts[0].Param != "y" || rep.Parts[0].Op != "/" {
		t.Fatalf("replace param: got %+v", rep.Parts)
	}
}

func TestRedirects(t *testing.T) {
	p := parseOK(t, Bash, `cat <in >>out 2>&1`)
	s := p.Stmts[0]
	if len(s.Redirs) != 3 {
		t.Fatalf("redirs: got %d want 3", len(s.Redirs))
	}
	if s.Redirs[0].Op != "<" || s.Redirs[0].Word.Value != "in" {
		t.Errorf("redir0: got %+v", s.Redirs[0])
	}
	if s.Redirs[1].Op != ">>" || s.Redirs[1].Word.Value != "out" {
		t.Errorf("redir1: got %+v", s.Redirs[1])
	}
	if s.Redirs[2].Op != ">&" || s.Redirs[2].N != "2" || s.Redirs[2].Word.Value != "1" {
		t.Errorf("redir2: got %+v", s.Redirs[2])
	}
	wantPos(t, "redirN", s.Redirs[2].Pos, Pos{Line: 1, Col: 15, Offset: 14})

	// A redirection-only command and is modelled as an empty named command
	// carrying the redirection.
	only := parseOK(t, Bash, `> file`).Stmts[0]
	if only.Kind != KindSimple || only.Cmd == nil || only.Cmd.Name != "" {
		t.Fatalf("redirection-only command: got %+v", only)
	}
	if len(only.Redirs) != 1 || only.Redirs[0].Op != ">" || only.Redirs[0].Word.Value != "file" {
		t.Errorf("redirection-only redirs: got %+v", only.Redirs)
	}
}

func TestMultipleStatementsAndMultiline(t *testing.T) {
	p := parseOK(t, Bash, "a\nb; c &")
	if len(p.Stmts) != 3 {
		t.Fatalf("stmts: got %d want 3", len(p.Stmts))
	}
	if p.Stmts[1].Cmd.Name != "b" || p.Stmts[1].Pos.Line != 2 || p.Stmts[1].Pos.Col != 1 {
		t.Errorf("stmt1: got %+v", p.Stmts[1])
	}
	if !p.Stmts[2].Background {
		t.Errorf("stmt2 should be background")
	}
	if p.Stmts[2].Pos.Line != 2 || p.Stmts[2].Pos.Col != 4 {
		t.Errorf("stmt2 pos: got %+v", p.Stmts[2].Pos)
	}
}

func TestLiteralVersusDynamic(t *testing.T) {
	cmd := singleCommand(t, `echo plain '$x' "$y" pre"$z"post`)
	if len(cmd.Args) != 4 {
		t.Fatalf("args: got %d", len(cmd.Args))
	}
	if !cmd.Args[0].Literal || cmd.Args[0].Value != "plain" {
		t.Errorf("arg0: got %+v", cmd.Args[0])
	}
	// Single quotes are literal even around a $-looking body.
	if !cmd.Args[1].Literal || cmd.Args[1].Value != "$x" {
		t.Errorf("arg1: got %+v", cmd.Args[1])
	}
	if cmd.Args[2].Literal {
		t.Errorf("arg2 should be dynamic: %+v", cmd.Args[2])
	}
	if cmd.Args[3].Literal {
		t.Errorf("arg3 should be dynamic: %+v", cmd.Args[3])
	}
}

// ---------------------------------------------------------------------------
// Program-level properties
// ---------------------------------------------------------------------------

func TestProgramValidate(t *testing.T) {
	if err := parseOK(t, Bash, "ls").Validate(); err != nil {
		t.Errorf("valid program rejected: %v", err)
	}
	if err := (&Program{Variant: Variant("zsh")}).Validate(); err == nil {
		t.Errorf("unknown variant accepted")
	}
	if err := (&Program{Variant: Bash, Top: true}).Validate(); err == nil {
		t.Errorf("top without a reason accepted")
	}
	if err := (&Program{Variant: Bash, Top: true, Reason: "x", Stmts: []*Stmt{{Kind: KindSimple}}}).Validate(); err == nil {
		t.Errorf("top with statements accepted")
	}
	if err := (&Program{Variant: Bash, Top: true, Reason: "x"}).Validate(); err != nil {
		t.Errorf("well-formed top rejected: %v", err)
	}
}

func TestProgramEncodeStable(t *testing.T) {
	const src = `sudo env FOO=1 cmd "$x" | grep y`
	a := parseOK(t, Bash, src)
	b := parseOK(t, Bash, src)
	ea, err := a.Encode()
	if err != nil {
		t.Fatalf("encode a: %v", err)
	}
	eb, err := b.Encode()
	if err != nil {
		t.Fatalf("encode b: %v", err)
	}
	if !bytes.Equal(ea, eb) {
		t.Errorf("encoding is not deterministic:\n%s\n%s", ea, eb)
	}

	// Round-trip through JSON must preserve the canonical encoding.
	var back Program
	if err := json.Unmarshal(ea, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	eb2, err := back.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(ea, eb2) {
		t.Errorf("round-trip changed the encoding:\n%s\n%s", ea, eb2)
	}
}

// ---------------------------------------------------------------------------
// Golden fixtures
// ---------------------------------------------------------------------------

const goldenProgramSrc = `#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:$PATH
sudo -u root env FOO=1 nohup /usr/bin/daemon --flag "a b" > /var/log/daemon.log 2>&1
if [[ -n "$X" ]]; then
  curl -fsSL "$URL" | xargs -0 command rm -f
else
  echo "$(uptime)"
fi
function deploy() { scp "$1" host:/tmp/; }
alias ll='ls -l'
for f in *.txt; do cat "$f"; done
`

const goldenWrappersSrc = `nohup timeout 30 nice -n 5 sudo env A=1 command xargs -0 rm -rf /x`

func TestGoldenProgram(t *testing.T) {
	got, err := parseOK(t, Bash, goldenProgramSrc).Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	checkGolden(t, filepath.Join("testdata", "program.golden.json"), got)
}

func TestGoldenWrappers(t *testing.T) {
	got, err := parseOK(t, Bash, goldenWrappersSrc).Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	checkGolden(t, filepath.Join("testdata", "wrappers.golden.json"), got)
}

func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(append([]byte(nil), got...), '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with: go test ./front/bash -run %s -update)", path, err, t.Name())
	}
	if !bytes.Equal(bytes.TrimRight(want, "\n"), bytes.TrimRight(got, "\n")) {
		t.Errorf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}

// FuzzParse asserts the frontend contract on arbitrary input: it never panics,
// and every non-top result is a valid, re-encodable program.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"", "ls -la", `sudo env FOO=1 cmd`, "$(date)", "a | b && c",
		`echo "unterminated`, "for", "${x//a/b}", "<(ls)", "&&&",
		"cat <<EOF\nhi\nEOF\n", "function f { :; }",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		for _, v := range []Variant{Bash, POSIX} {
			p := Parse(v, "fuzz", src)
			if p == nil {
				t.Fatalf("nil program for %q", src)
			}
			if p.Top {
				if p.Reason == "" {
					t.Fatalf("top without a reason for %q", src)
				}
				continue
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("invalid program for %q: %v", src, err)
			}
			if _, err := p.Encode(); err != nil {
				t.Fatalf("encode failed for %q: %v", src, err)
			}
		}
	})
}
