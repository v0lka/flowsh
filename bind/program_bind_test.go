package bind

import (
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/bash"
)

// This file holds the whole-program binding helpers — BindScript,
// BindProgram and the recursive walkers they drive. They bind every
// command invocation in a normalized program (rather than a single call)
// and are exercised only by the binder tests (bind_test.go) and the fuzz
// target (fuzz_test.go); production binding enters through BindBash/Bind.
// Keeping them here means the shipped package carries only the
// single-call path.

// BindScript parses src as bash and binds every command it invokes.
func (b *Binder) BindScript(src string) []*Result {
	return b.BindProgram(bash.Parse(bash.Bash, "script", src))
}

// BindProgram binds every command invocation in a normalized program: the
// simple commands at every nesting level plus the commands inside command and
// process substitutions. Control-flow is not interpreted here (that is the
// abstract-execution layer), so the union of all branches is bound. A function
// *body* is not bound, because defining a function does not execute it.
func (b *Binder) BindProgram(prog *bash.Program) []*Result {
	if prog == nil {
		return nil
	}
	if prog.Top {
		return []*Result{conservativeResult(StyleBash, "program is ⊤: "+prog.Reason, engine.ModeDirect)}
	}
	var out []*Result
	out = append(out, b.bindStmts(prog.Stmts, prog)...)
	return out
}

func (b *Binder) bindStmts(ss []*bash.Stmt, prog *bash.Program) []*Result {
	var out []*Result
	for _, s := range ss {
		out = append(out, b.bindStmt(s, prog)...)
	}
	return out
}

func (b *Binder) bindStmt(s *bash.Stmt, prog *bash.Program) []*Result {
	if s == nil {
		return nil
	}
	var out []*Result

	if s.Cmd != nil {
		out = append(out, b.BindBash(s.Cmd, prog))
		// Commands nested in the name and arguments (command substitutions).
		out = append(out, b.bindWords(append([]*bash.Word{s.Cmd.NameWord}, s.Cmd.Args...), prog)...)
	}
	if s.Kind == bash.KindDecl && s.Decl != "" {
		out = append(out, b.Bind(&Call{
			Style:       StyleBash,
			Name:        s.Decl,
			NameOK:      true,
			NamePresent: true,
			Args:        wordsToArgs(s.Words),
		}))
	}
	for _, rd := range s.Redirs {
		if rd != nil {
			out = append(out, b.bindWords([]*bash.Word{rd.Word, rd.Hdoc}, prog)...)
		}
	}
	for _, it := range s.Items {
		if it != nil {
			out = append(out, b.bindStmts(it.Body, prog)...)
			out = append(out, b.bindWords(it.Patterns, prog)...)
		}
	}
	out = append(out, b.bindWords(s.Words, prog)...)
	out = append(out, b.bindStmts(s.Cond, prog)...)
	out = append(out, b.bindStmts(s.Body, prog)...)
	out = append(out, b.bindStmts(s.Else, prog)...)
	if s.Left != nil {
		out = append(out, b.bindStmt(s.Left, prog)...)
	}
	if s.Right != nil {
		out = append(out, b.bindStmt(s.Right, prog)...)
	}
	return out
}

func (b *Binder) bindWords(ws []*bash.Word, prog *bash.Program) []*Result {
	var out []*Result
	for _, w := range ws {
		if w == nil {
			continue
		}
		out = append(out, b.bindParts(w.Parts, prog)...)
	}
	return out
}

func (b *Binder) bindParts(parts []bash.Part, prog *bash.Program) []*Result {
	var out []*Result
	for _, p := range parts {
		switch p.Kind {
		case bash.PartCmdSubst, bash.PartProcSubst:
			out = append(out, b.bindStmts(p.Stmts, prog)...)
		}
		out = append(out, b.bindParts(p.Parts, prog)...)
	}
	return out
}

func wordsToArgs(ws []*bash.Word) []Arg {
	var out []Arg
	for _, w := range ws {
		out = append(out, wordArg(w))
	}
	return out
}
