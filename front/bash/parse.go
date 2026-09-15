// Package bash is the shell frontend of the effect IR.
//
// It has exactly two responsibilities:
//
//   - Parse turns shell source text into a faithful, position-preserving
//     syntax tree; and
//   - normalize (see normalize.go) lowers that tree into the frontend's own
//     normalized AST, unwrapping the ubiquitous command wrappers (sudo, env,
//     nohup, command, nice, timeout, xargs) and recording the aliases and
//     functions the program declares.
//
// A frontend may fail to understand its input. Where it cannot, it must degrade
// to the top element ⊤ rather than guess or crash, so Parse never panics: every
// parse failure is folded into the returned Program as Top=true, carrying a
// human-readable Reason and, when available, the position of the failure.
//
// Dependency direction is one-way: this package is a frontend and may import
// the frontend-agnostic core (github.com/v0lka/flowsh/engine), never the other
// way around.
package bash

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Variant selects the shell dialect a source is parsed as. The two dialects the
// effect IR frontend supports are Bash and POSIX; they are kept distinct because
// the same text can be well-formed in one and meaningless in the other
// (bash-only forms such as ${x//a/b}, <(cmd), <<<word and $'...').
type Variant string

const (
	// Bash is GNU Bash, the default dialect.
	Bash Variant = "bash"
	// POSIX is the POSIX shell (a.k.a. sh).
	POSIX Variant = "posix"
)

// String returns the canonical dialect name.
func (v Variant) String() string { return string(v) }

// Valid reports whether v is a known variant.
func (v Variant) Valid() bool { return v == Bash || v == POSIX }

// langVariant maps a Variant onto the underlying parser dialect. The boolean is
// false for an unknown variant.
func (v Variant) langVariant() (syntax.LangVariant, bool) {
	switch v {
	case Bash:
		return syntax.LangBash, true
	case POSIX:
		return syntax.LangPOSIX, true
	default:
		return syntax.LangBash, false
	}
}

// Parse parses src as a shell program written in dialect v. name is used only
// for diagnostics; it is recorded on the returned Program.
//
// Parse never panics. An unknown variant or a parse failure is not returned as
// a Go error — it is represented as the top element ⊤ of the analysis: the
// returned Program has Top=true, an explanatory Reason, and (for parse errors)
// the position at which parsing stopped, with no statements. Callers that must
// tell "parsed" from "unparseable" inspect Program.Top.
func Parse(v Variant, name, src string) (prog *Program) {
	if _, ok := v.langVariant(); !ok {
		return topProgram(v, name, src, Pos{}, fmt.Sprintf("unknown shell variant %q", string(v)))
	}

	// A misbehaving parser must degrade to ⊤, never take the process down.
	defer func() {
		if r := recover(); r != nil {
			prog = topProgram(v, name, src, Pos{}, fmt.Sprintf("internal parser panic: %v", r))
		}
	}()

	lang, _ := v.langVariant()
	parser := syntax.NewParser(syntax.Variant(lang))
	file, err := parser.Parse(strings.NewReader(src), name)
	if err != nil {
		var p Pos
		var perr syntax.ParseError
		if errors.As(err, &perr) {
			p = fromMvdanPos(perr.Pos)
		}
		return topProgram(v, name, src, p, err.Error())
	}

	// Canonicalise redundant syntax before lowering so that equivalent inputs
	// (e.g. $( (a) ) and $(a)) lower to the same AST.
	syntax.Simplify(file)

	prog = &Program{
		Variant: v,
		File:    name,
		Source:  src,
		Stmts:   []*Stmt{},
	}
	norm := newNormalizer(src)
	norm.fill(file, prog)
	return prog
}

// topProgram builds the ⊤ program: no statements, Top set, and a reason. errPos
// is attached only when it is a real (non-zero) position.
func topProgram(v Variant, name, src string, errPos Pos, reason string) *Program {
	p := &Program{
		Variant: v,
		File:    name,
		Source:  src,
		Top:     true,
		Reason:  reason,
		Stmts:   []*Stmt{},
	}
	if errPos.Line > 0 || errPos.Offset > 0 {
		ep := errPos
		p.ErrPos = &ep
	}
	return p
}

// Pos is a source position within a parsed program: a 1-based line and column
// (counted in bytes, as the shell lexer does) plus a 0-based byte offset. The
// zero Pos means "no position".
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
	return strconv.Itoa(p.Line) + ":" + strconv.Itoa(p.Col)
}

// fromMvdanPos converts an underlying parser position into a Pos, mapping an
// invalid position to the zero Pos.
func fromMvdanPos(p syntax.Pos) Pos {
	if !p.IsValid() {
		return Pos{}
	}
	return Pos{Line: int(p.Line()), Col: int(p.Col()), Offset: int(p.Offset())}
}

// shiftPos returns p moved right by n bytes on the same line. It is used to
// point at the value part of an assignment word such as FOO=1.
func shiftPos(p Pos, n int) Pos {
	if n == 0 || p.IsZero() {
		return p
	}
	return Pos{Line: p.Line, Col: p.Col + n, Offset: p.Offset + n}
}
