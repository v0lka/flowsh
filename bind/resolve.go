package bind

import (
	"strings"

	"github.com/v0lka/flowsh/front/bash"
	"github.com/v0lka/flowsh/kb"
)

// ResolveKind classifies where a command name resolves. The chain followed is
// alias → function → builtin → PATH, plus the two degenerate cases of a call
// that names no command at all.
type ResolveKind string

const (
	// ResolveEmpty is a statement with neither a command nor an assignment
	// (e.g. a bare redirection). It contributes no command effects.
	ResolveEmpty ResolveKind = "empty"
	// ResolveAssignment is a statement that is a bare environment assignment
	// (FOO=1) with no command word.
	ResolveAssignment ResolveKind = "assignment"
	// ResolveBuiltin is a shell builtin — the first link of the chain.
	ResolveBuiltin ResolveKind = "builtin"
	// ResolveFunction is a shell function declared by the analysed program.
	ResolveFunction ResolveKind = "function"
	// ResolveAlias is a shell alias declared by the analysed program.
	ResolveAlias ResolveKind = "alias"
	// ResolveCommand is an external command for which the knowledge base has a
	// signature — the PATH link of the chain.
	ResolveCommand ResolveKind = "command"
	// ResolveUnknown is the top: nothing named the command, so the analysis
	// must assume ⊤.
	ResolveUnknown ResolveKind = "unknown"
)

// maxAliasDepth bounds alias-chain expansion so that a self- or
// mutually-recursive set of aliases can never make resolution diverge.
const maxAliasDepth = 32

// Resolution is the step-4 answer to "which command does this call actually
// name?" — reported independently of the effects that command then contributes.
type Resolution struct {
	// Invoked is the name exactly as written at the call site.
	Invoked string `json:"invoked,omitempty"`
	// Kind is the decisive source the name resolved to.
	Kind ResolveKind `json:"kind"`
	// Name is the canonical name after resolution: the knowledge-base command
	// name for a builtin or an external command, the effective command name for
	// an alias, or the function/alias's own name otherwise.
	Name string `json:"name,omitempty"`
	// AliasChain lists every alias name expanded on the way to Name, outermost
	// first. It is non-empty exactly when the name resolved through aliases.
	AliasChain []string `json:"aliasChain,omitempty"`
}

// resolved is the internal outcome of resolution: the public Resolution plus
// the resolved knowledge-base command (nil when the name did not resolve to a
// command) and the effective argv after alias expansion.
type resolved struct {
	res     Resolution
	command *kb.Command
	args    []Arg
}

// resolve runs the name-resolution chain for a call: alias → function → builtin
// → command (PATH), matching the shell's own precedence (a declared alias or
// function shadows a builtin of the same name). Aliases are expanded (bounded by
// maxAliasDepth) to the effective command and argv, while Kind records that the
// name resolved through an alias. A name that matches nothing resolves to
// ResolveUnknown, and a call with no statically-known name resolves to
// ResolveUnknown as well.
func (b *Binder) resolve(c *Call) resolved {
	if !c.NameOK || c.Name == "" {
		return resolved{res: Resolution{Kind: ResolveUnknown, Invoked: c.Name}}
	}

	// A wrapper-prefixed invocation (command/env/sudo/nohup/timeout/setsid) is
	// looked up in PATH and executed by a new process, so shell aliases and
	// functions are bypassed.
	external := len(c.Wrappers) > 0

	// 1. alias — bash/POSIX resolve a declared alias before a function or a
	// builtin of the same name, so an alias must shadow both.
	if !external {
		if _, ok := c.Aliases[c.Name]; ok {
			name, args, chain, ok := b.expandAliases(c)
			r := Resolution{Kind: ResolveAlias, Invoked: c.Name, AliasChain: chain}
			if !ok {
				r.Name = c.Name
				return resolved{res: r}
			}
			// The effective command may itself be shadowed by a function: report
			// it as a function call (⊤/Transitive at Bind), not as an unresolved
			// name.
			if c.Funcs[name] {
				return resolved{res: Resolution{Kind: ResolveFunction, Name: name, Invoked: c.Name, AliasChain: chain}}
			}
			if cmd, ok := b.k.Command(name); ok {
				r.Name = cmd.Name
				return resolved{res: r, command: cmd, args: args}
			}
			r.Name = name
			return resolved{res: r}
		}
	}

	// 2. function — a shell function shadows a builtin of the same name.
	if !external && c.Funcs[c.Name] {
		return resolved{res: Resolution{Kind: ResolveFunction, Name: c.Name, Invoked: c.Name}}
	}

	// 3. builtin
	if cmd, ok := b.k.Command(c.Name); ok && cmd.Dialect == kb.DialectBuiltin {
		return resolved{
			res:     Resolution{Kind: ResolveBuiltin, Name: cmd.Name, Invoked: c.Name},
			command: cmd,
			args:    c.Args,
		}
	}

	// 4. command (PATH)
	if cmd, ok := b.k.Command(c.Name); ok {
		return resolved{
			res:     Resolution{Kind: ResolveCommand, Name: cmd.Name, Invoked: c.Name},
			command: cmd,
			args:    c.Args,
		}
	}

	// 4a. project-local binary path — ./node_modules/.bin/tsc,
	// node_modules/.bin/tsc, /abs/node_modules/.bin/tsc: the seam the package
	// manager manages exposes the same binaries a package runner resolves, so
	// the path form resolves to the bare binary name exactly like the runner
	// form (one KB command, one canonical identity — the audited 963134/963140
	// retry pair stays unified, now deterministically bounded instead of ⊤).
	if base := StripBinaryPath(c.Name); base != c.Name {
		if cmd, ok := b.k.Command(base); ok {
			return resolved{
				res:     Resolution{Kind: ResolveCommand, Name: cmd.Name, Invoked: c.Name},
				command: cmd,
				args:    c.Args,
			}
		}
	}

	// 4b. package runner — npx vitest …, bunx tsc …: the first non-flag literal
	// operand names the binary that actually executes, so it is looked up in
	// the knowledge base and bound with the runner's own words consumed. The
	// fail-closed shapes degrade to ⊤ in runnerBinaryArgs and below: a runner
	// that names no literal operand, an operand outside the knowledge base (a
	// registry fetch whose code the analysis cannot see), and -c/--call (an
	// arbitrary shell string — never boundable by name resolution).
	if packageRunners[c.Name] {
		if operand, rest, ok := runnerBinaryArgs(c.Args); ok {
			if cmd, ok := b.k.Command(StripBinaryPath(operand.Value)); ok {
				return resolved{
					res:     Resolution{Kind: ResolveCommand, Name: cmd.Name, Invoked: c.Name},
					command: cmd,
					args:    rest,
				}
			}
		}
		return resolved{res: Resolution{Kind: ResolveUnknown, Name: c.Name, Invoked: c.Name}}
	}

	// 5. ⊤
	return resolved{res: Resolution{Kind: ResolveUnknown, Name: c.Name, Invoked: c.Name}}
}

// expandAliases follows the alias chain starting at c.Name, returning the final
// command name, the effective argv (the alias bodies' words prepended to the
// call's own words) and the chain of alias names expanded, outermost first. The
// boolean is false when the chain is unparseable, cyclic, or too deep — the
// caller then degrades to ⊤.
func (b *Binder) expandAliases(c *Call) (string, []Arg, []string, bool) {
	cur := c.Name
	var prefix []Arg
	var chain []string
	seen := map[string]bool{cur: true}

	for depth := 0; depth < maxAliasDepth; depth++ {
		body, isAlias := c.Aliases[cur]
		if !isAlias {
			args := make([]Arg, 0, len(prefix)+len(c.Args))
			args = append(args, prefix...)
			args = append(args, c.Args...)
			return cur, args, chain, true
		}
		name, words, ok := tokenizeAlias(body)
		if !ok {
			chain = append(chain, cur)
			return "", nil, chain, false
		}
		chain = append(chain, cur)
		// Alias expansion is textual: the body's words precede everything that
		// was already accumulated (an outer alias expands to an inner one whose
		// words come first).
		next := make([]Arg, 0, len(words)+len(prefix))
		next = append(next, words...)
		next = append(next, prefix...)
		prefix = next
		cur = name
		if seen[cur] {
			return "", nil, chain, false // cycle
		}
		seen[cur] = true
	}
	return "", nil, chain, false
}

// tokenizeAlias splits an alias body ("ls -la") into a command name and its
// argument words. It reuses the shell frontend's parser so quoting inside the
// body is handled exactly as the shell would; a body that is not a single
// simple command is rejected (the caller then degrades to ⊤).
func tokenizeAlias(body string) (string, []Arg, bool) {
	if strings.TrimSpace(body) == "" {
		return "", nil, false
	}
	prog := bash.Parse(bash.Bash, "<alias>", body)
	if prog.Top || len(prog.Stmts) != 1 {
		return "", nil, false
	}
	s := prog.Stmts[0]
	if s == nil || s.Kind != bash.KindSimple || s.Cmd == nil || s.Cmd.Name == "" {
		return "", nil, false
	}
	// An alias body carrying redirections or embedded command/process
	// substitutions cannot be reduced to a name plus argument words without
	// silently dropping their effects, so it is rejected here and the caller
	// degrades to ⊤ rather than under-reporting.
	if len(s.Redirs) > 0 || aliasBodyHasSubst(s) {
		return "", nil, false
	}
	var args []Arg
	for _, w := range s.Cmd.Args {
		args = append(args, wordArg(w))
	}
	return s.Cmd.Name, args, true
}

// aliasBodyHasSubst reports whether an alias body's command carries a command or
// process substitution in any of its argument words (directly or inside double
// quotes), which would execute code the name-plus-words reduction drops.
func aliasBodyHasSubst(s *bash.Stmt) bool {
	if s == nil || s.Cmd == nil {
		return false
	}
	for _, w := range s.Cmd.Args {
		if wordHasSubst(w) {
			return true
		}
	}
	return false
}

// wordHasSubst reports whether a word contains a command or process substitution.
func wordHasSubst(w *bash.Word) bool {
	if w == nil {
		return false
	}
	for _, p := range w.Parts {
		switch p.Kind {
		case bash.PartCmdSubst, bash.PartProcSubst:
			return true
		case bash.PartDblQuoted:
			for _, ip := range p.Parts {
				if ip.Kind == bash.PartCmdSubst || ip.Kind == bash.PartProcSubst {
					return true
				}
			}
		}
	}
	return false
}
