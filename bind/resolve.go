package bind

import (
	"strings"

	"github.com/v0lka/flowsh/front/bash"
	"github.com/v0lka/flowsh/kb"
)

// ResolveKind classifies where a command name resolves. The chain followed is
// builtin → function → alias → PATH, plus the two degenerate cases of a call
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

// resolve runs the name-resolution chain for a call: builtin → function →
// alias → command (PATH). Aliases are expanded (bounded by maxAliasDepth) to
// the effective command and argv, while Kind records that the name resolved
// through an alias. A name that matches nothing resolves to ResolveUnknown, and
// a call with no statically-known name resolves to ResolveUnknown as well.
func (b *Binder) resolve(c *Call) resolved {
	if !c.NameOK || c.Name == "" {
		return resolved{res: Resolution{Kind: ResolveUnknown, Invoked: c.Name}}
	}

	// 1. builtin
	if cmd, ok := b.k.Command(c.Name); ok && cmd.Dialect == kb.DialectBuiltin {
		return resolved{
			res:     Resolution{Kind: ResolveBuiltin, Name: cmd.Name, Invoked: c.Name},
			command: cmd,
			args:    c.Args,
		}
	}

	// 2. function
	if c.Funcs[c.Name] {
		return resolved{res: Resolution{Kind: ResolveFunction, Name: c.Name, Invoked: c.Name}}
	}

	// 3. alias
	if _, ok := c.Aliases[c.Name]; ok {
		name, args, chain, ok := b.expandAliases(c)
		r := Resolution{Kind: ResolveAlias, Invoked: c.Name, AliasChain: chain}
		if !ok {
			r.Name = c.Name
			return resolved{res: r}
		}
		// The effective command may itself be shadowed by a function.
		if c.Funcs[name] {
			r.Name = name
			return resolved{res: r}
		}
		if cmd, ok := b.k.Command(name); ok {
			r.Name = cmd.Name
			return resolved{res: r, command: cmd, args: args}
		}
		r.Name = name
		return resolved{res: r}
	}

	// 4. command (PATH)
	if cmd, ok := b.k.Command(c.Name); ok {
		return resolved{
			res:     Resolution{Kind: ResolveCommand, Name: cmd.Name, Invoked: c.Name},
			command: cmd,
			args:    c.Args,
		}
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
	var args []Arg
	for _, w := range s.Cmd.Args {
		args = append(args, wordArg(w))
	}
	return s.Cmd.Name, args, true
}
