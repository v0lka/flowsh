package bash

import (
	"encoding/base64"
	"path"
	"strconv"
	"strings"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// Command sinks and code-executing builtins
// ===========================================================================

// sinkSet is the closed set of programs the value-flow analysis treats as code
// execution sinks: feeding data to any of them means that data is executed as
// code, whose effects are by definition unknown (⊤).
var sinkSet = map[string]bool{
	"sh": true, "bash": true, "dash": true, "ash": true, "zsh": true,
	"ksh": true, "ksh93": true, "csh": true, "tcsh": true, "fish": true,
	"python": true, "python2": true, "python3": true,
	"node": true, "nodejs": true, "deno": true, "bun": true,
	"perl": true, "ruby": true, "php": true, "lua": true, "tclsh": true,
	"awk": true, "gawk": true, "mawk": true, "nawk": true,
	"osascript": true, "docker": true, "podman": true,
}

// isSink reports whether name is a code-execution sink.
func isSink(name string) bool { return sinkSet[name] }

// codeExecBuiltins execute shell source supplied as an argument or read from a
// file, so — like a sink — their effects cannot be bounded statically. `trap`
// runs its ACTION (arbitrary code) when the signal fires, so it is included
// too.
var codeExecBuiltins = map[string]bool{
	"eval": true, "source": true, ".": true, "trap": true,
}

// isCodeExecBuiltin reports whether name executes code supplied at run time.
func isCodeExecBuiltin(name string) bool { return codeExecBuiltins[name] }

// trapHasAction reports whether a `trap` invocation registers a non-empty
// ACTION operand (trap 'cmd' INT). The bare listing/query forms (`trap`,
// `trap -p`, `trap -l`) and the reset form (`trap - INT`) carry no action and
// therefore execute no code.
func trapHasAction(argv []string) bool {
	skipOpts := true
	for _, a := range argv {
		if skipOpts {
			if a == "--" {
				skipOpts = false
				continue
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				// An option (‑p, ‑l, a cluster): keep looking for the action.
				continue
			}
		}
		// The first operand is the action, unless it is "-" (reset) or empty.
		return a != "-" && a != ""
	}
	return false
}

// shellOnlyBuiltins are builtins that only manipulate the shell's own state and
// have no external effect. The knowledge base does not describe them, so asking
// it about them would produce a spurious ⊤; they are instead handled entirely
// here.
var shellOnlyBuiltins = map[string]bool{
	":": true, "true": true, "false": true,
	"break": true, "continue": true, "return": true, "exit": true,
	"alias": true, "unalias": true, "shift": true, "getopts": true,
	"shopt": true, "jobs": true, "bg": true, "fg": true, "times": true,
	"dirs": true, "pushd": true, "popd": true, "let": true,
	"builtin": true, "command": true, "logout": true, "disown": true,
	"suspend": true, "[": true,
}

// isShellOnlyBuiltin reports whether name is a pure shell-state builtin.
func isShellOnlyBuiltin(name string) bool { return shellOnlyBuiltins[name] }

// ===========================================================================
// stdout folding
// ===========================================================================

// stdoutOf returns the standard output of a simple command when the analysis can
// pin it down. It is the "fold stdout" half of the command-substitution hook: a
// command substitution is only statically known when the command producing its
// stdout is.
//
// Only commands whose output is a pure function of their expanded arguments (and
// of stdin, for the deliberately simple base64 case) are folded; everything else
// reports unknown, which keeps the analysis sound.
func (it *interp) stdoutOf(name string, argv []string) (string, bool) {
	switch name {
	case "":
		return "", true
	case "echo":
		return echoOut(argv), true
	case "printf":
		return printfOut(argv)
	case "true", ":", "false", "sleep", "wait", "export", "unset", "read",
		"readonly", "declare", "local", "typeset", "set", "shift", "trap":
		return "", true
	case "base64":
		return it.base64Out(argv)
	}
	return "", false
}

// echoOut folds the echo builtin: recognised leading flags are consumed, the
// remaining arguments are joined with a single space and the result is
// newline-terminated unless -n was given.
func echoOut(argv []string) string {
	noNewline := false
	i := 0
	for i < len(argv) {
		switch argv[i] {
		case "-n":
			noNewline = true
		case "-e", "-E":
			// escape handling is not modelled
		default:
			goto done
		}
		i++
	}
done:
	out := strings.Join(argv[i:], " ")
	if !noNewline {
		out += "\n"
	}
	return out
}

// printfOut folds a small, well-defined subset of printf: literal text with the
// usual backslash escapes, plus %s and %d conversions. The format is replayed
// until the argument list is exhausted, as printf does. Anything else is
// unknown.
func printfOut(argv []string) (string, bool) {
	if len(argv) == 0 {
		return "", true
	}
	format := argv[0]
	args := argv[1:]
	var b strings.Builder
	argi := 0
	for pass := 0; ; pass++ {
		start := argi
		if ok := printfPass(&b, format, args, &argi); !ok {
			return "", false
		}
		if argi >= len(args) {
			break
		}
		if argi == start {
			// The format consumed no argument: replaying it forever would
			// diverge.
			return "", false
		}
		if pass > len(args)+1 {
			return "", false
		}
	}
	return b.String(), true
}

// printfPass folds one pass over the format string, consuming arguments from
// args starting at *argi. It reports false for an unsupported conversion.
func printfPass(b *strings.Builder, format string, args []string, argi *int) bool {
	for i := 0; i < len(format); {
		c := format[i]
		switch c {
		case '\\':
			if i+1 >= len(format) {
				b.WriteByte('\\')
				i++
				continue
			}
			switch format[i+1] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\':
				b.WriteByte('\\')
			default:
				b.WriteByte('\\')
				b.WriteByte(format[i+1])
			}
			i += 2
			continue
		case '%':
			if i+1 >= len(format) {
				b.WriteByte('%')
				i++
				continue
			}
			switch format[i+1] {
			case '%':
				b.WriteByte('%')
				i += 2
				continue
			case 's', 'd', 'i':
				if *argi >= len(args) {
					return false
				}
				a := args[*argi]
				*argi++
				if format[i+1] != 's' {
					if _, err := strconv.Atoi(strings.TrimSpace(a)); err != nil {
						return false
					}
				}
				b.WriteString(a)
				i += 2
				continue
			default:
				return false
			}
		default:
			b.WriteByte(c)
			i++
		}
	}
	return true
}

// base64Out folds base64 encode/decode when its input (stdin) is known. It is
// what lets a value flow through "base64 -d" in a pipeline.
func (it *interp) base64Out(argv []string) (string, bool) {
	if !it.stdinKnown {
		return "", false
	}
	decode := false
	for _, a := range argv {
		switch a {
		case "-d", "--decode":
			decode = true
		case "-e", "--encode":
			decode = false
		}
	}
	in := it.stdin
	if decode {
		if b, err := base64.StdEncoding.DecodeString(strings.TrimRight(in, "\n")); err == nil {
			return string(b), true
		}
		if b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(in, "\n")); err == nil {
			return string(b), true
		}
		return "", false
	}
	return base64.StdEncoding.EncodeToString([]byte(in)), true
}

// ===========================================================================
// Builtin transfer functions
// ===========================================================================

// builtinState applies the state component of a builtin's transfer function to
// Σ. It is deliberately silent about effects: those come from the binding layer,
// which knows the builtin's declared effect set.
func (it *interp) builtinState(name string, argv []string) {
	switch name {
	case "cd":
		dir := it.state.envGet("HOME")
		if len(argv) > 0 {
			dir = argv[0]
		}
		if dir == "-" {
			dir = it.state.envGet("OLDPWD")
		}
		if dir == "" {
			dir = "/"
		}
		nwd := resolveCwd(it.state.PWD, dir)
		it.state.PWD = nwd
		it.state.SetKnown("PWD", nwd, engine.TaintBottom())

	case "umask":
		if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
			it.state.Umask = argv[0]
		}

	case "unset":
		for _, a := range argv {
			if strings.HasPrefix(a, "-") {
				continue
			}
			it.state.Unset(a)
		}

	case "alias":
		for _, a := range argv {
			if n, v, ok := splitEq(a); ok {
				it.state.Aliases[n] = v
			}
		}

	case "unalias":
		for _, a := range argv {
			delete(it.state.Aliases, a)
		}

	case "read":
		vars := readVars(argv)
		if len(vars) == 0 {
			vars = []string{"REPLY"}
		}
		for _, n := range vars {
			it.state.SetUnknown(n, engine.TaintOf(engine.TaintUntrusted))
		}
	}
}

// readVars extracts the variable names a read builtin assigns to, skipping
// options and the option terminator.
func readVars(argv []string) []string {
	var out []string
	opts := true
	for _, a := range argv {
		if opts {
			if a == "--" {
				opts = false
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			opts = false
		}
		out = append(out, a)
	}
	return out
}

// resolveCwd resolves dir against the current working directory base, treating
// absolute paths and $HOME-relative paths as the shell does.
func resolveCwd(base, dir string) string {
	if dir == "" {
		return base
	}
	if strings.HasPrefix(dir, "/") {
		return path.Clean(dir)
	}
	if base == "" {
		base = "/"
	}
	return path.Clean(path.Join(base, dir))
}
