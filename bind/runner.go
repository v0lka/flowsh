// Runner (npx, bunx) and project-local binary-path resolution.
//
// A JavaScript project invokes the same binary under three spellings — the
// package runner (npx vitest …), the project-local bin path
// (./node_modules/.bin/vitest …) and the bare name (vitest …). The executed
// binary — and therefore its effect — is the same, so the binder resolves all
// three onto one knowledge-base command. This is the endgame the KB note in
// kb/data/toolchain.yaml prescribed: npx stays WITHOUT a KB signature of its
// own (a signature would bound the runner form while the path form stayed ⊤,
// splitting the audited 963134/963140 retry pair); instead the binder resolves
// the runner and the node_modules/.bin path to the bare binary and binds that.
//
// Fail-closed rules (each degrades to the top ⊤, never to a guess):
//   - the runner names no operand, or the operand is not a literal word
//     (npx $PKG — the executed binary is not statically known);
//   - the resolved operand matches no knowledge-base command (npx
//     some-unmodelled-pkg — a registry fetch whose code the analysis cannot
//     see);
//   - the runner's -c/--call flag is present: it executes an arbitrary shell
//     string (npx -c 'curl … | sh'), the exact download-cradle shape the
//     criteria exist for — never bounded by name resolution.
//
// The registry fetch the runner MAY perform when the package is not installed
// locally is deliberately not modelled, matching the sibling entries the KB
// already ships: npm run/exec and bun execute package scripts without a
// NetEgress effect. The executed binary's own signature is the bound surface.

package bind

import "strings"

// packageRunners are the package runners whose first non-flag operand names
// the binary that actually executes. Their invocation form differs from the
// direct binary path while the executed binary — and its effect — is the same.
var packageRunners = map[string]bool{
	"npx":  true,
	"bunx": true,
}

// runnerValueFlags are the package-runner flags that take a separate value
// operand, so the word after one is that flag's value, not the executed binary
// (npx -p foo bar runs bar, not foo). -c/--call additionally forces the whole
// call unresolvable (see the fail-closed rules above).
var runnerValueFlags = map[string]bool{
	"-p": true, "--package": true, "-c": true, "--call": true,
}

// runnerShellExecFlags force the ⊤: their value is an arbitrary shell string
// the runner passes to a shell, so no name resolution can bound the call.
var runnerShellExecFlags = map[string]bool{
	"-c": true, "--call": true,
}

// nodeModulesBin is the directory segment every JavaScript project exposes its
// local tool binaries under; stripping it maps a project-local binary path onto
// the bare binary name.
const nodeModulesBin = "node_modules/.bin"

// IsPackageRunner reports whether name is a package runner whose first
// non-flag operand names the executed binary (npx, bunx).
func IsPackageRunner(name string) bool {
	return packageRunners[name]
}

// StripBinaryPath reduces a command name to its bare binary: any
// node_modules/.bin directory segment is stripped (whole-segment match, so
// ./node_modules/.binx/ never trips it) and any remaining directory is cut.
// ./node_modules/.bin/tsc, node_modules/.bin/tsc, /abs/node_modules/.bin/tsc
// and /usr/bin/tsc all reduce to tsc.
func StripBinaryPath(name string) string {
	if i := strings.LastIndex(name, nodeModulesBin); i >= 0 {
		end := i + len(nodeModulesBin)
		// Strip only a whole path segment (node_modules/.bin/…), never a
		// directory that merely contains the substring (./node_modules/.binx/…).
		if (i == 0 || name[i-1] == '/' || name[i-1] == '\\') &&
			(end == len(name) || name[end] == '/' || name[end] == '\\') {
			name = name[end:]
		}
	}
	if j := strings.LastIndexAny(name, `/\`); j >= 0 {
		name = name[j+1:]
	}
	return name
}

// runnerFlag splits a runner flag word into its flag name and whether its value
// is attached to the same word. --call=X and -cX bind the same flag as
// --call X and -c X, so the fail-closed check must see through the attachment.
func runnerFlag(word string) (name string, attached bool) {
	if !strings.HasPrefix(word, "-") || word == "-" || word == "--" {
		return word, false
	}
	if eq := strings.IndexByte(word, '='); eq >= 0 {
		return word[:eq], true
	}
	if !strings.HasPrefix(word, "--") && len(word) > 2 {
		return word[:2], true
	}
	return word, false
}

// runnerBinary consumes the runner's own words from a plain-string argv and
// returns the executed binary operand plus the argv that survives for it. It is
// the string-level twin of runnerBinaryArgs, kept for the comparable form (the
// canonical view), which carries no literalness information: every word is
// literal, so it delegates to runnerBinaryArgs rather than duplicating the
// consumption rule — the two cannot drift.
func runnerBinary(args []string) (bin string, rest []string, ok bool) {
	argv := make([]Arg, len(args))
	for i, a := range args {
		argv[i] = Arg{Value: a, Literal: true}
	}
	operand, tail, ok := runnerBinaryArgs(argv)
	if !ok {
		return "", nil, false
	}
	rest = make([]string, len(tail))
	for i, a := range tail {
		rest[i] = a.Value
	}
	return operand.Value, rest, true
}

// runnerBinaryArgs is the Arg-level runner consumption used by resolution: the
// runner's own words (flags and value operands, the terminator) are consumed
// and the first non-flag LITERAL operand — before or after the -- terminator —
// is the executed binary. A non-literal word met before the operand (npx $PKG)
// or as the -- operand (npx -- $PKG) makes the binary unknowable — the call
// stays ⊤.
func runnerBinaryArgs(args []Arg) (operand Arg, rest []Arg, ok bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a.Value == "--" && a.Literal {
			// The binary follows the option terminator.
			if i+1 < len(args) {
				if !args[i+1].Literal {
					// A dynamic operand is not statically known: refuse it
					// exactly as the sibling branches below do.
					return Arg{}, nil, false
				}
				return args[i+1], args[i+2:], true
			}
			continue
		}
		if strings.HasPrefix(a.Value, "-") {
			if !a.Literal {
				// A dynamic word in flag position: what follows it cannot be
				// known to be a flag value or the binary.
				return Arg{}, nil, false
			}
			flag, attached := runnerFlag(a.Value)
			// -c/--call executes an arbitrary shell string: unresolvable,
			// whether written -c X, --call X, --call=X or -cX.
			if runnerShellExecFlags[flag] {
				return Arg{}, nil, false
			}
			// Skip a value-taking runner flag together with its value
			// (-p foo); a value attached to the flag (--package=foo) has no
			// separate word to skip.
			if runnerValueFlags[flag] && !attached {
				i++
			}
			continue
		}
		if !a.Literal {
			return Arg{}, nil, false
		}
		return a, args[i+1:], true
	}
	return Arg{}, nil, false
}

// NormalizeBinaryName reduces a resolved command name, with its argument
// values, to the normalized binary plus the argument list that survives: the
// basename of the name with any node_modules/.bin segment stripped
// (./node_modules/.bin/tsc, node_modules/.bin/tsc and /abs/node_modules/.bin/
// tsc all reduce to tsc), or — for a package runner — the runner's first
// non-flag operand with the runner's own words consumed (npx --yes tsc -b →
// (tsc, [-b])). A runner that names no operand keeps the basename rule, so
// bare npx still reports itself.
//
// This is the comparable-FORM normalization the report's CommandCall view is
// built on. It carries no literalness information, but it applies the same
// fail-closed rule the binding layer does: a runner invocation carrying
// -c/--call consumes no operand, so the runner keeps its own basename
// (npx -c 'X' Y normalizes to (npx, [-c X Y]), not (Y, [])) rather than
// reporting the arbitrary shell string's word as the executed binary. That
// tightening is the only comparable-form change from the pre-bind npx
// handling; the audited runner/path retry pair is unaffected.
func NormalizeBinaryName(name string, args []string) (string, []string) {
	if name == "" {
		return "", args
	}
	if packageRunners[name] {
		if bin, rest, ok := runnerBinary(args); ok {
			return StripBinaryPath(bin), rest
		}
	}
	return StripBinaryPath(name), args
}
