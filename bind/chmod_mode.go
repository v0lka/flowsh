package bind

import (
	"strings"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/kb"
)

// chmodEscalates reports whether a chmod invocation sets the set-user-ID or
// set-group-ID bit, and returns the escalation effect it therefore asserts.
//
// A knowledge-base effect belongs to a *parameter*, not to a parameter *value*,
// so chmod's MODE operand can only carry FSMeta, and the destructive table's
// row for the mode is gated on the resolved value (kb/data/destructive.yaml,
// `value: suid`) rather than on the parameter. The spelling-parity defect this
// closes: `chmod 4755 /tmp/evil` graded Medium with no escalation claim, while
// the identical operation spelled `install -m 4755` graded Critical with a
// PrivEsc effect — although the destructive doctrine says the mode *is* the
// escalation ("mode 4755 or 2755 sets the SUID/SGID bits, enabling privilege
// escalation").
//
// The mode is a literal the analysis can read, so the question is decided from
// it: the octal special-bit digit, the symbolic `+s`/`=s` clauses, and the
// `--reference` spelling, whose mode is copied from a file the analysis does not
// read (so it is reported over a target that includes the reference, never
// assumed benign).
func chmodEscalates(matches []match, rest []Arg, cmdAtom engine.Atom, file string) (engine.Effect, engine.Derivation, bool) {
	atoms := []engine.Atom{cmdAtom}
	files := rest
	escalates := false
	// `--reference` copies the mode from a file the analysis does not read, so
	// the copied mode may carry the identity bit. The option is bound through
	// the same resolver as every other long option, so its documented prefix
	// spelling (`--ref=…`) reaches this point too; the reference path itself was
	// consumed by option binding and is not a chmod target.
	for _, m := range matches {
		if m.param.Spec != "--reference" {
			continue
		}
		escalates = true
		atoms = append(atoms, flagAtom(m.param.Spec, withFile(m.pos, file)))
		if m.hasVal && m.value.Value != "" {
			atoms = append(atoms, operandAtom(m.value.Value, withFile(m.value.Pos, file)))
		}
	}
	if !escalates {
		if mode, ok := chmodModeOperand(rest); ok && modeOperandEscalates(mode) {
			escalates = true
			if mode.Value != "" {
				atoms = append(atoms, operandAtom(mode.Value, withFile(mode.Pos, file)))
			}
			files = dropArg(files, mode)
		}
	}
	if !escalates {
		return engine.Effect{}, engine.Derivation{}, false
	}
	// The escalation is a property of the target files; with no file operand the
	// invocation names none, so the extent is ⊤ rather than empty.
	scope := engine.ScopeTop()
	if len(files) > 0 {
		scope = metaScope(files)
		for _, a := range files {
			atoms = append(atoms, operandAtom(a.Value, withFile(a.Pos, file)))
		}
	}
	e := engine.Effect{
		Kind:       engine.KindPrivEsc,
		Target:     scope,
		Mode:       engine.ModeConditional,
		Certainty:  certaintyOf(engine.ModeConditional),
		Taint:      engine.TaintBottom(),
		Reversible: kb.DefaultReversible(engine.KindPrivEsc),
	}
	return e, derive(e, atoms, ruleForKind(engine.KindPrivEsc)), true
}

// installEscalates reports whether an `install -m MODE` / `install --mode MODE`
// invocation sets the set-user-ID or set-group-ID bit, and returns the
// escalation effect it therefore asserts over the files the invocation writes.
//
// It is the parity counterpart of chmodEscalates (Finding 100): `install -m
// 4755 SRC DEST` installs a set-user-ID program, so the escalation is a
// property of DEST — not of the mode text and not something a bare PrivEsc
// declaration on the `-m` parameter can express (a knowledge-base effect
// belongs to a parameter, not to its value).
//
// The mode is decided from the literal operand exactly as chmod's is, so
// `install -m 755` (no identity bit) asserts nothing while a mode the analysis
// cannot read (`-m "$M"`) asserts the escalation over the destination: the
// unknown value may carry the bit, and the claim is the sound direction.
func installEscalates(matches []match, rest []Arg, cmdAtom engine.Atom, file string) (engine.Effect, engine.Derivation, bool) {
	mode, ok := installModeMatch(matches)
	if !ok || !installModeEscalates(mode) {
		return engine.Effect{}, engine.Derivation{}, false
	}
	atoms := []engine.Atom{cmdAtom}
	if mode.hasVal && mode.value.Value != "" {
		atoms = append(atoms, operandAtom(mode.value.Value, withFile(mode.value.Pos, file)))
	}
	// The escalation is a property of the files the invocation creates or
	// rewrites: `-t DIR` names the directory, `-d` creates every operand, and
	// otherwise the last operand is DEST. With no destination at all the
	// invocation names none, so the extent is ⊤ rather than empty.
	scope := engine.ScopeTop()
	if files := installDestinations(matches, rest); len(files) > 0 {
		scope = metaScope(files)
		for _, a := range files {
			atoms = append(atoms, operandAtom(a.Value, withFile(a.Pos, file)))
		}
	}
	e := engine.Effect{
		Kind:       engine.KindPrivEsc,
		Target:     scope,
		Mode:       engine.ModeConditional,
		Certainty:  certaintyOf(engine.ModeConditional),
		Taint:      engine.TaintBottom(),
		Reversible: kb.DefaultReversible(engine.KindPrivEsc),
	}
	return e, derive(e, atoms, ruleForKind(engine.KindPrivEsc)), true
}

// installDestinations returns the operands install writes: the `-t` /
// `--target-directory` value when one is present, every operand in create mode
// (`-d`), and otherwise the last operand (DEST).
//
// The values come from the *bound* matches rather than from the raw words, so
// every spelling the resolver accepts (`-t DIR`, `-tDIR`, `--target-directory
// DIR`, `--target-directory=DIR`, and the unique-prefix `--target-dir=DIR`)
// names the same destination.
func installDestinations(matches []match, rest []Arg) []Arg {
	for _, m := range matches {
		if m.param.Spec == "-t" || m.param.Spec == "--target-directory" {
			if m.hasVal {
				return []Arg{m.value}
			}
			return nil
		}
	}
	for _, m := range matches {
		if m.param.Spec == "-d" {
			return rest // create mode: every operand is a directory
		}
	}
	if len(rest) == 0 {
		return nil
	}
	return rest[len(rest)-1:]
}

// installModeMatch returns the bound `-m` / `--mode` match, in every spelling
// the option resolver accepts: `-m 4755`, `-m4755`, a short cluster that ends in
// `-m` (`install -vm 4755`), `--mode 4755`, `--mode=4755` and the unique long
// prefix (`--mod=4755`). Reading the bound match rather than the raw word is
// what keeps a clustered or abbreviated spelling from silently dropping the
// escalation — the defect this helper exists to prevent.
func installModeMatch(matches []match) (match, bool) {
	// The last occurrence wins, which is what getopt does: `install -m 755
	// --mode=4755 SRC DEST` installs a set-user-ID program (verified against
	// coreutils: the file is 4755), so reading the first occurrence would report
	// no escalation for a command that sets the bit.
	for i := len(matches) - 1; i >= 0; i-- {
		if m := matches[i]; m.param.Spec == "-m" || m.param.Spec == "--mode" {
			return m, true
		}
	}
	return match{}, false
}

// installModeEscalates reports whether install's MODE value may set the
// set-user-ID or set-group-ID bit. An option written without a value (the
// invocation consumes nothing) and a value the analysis cannot read may both
// carry the bit, so they are treated as escalating.
func installModeEscalates(m match) bool {
	if !m.hasVal {
		return true
	}
	return modeOperandEscalates(m.value)
}

// installSetsIdentityBit reports whether the invocation's MODE operand sets the
// identity bit — the value predicate the destructive table gates install's
// class-E row on, symmetric with chmodSetsIdentityBit.
func installSetsIdentityBit(matches []match) bool {
	mode, ok := installModeMatch(matches)
	return ok && installModeEscalates(mode)
}

// resolvedValuePredicates reports which value-gated destructive predicates the
// invocation satisfies. The knowledge base names the predicate (it cannot
// evaluate one: it never sees an operand), so the resolution lives here, next to
// the doctrine that decides the same question for the effect.
func resolvedValuePredicates(cmd *kb.Command, argv []Arg) map[kb.ValuePredicate]bool {
	if cmd == nil {
		return nil
	}
	// The predicate is evaluated over the *bound* arguments, not over the raw
	// words: a mode spelled through a short cluster, an attached value or a long
	// option prefix is recognised by the same resolver that binds the option, so
	// a value-gated class cannot be lost by a spelling the resolver accepts.
	rest, matches, _, _ := parseArgs(cmd, argv)
	out := map[kb.ValuePredicate]bool{}
	if isChmodCommand(cmd) && chmodSetsIdentityBit(matches, rest) {
		out[kb.ValueSuid] = true
	}
	if isInstallCommand(cmd) && installSetsIdentityBit(matches) {
		out[kb.ValueSuid] = true
	}
	return out
}

// chmodSetsIdentityBit reports whether a chmod argv sets the set-user-ID or
// set-group-ID bit: a `--reference[=FILE]` mode (copied from a file the analysis
// does not read, so it may carry the bit) or a literal MODE operand that does.
func chmodSetsIdentityBit(matches []match, rest []Arg) bool {
	for _, m := range matches {
		if m.param.Spec == "--reference" {
			return true
		}
	}
	mode, ok := chmodModeOperand(rest)
	return ok && modeOperandEscalates(mode)
}

// modeOperandEscalates reports whether a chmod/install MODE value may set the
// set-user-ID or set-group-ID bit. A value the analysis cannot read (`"$M"`, an
// empty expansion) may carry the bit, so it is treated as escalating: the
// unknown case is the one where assuming "benign" would be a fail-open.
func modeOperandEscalates(mode Arg) bool {
	if !mode.Literal || mode.Value == "" {
		return true
	}
	return chmodModeEscalates(mode.Value)
}

// chmodModeOperand returns the MODE operand of a chmod argument list: the first
// operand that is not an option. A bare `-` is an operand; `--` ends the option
// run; `--reference` consumes the following word.
func chmodModeOperand(argv []Arg) (Arg, bool) {
	for i := 0; i < len(argv); i++ {
		v := argv[i].Value
		switch {
		case v == "--":
			continue
		case v == "--reference":
			i++
			continue
		case strings.HasPrefix(v, "-") && v != "-":
			continue
		}
		return argv[i], true
	}
	return Arg{}, false
}

// dropArg returns args without the element that is drop (matched by position,
// which identifies an argument uniquely within one command line).
func dropArg(args []Arg, drop Arg) []Arg {
	out := make([]Arg, 0, len(args))
	for _, a := range args {
		if a.Value == drop.Value && a.Pos == drop.Pos {
			continue
		}
		out = append(out, a)
	}
	return out
}

// chmodModeEscalates reports whether a chmod MODE operand sets the set-user-ID
// or set-group-ID bit. A mode is a comma-separated list of clauses, each either
// an octal mode or a symbolic one (`[ugoa]*[+=-][rwxXst]*`), and the escalation
// holds when *any* clause sets the bit.
func chmodModeEscalates(mode string) bool {
	for _, clause := range strings.Split(mode, ",") {
		if clause == "" {
			continue
		}
		if value, ok := chmodOctalMode(clause); ok {
			// The identity bits are the 0o4000/0o2000 bits of the numeric
			// mode, so 4755 sets set-user-ID, 2755 set-group-ID, and the
			// sticky-only 0o1000 bit is not an escalation. The test is on the
			// *value*: leading zeros do not change it, so `004755` — accepted
			// and applied as 4755 by GNU chmod — sets the bit exactly as
			// `4755` does (Finding 100; the digit-count spelling missed it).
			if value&0o6000 != 0 {
				return true
			}
			continue
		}
		if chmodSymbolicEscalates(clause) {
			return true
		}
	}
	return false
}

// chmodOctalMode parses s as the numeric chmod mode coreutils' mode_compile
// accepts: octal digits whose accumulated value fits in the permission bits
// (0o7777). Leading zeros are accepted, so `004755` (value 0o4755) is a valid
// mode while `44755` (value 0o44755, over 0o7777) is rejected as an "invalid
// mode" — the rule GNU chmod applies, and the reason a digit count is the wrong
// test (Finding 100).
func chmodOctalMode(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	var v uint32
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '7' {
			return 0, false
		}
		v = v*8 + uint32(s[i]-'0')
		if v > 0o7777 {
			return 0, false
		}
	}
	return v, true
}

// chmodSymbolicEscalates reports whether one symbolic chmod clause sets the
// set-user-ID or set-group-ID bit: `u+s`, `g+s`, `a+s`, the who-less `+s` and
// `=s` (who-less means all), and the `=` forms that carry an `s` among their
// permissions (`u=rwxs`). `o+s` is not an escalation — the `s` bit has no
// meaning for others — and `-s` removes the bit rather than setting it.
func chmodSymbolicEscalates(clause string) bool {
	i := 0
	for i < len(clause) && strings.ContainsRune("ugoa", rune(clause[i])) {
		i++
	}
	who, rest := clause[:i], clause[i:]
	if len(rest) < 2 {
		return false
	}
	if op := rest[0]; op != '+' && op != '=' {
		return false
	}
	if !strings.ContainsRune(rest[1:], 's') {
		return false
	}
	if who == "" {
		return true
	}
	return strings.ContainsAny(who, "uga")
}
