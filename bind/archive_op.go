package bind

import (
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/kb"
)

// ===========================================================================
// Mode-dependent operations: single-file compressors and tar's old-style
// option bundle (Findings 12, 84, 85)
// ===========================================================================
//
// Two command families have an operation whose *effect* depends on how the
// command is spelled, not on which file it is given:
//
//   - a single-file compressor reads its FILE operand and, in its default
//     mode, rewrites that operand in place (gzip FILE creates FILE.gz and
//     removes FILE; xz, bzip2, zstd, compress and their -d twins do the same).
//     The rewrite is the operation, so it belongs to the invocation, not to
//     one of the tuning flags -f/-9/-z/-d; and it does not happen at all when
//     the result streams to stdout (-c/--stdout) or when the file is only
//     inspected (-t/--test, -l/--list);
//
//   - tar's POSIX old-style option bundle (`tar cf ARCHIVE SRC…`, `tar czf -
//     SRC…`) names the operation in its first operand instead of in dashed
//     flags. The row declares the bundle a read, so an archive the command
//     *creates* was reported as a pure read: `tar cf /etc/passwd /etc/hostname`
//     bound FSRead only, `tar cf //host/share/x /etc/shadow` produced no write
//     and therefore no remote-write egress, and both were allowed by an
//     FSWrite-denying policy while their `-cf` twins were denied.
//
// Both are one-sided corrections applied to the command's own effects: they add
// the write the operation performs and never invent a target the command line
// does not name (an unnamed archive is ⊤, `-` is standard output). Delegating
// the mode to the binder keeps the KB schema frozen at effect-kb/v2 - the row
// still declares every token's effect, and the binder only applies the
// mode-dependent half the one-effect-per-parameter schema cannot express.

// ---------------------------------------------------------------------------
// Single-file compressors
// ---------------------------------------------------------------------------

// compressorStreamSpecs are the parameters that make a single-file compressor
// write no file at all: `-c`/`--stdout` streams the result to standard output,
// `-t`/`--test` verifies its integrity and `-l`/`--list` prints its metadata.
// The long spellings are listed even where a row does not declare one; an
// undeclared parameter simply never matches.
var compressorStreamSpecs = map[string]bool{
	"-c": true, "--stdout": true,
	"-t": true, "--test": true,
	"-l": true, "--list": true,
}

// compressorOutputSpecs are the parameters that name the output file
// explicitly (zstd -o/--output). When one of them matched, the operation
// writes that file and leaves the input operand alone, so the in-place write
// must not be synthesised on top of it.
var compressorOutputSpecs = map[string]bool{
	"-o": true, "--output": true,
}

// isSingleFileCompressor reports whether cmd is a single-file
// compressor/decompressor: a command that takes FILE operands and, by default,
// rewrites each one in place. zcat and other read-only friends are excluded -
// they never write.
func isSingleFileCompressor(cmd *kb.Command) bool {
	if cmd == nil || cmd.Dialect != kb.DialectArchive {
		return false
	}
	switch cmd.Name {
	case "gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz", "zstd", "compress", "uncompress":
		return true
	}
	return false
}

// compressorStreams reports whether a matched parameter selects a mode in
// which the compressor writes no file.
func compressorStreams(matches []match) bool {
	for _, m := range matches {
		if compressorStreamSpecs[m.param.Spec] {
			return true
		}
	}
	return false
}

// compressorNamesOutput reports whether a matched parameter names the output
// file, so the operand is not rewritten in place.
func compressorNamesOutput(matches []match) bool {
	for _, m := range matches {
		if compressorOutputSpecs[m.param.Spec] {
			return true
		}
	}
	return false
}

// dropInPlaceWrites removes the matches whose declared effect is a filesystem
// write, for an invocation that cannot perform one. The row attaches FSWrite
// to the mode and tuning flags (-d/--decompress, -z, -f, -9, -b) because in the
// default mode they *accompany* the operation's rewrite; when the operation
// streams to stdout or only inspects the file those declarations are not
// effects of this invocation, and keeping them fabricated a write for
// `gzip -9c FILE` (a stream) while the real read was missing.
//
// Only the compressor family reaches this function, and only in a stream or
// inspect mode, so no other row's write can be lost through it.
func dropInPlaceWrites(matches []match) []match {
	kept := matches[:0]
	for _, m := range matches {
		if m.param.Effect.Kind == engine.KindFSWrite {
			continue
		}
		kept = append(kept, m)
	}
	return kept
}

// compressorOperationWrite is the write a compressor's default operation
// performs on each named FILE operand. It is skipped when the invocation
// streams its result, inspects the file, or names a different output file, and
// for the `-` operand (standard input/output, not a file called "-").
func compressorOperationWrite(cmd *kb.Command, matches []match, operands []Arg, cmdAtom engine.Atom, file string) ([]engine.Effect, []engine.Derivation) {
	if !isSingleFileCompressor(cmd) || compressorStreams(matches) || compressorNamesOutput(matches) {
		return nil, nil
	}
	var effs []engine.Effect
	var ders []engine.Derivation
	seen := make(map[string]bool, len(operands))
	for _, op := range operands {
		if op.Literal && op.Value == "-" {
			continue
		}
		target := argsScope([]Arg{op}, false)
		if target.IsBottom() {
			continue
		}
		key := target.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		e := engine.Effect{
			Kind:       engine.KindFSWrite,
			Target:     target,
			Mode:       engine.ModeDirect,
			Certainty:  engine.CertaintyCertain,
			Taint:      op.Taint,
			Reversible: kb.DefaultReversible(engine.KindFSWrite),
		}
		effs = append(effs, e)
		ders = append(ders, derive(e, []engine.Atom{cmdAtom, operandAtom(op.Value, withFile(op.Pos, file))}, ruleForKind(engine.KindFSWrite)))
	}
	return effs, ders
}

// ---------------------------------------------------------------------------
// tar's POSIX old-style option bundle
// ---------------------------------------------------------------------------

// tarShortLetters is the vocabulary of tar's old-style option bundle: every
// letter GNU tar and bsdtar accept as a short option. The word is read as a
// bundle only when all of its letters are in this set, so an ordinary operand
// (`tar archive.tar`, a path) is never mistaken for options.
var tarShortLetters = map[rune]bool{
	// Operations.
	'c': true, 'x': true, 't': true, 'r': true, 'u': true, 'A': true, 'd': true,
	// Modifiers.
	'z': true, 'j': true, 'J': true, 'Z': true, 'a': true,
	'p': true, 'P': true, 'v': true, 'w': true, 'i': true, 'k': true, 'm': true,
	'o': true, 's': true, 'R': true, 'B': true, 'G': true, 'M': true, 'O': true,
	'U': true, 'W': true, 'l': true, 'S': true, 'H': true, 'h': true, 'q': true,
	// Letters that consume the word that follows them.
	'f': true, 'C': true, 'T': true, 'b': true, 'F': true, 'g': true,
	'I': true, 'K': true, 'L': true, 'N': true, 'V': true, 'X': true,
}

// tarArgLetters are the bundle letters that take the next word as their value,
// in bundle order. `tar cTf LIST ARCHIVE SRC` therefore names ARCHIVE two
// words after the bundle: T consumes LIST and f consumes ARCHIVE.
var tarArgLetters = map[rune]bool{
	'f': true, 'C': true, 'T': true, 'b': true, 'F': true, 'g': true,
	'I': true, 'K': true, 'L': true, 'N': true, 'V': true, 'X': true,
}

// tarWriteOps are the operations that create or modify an archive: create,
// append, update and concatenate. Extraction (x) writes the *members*, which
// the row already declares, and the list (t) and compare (d) operations write
// nothing at all.
var tarWriteOps = map[rune]bool{'c': true, 'r': true, 'u': true, 'A': true}

// tarOldStyleOp reports the operation letter of tar's old-style option bundle
// and whether the invocation is written that way. It fires only for a leading
// operand that is a letters-only word carrying exactly one operation letter,
// which is exactly how tar itself reads its first argument.
func tarOldStyleOp(cmd *kb.Command, operands []Arg) (rune, bool) {
	if cmd == nil || cmd.Dialect != kb.DialectTar || len(operands) == 0 {
		return 0, false
	}
	word := operands[0]
	if !word.Literal || word.Value == "" || word.Value[0] == '-' {
		return 0, false
	}
	op := rune(0)
	for _, r := range word.Value {
		if !tarShortLetters[r] {
			return 0, false
		}
		// An operation letter is unique: two of them in one bundle is not a
		// spelling tar accepts, and guessing between them would be a guess.
		if tarShortLetters[r] && isTarOperation(r) {
			if op != 0 {
				return 0, false
			}
			op = r
		}
	}
	if op == 0 {
		return 0, false
	}
	return op, true
}

// isTarOperation reports whether r selects one of tar's operations.
func isTarOperation(r rune) bool {
	switch r {
	case 'c', 'x', 't', 'r', 'u', 'A', 'd':
		return true
	}
	return false
}

// tarArchiveOperand returns the operand the bundle's `f` letter names, and the
// operands that follow every value-taking letter (the members or sources).
// ok is false when the bundle carries no `f`, in which case the archive is
// tar's default device: unnamed, hence ⊤.
func tarArchiveOperand(bundle Arg, operands []Arg) (archive Arg, hasArchive bool, rest []Arg) {
	archive, hasArchive, _, rest = tarBundleArgs(bundle, operands)
	return archive, hasArchive, rest
}

// tarBundleArgs is tarArchiveOperand plus the words the bundle's other
// value-taking letters consume, keyed by letter: `C` names the base directory
// and `T` the file the operands are read from, and both are reads in create
// mode — the same effects the dashed `-C`/`-T` options carry (Findings 44, 66).
func tarBundleArgs(bundle Arg, operands []Arg) (archive Arg, hasArchive bool, consumed map[rune][]Arg, rest []Arg) {
	consumed = make(map[rune][]Arg, len(tarArgLetters))
	idx := 1
	archiveIdx := -1
	for _, r := range bundle.Value {
		if !tarArgLetters[r] {
			continue
		}
		if idx < len(operands) {
			consumed[r] = append(consumed[r], operands[idx])
		}
		if r == 'f' && archiveIdx < 0 {
			archiveIdx = idx
		}
		idx++
	}
	if idx > len(operands) {
		idx = len(operands)
	}
	if archiveIdx >= 0 && archiveIdx < len(operands) {
		return operands[archiveIdx], true, consumed, operands[idx:]
	}
	return Arg{}, false, consumed, operands[idx:]
}

// tarWriteOpFromMatches reports the archive-write operation a dashed tar flag
// selects. The KB declares `-c`/`--create`, `-r` and `-u` as the operation's
// reads (their operands are the sources, as in the old-style bundle); the write
// they imply is the archive, which `-f`/`--file` names.
func tarWriteOpFromMatches(matches []match) (rune, bool) {
	for _, m := range matches {
		switch m.param.Spec {
		case "-c", "--create":
			return 'c', true
		case "-r":
			return 'r', true
		case "-u":
			return 'u', true
		}
	}
	return 0, false
}

// tarNamesArchive reports whether the invocation names its archive with the
// `-f`/`--file` option, whose own declared effect (a write, or the stream for
// `-`) already carries it.
func tarNamesArchive(matches []match) bool {
	for _, m := range matches {
		if m.param.Spec == "-f" || m.param.Spec == "--file" {
			return true
		}
	}
	return false
}

// tarWriteOperation reports the archive-write operation an invocation selects,
// in either spelling: the old-style bundle's operation letter or the dashed
// `-c`/`-r`/`-u` flag.
func tarWriteOperation(cmd *kb.Command, matches []match, operands []Arg) (rune, bool) {
	if cmd == nil || cmd.Dialect != kb.DialectTar {
		return 0, false
	}
	if op, ok := tarOldStyleOp(cmd, operands); ok && tarWriteOps[op] {
		return op, true
	}
	return tarWriteOpFromMatches(matches)
}

// tarBundleEffects is the whole positional picture of an old-style bundle when
// the row's positional binding did not supply it: the operation's write over the
// archive (or the stream for `-`, or ⊤ when the bundle names no archive) plus
// the reads of the words that are actually archived. `bound` reports that the
// bundle matched a declared positional spec, in which case the row has already
// lowered the operand group and only the missing write is added.
func tarBundleEffects(cmd *kb.Command, operands []Arg, bound, archiveNamed bool, cmdAtom engine.Atom, file string) ([]engine.Effect, []engine.Derivation) {
	op, ok := tarOldStyleOp(cmd, operands)
	if !ok {
		return nil, nil
	}
	archive, hasArchive, sources := tarArchiveOperand(operands[0], operands)
	var effs []engine.Effect
	var ders []engine.Derivation
	add := func(e engine.Effect, atoms []engine.Atom, rules ...string) {
		effs = append(effs, e)
		ders = append(ders, derive(e, withSink(atoms, e), rules...))
	}
	writeEffect := func() (engine.Effect, []engine.Atom) {
		switch {
		case hasArchive && archive.Literal && archive.Value == "-":
			// `tar cf - …` writes the archive to standard output. Reporting an
			// FSWrite to a file literally named "-" would name a target the
			// command line does not write.
			return engine.Effect{
				Kind:       engine.KindStdio,
				Target:     engine.ScopeBottom(),
				Mode:       engine.ModeDirect,
				Certainty:  engine.CertaintyCertain,
				Taint:      engine.TaintBottom(),
				Reversible: kb.DefaultReversible(engine.KindStdio),
			}, []engine.Atom{cmdAtom, operandAtom(archive.Value, withFile(archive.Pos, file))}
		case hasArchive:
			return engine.Effect{
				Kind:       engine.KindFSWrite,
				Target:     argsScope([]Arg{archive}, false),
				Mode:       engine.ModeDirect,
				Certainty:  engine.CertaintyCertain,
				Taint:      archive.Taint,
				Reversible: kb.DefaultReversible(engine.KindFSWrite),
			}, []engine.Atom{cmdAtom, operandAtom(archive.Value, withFile(archive.Pos, file))}
		default:
			// No archive named by the bundle: either the separate -f/--file
			// option names it (its own declared effect already carries the
			// write, or the stream for `-`), or the archive goes to tar's
			// default device, which the command line does not name.
			if archiveNamed {
				return engine.Effect{}, nil
			}
			return topWrite(), []engine.Atom{cmdAtom, operandAtom(operands[0].Value, withFile(operands[0].Pos, file))}
		}
	}
	switch {
	case tarWriteOps[op]:
		e, atoms := writeEffect()
		if e.Kind != "" {
			add(e, atoms, ruleForKind(e.Kind))
		}
		// The words `C` and `T` consume are reads in create mode, exactly as
		// the dashed `-C`/`-T` options declare (Findings 44, 66): the base
		// directory is archived recursively and the list file supplies the
		// operand names. They are bound here for both spellings of the bundle,
		// because the row's value-matched positional would otherwise cover them
		// with the archive's write or with nothing at all.
		_, _, consumed, _ := tarBundleArgs(operands[0], operands)
		reads := append([]Arg{}, consumed['C']...)
		reads = append(reads, consumed['T']...)
		readEffs, readDers := operandReadEffects(reads, cmdAtom, file)
		effs = append(effs, readEffs...)
		ders = append(ders, readDers...)
		if !bound {
			srcEffs, srcDers := operandReadEffects(sources, cmdAtom, file)
			effs = append(effs, srcEffs...)
			ders = append(ders, srcDers...)
		}
	case op == 'x':
		if bound {
			// The row declares the extraction write (`x`, `xf`, `xzf`, …).
			return nil, nil
		}
		e, atoms := writeEffect()
		add(e, atoms, ruleForKind(e.Kind))
	case op == 't' || op == 'd':
		if bound {
			return nil, nil
		}
		// A listing or a comparison writes nothing: the archive is read.
		target := engine.ScopeTop()
		atoms := []engine.Atom{cmdAtom}
		if hasArchive {
			target = argsScope([]Arg{archive}, false)
			atoms = append(atoms, operandAtom(archive.Value, withFile(archive.Pos, file)))
		}
		e := engine.Effect{
			Kind:       engine.KindFSRead,
			Target:     target,
			Mode:       engine.ModeDirect,
			Certainty:  engine.CertaintyCertain,
			Taint:      engine.TaintBottom(),
			Reversible: kb.DefaultReversible(engine.KindFSRead),
		}
		add(e, atoms, ruleForKind(engine.KindFSRead))
	}
	return effs, ders
}

// operandReadEffects lowers a group of source operands as filesystem reads: the
// words an old-style tar bundle archives are read, whichever spelling names
// them. It returns the effects with their why-trace derivations.
func operandReadEffects(sources []Arg, cmdAtom engine.Atom, file string) ([]engine.Effect, []engine.Derivation) {
	var effs []engine.Effect
	var ders []engine.Derivation
	seen := make(map[string]bool, len(sources))
	for _, src := range sources {
		if src.Literal && src.Value == "-" {
			continue
		}
		target := argsScope([]Arg{src}, false)
		if target.IsBottom() || seen[target.String()] {
			continue
		}
		seen[target.String()] = true
		e := engine.Effect{
			Kind:       engine.KindFSRead,
			Target:     target,
			Mode:       engine.ModeDirect,
			Certainty:  engine.CertaintyCertain,
			Taint:      src.Taint,
			Reversible: kb.DefaultReversible(engine.KindFSRead),
		}
		effs = append(effs, e)
		ders = append(ders, derive(e, []engine.Atom{cmdAtom, operandAtom(src.Value, withFile(src.Pos, file))}, ruleForKind(engine.KindFSRead)))
	}
	return effs, ders
}

// tarCreateSourceGroup narrows the operands a create/append/update bundle's
// read covers to the words that are actually archived: the bundle word and the
// values its argument letters consume (the archive named by `f`, the list named
// by `T`, the directory named by `C`, …) are not sources. Without the
// narrowing, `tar cf /etc/passwd x` reported a *read* of the file it writes,
// which fabricated a credential read — and, next to an egress in the same
// command, a fabricated exfiltration pair.
func tarCreateSourceGroup(cmd *kb.Command, operands []Arg) ([]Arg, bool) {
	op, ok := tarOldStyleOp(cmd, operands)
	if !ok || !tarWriteOps[op] {
		return nil, false
	}
	if _, has, rest := tarArchiveOperand(operands[0], operands); has {
		return rest, true
	}
	return nil, false
}

// tarOperationWrite is the archive write the *dashed* spelling of a
// create/append/update operation performs when the archive is not named by
// `-f`/`--file`: tar then writes its default device, whose location the command
// line does not name (⊤). When the archive is named, the option's own declared
// effect already carries the write (or the stream, for `-`).
func tarOperationWrite(cmd *kb.Command, operands []Arg, op rune, archiveNamed bool, cmdAtom engine.Atom, file string) ([]engine.Effect, []engine.Derivation) {
	if !tarWriteOps[op] || archiveNamed {
		return nil, nil
	}
	e := topWrite()
	atoms := []engine.Atom{cmdAtom}
	if len(operands) > 0 {
		atoms = append(atoms, operandAtom(operands[0].Value, withFile(operands[0].Pos, file)))
	}
	return []engine.Effect{e}, []engine.Derivation{derive(e, withSink(atoms, e), ruleForKind(e.Kind))}
}

// isTarArchiveDash reports whether p is tar's archive parameter (-f/--file).
// Its value "-" names standard input or output, so it is a stream, never a
// file literally called "-".
func isTarArchiveDash(cmd *kb.Command, p kb.Param) bool {
	if cmd == nil || cmd.Dialect != kb.DialectTar || p.Kind != kb.ParamOption {
		return false
	}
	return p.Spec == "-f" || p.Spec == "--file"
}
