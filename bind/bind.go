// Package bind turns a normalized command invocation into the set of effects it
// implies, by resolving the invoked name and binding its flags and operands
// against the effect knowledge base.
//
// Two deliberate empty-result shapes for direct Bind/BindBash callers — Bind
// reports no effects and no Conservative flag for either, and the ⊤
// degradation for both is the frontend interpreter's (its wrapper-only path);
// embedding consumers must treat such an empty result as covered upstream
// rather than fail-open:
//
//   - an inert privilege-wrapper line that consumed the whole command line
//     and names no command word (`sudo`, `sudo -k`, `sudo -l`, a command-less
//     `sudo -u <user>` naming a non-root target) runs nothing — the -u
//     spelling still names its target;
//   - a fully-peeled wrapper chain with no command word left to bind whose
//     privileged wrapper de-elevates (`env sudo -u nobody env`): the line
//     runs, but unprivileged and effect-free, so nothing is claimed and
//     nothing remains to analyse.
//
// A third shape is deliberately NOT empty: an inert wrapper line that still
// carries command words (`sudo -l touch /x`) reports the ⊤ `CodeExec` effect
// (with `Conservative` set) the frontend gives a consumed line, so the words
// that follow cannot fabricate effects for a process that never starts.
//
// It is the join of the two lower layers:
//
//	front/bash ──normalized call──▶ bind ──▶ []engine.Effect
//	                     ▲             ▲
//	              kb (command /     engine (effect IR,
//	               flag signatures)   lattices, report)
//
// Dependency direction stays strictly one-way: bind imports engine, kb and
// front/bash, and none of them imports bind. This is why the package is a
// sibling of engine rather than a file inside it: the core (engine) must not
// import a frontend (front/bash) — TestCoreDoesNotImportFrontends enforces that
// — and engine cannot import kb at all, because kb already imports engine.
//
// The analysis is deliberately conservative where it cannot see: a call whose
// name is not statically known, or that matches neither a builtin, a function,
// an alias, nor a command in the knowledge base, degrades to the top element ⊤
// represented as CodeExec over the any-target scope — never to "no effect".
package bind

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/bash"
	"github.com/v0lka/flowsh/kb"
)

// Style names the command-line dialect a call is written in.
type Style string

const (
	// StyleBash is POSIX/bash argv with -flags and --options.
	StyleBash Style = "bash"
	// StylePS is PowerShell cmdlet syntax (named and positional parameters).
	StylePS Style = "ps"
)

// Arg is one normalized argument word. Literal is true when the word's text is
// fully known at analysis time; a non-literal word (parameter expansion, command
// substitution, …) has an unreliable Value and forces the targets derived from
// it to ⊤ — unless Dir is set: the directory its expansion is provably confined
// to, which the derived targets use instead of ⊤.
type Arg struct {
	Value   string `json:"value"`
	Literal bool   `json:"literal"`

	// Dir names the directory a non-literal word is confined to when every one
	// of its dynamic parts is numeric-class (an exit status, a pid, a length:
	// digits cannot form a path structure). Empty for literal words and for
	// dynamic words the analysis cannot bound, which stay ⊤. It is analysis
	// metadata and is deliberately not part of the serialized call.
	Dir string `json:"-"`

	// Taint is the provenance of the value, propagated from the frontend's
	// dataflow (variable reads, command substitutions, …). It is analysis
	// metadata and is deliberately not part of the serialized call.
	Taint engine.Taint `json:"-"`

	// Root marks a literal relative operand that the shell's tracked working
	// directory resolves to the filesystem root: "." after `cd /`, "../../"
	// after `cd /tmp`, and every other spelling whose resolved path is "/". The
	// operand text is kept as written; a consumer that grades extents (a
	// metadata change under `chmod -R`) resolves it to the root it names
	// instead of treating the literal "." as one exact file (Finding 70).
	Root bool `json:"-"`

	// FromXargs marks an operand whose value xargs substitutes from its input
	// items (Finding 92). The value is data rather than text, so it is unknown
	// (⊤): a parameter that reads a file reads a path the analysis cannot name,
	// and the read is reported as secret-bearing by construction — the same
	// rule engine.IsSecretRead applies to an environment read whose variable
	// name is not statically known.
	FromXargs bool `json:"-"`

	// Pos is the source position of the word this argument was lowered from,
	// when the frontend knows it. It rides on the why-trace atoms so an effect
	// can be pinned back to the token (flag/operand) that justified it. It is
	// analysis metadata and is not part of the serialized call.
	Pos engine.SourceLoc `json:"-"`
}

// EnvAssign is a NAME=value environment assignment that applies to the
// invocation. Via is empty for an assignment written directly on the command
// and otherwise names the wrapper that introduced it ("env", "sudo").
type EnvAssign struct {
	Name  string `json:"name"`
	Value Arg    `json:"value"`
	Via   string `json:"via,omitempty"`

	// Pos is the source position of the assignment, for the why-trace atom that
	// justifies the environment write. It is analysis metadata.
	Pos engine.SourceLoc `json:"-"`
}

// Wrapper is one command wrapper that was peeled off a call (sudo, env, …),
// outermost first. Name is the wrapper's own name; Options are the wrapper's
// literal option words: a value-taking option's statically known value is
// recorded immediately after it, a dynamic one as the "@" placeholder (the
// option stays unsatisfied, so the separated `sudo -u $U` and its absorbed
// quoted twin `sudo -u"$U"` alike keep `-u` plus the placeholder, and
// re-pairing never glues a following word as the value; only an unquoted
// attached spelling like `sudo -u$U` stays the dynamically-named inner
// command, its option recorded without a value); Pos is
// the position of the wrapper's own name word, so the elevation an
// effect-carrying wrapper implies can be traced back to its token. The inner
// command's own Name and Args are what remains of the statement.
type Wrapper struct {
	Name    string           `json:"name"`
	Options []Arg            `json:"options,omitempty"`
	Pos     engine.SourceLoc `json:"-"`
}

// Call is a frontend-agnostic normalized invocation: the effective program name
// plus its argv, together with the shell context needed to resolve the name.
type Call struct {
	Style Style `json:"style"`

	// Name is the statically-known program name ("" when it is not literal).
	Name string `json:"name,omitempty"`
	// NameOK reports whether Name is statically known.
	NameOK bool `json:"-"`
	// NamePresent reports whether the statement has a command word at all; when
	// it is false the statement is a bare assignment or redirection.
	NamePresent bool `json:"-"`

	Args []Arg       `json:"args,omitempty"`
	Env  []EnvAssign `json:"env,omitempty"`

	// Wrappers lists the command wrappers (sudo, env, …) peeled off the call,
	// outermost first, each with the option words it carried and the position
	// of its own name — so the binder can refine a wrapper whose
	// knowledge-base entry declares PrivEsc (sudo) by the wrapper's own
	// command line.
	Wrappers []Wrapper `json:"wrappers,omitempty"`

	// Funcs and Aliases hold the shell symbols visible at the call site, which
	// resolution consults after builtins.
	Funcs   map[string]bool   `json:"funcs,omitempty"`
	Aliases map[string]string `json:"aliases,omitempty"`

	Pos engine.SourceLoc `json:"pos,omitempty"`

	// StdinTaint is the provenance of the data the invoked command reads from
	// its standard input (a pipeline's upstream output, or an input
	// redirection). It is analysis metadata and is not serialized.
	StdinTaint engine.Taint `json:"-"`
}

// Binder binds calls against a loaded knowledge base.
type Binder struct {
	k *kb.KB
}

// NewDefault returns a binder over the embedded knowledge base.
func NewDefault() (*Binder, error) {
	k, err := kb.Default()
	if err != nil {
		return nil, err
	}
	return &Binder{k: k}, nil
}

// Result is the outcome of binding one normalized call.
type Result struct {
	Style           Style                  `json:"style"`
	Resolution      Resolution             `json:"resolution"`
	Effects         []engine.Effect        `json:"effects"`
	Destructiveness engine.Destructiveness `json:"destructiveness"`
	// Destructive lists the knowledge base's destructive-flags entries that the
	// call matched, for the composition layer to consume.
	Destructive []kb.Destructive `json:"destructive,omitempty"`
	// Derivations justifies every reported effect with the concrete source atoms
	// (command, flag, operand, source, sink) it rests on. It is analysis
	// metadata for the why-trace, not part of the serialized call.
	Derivations []engine.Derivation `json:"-"`
	// Conservative is true when the outcome includes a ⊤ (CodeExec) effect
	// because the call could not be bounded.
	Conservative bool     `json:"conservative"`
	Notes        []string `json:"notes,omitempty"`
}

// Encode returns the canonical indented JSON of the result.
func (r *Result) Encode() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Bind resolves and binds a single normalized call. It is total and
// deterministic: it never returns nil and never panics on a well-formed Call.
// For the two deliberate empty-result shapes of direct callers — an inert
// privilege-wrapper line that consumed the whole command line, and a
// fully-peeled wrapper chain whose privileged wrapper de-elevates — see the
// package documentation.
func (b *Binder) Bind(c *Call) *Result {
	if c == nil {
		return conservativeResult(StyleBash, "nil call", engine.ModeDirect)
	}
	r := &Result{Style: c.Style}
	var raw []engine.Effect
	var ders []engine.Derivation

	if b == nil || b.k == nil {
		r.Resolution = Resolution{Kind: ResolveUnknown, Invoked: callName(c)}
		te := topEffect(engine.ModeDirect)
		raw = append(raw, te)
		ders = append(ders, derive(te, []engine.Atom{commandAtom(callName(c), c.Pos)}, "code.exec"))
		r.Conservative = true
		r.Notes = append(r.Notes, "no knowledge base bound")
		// Without a knowledge base nothing can be inert: report the
		// environment writes and the code-execution channel they can carry as
		// before the wrapper pass existed.
		effs, envDers := envAssignEffects(c)
		raw = append(raw, effs...)
		ders = append(ders, envDers...)
		r.Effects = raw
		r.Derivations = ders
		normalizeResult(r)
		return r
	}

	// Wrapper elevation, before the inner command is resolved: a wrapper whose
	// knowledge-base entry declares a PrivEsc parameter (sudo) elevates by its
	// own command line, not by the inner command's — `sudo -u nobody touch /x`
	// runs touch unprivileged, while bare `sudo touch /x` elevates to root.
	// The fired elevations are held back until the whole wrapper chain has
	// spoken: an inert wrapper (`sudo -l …`) means no privileged command
	// executes on the line, so no wrapper on it may claim an elevation.
	inert := false
	type firedElevation struct {
		e     engine.Effect
		atoms []engine.Atom
	}
	var fired []firedElevation
	for i, w := range c.Wrappers {
		kw, ok := b.k.Command(w.Name)
		if !ok || !declaresPrivEsc(kw) {
			continue
		}
		// Whether this wrapper has anything left to execute is decided at its
		// own position in the chain, not for the chain as a whole: Wrappers
		// are outermost-first, so what it would exec is the command word and
		// the wrappers deeper in the chain — a wrapper above it (`env sudo
		// -k`, `nohup sudo -k`) execs the privileged wrapper, not the other
		// way round, and cannot keep its inert flag-only line alive.
		innerPresent := c.NamePresent || i < len(c.Wrappers)-1
		e, atoms, fires, notes, inertLine := wrapperElevation(kw, w, c.Pos.File, innerPresent)
		r.Notes = append(r.Notes, notes...)
		if inertLine {
			inert = true
		}
		if !fires {
			continue
		}
		fired = append(fired, firedElevation{e: e, atoms: atoms})
	}
	if inert {
		// Any inert wrapper decides the whole line — no privileged command
		// executes — but an OUTER wrapper's -k note is appended per its own
		// option list, before this chain-wide decision is known. Drop the
		// "still runs" notes so a nested inert spelling (`sudo -k sudo -l`)
		// cannot leave one report claiming both that the line runs and that
		// nothing executes.
		r.Notes = dropStillRunsNotes(r.Notes)
	}
	if !inert {
		for _, f := range fired {
			raw = append(raw, f.e)
			ders = append(ders, derive(f.e, f.atoms, ruleForKind(engine.KindPrivEsc)))
		}
		// Environment assignments (VAR=x cmd, env VAR=x cmd) mutate the
		// environment, and an assignment to a variable the runtime executes
		// (LD_PRELOAD, JAVA_TOOL_OPTIONS, TAR_OPTIONS, git's GIT_CONFIG_*)
		// executes a program as well. An inert wrapper line runs nothing, so
		// the binder's copy of them is suppressed with the rest of the line
		// (the wrapper-donated writes the bash interpreter recorded at peel
		// time are not retracted — an accepted precision residual,
		// SECURITY.md Known Risks).
		effs, envDers := envAssignEffects(c)
		raw = append(raw, effs...)
		ders = append(ders, envDers...)
	}

	if !c.NamePresent {
		if len(c.Env) > 0 {
			r.Resolution = Resolution{Kind: ResolveAssignment, Name: firstEnvName(c)}
		} else {
			r.Resolution = Resolution{Kind: ResolveEmpty}
		}
	} else if inert {
		// The wrapper's own command line runs nothing (the `sudo -l` list
		// form, an inert flag-only line): the words that follow name no
		// executing process, so binding them as the "inner command" would
		// fabricate effects for a process that never starts. Degrade to ⊤ —
		// the same verdict the frontend gives a consumed command line — with
		// the explanatory note already recorded above.
		te := topEffect(engine.ModeDirect)
		raw = append(raw, te)
		ders = append(ders, derive(te, []engine.Atom{commandAtom(callName(c), c.Pos)}, "code.exec"))
		r.Conservative = true
		r.Resolution = Resolution{Kind: ResolveUnknown, Name: c.Name, Invoked: callName(c)}
	} else {
		res := b.resolve(c)
		r.Resolution = res.res
		if res.command != nil && declaresWrapperPayload(res.command) {
			// A privilege wrapper the frontend did not peel (a path-qualified
			// `/usr/bin/sudo …`, a package-runner operand naming one): the
			// wrapped command reached the binder only as the entry's payload
			// positional, so its own effects — filesystem, network,
			// credentials — are beyond binding. Degrade to ⊤ like an unknown
			// command (the soundness this spelling had before wrapper
			// elevation existed) instead of the entry's limited PrivEsc-only
			// report, which would turn an unanalysable payload into a
			// confident, narrow effect set. The note names the payload entry
			// and the spelling it was reached through — a runner operand or a
			// path is not itself the privilege wrapper.
			te := topEffect(engine.ModeDirect)
			raw = append(raw, te)
			ders = append(ders, derive(te, []engine.Atom{commandAtom(callName(c), c.Pos)}, "code.exec"))
			r.Conservative = true
			if res.command.Name == callName(c) {
				r.Notes = append(r.Notes, quote(res.command.Name)+": wrapped command not analyzable; assuming ⊤ (CodeExec)")
			} else {
				r.Notes = append(r.Notes, quote(res.command.Name)+" resolved behind "+quote(callName(c))+": wrapped command not analyzable; assuming ⊤ (CodeExec)")
			}
		} else if res.command != nil {
			eff, ds, ms, unknown, posModelled, opFlagEffect, _ := b.bindCommand(res.command, res.args, c.StdinTaint, c.Pos)
			// Finding 65: the intrinsic "it ran" effect keys on whether the
			// command's operation slot was modelled, not on the effect count.
			// An invocation whose subcommand matched nothing contributes no
			// operation effect (git branch -D, make, an unmodelled subcommand),
			// even when a read-only option added an unrelated read — that read
			// must not certify the operation as modelled. A flag-only entry
			// (reboot/poweroff/halt/shutdown, date/id/sync) has no operation
			// slot at all and keeps the empty-effect condition.
			fallback := len(eff) == 0 || (!posModelled && !opFlagEffect && declaresOperationSlot(res.command))
			if fallback {
				// Emitting nothing would fail open to an empty, benign result,
				// so contribute the command's intrinsic "it ran" effect
				// (ProcSpawn over the command's own scope).
				e := intrinsicProcSpawn(res.command.Name, c.Pos)
				eff = append(eff, e)
				ds = append(ds, derive(e, []engine.Atom{commandAtom(callName(c), c.Pos)}, "proc.spawn"))
			}
			raw = append(raw, eff...)
			ders = append(ders, ds...)
			r.Destructive = destructiveEntries(b.k, res.command.Name, ms, resolvedValuePredicates(res.command, res.args))
			if len(unknown) > 0 {
				r.Notes = append(r.Notes, "unrecognized flag(s): "+strings.Join(dedup(unknown), " "))
			}
		} else {
			switch res.res.Kind {
			case ResolveFunction:
				te := topEffect(engine.ModeTransitive)
				raw = append(raw, te)
				ders = append(ders, derive(te, []engine.Atom{commandAtom(callName(c), c.Pos)}, "code.exec"))
				r.Conservative = true
				r.Notes = append(r.Notes, "shell function body is opaque to command binding")
			default: // alias that did not resolve to a command, or unknown
				te := topEffect(engine.ModeDirect)
				raw = append(raw, te)
				ders = append(ders, derive(te, []engine.Atom{commandAtom(callName(c), c.Pos)}, "code.exec"))
				r.Conservative = true
				r.Notes = append(r.Notes, "unresolved command "+quote(callName(c))+": assuming ⊤ (CodeExec)")
			}
		}
	}

	r.Effects = taintEgress(raw, c.StdinTaint)
	r.Derivations = ders
	normalizeResult(r)
	return r
}

// BindBash binds one normalized bash command, using prog for the declared
// functions and aliases.
func (b *Binder) BindBash(cmd *bash.Command, prog *bash.Program) *Result {
	return b.Bind(FromBash(cmd, prog))
}

// ===========================================================================
// Flag / operand binding
// ===========================================================================

// match is a flag or option that matched a declared parameter.
type match struct {
	param  kb.Param
	value  Arg
	hasVal bool
	// pos is the source position of the flag/option token that matched, for the
	// why-trace atom that cites it.
	pos engine.SourceLoc
}

// bindCommand parses argv against cmd's declared parameters and emits the
// effect each matched parameter contributes. It returns the effects, the
// derivations, the specs that matched (for the destructive table), any
// unrecognized flag names, whether the command's operation slot was modelled
// (the condition the intrinsic ProcSpawn fallback keys on, Finding 65), and
// whether a token could not be bound faithfully (⊤, Finding 34).
func (b *Binder) bindCommand(cmd *kb.Command, argv []Arg, stdinTaint engine.Taint, callLoc engine.SourceLoc) ([]engine.Effect, []engine.Derivation, []string, []string, bool, bool, bool) {
	if cmd == nil {
		return nil, nil, nil, nil, false, false, false
	}
	operands, matches, unknown, degrade := parseArgs(cmd, argv)

	// Finding 85: a single-file compressor that streams its result to standard
	// output (or only inspects the file) performs no in-place rewrite, so the
	// write the row attaches to its mode and tuning flags (-d, -z, -f, -9, -b)
	// is not an effect of this invocation. Dropping those matches here — before
	// they are lowered — keeps `gzip -9c FILE` a read plus a stream instead of
	// a fabricated write, and lets the operation's own write be synthesised
	// below for the spellings that really do rewrite the file.
	if isSingleFileCompressor(cmd) && compressorStreams(matches) {
		matches = dropInPlaceWrites(matches)
	}

	var out []engine.Effect
	var ders []engine.Derivation
	var specs []string

	cmdAtom := commandAtom(cmd.Name, callLoc)
	file := callLoc.File

	// posModelled records that a positional/subcommand/assign parameter
	// produced an effect, and opFlagEffect that a *flag* carrying the
	// invocation's operation (valueFrom: args — java -version, ls -l) did. The
	// intrinsic ProcSpawn fallback keys on both (Finding 65): a read-only option
	// whose value is its own operand (git -C DIR, make -C DIR, -f FILE) does not
	// model the operation, while a flag that *is* the operation does.
	var posModelled, opFlagEffect bool

	// Assignment operands (dd of=FILE, if=FILE): a key=value operand whose key
	// matches a declared assign parameter. The frontend keeps the literal key of
	// a partly-dynamic word (`of=$X` expands to the text "of=" with a dynamic
	// tail), so a known key with an unknown value binds the parameter over ⊤
	// rather than being dropped (Finding 42): the write certainly happens, only
	// its target is unbound.
	var rest []Arg
	assigns := cmd.AssignParams()
	for _, op := range operands {
		done := false
		if op.Value != "" {
			for _, p := range assigns {
				if strings.HasPrefix(op.Value, p.Spec) {
					val := Arg{
						Value:   op.Value[len(p.Spec):],
						Literal: op.Literal,
						Dir:     op.Dir,
						Taint:   op.Taint,
						Pos:     withFile(op.Pos, file),
					}
					group := []Arg{val}
					effs, ds := lowerParam(cmd, p, val, scopeForGroup(group, p.Effect.Kind), argsTaint(group), stdinTaint, []engine.Atom{cmdAtom, operandAtom(op.Value, withFile(op.Pos, file))}, false, "")
					out = append(out, effs...)
					ders = append(ders, ds...)
					specs = append(specs, p.Spec)
					if len(effs) > 0 {
						posModelled = true
					}
					done = true
					break
				}
			}
		}
		if !done {
			rest = append(rest, op)
		}
	}

	// Finding 84: tar's POSIX old-style option bundle (`tar cf ARCHIVE SRC…`)
	// names the operation and its operands in the first word. When it is
	// present, the bundle — not the row's index-order positional fallback —
	// binds the operands below, so a bundle the row does not declare by name
	// (`rf`, `zcf`, `xvzf`, `tf`) cannot be distributed over unrelated
	// positional specs and fabricate effects for the wrong words.
	tarBundle := false
	tarOp := rune(0)
	if op, ok := tarOldStyleOp(cmd, rest); ok {
		tarBundle, tarOp = true, op
	}

	// Flags and options matched by name; their effect target defaults to the
	// operand set for valueFrom=args.
	operandScope, operandTaint := argsScope(rest, false), argsTaint(rest)

	// Finding 28: an ssh_config file's PermitLocalCommand only *enables* the
	// LocalCommand path; when the same line already supplies the command, the
	// command (not the enabling directive) is the subject of the spawn.
	sshExecNamed := false
	for _, m := range matches {
		if isOpenSSH(cmd) && m.param.Spec == "-o" && m.hasVal && m.value.Literal {
			if text, ok := sshDirectiveExec(m.value.Value); ok && text != "" {
				sshExecNamed = true
			}
		}
	}
	for _, m := range matches {
		mv := m.value
		mv.Pos = withFile(mv.Pos, file)
		atoms := []engine.Atom{cmdAtom, flagAtom(m.param.Spec, withFile(m.pos, file))}
		if m.hasVal && mv.Value != "" {
			atoms = append(atoms, operandAtom(mv.Value, mv.Pos))
		}
		// Finding 28: a `-o` value the analysis cannot read statically may hide
		// an exec-bearing directive (`ssh -o "$OPT" host` with
		// OPT=ProxyCommand=…), so the option degrades to ⊤ CodeExec instead of
		// the bounded egress a benign value would keep. The invocation is
		// certainly able to run a local command; only the host operand's egress
		// remains, which is what `ssh host` reports.
		if isOpenSSH(cmd) && m.param.Spec == "-o" && m.hasVal && !mv.Literal {
			te := topEffect(engine.ModeDirect)
			out = append(out, te)
			ders = append(ders, derive(te, atoms, "code.exec"))
			specs = append(specs, m.param.Spec)
			continue
		}
		// Finding 28: ssh_config's exec-bearing directives. `-o ProxyCommand=…`,
		// `-o LocalCommand=…` and `-o KnownHostsCommand=…` carry a shell command
		// line the client runs locally, so the option is a code-execution sink,
		// not an egress destination; PermitLocalCommand enables the same path.
		// Every other directive keeps its declared treatment.
		if isOpenSSH(cmd) && m.param.Spec == "-o" && m.hasVal && mv.Literal {
			if text, ok := sshDirectiveExec(mv.Value); ok && (text != "" || !sshExecNamed) {
				e := execTextEffect(text, mv)
				out = append(out, e)
				ders = append(ders, derive(e, withSink(atoms, e), "code.exec"))
				specs = append(specs, m.param.Spec)
				continue
			}
		}
		// Finding 66: in create mode `tar -C DIR` is the base directory whose
		// contents are archived, so the option reads DIR recursively. The row's
		// declared FSWrite is the extract-mode meaning of the same option and
		// stays in force there.
		if m.hasVal {
			if e, ok := tarCreateBaseDirRead(cmd, m.param.Spec, mv, tarCreates(cmd, matches, rest)); ok {
				out = append(out, e)
				ders = append(ders, derive(e, atoms, "fs.read"))
				specs = append(specs, m.param.Spec)
				continue
			}
		}
		// Finding 44: a parameter whose value is a file of options. What the
		// invocation does is written in that file, which the analysis cannot
		// read (no runtime I/O) and, for the stdin spellings, belongs to another
		// command: the net effect is unknown, so the result widens to ⊤ rather
		// than asserting a bounded read of the file's own path.
		// Finding 95: the same holds for a file of the tool's own *command
		// language* — psql -f runs the script's `\!` meta-commands, sqlite3
		// -init its dot-commands, gdb -x its `shell` commands — so the script
		// spelling of a capability the row declares inline (`-c`, `-ex`, `-cmd`)
		// is unknown here while the inline text stays bounded.
		if isOptionFile(cmd, m.param.Spec) || isLanguageFile(cmd, m.param.Spec) {
			te := topEffect(engine.ModeDirect)
			out = append(out, te)
			ders = append(ders, derive(te, atoms, "code.exec"))
			// Finding 95: the tool reads the script file, and that read is a
			// fact of the invocation. A row that declares the script parameter
			// as CodeExec (`sqlite3 -init`, `gdb -x`) loses it when the ⊤
			// subsumes the bounded effect, and a row that declares the read
			// (`psql -f`) keeps it; emitting it here makes all three report the
			// same shape. Standard input (`-`) names no file.
			if isLanguageFile(cmd, m.param.Spec) && m.hasVal && mv.Literal && mv.Value != "" && mv.Value != "-" {
				e, d := uploadSourceRead(mv, atoms)
				out = append(out, e)
				ders = append(ders, d)
			}
		}
		scope := operandScope
		switch m.param.Effect.Kind {
		case engine.KindNetEgress:
			scope = argsScope(rest, true)
		case engine.KindFSMeta:
			scope = metaScope(rest)
		}
		// Finding 71: an upload whose local payload is an option value
		// (`az storage blob upload -f FILE`) reads that file.
		if m.hasVal && mv.Literal && uploadSourceFlagSpecs(cmd, rest)[m.param.Spec] {
			e, d := uploadSourceRead(mv, atoms)
			out = append(out, e)
			ders = append(ders, d)
		}
		effs, ds := lowerParam(cmd, m.param, mv, scope, operandTaint, stdinTaint, atoms, false, "")
		if len(effs) > 0 && m.param.Effect.ValueFrom == kb.ValueArgs {
			opFlagEffect = true
		}
		out = append(out, effs...)
		ders = append(ders, ds...)
		specs = append(specs, m.param.Spec)
		// Finding 29: `git -c key=value` also *runs* the value when the key is
		// one git interprets as a command (core.pager, core.sshCommand, an
		// alias, a diff/filter driver, include.path). The assignment stays an
		// EnvWrite — it is one — and the executed program is the CodeExec the
		// report was missing.
		if text, ok := gitConfigExecKey(cmd, m.param.Spec, mv); ok {
			e := codeTextEffect(text)
			out = append(out, e)
			ders = append(ders, derive(e, withSink(atoms, e), "code.exec"))
		}
	}

	// Positional operands. A leading literal operand that names a declared
	// positional parameter is matched by value first (the KB models CLI
	// subcommands this way: 7z l ARCHIVE, git clone|clean, systemctl start|stop,
	// nft list|flush); the remaining positional parameters fall back to index
	// order for generic operands (SRC/DEST/FILE).
	ps := positionalParams(cmd)
	// Finding 27, spelling parity: an option can already have filled a
	// positional slot. GNU sed takes its script from `-e SCRIPT` / `-f FILE`,
	// and every operand is then an input file; binding the first operand to the
	// SCRIPT positional described a credential path as script text (Stdio) and
	// lost its FSRead, so `sed -e 'p' /etc/shadow | curl -d @- …` formed no
	// exfiltration pair while its non-`-e` twin was Critical.
	ps = dropOptionFilledPositionals(cmd, ps, matches)
	idxBySpec := make(map[string]int, len(ps))
	for i, p := range ps {
		idxBySpec[p.Spec] = i
	}
	// When the leading operand matched a declared positional BY VALUE, that
	// parameter already consumed the rest of the operands as its group; binding
	// those operands again to the OTHER positional parameters by index would
	// fabricate effects (7z l ARCHIVE → bogus FSWrite{ARCHIVE}, git clean PATH →
	// bogus NetEgress{PATH}). So the index-order fallback is skipped whenever a
	// value match occurred: the value-matched parameter is the whole positional
	// binding.
	valueMatched := false
	var targetBound bool
	if len(rest) > 0 && rest[0].Literal {
		if pi, ok := idxBySpec[rest[0].Value]; ok {
			p := ps[pi]
			group := rest[1:]
			// Finding 84: in tar's old-style create bundle the word the `f`
			// letter names is the archive being written, not a member being
			// read, so it is not part of the operands the bundle's read covers.
			if sources, ok := tarCreateSourceGroup(cmd, rest); ok {
				group = sources
			}
			// Finding 25: socat's EXEC:/SYSTEM: address types run a program;
			// they are not destinations and must not be lowered as one.
			group, execs := splitAddressGroup(cmd, p, group)
			out = append(out, addressExecEffects(execs)...)
			ders = append(ders, addressExecDerivations(execs, cmdAtom)...)
			atoms := []engine.Atom{cmdAtom}
			for _, g := range group {
				atoms = append(atoms, operandAtom(g.Value, withFile(g.Pos, file)))
			}
			// Finding 14: a subcommand's declared network effect survives even
			// when its remote is a name the host grammar rejects (`origin`,
			// `requests`); a local path still names no destination.
			var subName string
			if paramDeclaresEgress(p) {
				subName = firstRemoteOperand(group)
			}
			effs, ds := lowerParam(cmd, p, Arg{}, scopeForGroup(group, p.Effect.Kind), argsTaint(group), stdinTaint, atoms, true, subName)
			out = append(out, effs...)
			ders = append(ders, ds...)
			specs = append(specs, p.Spec)
			valueMatched = true
			if p.Spec == "TARGET" && len(group) > 0 {
				targetBound = true
			}
			if len(effs) > 0 {
				posModelled = true
			}
			// Finding 52: `kubectl get|describe secret…` and `helm get
			// values|all` print credential material to stdout, so the
			// subcommand is a CredAccess — the secret source the exfiltration
			// detector needs before it can pair the upload.
			if e, ok := secretSubcommandRead(cmd, p, group); ok {
				out = append(out, e)
				ders = append(ders, derive(e, withSink(atoms, e), "cred.access"))
				posModelled = true
			}
			// Finding 18: the verb of `ip <object> <verb> …` is the second
			// operand of the phrase, which the value match never reaches.
			if verb, vgroup, ok := ipVerbParam(cmd, p, group); ok {
				vatoms := []engine.Atom{cmdAtom, operandAtom(group[0].Value, withFile(group[0].Pos, file))}
				for _, g := range vgroup {
					vatoms = append(vatoms, operandAtom(g.Value, withFile(g.Pos, file)))
				}
				veffs, vds := lowerParam(cmd, verb, Arg{}, argsScope(vgroup, false), argsTaint(vgroup), stdinTaint, vatoms, false, "")
				out = append(out, veffs...)
				ders = append(ders, vds...)
				specs = append(specs, verb.Spec)
				if len(veffs) > 0 {
					posModelled = true
				}
			}
		}
	}
	if !valueMatched && !tarBundle {
		for i, p := range ps {
			var group []Arg
			switch {
			case i == len(ps)-1:
				if i < len(rest) {
					group = rest[i:]
				}
			case i < len(rest):
				group = rest[i : i+1]
			}
			if len(group) == 0 {
				continue
			}
			group, execs := splitAddressGroup(cmd, p, group)
			out = append(out, addressExecEffects(execs)...)
			ders = append(ders, addressExecDerivations(execs, cmdAtom)...)
			atoms := []engine.Atom{cmdAtom}
			for _, g := range group {
				atoms = append(atoms, operandAtom(g.Value, withFile(g.Pos, file)))
			}
			effs, ds := lowerParam(cmd, p, Arg{}, scopeForGroup(group, p.Effect.Kind), argsTaint(group), stdinTaint, atoms, false, "")
			out = append(out, effs...)
			ders = append(ders, ds...)
			specs = append(specs, p.Spec)
			if p.Spec == "TARGET" {
				targetBound = true
			}
			if len(effs) > 0 {
				posModelled = true
			}
		}
	}

	// Intrinsic parameters (kind: self): an effect the command contributes by the
	// mere fact of being invoked, with no token on the command line to match. It
	// is lowered unconditionally — regardless of what else matched — so a
	// power-control command keeps its ProcSpawn even when a flag matched
	// (reboot -f, shutdown -h now), and its effect no longer depends on the
	// empty-match fallback in Bind.
	for _, p := range cmd.Params {
		if p.Kind != kb.ParamSelf {
			continue
		}
		effs, ds := lowerParam(cmd, p, Arg{}, engine.ScopeBottom(), engine.TaintBottom(), stdinTaint, []engine.Atom{cmdAtom}, false, "")
		out = append(out, effs...)
		ders = append(ders, ds...)
		specs = append(specs, p.Spec)
	}

	// Finding 27: GNU sed's script language. `w FILE` writes (and truncates)
	// FILE, `r FILE` reads it and `e CMD` (or `s///e`) runs CMD — none of which
	// the row's SCRIPT/Stdio declaration models. A script the analysis cannot
	// see (-f FILE) degrades to ⊤, exactly like another interpreter's script.
	if isSedCommand(cmd) {
		effs, ds, sedDegrade := sedEffects(cmd, rest, matches, cmdAtom, file)
		out = append(out, effs...)
		ders = append(ders, ds...)
		if sedDegrade {
			te := topEffect(engine.ModeDirect)
			out = append(out, te)
			ders = append(ders, derive(te, []engine.Atom{cmdAtom}, "code.exec"))
		}
	}

	// Finding 100: `chmod` MODE that sets the SUID/SGID bit — privilege
	// escalation spelled as a permission change. The KB's MODE parameter can
	// only carry FSMeta (an effect belongs to a parameter, not to its value), so
	// the mode is decided here; `install -m 4755` has always reported the same
	// escalation, and `chmod 4755` did not.
	if isChmodCommand(cmd) {
		if e, d, ok := chmodEscalates(matches, rest, cmdAtom, file); ok {
			out = append(out, e)
			ders = append(ders, d)
		}
	}

	// Finding 100, install spelling: `install -m 4755 SRC DEST` installs a
	// set-user-ID program, exactly as the `chmod 4755 DEST` twin does. The KB's
	// `-m` parameter declares the metadata change; the escalation is decided
	// from the literal mode here and asserted over the files install writes.
	if isInstallCommand(cmd) {
		if e, d, ok := installEscalates(matches, rest, cmdAtom, file); ok {
			out = append(out, e)
			ders = append(ders, d)
		}
	}

	// Finding 11: `patch` rewrites the files named in the diff's headers. When
	// no TARGET operand names them, the write is certain but its target comes
	// from data, so it is reported over ⊤ — never dropped, and never narrowed to
	// a bounded read of the patch file.
	if isPatchCommand(cmd) && !targetBound && patchApplies(specs) && !hasFlagSpec(specs, "--dry-run") {
		e := topWrite()
		out = append(out, e)
		ders = append(ders, derive(e, []engine.Atom{cmdAtom, operandAtom("patch", callLoc)}, "fs.write"))
	}

	// Finding 7, whole-environment spelling: `printenv`, `export -p`,
	// `declare -p` and bare `set` print every variable the environment holds.
	// The row declares no target for the bare form (there is no operand), so
	// the invocation used to contribute only its intrinsic ProcSpawn and an
	// upload of the dump paired with nothing. The read is emitted here, over no
	// named variable, and carries the secret label the exfiltration detector
	// needs.
	if e, d, ok := wholeEnvironmentRead(cmd, rest, matches, cmdAtom); ok {
		out = append(out, e)
		ders = append(ders, d)
		posModelled = true
	}

	// Finding 34: a token that could not be bound faithfully (an ambiguous
	// long-option abbreviation) leaves the invocation's effects unknown, so the
	// result widens to ⊤ rather than silently binding nothing or the wrong
	// declared option.
	if degrade {
		te := topEffect(engine.ModeDirect)
		out = append(out, te)
		ders = append(ders, derive(te, []engine.Atom{cmdAtom}, "code.exec"))
	}

	// Finding 96: a response file (`gcc @args.rsp`, `ld @args`, `javac @args`)
	// supplies *options*, not an operand: the tool replaces the word before it
	// runs. What the invocation does is written in that file — including the
	// options that run or load a program (-wrapper, -fplugin=, --plugin) and the
	// ones that relocate an output (-specs=, -o) — and the analysis cannot read
	// it, so the effect set is unknown and the result widens to ⊤ instead of
	// claiming the bounded write the SRC positional declares. The file itself is
	// read by the tool, so its read is reported beside the ⊤.
	if paths, ok := responseFileOperands(cmd, rest); ok {
		for _, p := range paths {
			atoms := []engine.Atom{cmdAtom, operandAtom("@"+p.Value, withFile(p.Pos, file))}
			e, d := uploadSourceRead(p, atoms)
			out = append(out, e)
			ders = append(ders, d)
		}
		te := topEffect(engine.ModeDirect)
		out = append(out, te)
		ders = append(ders, derive(te, []engine.Atom{cmdAtom}, "code.exec"))
	}

	// Finding 71: a remote-upload client's local payload operand is a read.
	// Without it the credential-exfiltration detector has no secret source and
	// the upload is certified as egress-only. A code-host client may name
	// several payloads in one invocation (`gh release upload TAG A B`), and
	// each is read.
	if idxs, ok := uploadSourceIndices(cmd, rest); ok {
		for _, idx := range idxs {
			if idx < 0 || idx >= len(rest) {
				continue
			}
			src := rest[idx]
			e, d := uploadSourceRead(src, []engine.Atom{cmdAtom, operandAtom(src.Value, withFile(src.Pos, file))})
			out = append(out, e)
			ders = append(ders, d)
		}
		// `kubectl cp SRC DEST` streams the source to the pod: the destination
		// is a network sink, not a local file (its path lives inside the
		// container, so the address itself is unresolved).
		if cmd.Name == "kubectl" && len(idxs) > 0 && idxs[0]+1 < len(rest) {
			dst := rest[idxs[0]+1]
			we := engine.Effect{Kind: engine.KindNetEgress, Target: engine.ScopeTop(), Mode: engine.ModeDirect, Certainty: engine.CertaintyCertain, Taint: engine.TaintBottom(), Reversible: true}
			out = append(out, we)
			ders = append(ders, derive(we, []engine.Atom{cmdAtom, operandAtom(dst.Value, withFile(dst.Pos, file))}, "net.egress"))
		}
	}

	// A wget invocation that names concrete URL operands writes each fetched
	// body to a local file by default — named after the URL's last path segment
	// (plus its query string, as wget does), inside the -P/--directory-prefix
	// directory when one is given: an ingest of downloaded content. The KB
	// models only the URL positional's egress, so the implicit file output is
	// synthesised here, one sink per URL operand.
	//
	// The sink is named from the URL *operand* and never from the first
	// concrete egress in effect order: an option value that is itself an
	// egress target (wget --user-agent Foo) names no local file. The synthesis
	// is suppressed when an output parameter already named the destination
	// (-O/--output-document), when the invocation writes no body at all
	// (--spider, --delete-after), and for a dynamic (⊤) destination — its local
	// file name is unknown, so there is no ingest sink to point at.
	if isImplicitDownload(cmd) && !matchesAnySpec(specs, downloadOutputSpecs[cmd.Name]) &&
		!matchesAnySpec(specs, downloadNoOutputSpecs[cmd.Name]) {
		urls := downloadURLs(rest, lenientHostDialect(cmd))
		prefix, prefixKnown := downloadPrefix(cmd, matches)
		for _, url := range urls {
			// The -P directory, when present and statically known, relocates
			// the write; an unresolved prefix leaves the written path unknown
			// (⊤), never a fabricated concrete file.
			var target engine.Scope
			if !prefixKnown {
				target = engine.ScopeTop()
			} else {
				name := downloadFileName(url)
				if prefix != "" {
					name = strings.TrimRight(prefix, "/") + "/" + name
				}
				target = engine.ScopeOf(name)
			}
			e := engine.Effect{
				Kind:       engine.KindFSWrite,
				Target:     target,
				Mode:       engine.ModeDirect,
				Certainty:  engine.CertaintyCertain,
				Taint:      engine.TaintBottom(),
				Reversible: false,
				NetFlow:    engine.FlowIngest,
			}
			out = append(out, e)
			ders = append(ders, derive(e, []engine.Atom{cmdAtom, {Kind: engine.AtomSink, Text: "NetIngest"}}, "fs.write", "net.ingest"))
		}
		if len(urls) > 0 {
			specs = append(specs, "URL")
		}
	}

	// Finding 85: the single-file compressors' default operation rewrites each
	// named FILE operand in place. The row declares the operand a read (it is
	// always read), so the write half is synthesised here — unless the
	// invocation streams the result to stdout, only inspects the file, or names
	// its output explicitly (zstd -o). Without it `gzip FILE` reported a read
	// and no write; with it declared on the operand instead, `gzip -c FILE`
	// fabricated a write and lost the read that carries the credential.
	if effs, ds := compressorOperationWrite(cmd, matches, rest, cmdAtom, file); len(effs) > 0 {
		out = append(out, effs...)
		ders = append(ders, ds...)
		posModelled = true
	}

	// Finding 84: tar's POSIX old-style option bundle (`tar cf ARCHIVE SRC…`)
	// names the operation in its first operand. The row declares that operand a
	// read, so the archive a create/append/update spelling writes was missing
	// from the report entirely — including the remote (UNC) archive, whose
	// write is what turns the copy into a tainted egress. Add the write half.
	if tarBundle {
		if effs, ds := tarBundleEffects(cmd, rest, valueMatched, tarNamesArchive(matches), cmdAtom, file); len(effs) > 0 {
			out = append(out, effs...)
			ders = append(ders, ds...)
			posModelled = true
		}
		// A bundle the row does not declare by name (`xvzf`, `xtf`) still
		// extracts, so it carries the destructive class the declared `x`/`xf`
		// specs carry: the class lookup is keyed on specs, and the index-order
		// fallback that used to supply them is suppressed for a bundle.
		if tarOp == 'x' {
			specs = append(specs, "x")
		}
	}
	// The dashed spelling of the same operations: `-c`/`-r`/`-u` name the
	// operation and its sources, and the archive is the `-f`/`--file` value —
	// which the row already writes, or the default device when no -f is given.
	if !tarBundle {
		if op, ok := tarWriteOperation(cmd, matches, rest); ok {
			if effs, ds := tarOperationWrite(cmd, rest, op, tarNamesArchive(matches), cmdAtom, file); len(effs) > 0 {
				out = append(out, effs...)
				ders = append(ders, ds...)
				posModelled = true
			}
		}
	}

	return out, ders, specs, unknown, posModelled, opFlagEffect, degrade
}

// parseArgs splits argv into positional operands, matched flags/options, and
// unrecognized flag names. degrade reports that a token could not be bound
// faithfully (a long-option abbreviation that is ambiguous between declared
// specs), so the caller widens the result to ⊤ instead of guessing.
func parseArgs(cmd *kb.Command, argv []Arg) ([]Arg, []match, []string, bool) {
	var (
		operands []Arg
		matches  []match
		unknown  []string
		degrade  bool
	)
	noMore := false

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !a.Literal {
			// A dynamic word: conservatively an operand with an unknown value.
			operands = append(operands, a)
			continue
		}
		v := a.Value
		switch {
		case noMore:
			operands = append(operands, a)

		case v == "--":
			noMore = true

		case v == "-":
			operands = append(operands, a)

		case strings.HasPrefix(v, "--"):
			name, val, hasVal := v, "", false
			if k := strings.IndexByte(v, '='); k >= 0 {
				name, val, hasVal = v[:k], v[k+1:], true
			}
			p, ok := cmd.Param(name)
			if !ok {
				// Finding 34: getopt_long/argp resolve an unambiguous prefix of
				// a long option, so `tar --to-com=…` names --to-command and
				// `xz --decompres` names --decompress. Matching the name
				// literally dropped the declared effect; an *ambiguous* prefix
				// is not decidable, so the invocation degrades to ⊤ instead of
				// silently binding nothing (or the wrong option).
				pp, found, ambiguous := longOptionPrefix(cmd, name)
				switch {
				case ambiguous:
					degrade = true
					unknown = append(unknown, name)
					continue
				case found:
					p = pp
				default:
					unknown = append(unknown, name)
					continue
				}
			}
			if p.Kind == kb.ParamOption {
				switch {
				case hasVal:
					matches = append(matches, match{param: p, value: Arg{Value: val, Literal: true, Pos: shiftCol(a.Pos, len(name)+1)}, hasVal: true, pos: a.Pos})
				case i+1 < len(argv):
					matches = append(matches, match{param: p, value: argv[i+1], hasVal: true, pos: a.Pos})
					i++
				default:
					matches = append(matches, match{param: p, pos: a.Pos})
				}
			} else if hasVal {
				// A declared non-option flag written as --flag=value: keep the
				// attached value rather than silently discarding it.
				matches = append(matches, match{param: p, value: Arg{Value: val, Literal: true, Pos: shiftCol(a.Pos, len(name)+1)}, hasVal: true, pos: a.Pos})
			} else {
				matches = append(matches, match{param: p, pos: a.Pos})
			}

		case len(v) >= 2 && v[0] == '-':
			// A single-dash token is first tried whole (find -delete, tar -C,
			// curl -o): a DECLARED parameter always wins, so a numeric flag
			// (gzip -9, comm -1, join -1, printenv -0, ssh -4, ping -6,
			// xargs -0) is never mistaken for an operand and its effect is not
			// dropped. Only when the token is not declared is a signed number
			// (kill -9 -1, tail -1) taken as an operand; every other undeclared
			// token is split into a cluster of short flags (-rf → -r, -f).
			if p, ok := cmd.Param(v); ok {
				if p.Kind == kb.ParamOption {
					if i+1 < len(argv) {
						matches = append(matches, match{param: p, value: argv[i+1], hasVal: true, pos: a.Pos})
						i++
					} else {
						matches = append(matches, match{param: p, pos: a.Pos})
					}
				} else {
					matches = append(matches, match{param: p, pos: a.Pos})
				}
				continue
			}
			if isSignedNumber(v) {
				operands = append(operands, a)
				continue
			}
			// Finding 31: a multi-character short option written with an
			// attached value (`java -agentlib:jdwp=…`, `-agentpath:/x.so`) is
			// the tool's documented grammar. Match the longest declared spec
			// that prefixes the token when it continues with ':' or '=', and
			// bind the remainder as the option's value, before the one-letter
			// cluster splitter can cut the token into fabricated flags.
			if p, val, ok := attachedShortOption(cmd, v); ok {
				matches = append(matches, match{param: p, value: Arg{Value: val, Literal: true, Pos: shiftCol(a.Pos, len(p.Spec)+1)}, hasVal: true, pos: a.Pos})
				continue
			}
			cluster := v[1:]
			// A token that carries a ':' or '=' is an attached-value spelling,
			// not a bundle of one-letter switches: only a declared option in
			// the first position may bind it (and it takes the rest as its
			// value). Without this guard the `p` in `agentpath` or the `m`
			// inside `/tmp` fired an unrelated one-letter option and stole the
			// token tail as its operand (Finding 31b).
			limit := len(cluster)
			if k := strings.IndexAny(cluster, ":="); k > 0 {
				limit = 1
			}
			consumed := false
			// Dedupe by spec so a long cluster token (-rrrr…) contributes one
			// match per distinct flag, not one per byte: this bounds the memory
			// a single token can allocate (ADR-0006) without changing the
			// effects of a repeated flag.
			seenSpec := make(map[string]bool, len(cluster))
			unknownSeen := make(map[string]bool, len(cluster))
			for j := 0; j < limit; j++ {
				spec := "-" + string(cluster[j])
				if seenSpec[spec] {
					continue
				}
				p, ok := cmd.Param(spec)
				if !ok {
					if !unknownSeen[spec] {
						unknownSeen[spec] = true
						unknown = append(unknown, spec)
					}
					continue
				}
				seenSpec[spec] = true
				if p.Kind == kb.ParamOption {
					switch val := cluster[j+1:]; {
					case val != "":
						matches = append(matches, match{param: p, value: Arg{Value: val, Literal: true, Pos: shiftCol(a.Pos, j+2)}, hasVal: true, pos: shiftCol(a.Pos, j+1)})
					case i+1 < len(argv):
						matches = append(matches, match{param: p, value: argv[i+1], hasVal: true, pos: shiftCol(a.Pos, j+1)})
						consumed = true
					default:
						matches = append(matches, match{param: p, pos: shiftCol(a.Pos, j+1)})
					}
					break
				}
				matches = append(matches, match{param: p, pos: shiftCol(a.Pos, j+1)})
			}
			if consumed {
				i++
			}

		default:
			operands = append(operands, a)
		}
	}
	return operands, matches, unknown, degrade
}

// ===========================================================================
// Wrapper elevation (refined -u)
// ===========================================================================

// rootUser is the user `sudo` elevates to by default, and the user a literal
// `root` -u value names.
const rootUser = "root"

// sudoName is the wrapper whose inert-line semantics wrapperElevation models:
// the only privilege wrapper in the knowledge base today.
const sudoName = "sudo"

// userTargetClass classifies a literal -u/--user value the way sudo spells
// targets: `root` names root; `#N` names the numeric UID N (32-bit; the
// reserved -1 spelling `#4294967295` is sudo-invalid, as is any value beyond
// the range); a bare digit string
// is compared by its numeric value too, so `0` and `00` name root exactly like
// `#0` does (sudo itself spells a UID with the `#` prefix and would read a bare
// `0` as a username, but claiming root for it is the safe over-report —
// documented by the elevation matrix test); any other value is a username. The
// direction asymmetry is intentional: a #-spelling carries sudo's rejection in
// its syntax, so no direction is claimed; a bare word is syntactically a valid
// username whose existence the analysis cannot check, so the de-elevation claim
// reads the text as written — and if the user does not exist, sudo runs
// nothing and the claim still holds. A whitespace-only value can still pass
// here (the inert-note path); an empty one or the "@" placeholder is
// intercepted upstream.
type userTargetClass int

const (
	targetRoot userTargetClass = iota
	targetNumericNonRoot
	targetName
	// targetMalformedSpec is a #-prefixed value that is not a valid numeric
	// UID (`#`, `#-1`, `#abc`): sudo rejects it, so no direction is claimed.
	targetMalformedSpec
)

// classifyUserTarget classifies a literal -u/--user value into a
// userTargetClass; the doctrine — what each class claims and why — lives on
// the type.
func classifyUserTarget(v string) userTargetClass {
	if strings.TrimSpace(v) == "" || strings.TrimSpace(v) != v || strings.HasPrefix(v, "+") {
		// Whitespace-padded, whitespace-only, or a leading `+`: sudo rejects
		// these, so no direction is claimed.
		return targetMalformedSpec
	}
	if v == "@" {
		// The frontend's placeholder for a dynamic option value: never a
		// user name, no direction claimed.
		return targetMalformedSpec
	}
	spec := strings.TrimPrefix(v, "#")
	digits := spec != ""
	for i := 0; i < len(spec); i++ {
		if spec[i] < '0' || spec[i] > '9' {
			digits = false
			break
		}
	}
	if !digits {
		if strings.HasPrefix(v, "#") {
			return targetMalformedSpec
		}
		// User-name lookup is case-insensitive on some systems (macOS local
		// accounts, AD/LDAP backends), so any case spelling of root claims
		// root: correct where the lookup folds case, the safe over-report
		// where the name does not exist.
		if strings.EqualFold(v, rootUser) {
			return targetRoot
		}
		return targetName
	}
	// Linux UIDs are 32-bit and 4294967295 (uid_t's -1) is reserved — the
	// CVE-2019-14287 spelling. A #-spelling naming it is sudo-invalid, so no
	// direction is claimed; a bare spelling stays a username.
	u, err := strconv.ParseUint(spec, 10, 32)
	if err != nil {
		if strings.HasPrefix(v, "#") {
			return targetMalformedSpec
		}
		return targetName
	}
	if u == 0 {
		return targetRoot
	}
	if strings.HasPrefix(v, "#") && u == 1<<32-1 {
		return targetMalformedSpec
	}
	return targetNumericNonRoot
}

// declaresPrivEsc reports whether a knowledge-base command declares any
// PrivEsc parameter — the predicate that makes the binder treat a peeled-off
// wrapper as an elevation to refine by its own command line, rather than
// transparent plumbing.
func declaresPrivEsc(cmd *kb.Command) bool {
	if cmd == nil {
		return false
	}
	for _, p := range cmd.Params {
		if p.Effect.Kind == engine.KindPrivEsc {
			return true
		}
	}
	return false
}

// declaresWrapperPayload reports whether a knowledge-base command models its
// payload — the WRAPPED command line — as a Direct privilege-escalation
// COMMAND positional (sudo's COMMAND): a call resolved onto such an entry
// without the frontend peeling the wrapper (a path-qualified `/usr/bin/sudo …`)
// has handed the whole wrapped argv to that slot, so nothing beyond it is
// bindable and the call degrades to ⊤. Entries whose PrivEsc declarations name
// their own operands instead (yarn's `global` positional, `install -m`, su's
// USER, chroot's NEWROOT — and the COMMAND positionals of chroot/runuser,
// which are ProcSpawn) do not match: those argv stay fully bindable.
func declaresWrapperPayload(cmd *kb.Command) bool {
	if cmd == nil {
		return false
	}
	for _, p := range cmd.Params {
		if p.Kind == kb.ParamPositional && p.Spec == "COMMAND" &&
			p.Effect.Kind == engine.KindPrivEsc && p.Effect.Mode == engine.ModeDirect {
			return true
		}
	}
	return false
}

// wrapperElevation binds a PrivEsc-declaring wrapper's own command line (its
// option words against the wrapper's knowledge-base entry) and lowers it by the
// refined -u doctrine. The doctrine models sudo — today the only KB entry
// whose COMMAND positional is PrivEsc/Direct (pinned by the grammar-layer
// test); a future privilege wrapper (doas, pkexec) with different semantics
// must split it consciously:
//
//   - no -u/--user at all, or a literal value naming root (`root`, and the
//     numeric spellings `0`, `00`, `#0`): the escalation is certain (Direct)
//     and targets root;
//   - a literal value naming any other valid target (a username, or a numeric
//     UID other than 0): the wrapped command runs unprivileged — no elevation
//     fires, and a note says why;
//   - a value that is missing, not statically known, option-shaped (the glued
//     token of an unsatisfied -u: `sudo -u $U -g root`), or a #-spelling sudo
//     would reject (`#abc`): the escalation stays certain but its target user
//     is unresolved — Direct over ⊤, with a note where the value lied;
//   - more than one -u/--user (`sudo -u a -u b`): sudo documents value-taking
//     options as single-use and does not spell out the behavior on violation,
//     so the doctrine resolves nothing: the escalation stays certain over a
//     ⊤ target and a note reports the ambiguity.
//
// A line that names nothing to execute never elevates: the `-l` list form
// runs nothing even with a command word following, and any inert flag-only
// form (`sudo -v`, `-k`, `-K`, `-h`, `-V`, `--version` — nothing inside the
// wrapper and no shell-implying `-i`/`-s`) decides nothing. innerPresent is
// that answer for this wrapper's own position, decided by the caller: the
// command word and the wrappers deeper in the chain are what it would exec
// (`sudo env FOO=1` runs env as root), a wrapper above it (`env sudo -k`)
// is not — it execs the privileged wrapper, not the other way round. No
// elevation and no
// de-elevation of an inner run is claimed for them; a named -u target is
// still reported for completeness. In that case the elevation reports inert:
// the caller must not bind the words that follow, or it would fabricate
// effects for a process that never starts; the ⊤ degradation (the frontend's
// for a consumed command line, the caller's own otherwise) already covers
// their report.
//
// `-g`/`--group` never decides nor elevates: by man sudo a bare `-g` runs the
// command as the invoking user with only the primary group replaced, and with
// `-u` present the target user decides. Group escalation is not modelled — a
// matched `-g` value contributes a note saying so.
//
// Sound: the escalation's certainty follows sudo's own -u semantics (it never
// softens), and a ⊤ target is a target question, not unknown code execution,
// so Result.Conservative is never touched. The derivation cites the wrapper's
// own name, the -u token and its value — all at the wrapper's position — so
// the why-trace names the concrete premise. Unrecognized wrapper flags surface
// as a note, never silently. When the elevation does not fire, no atoms are
// returned: the caller ignores them, and an unexplained non-nil set would be
// a contract smell.
// dropStillRunsNotes removes the -k "the command still runs" notes a wrapper
// appends per its own option list, before the chain-wide inert decision is
// known (see Bind). The suffix is the note's own contract; only the -k note
// ever asserts that the line runs.
func dropStillRunsNotes(notes []string) []string {
	kept := notes[:0]
	for _, n := range notes {
		if strings.HasSuffix(n, "the command still runs") {
			continue
		}
		kept = append(kept, n)
	}
	return kept
}

func wrapperElevation(cmd *kb.Command, w Wrapper, file string, innerPresent bool) (e engine.Effect, atoms []engine.Atom, fires bool, notes []string, inert bool) {
	// Unwrap records a value-taking option and its absorbed value as adjacent
	// words; parseArgs re-pairs a MODELLED option with its absorbed value.
	// An UNMODELLED value-taking option's absorbed word is blanked to "@"
	// instead — it is data, never a free-standing flag, whether or not it
	// spells a knowledge-base spec (`sudo -p -l cmd` — -p takes -l as its
	// prompt — really runs cmd as root; a value-constrained option like -C
	// instead makes sudo usage-error and run nothing — the parse-level
	// decision is identical either way). (A value that was not statically
	// known was never recorded; the blanking then hits the next recorded
	// word — the over-approximation only affects that spelling, in the safe
	// over-report direction.)
	var opts []Arg
	valueNext := false
	ownerUnmodelled := false
	ownerSpec := ""
	// hostNamed records that a -h/--host spelling carried a host value (the
	// separate-value form the walk below absorbs): `sudo -h host` names a
	// remote host, unlike a bare `-h`, which only prints help. The binder
	// re-walks the recorded option words itself (the frontend's pairing is not
	// on the seam), so it is the only place that can tell the two apart.
	hostNamed := false
	for _, o := range w.Options {
		if valueNext {
			valueNext = false
			if ownerUnmodelled {
				if ownerSpec == "-h" || ownerSpec == "--host" {
					hostNamed = true
				}
				opts = append(opts, Arg{Value: "@", Literal: true})
				// The absorbed word was data, never a free-standing flag —
				// name the consumption, whatever the word was (`sudo -C -l
				// cmd` consumes -l as -C's value; `sudo -C -u nobody cmd`
				// consumes -u).
				notes = append(notes, w.Name+": "+ownerSpec+" consumed the following word as its value; nothing about it decides this line")
				// -D/--chdir and -R/--chroot relocate the path context the
				// wrapped command's operands resolve in; the model does not
				// carry it, so the report says so instead of staying silent.
				switch ownerSpec {
				case "-D", "--chdir":
					notes = append(notes, w.Name+": -D/--chdir changes the working directory; operand paths resolve under it (path context not modelled)")
				case "-R", "--chroot":
					notes = append(notes, w.Name+": -R/--chroot changes the root directory; operand paths change meaning (path context not modelled)")
				}
			} else {
				opts = append(opts, o)
			}
			continue
		}
		opts = append(opts, o)
		if o.Literal && bash.SudoValueOpts(o.Value) {
			valueNext = true
			_, known := cmd.Param(o.Value)
			ownerUnmodelled = !known
			ownerSpec = o.Value
		}
	}
	_, matches, unknown, _ := parseArgs(cmd, opts)
	// The print-and-exit and usage-error spellings are unknown to the
	// knowledge base by design (pinned by kb's inert-spellings test): they
	// must not surface as "unrecognized flag(s)" — sudo recognizes every one
	// of them, and the inert note below names them accurately. -k is equally
	// recognized, but unlike -v/-K it runs the command, so it only gets its
	// own explanatory note. The inert semantics collected here are sudo's own;
	// if a second privilege wrapper ever joins the knowledge base, key this
	// table on the wrapper's name rather than sharing it.
	var inertUnknown []string
	rest := make([]string, 0, len(unknown))
	if w.Name == sudoName {
		for _, spec := range unknown {
			switch spec {
			case "--version", "-V", "--help", "-h", "--host", "-v", "-K", "-k", "-U", "--other-user":
				inertUnknown = append(inertUnknown, spec)
			default:
				rest = append(rest, spec)
			}
		}
	} else {
		rest = append(rest, unknown...)
	}
	if len(rest) > 0 {
		// The wrapper surface reports the knowledge base's modelling, not
		// sudo's own flag table: an unmodelled flag is not one sudo rejects.
		notes = append(notes, w.Name+": flags not modelled by the knowledge base: "+strings.Join(dedup(rest), " "))
	}

	loc := withFile(w.Pos, file)
	atoms = []engine.Atom{commandAtom(w.Name, loc)}

	var (
		user      *match
		userCount int
		group     *match
		shellFlag bool
		listOnly  bool
		listSpec  string
		printExit string
		usageErr  string
	)
	for i := range matches {
		m := &matches[i]
		if m.param.Effect.Kind != engine.KindPrivEsc {
			continue
		}
		switch m.param.Spec {
		case "-u", "--user":
			if user == nil {
				user = m
			}
			userCount++
		case "-g", "--group":
			group = m
		case "-i", "-s":
			shellFlag = true
		case "-l", "--list":
			listOnly = true
			listSpec = m.param.Spec
		}
	}
	// Spellings sudo documents as running nothing, but which the knowledge
	// base does not model as parameters, end the inert-line decision too:
	//   - --version/-V/--help print and exit, with or without a command word;
	//   - -h names a remote host, which sudo only accepts when listing
	//     privileges, so a line carrying it either lists or usage-errors;
	//   - -v only validates credentials and -K cannot be combined with a
	//     command — with a command word the line usage-errors.
	// With a command word present, none of them executes anything. (-k runs
	// the command; only its note below differs from the plain unknown flags.)
	for _, spec := range inertUnknown {
		// Among the unmodelled inert spellings the first in argument order
		// decides the line; later ones yield (every outcome is the same
		// inert ⊤ — only the note's attribution follows the deciding
		// spelling). A modelled `-l`/`--list` decides over all of them,
		// whatever its position.
		switch spec {
		case "--version", "-V", "--help":
			if !listOnly {
				listOnly = true
				printExit = spec
			}
		case "-h", "--host", "-U", "--other-user":
			// -h is help or a remote host; --host/-U/--other-user are only
			// valid in conjunction with -l. The sudoers policy runs no
			// remote commands, so none of them executes a command. Only a
			// bare -h (no absorbed host value and no command word) is the
			// help reading; a host-naming spelling is never.
			if !listOnly {
				listOnly = true
				switch {
				case spec == "-h" && !hostNamed && !innerPresent:
					usageErr = "-h prints help and exits"
				case spec == "-h":
					usageErr = "-h prints help or names a remote host; the sudoers policy runs no remote commands"
				case spec == "--host":
					usageErr = "--host names a remote host; only valid in conjunction with -l; the sudoers policy runs no remote commands"
				default:
					usageErr = spec + " is only valid in conjunction with -l"
				}
			}
		case "-v", "-K":
			if !listOnly {
				listOnly = true
				switch {
				case innerPresent:
					usageErr = spec + " runs no command in combination with a command word"
				case spec == "-v":
					usageErr = "-v refreshes cached credentials and runs no command"
				default:
					usageErr = "-K invalidates every cached credential and runs no command"
				}
			}
		}
		if listOnly {
			break
		}
	}
	for _, spec := range inertUnknown {
		// -k's "still runs" note is only truthful when the line is not
		// decided inert by another spelling; on a listing line the inert
		// note stands alone. It must also agree with the inert-line guard
		// below: a shell-implying -i/-s keeps the line alive (sudo runs a
		// root shell), so -k beside it resets credentials and executes
		// anyway — never the "runs no command" a shell-flag-blind reading
		// would claim beside the elevation the line still carries.
		if spec == "-k" && !listOnly {
			if innerPresent || shellFlag {
				notes = append(notes, w.Name+": -k resets cached credentials; the command still runs")
			} else {
				// The line is inert (the guard below cannot but take the
				// early return), so this note stands beside the ⊤ verdict
				// and qualifies it like its inert siblings.
				notes = append(notes, w.Name+": -k invalidates cached credentials and runs no command; nothing is executed — the report degrades to ⊤ (CodeExec)")
			}
			break
		}
	}
	// A matched -g/--group replaces the primary group "in either case" (man
	// sudo) — with a literal, dynamic or skipped value alike — so the
	// unmodelled membership gain is named whenever the option is present.
	groupNote := group != nil

	if listOnly {
		switch {
		case printExit != "":
			notes = append(notes, w.Name+": "+printExit+" prints help/version, or usage-errors with a command word; nothing is executed — the report degrades to ⊤ (CodeExec)")
		case usageErr != "":
			notes = append(notes, w.Name+": "+usageErr+"; nothing is executed — the report degrades to ⊤ (CodeExec)")
		default:
			notes = append(notes, w.Name+": "+listSpec+" only lists permissions; nothing is executed — the report degrades to ⊤ (CodeExec)")
		}
		return engine.Effect{}, nil, false, notes, true
	}
	if !innerPresent && !shellFlag {
		// Nothing on this line runs under sudo (the inert flag-only forms).
		// A -u target is still named — real sudo usage-errors on the missing
		// command, so the note stays accurate — but no elevation and no
		// de-elevation of any inner run is claimed.
		if userCount > 1 {
			notes = append(notes, w.Name+": multiple -u/--user options; target user unresolved")
		}
		if userCount == 1 && user != nil && !user.hasVal {
			// A trailing bare `-u`/`--user` with no following word: real sudo
			// usage-errors on the missing argument — name it like the other
			// sudo-rejected spellings below.
			notes = append(notes, w.Name+": -u/--user requires a value; nothing runs on this line")
		}
		// A literal value is named whatever its content — including the
		// statically-empty one (`-u ''`, `--user=`), which sudo rejects:
		// staying silent for it would leave the one user-bearing spelling
		// with no user note on an inert line (classifyUserTarget reads the
		// empty value as a malformed specification).
		if userCount == 1 && user != nil && user.hasVal && user.value.Literal {
			if user.value.Value == "@" {
				// The frontend's placeholder for a dynamic value — never
				// script text; keep it out of the user-facing note.
				notes = append(notes, w.Name+": target user is not statically known; nothing runs on this line")
			} else if strings.HasPrefix(user.value.Value, "-") {
				// An option-shaped "value" is a token sudo reads as a flag,
				// never a user name — the glue after an unsatisfied -u, or a
				// literal sudo rejects; same doctrine as the elevation branch.
				notes = append(notes, w.Name+": target user "+quote(user.value.Value)+" is not a valid user specification; nothing runs on this line")
			} else {
				switch classifyUserTarget(user.value.Value) {
				case targetRoot:
					notes = append(notes, w.Name+": target user "+quote(user.value.Value)+" is root; nothing runs on this line")
				case targetMalformedSpec:
					notes = append(notes, w.Name+": target user "+quote(user.value.Value)+" is not a valid user specification; nothing runs on this line")
				default:
					notes = append(notes, w.Name+": target user "+quote(user.value.Value)+" is not root; nothing runs on this line")
				}
			}
		}
		return engine.Effect{}, nil, false, notes, true
	}

	target := engine.ScopeOf(rootUser)
	switch {
	case userCount > 1:
		atoms = append(atoms, flagAtom(user.param.Spec, loc))
		target = engine.ScopeTop()
		notes = append(notes, w.Name+": multiple -u/--user options; target user unresolved")
	case user != nil:
		atoms = append(atoms, flagAtom(user.param.Spec, loc))
		v := user.value
		switch {
		case !user.hasVal || !v.Literal || v.Value == "@":
			// The value was not statically known — or it is the frontend's
			// "@" placeholder for a dynamic value, which is never script
			// text: the escalation is certain, its target user unknown (⊤).
			target = engine.ScopeTop()
		case v.Value == "":
			// A statically-empty target: sudo rejects it — say so, like the
			// other sudo-rejected spellings.
			target = engine.ScopeTop()
			notes = append(notes, w.Name+": target user "+quote(v.Value)+" is not a valid user specification; assuming a privileged target")
		case strings.HasPrefix(v.Value, "-"):
			// An option-shaped "value" is a token sudo reads as a flag, not a
			// user name — either the glue after an unsatisfied -u (`sudo -u
			// $U -g root`) or a literal sudo rejects (`sudo -u -1`). Never
			// trusted as a user name.
			target = engine.ScopeTop()
			gp, isSpec := cmd.Param(v.Value)
			switch {
			case isSpec && (gp.Spec == "-u" || gp.Spec == "--user"):
				// A glued repeat (`sudo -u $U -u root`): the same ambiguity
				// as the separated spelling.
				notes = append(notes, w.Name+": multiple -u/--user options; target user unresolved")
			case isSpec && (gp.Spec == "-g" || gp.Spec == "--group"):
				// The token is a group spec in sudo's grammar, but on this
				// line it was glued to the unsatisfied -u — whether as that
				// option's value or as part of the spelling, the target user
				// is unresolved either way.
				notes = append(notes, w.Name+": the glued -u absorbed the following -g as its value; target user unresolved (group escalation is not modelled)")
			case isSpec:
				notes = append(notes, w.Name+": the glued -u absorbed the following option as its value; target user unresolved")
			default:
				notes = append(notes, w.Name+": target user "+quote(v.Value)+" is not a valid user specification; assuming a privileged target")
			}
		default:
			switch classifyUserTarget(v.Value) {
			case targetRoot:
				atoms = append(atoms, operandAtom(v.Value, loc))
			case targetNumericNonRoot, targetName:
				// A literal target that is not root: no elevation at all.
				notes = append(notes, w.Name+": target user "+quote(v.Value)+" is not root; no privilege escalation")
				if groupNote {
					notes = append(notes, w.Name+": -g sets only the primary group (group escalation is not modelled)")
				}
				return engine.Effect{}, nil, false, notes, false
			case targetMalformedSpec:
				target = engine.ScopeTop()
				notes = append(notes, w.Name+": target user "+quote(v.Value)+" is not a valid user specification; assuming a privileged target")
			}
		}
	case group != nil:
		// A bare -g/--group (no -u): by man sudo the command runs as the
		// INVOKING user with only the primary group replaced — no escalation.
		notes = append(notes, w.Name+": -g without -u runs the command as the invoking user; no privilege escalation (group escalation is not modelled)")
		return engine.Effect{}, nil, false, notes, false
	}
	if groupNote {
		notes = append(notes, w.Name+": -g sets only the primary group (group escalation is not modelled)")
	}

	e = engine.Effect{
		Kind:       engine.KindPrivEsc,
		Target:     target,
		Mode:       engine.ModeDirect,
		Certainty:  certaintyOf(engine.ModeDirect),
		Taint:      engine.TaintBottom(),
		Reversible: kb.DefaultReversible(engine.KindPrivEsc),
	}
	return e, atoms, true, notes, false
}

// lowerParam lowers one matched parameter into the effects it contributes. Most
// parameters contribute exactly one effect. A parameter marked fileRef whose
// value uses the @file convention additionally contributes the filesystem read
// of the named file — or, for `@-`, no read at all, because the content comes
// from standard input — and carries the payload's provenance into its own
// effect, so that a data-carrying flag becomes a tainted egress.
// lowerParam lowers one matched parameter into the effects it contributes: the
// declared primary effect plus every secondary effect the row lists in `also`.
// A single token frequently carries two independent effects (a package
// manager's install reaches a registry and rewrites the local store; a VCS
// update fetches and rewrites the working copy), and a row that declares only
// one of them makes every deny rule keyed on the other admit the operation.
// Each secondary is lowered by exactly the same path as a primary effect of its
// kind, so the egress-target gate, the taint join and the target vocabulary
// cannot drift between the two declarations; an entry that lowers to nothing
// contributes nothing, and one that duplicates an effect already present is
// dropped rather than reported twice.
func lowerParam(cmd *kb.Command, p kb.Param, value Arg, argScope engine.Scope, argTaint, stdinTaint engine.Taint, atoms []engine.Atom, subcommand bool, subName string) ([]engine.Effect, []engine.Derivation) {
	effs, ders := lowerParamPrimary(cmd, p, value, argScope, argTaint, stdinTaint, atoms, subcommand, subName)
	if len(p.Also) == 0 {
		return effs, ders
	}
	seen := make(map[string]bool, len(effs))
	for _, e := range effs {
		seen[e.Key()] = true
	}
	for _, also := range p.Also {
		secondary := p
		secondary.Effect = also
		secondary.Also = nil
		more, moreDers := lowerParamPrimary(cmd, secondary, value, argScope, argTaint, stdinTaint, atoms, subcommand, subName)
		for i, e := range more {
			// A secondary egress that names no destination is not a network
			// event: the row's primary effect already reports the operation
			// (`npm install` with no operand writes the local store and
			// contacts no registry). Only an egress with a target — a named
			// remote, a package name, or an unresolved (top) destination —
			// contributes the network half.
			if e.Kind == engine.KindNetEgress && !namesRemote(e.Target) {
				continue
			}
			k := e.Key()
			if seen[k] {
				continue
			}
			seen[k] = true
			effs = append(effs, e)
			ders = append(ders, moreDers[i])
		}
	}
	return effs, ders
}

func lowerParamPrimary(cmd *kb.Command, p kb.Param, value Arg, argScope engine.Scope, argTaint, stdinTaint engine.Taint, atoms []engine.Atom, subcommand bool, subName string) ([]engine.Effect, []engine.Derivation) {
	cert := certaintyOf(p.Effect.Mode)
	target := targetFor(cmd, p, value, argScope)
	taint := taintFor(p, value, argTaint, stdinTaint)
	path, fromStdin, fileRef := fileRefPathFor(p.Spec, value)

	// Finding 92: the value is data xargs substituted from its input items, so
	// no path is known. A parameter that reads a file therefore reads an
	// unknown path, and the read is secret-bearing by construction — the input
	// may name any file, exactly as an environment read whose variable name is
	// not statically known may select any credential. Reporting the read keeps
	// it in the dataflow: without it, `echo /etc/shadow | xargs -I{} curl -d @{} …`
	// bound the payload to a file literally called "{}" and formed no
	// exfiltration pair while carrying the file out.
	if value.FromXargs && (p.Effect.FileRef || p.Effect.Kind == engine.KindFSRead) {
		re := engine.Effect{
			Kind:       engine.KindFSRead,
			Target:     engine.ScopeTop(),
			Mode:       engine.ModeDirect,
			Certainty:  cert,
			Taint:      engine.TaintOf(engine.TaintSecret),
			Reversible: kb.DefaultReversible(engine.KindFSRead),
		}
		out := []engine.Effect{re}
		ders := []engine.Derivation{derive(re, atoms, ruleForKind(engine.KindFSRead), "cred.path")}
		if p.Effect.FileRef && p.Effect.Kind != engine.KindFSRead {
			// The payload reference is not a destination: the declared effect
			// keeps the payload's provenance but not the file spec as its
			// target, as in the literal path below.
			de := p.Effect.EngineEffect(engine.ScopeBottom(), engine.TaintOf(engine.TaintSecret), cert)
			out = append(out, de)
			ders = append(ders, derive(de, withSink(atoms, de), ruleForKind(de.Kind)))
		}
		return out, ders
	}

	// Egress target gate: a NetEgress effect may only carry a target that
	// passes the host/URL grammar. A literal operand that names no address (a
	// git subcommand, a SHA, a pathspec force-fit onto a network positional)
	// creates no egress effect at all; an unresolved (⊤) target passes through
	// as the unresolved egress and keeps participating in the network
	// controls. A declared network client (curl, wget, nc, ssh/scp, rsync and
	// the net-tools family) has destination positionals, so its bare
	// single-label host names are accepted; every other dialect must spell a
	// dotted name, an address or a URL. A fileRef parameter that actually uses
	// the @file convention is exempt: its declared effect carries the payload,
	// not a destination (⊥ target), and the destination is another
	// parameter's business.
	if p.Effect.Kind == engine.KindNetEgress && (!p.Effect.FileRef || !fileRef) {
		// Finding 3: a copy client's destination is remote only when it is
		// spelled as one. scp/rsync name a remote as `[user@]host:path` (or an
		// rsync URL); a destination without that colon is a local path the copy
		// writes, whatever the lenient host grammar makes of a bare name. An
		// unresolved (⊤) destination stays the egress it was — the analysis
		// cannot prove it local.
		if isCopyClientDest(cmd, p) && !copyDestIsRemote(target) {
			e := localCopyDestWrite(target, taint, cert)
			return []engine.Effect{e}, []engine.Derivation{derive(e, withSink(atoms, e), "fs.write")}
		}
		filtered, keep := engine.FilterEgressTargets(target, lenientHostDialect(cmd))
		switch {
		case keep:
			target = filtered
		case subcommand && subName != "":
			// Finding 14: the operand belongs to a subcommand the row declares
			// as a network operation (git push/fetch/clone, npm publish, pip
			// download). Its remote is a *name* (`origin`, `requests`), which
			// the host grammar cannot accept as an address, but the declared
			// egress is real: keep it, naming the remote. A local path is never
			// reported as a destination.
			target = engine.ScopeOf(subName)
		case isCopyClientDest(cmd, p):
			// Finding 3: a copy client's destination that is not host-shaped is
			// the local file the copy creates. The row declares DEST NetEgress
			// for the `host:path` upload spelling; the gate has just established
			// that this operand names no host, so dropping the parameter would
			// drop the write a local copy performs (parity with `cp DEST`).
			e := localCopyDestWrite(target, taint, cert)
			return []engine.Effect{e}, []engine.Derivation{derive(e, withSink(atoms, e), "fs.write")}
		default:
			return nil, nil
		}
	}

	if !p.Effect.FileRef || !fileRef {
		// A download client's output parameter writes no file when its value is
		// "-": that is standard output (curl -o -, wget -O -), so it contributes
		// the Stdio effect of the body going to stdout. An FSWrite would name a
		// file literally called "-", and an ingest sink pointing at it would be
		// a fabricated write target.
		if isDownloadOutput(cmd, p) && value.Value == "-" {
			e := engine.Effect{
				Kind:       engine.KindStdio,
				Target:     engine.ScopeBottom(),
				Mode:       p.Effect.Mode,
				Certainty:  cert,
				Taint:      taint,
				Reversible: kb.DefaultReversible(engine.KindStdio),
			}
			return []engine.Effect{e}, []engine.Derivation{derive(e, withSink(atoms, e), ruleForKind(engine.KindStdio))}
		}
		// Finding 84: tar's archive parameter written as `-` names standard
		// input/output, not a file called "-". `tar cf - SRC` (the old-style
		// bundle) and `tar -cf - SRC` are the same operation, so both must
		// report the stream and neither may fabricate a file named "-".
		if isTarArchiveDash(cmd, p) && value.Value == "-" {
			e := engine.Effect{
				Kind:       engine.KindStdio,
				Target:     engine.ScopeBottom(),
				Mode:       p.Effect.Mode,
				Certainty:  cert,
				Taint:      taint,
				Reversible: kb.DefaultReversible(engine.KindStdio),
			}
			return []engine.Effect{e}, []engine.Derivation{derive(e, withSink(atoms, e), ruleForKind(engine.KindStdio))}
		}
		// curl's -O names the local file after the URL, not after a flag value.
		target = downloadOutputTarget(cmd, p, target)
		e := p.Effect.EngineEffect(target, taint, cert)
		// Mark the download client's file-output parameter as the sink of a
		// network ingest flow, so the report can assert the flow rather than
		// leave it to be inferred from co-occurrence.
		if isDownloadOutput(cmd, p) {
			e.NetFlow = engine.FlowIngest
		}
		return []engine.Effect{e}, []engine.Derivation{derive(e, withSink(atoms, e), ruleForKind(e.Kind))}
	}

	var out []engine.Effect
	var ders []engine.Derivation
	payload := engine.TaintOf(engine.TaintFileSystem)
	cred := false
	switch {
	case fromStdin:
		payload = stdinTaint
	default:
		payload = payload.Join(value.Taint)
		srcAtoms := atoms
		srcRules := []string{ruleForKind(engine.KindFSRead)}
		if engine.SecretPath(path) {
			payload = payload.Join(engine.TaintOf(engine.TaintSecret))
			cred = true
			// Cite the file the payload is read from as a taint source, so the
			// credential read is justified by a concrete source atom.
			srcAtoms = append(append([]engine.Atom{}, atoms...), engine.Atom{Kind: engine.AtomSource, Text: "File", Loc: locPtr(value.Pos)})
			srcRules = append(srcRules, "cred.path")
		}
		re := engine.Effect{
			Kind:       engine.KindFSRead,
			Target:     engine.ScopeOf(path),
			Mode:       engine.ModeDirect,
			Certainty:  engine.CertaintyCertain,
			Taint:      payload,
			Reversible: true,
		}
		out = append(out, re)
		ders = append(ders, derive(re, srcAtoms, srcRules...))
	}

	// The value is a payload reference, not a destination: the declared effect
	// keeps the payload's provenance but not the file spec as its target.
	de := p.Effect.EngineEffect(engine.ScopeBottom(), taint.Join(payload), cert)
	rules := []string{ruleForKind(de.Kind)}
	if cred && de.Kind == engine.KindNetEgress {
		// The payload carried out is credential material: name the cred.exfil
		// rule so the egress cites why it is dangerous.
		rules = append(rules, "cred.path")
	}
	out = append(out, de)
	ders = append(ders, derive(de, withSink(atoms, de), rules...))
	return out, ders
}

// commandAtom, flagAtom, operandAtom and envVarAtom build the concrete source
// atoms a derivation cites: the invoked program, a matched flag/option, a
// positional/argument operand, and an environment variable name. Each carries
// the source position of the token it names (loc) so the why-trace reaches the
// exact line/column, when the frontend knows it.
func commandAtom(name string, loc engine.SourceLoc) engine.Atom {
	return engine.Atom{Kind: engine.AtomCommand, Text: name, Loc: locPtr(loc)}
}
func flagAtom(spec string, loc engine.SourceLoc) engine.Atom {
	return engine.Atom{Kind: engine.AtomFlag, Text: spec, Loc: locPtr(loc)}
}
func operandAtom(text string, loc engine.SourceLoc) engine.Atom {
	return engine.Atom{Kind: engine.AtomOperand, Text: text, Loc: locPtr(loc)}
}
func envVarAtom(name string, loc engine.SourceLoc) engine.Atom {
	return engine.Atom{Kind: engine.AtomLiteral, Text: name, Loc: locPtr(loc)}
}

// locPtr returns a pointer to loc when it carries information, and nil
// otherwise, so an unknown position is omitted from the JSON (omitempty) rather
// than serialised as an empty object.
func locPtr(loc engine.SourceLoc) *engine.SourceLoc {
	if loc == (engine.SourceLoc{}) {
		return nil
	}
	return &loc
}

// shiftCol moves a source location right by n columns on the same line. It pins
// the individual flags inside a cluster (-rf → -r, -f) and the value that
// follows an inline option (–opt=val), which all share one token's start.
func shiftCol(loc engine.SourceLoc, n int) engine.SourceLoc {
	loc.Col += n
	return loc
}

// withFile fills in the program/file name of a source location when it is not
// already known, so a token position recorded without a file still names its
// source in the why-trace.
func withFile(loc engine.SourceLoc, file string) engine.SourceLoc {
	if loc.File == "" {
		loc.File = file
	}
	return loc
}

// withSink appends the sink atom an egress effect must cite, so that a
// data-carrying outbound request is explained by the network sink it reaches.
func withSink(atoms []engine.Atom, e engine.Effect) []engine.Atom {
	if e.Kind != engine.KindNetEgress {
		return atoms
	}
	return append(append([]engine.Atom{}, atoms...), engine.Atom{Kind: engine.AtomSink, Text: "NetEgress"})
}

// derive packages one effect with the atoms and rules that justify it.
func derive(e engine.Effect, atoms []engine.Atom, rules ...string) engine.Derivation {
	return engine.Derivation{Effect: e, Atoms: atoms, Rules: rules}
}

// ruleForKind names the rule the binder fires for an effect kind; the names
// mirror the why-trace vocabulary (fs.read, fs.write, net.egress, cred.access…).
func ruleForKind(k engine.EffectKind) string {
	switch k {
	case engine.KindFSRead:
		return "fs.read"
	case engine.KindFSWrite:
		return "fs.write"
	case engine.KindFSMeta:
		return "fs.meta"
	case engine.KindEnvRead:
		return "env.read"
	case engine.KindEnvWrite:
		return "env.write"
	case engine.KindNetEgress:
		return "net.egress"
	case engine.KindNetIngress:
		return "net.ingress"
	case engine.KindProcSpawn:
		return "proc.spawn"
	case engine.KindProcSignal:
		return "proc.signal"
	case engine.KindIPC:
		return "ipc"
	case engine.KindStdio:
		return "stdio"
	case engine.KindPrivEsc:
		return "priv.escalate"
	case engine.KindPersist:
		return "persist"
	case engine.KindCredAccess:
		return "cred.access"
	case engine.KindCodeExec:
		return "code.exec"
	default:
		return "effect.derive"
	}
}

// taintFor computes the provenance of the data an effect acts on, from the
// parameter's value source and the tokens the invocation supplied.
func taintFor(p kb.Param, value Arg, argTaint, stdinTaint engine.Taint) engine.Taint {
	switch p.Effect.ValueFrom {
	case kb.ValueFlagValue, kb.ValueLiteral:
		return value.Taint
	case kb.ValueArgs:
		return argTaint
	case kb.ValueStdin:
		return stdinTaint
	default:
		return engine.TaintBottom()
	}
}

// argsTaint returns the join of the provenance of a group of operand words.
func argsTaint(g []Arg) engine.Taint {
	t := engine.TaintBottom()
	for _, a := range g {
		t = t.Join(a.Taint)
	}
	return t
}

// taintEgress carries the provenance of everything a single command reads (or
// is fed on standard input) into its egress effects. This is what makes an
// outbound request that ships data — an upload (-T), a form field (-F), a body
// read from a file or from a pipeline — a tainted egress, while leaving an
// egress that merely accompanies an unrelated read elsewhere in the script
// untainted: the join is per command, never per script.
func taintEgress(effs []engine.Effect, stdinTaint engine.Taint) []engine.Effect {
	payload := stdinTaint
	for _, e := range effs {
		switch e.Kind {
		case engine.KindFSRead:
			payload = payload.Join(e.Taint)
			for _, tg := range e.Target.Targets() {
				if engine.SecretPath(tg) {
					payload = payload.Join(engine.TaintOf(engine.TaintSecret))
				}
			}
		case engine.KindCredAccess:
			payload = payload.Join(e.Taint).Join(engine.TaintOf(engine.TaintSecret))
		}
	}
	if payload.IsBottom() {
		return effs
	}
	for i := range effs {
		if effs[i].Kind == engine.KindNetEgress {
			effs[i].Taint = effs[i].Taint.Join(payload)
		}
	}
	return effs
}

// lenientHostDialect reports whether cmd is a declared network client — a
// command whose HOST/URL positionals are destination slots by construction.
// For such a command a bare single-label host name (an intranet name: nc evil
// 4444, ssh bastion) is accepted as an egress target; every other dialect
// (VCS clients, package managers, …) must spell a dotted name, an address or a
// URL, because its operands are refs, pathspecs and subcommands first.
func lenientHostDialect(cmd *kb.Command) bool {
	if cmd == nil {
		return false
	}
	switch cmd.Dialect {
	case kb.DialectCurl, kb.DialectWget, kb.DialectNetcat,
		kb.DialectOpenSSH, kb.DialectNetTools, kb.DialectRsync,
		kb.DialectUtilLinux, // logger -n/--server: the flag value is the syslog server
		kb.DialectSystemd:   // systemctl -H/--host: the flag value declares a destination host
		return true
	}
	return false
}

// isDownloadClient reports whether cmd is a download client: a command that
// fetches a remote resource and writes it to a local file. VCS clients are
// deliberately excluded — a working-copy update (git clone/fetch/pull) is a
// sync, not an ingest of fetched content, so its FSWrite is never an ingest
// sink.
func isDownloadClient(cmd *kb.Command) bool {
	if cmd == nil {
		return false
	}
	switch cmd.Dialect {
	case kb.DialectCurl, kb.DialectWget:
		return true
	}
	return false
}

// isDownloadOutput reports whether p is the parameter of download client cmd
// that names the file a fetched body is written to, so the FSWrite effect it
// contributes is an ingest sink.
func isDownloadOutput(cmd *kb.Command, p kb.Param) bool {
	if !isDownloadClient(cmd) || p.Effect.Kind != engine.KindFSWrite {
		return false
	}
	return downloadOutputSpecs[cmd.Name][p.Spec]
}

// isImplicitDownload reports whether cmd is the download client whose implicit
// output file the binder synthesises: wget, which writes every fetched body to
// a file named after the URL unless told otherwise. curl has no implicit output
// (without -o/-O the body goes to standard output), so it is excluded.
func isImplicitDownload(cmd *kb.Command) bool {
	return cmd != nil && cmd.Dialect == kb.DialectWget
}

// downloadOutputSpecs names, per download client, the parameters whose value is
// the file the fetched body is written to (the ingest sink). curl's -o/-O write
// the response body; wget's -O/--output-document does. wget's -o is a log file
// and -P/--directory-prefix a directory, so neither is a download output — they
// stay plain FSWrite effects.
var downloadOutputSpecs = map[string]map[string]bool{
	"curl": {"-o": true, "-O": true},
	"wget": {"-O": true, "--output-document": true},
}

// downloadNoOutputSpecs names, per download client, the parameters that leave no
// downloaded body on disk, so the implicit sink must not be synthesised for
// them: wget --spider fetches the response headers only and writes nothing, and
// --delete-after removes the file it has just written. Neither command leaves
// downloaded content at a file path, so claiming an ingest sink would be a
// fabricated write target.
var downloadNoOutputSpecs = map[string]map[string]bool{
	"wget": {"--spider": true, "--delete-after": true},
}

// downloadPrefixSpecs names, per download client, the parameters whose value is
// the directory the fetched body is written into (wget -P/--directory-prefix).
var downloadPrefixSpecs = map[string]map[string]bool{
	"wget": {"-P": true, "--directory-prefix": true},
}

// matchesAnySpec reports whether any of the given parameter specs is in the set.
func matchesAnySpec(specs []string, set map[string]bool) bool {
	if len(set) == 0 {
		return false
	}
	for _, s := range specs {
		if set[s] {
			return true
		}
	}
	return false
}

// downloadPrefix returns the directory a download client was told to write into
// (wget -P/--directory-prefix) and whether that directory is statically known.
// No prefix matched yields ("", true): the write happens in the working
// directory. A matched prefix whose value is not a known literal yields
// ("", false): the resulting path cannot be named, so the caller degrades the
// synthesised target to ⊤ rather than inventing a directory.
func downloadPrefix(cmd *kb.Command, matches []match) (string, bool) {
	if cmd == nil {
		return "", true
	}
	set := downloadPrefixSpecs[cmd.Name]
	if len(set) == 0 {
		return "", true
	}
	for _, m := range matches {
		if !set[m.param.Spec] {
			continue
		}
		if m.hasVal && m.value.Literal && m.value.Value != "" {
			return m.value.Value, true
		}
		return "", false
	}
	return "", true
}

// downloadURLs returns the concrete URL operands of a download invocation, in
// operand order: the operands the egress gate accepts as a host/URL under the
// client's grammar tier. A dynamic operand is skipped — its local file name is
// unknown — while the other, concrete URLs keep their synthesised sinks.
func downloadURLs(g []Arg, lenient bool) []string {
	var out []string
	for _, a := range g {
		if !a.Literal || a.Value == "" {
			continue
		}
		if _, keep := engine.FilterEgressTargets(engine.ScopeOf(a.Value), lenient); keep {
			out = append(out, a.Value)
		}
	}
	return out
}

// downloadFileName names the local file a download client writes a fetched URL
// to by default: the URL's last path segment, with its query string, or
// "index.html" when the path names no file. This is wget's naming rule,
// verified against GNU Wget 1.25: `wget HOST/dir/file.tgz` writes `file.tgz`,
// `wget HOST/dir/file.tgz?a=1&b=2` keeps the query and writes
// `file.tgz?a=1&b=2`, `wget HOST/dir/` writes `index.html`, and a fragment is
// dropped because it is never sent to the server.
func downloadFileName(url string) string {
	p := url
	if i := strings.Index(p, "://"); i >= 0 {
		p = p[i+3:]
	}
	// The fragment is not sent to the server and never reaches the file name.
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	// The query string, however, is part of the local name wget creates.
	query := ""
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p, query = p[:i], p[i:]
	}
	// Drop the authority (host[:port]); what remains is the path.
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	} else {
		p = ""
	}
	// A path that names no file — empty, or a directory (a trailing '/') — is
	// saved as index.html, matching wget.
	if p == "" || strings.HasSuffix(p, "/") {
		return "index.html" + query
	}
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	return p + query
}

// downloadOutputTarget rewrites the target of a download-output parameter whose
// value is the remote URL rather than a local file name. curl's -O is
// "remote-name" mode: it writes the response body to a file named after the
// URL's last path segment, so its FSWrite target is that local file — reporting
// the URL itself would name something the command never writes. Every other
// output parameter (curl -o FILE, wget -O FILE/--output-document) already
// carries the local file name as its flag value.
func downloadOutputTarget(cmd *kb.Command, p kb.Param, s engine.Scope) engine.Scope {
	if cmd == nil || cmd.Dialect != kb.DialectCurl || p.Spec != "-O" {
		return s
	}
	if s.IsTop() || s.IsBottom() {
		return s
	}
	names := make([]string, 0, len(s.Targets()))
	for _, t := range s.Targets() {
		names = append(names, downloadFileName(t))
	}
	return engine.ScopeOf(names...)
}

// targetFor computes the target scope an effect applies to from its value
// source and the tokens the invocation supplied.
func targetFor(cmd *kb.Command, p kb.Param, value Arg, argScope engine.Scope) engine.Scope {
	switch p.Effect.ValueFrom {
	case kb.ValueArgs:
		return argScope
	case kb.ValueFlagValue, kb.ValueLiteral:
		if value.Literal && value.Value != "" {
			return engine.ScopeOf(value.Value)
		}
		return engine.ScopeTop()
	case kb.ValueSelf:
		if cmd != nil && cmd.Name != "" {
			return engine.ScopeOf(cmd.Name)
		}
		return engine.ScopeTop()
	case kb.ValueCwd:
		return engine.ScopeOf(".")
	case kb.ValueEnv:
		// The target comes from outside the command line — an environment
		// variable, or the endpoint a service client is configured with
		// (AWS_REGION/AWS_ENDPOINT_URL, KUBECONFIG, GH_HOST, PGHOST, …), which
		// is how the KB models a remote subcommand whose operand names the
		// operation and not an address. The analysis cannot pin it down: ⊤
		// (unknown), never ⊥ (no target) — the call does reach that endpoint.
		return engine.ScopeTop()
	default: // stdin
		return engine.ScopeBottom()
	}
}

// argsScope returns the target scope of a group of operand words: their literal
// values, or ⊤ as soon as one operand is neither statically known nor confined.
// A confined operand (Dir set: every dynamic part is numeric-class, so the
// expansion lands inside that directory) contributes its directory as a target
// — precise enough for containment checks and strictly sound, since no
// expansion can name a path outside it.
//
// egress marks the group as feeding a NetEgress destination: a confined operand
// is a filesystem abstraction (a directory), not a network address, so it makes
// the destination unresolved (⊤) rather than contributing the directory as a
// literal target the host grammar would reject and drop — the safe side
// (unresolved egress) is preserved, matching the pre-gate behaviour.
func argsScope(g []Arg, egress bool) engine.Scope {
	if len(g) == 0 {
		return engine.ScopeBottom()
	}
	vals := make([]string, 0, len(g))
	for _, a := range g {
		if !a.Literal {
			if a.Dir != "" {
				if egress {
					return engine.ScopeTop()
				}
				vals = append(vals, a.Dir)
				continue
			}
			return engine.ScopeTop()
		}
		if a.Value != "" {
			vals = append(vals, a.Value)
		}
	}
	return engine.ScopeOf(vals...)
}

// scopeForGroup returns the target scope an operand group contributes to an
// effect of kind k.
//
// For a metadata change (chmod/chown/attr and their Windows counterparts) a
// relative operand that the shell resolved to the filesystem root is resolved
// to the root: `cd / && chmod -R 777 .` touches the whole host exactly as
// `chmod -R 777 /` does, and the written "." used to be graded as one exact
// file — one full severity band below its absolute twin (Finding 70; the same
// differential Finding 50 records for root *spellings*). The resolution is
// one-sided (it can only widen a metadata change's extent, never narrow one)
// and lexical — nothing is read from the filesystem.
//
// A read keeps its written target: the credential-source resolution of a
// relative read is `credentialOperandReads`' job, and rewriting it here would
// fabricate an absolute path for every ordinary `cat readme.txt`.
func scopeForGroup(g []Arg, k engine.EffectKind) engine.Scope {
	switch k {
	case engine.KindNetEgress:
		return argsScope(g, true)
	case engine.KindFSMeta:
		return metaScope(g)
	default:
		return argsScope(g, false)
	}
}

// metaScope is argsScope for a metadata-change operand group: an operand the
// frontend marked as resolving to the filesystem root contributes "/" as its
// target instead of its written spelling.
func metaScope(g []Arg) engine.Scope {
	// Copy before rewriting: the caller's operand list is shared with the
	// other parameters matched on the same invocation.
	out := make([]Arg, len(g))
	copy(out, g)
	for i := range out {
		if out[i].Literal && out[i].Root {
			out[i].Value = "/"
		}
	}
	return argsScope(out, false)
}

// positionalParams returns cmd's positional parameters in declaration order.
func positionalParams(cmd *kb.Command) []kb.Param {
	if cmd == nil {
		return nil
	}
	var out []kb.Param
	for _, p := range cmd.Params {
		if p.Kind == kb.ParamPositional {
			out = append(out, p)
		}
	}
	return out
}

// ===========================================================================
// Effect constructors and folding
// ===========================================================================

// certaintyOf maps an effect mode onto the certainty the binder assigns when the
// corresponding parameter is present: a directly performed effect certainly
// occurs, a conditional one only possibly, a transitive/ambient one likely.
func certaintyOf(m engine.EffectMode) engine.Certainty {
	switch m {
	case engine.ModeConditional:
		return engine.CertaintyPossible
	case engine.ModeTransitive, engine.ModeAmbient:
		return engine.CertaintyLikely
	default:
		return engine.CertaintyCertain
	}
}

// envAssignEffects lowers the environment assignments a call carries: the write
// each one performs, plus the code-execution effect an exec-bearing one implies.
// The exec channel is not a rule the binder owns — a variable whose value the
// runtime executes (LD_PRELOAD, JAVA_TOOL_OPTIONS), an option channel
// (TAR_OPTIONS) and git's environment configuration family (GIT_CONFIG_*) are
// front/bash's ExecEnvVar, and lowering them here through bash.ExecEnvEffect is
// what keeps the binder's copy of the shell's assignment channels from drifting
// from the interpreter's: a policy that denies code execution must see a prefix
// assignment or an `env` operand handed to Bind directly, not only the same line
// through the interpreter.
func envAssignEffects(c *Call) ([]engine.Effect, []engine.Derivation) {
	var effs []engine.Effect
	var ders []engine.Derivation
	for _, a := range c.Env {
		ew := envWrite(a)
		effs = append(effs, ew)
		ders = append(ders, derive(ew, []engine.Atom{envVarAtom(a.Name, withFile(a.Pos, c.Pos.File))}, "env.write"))
		if ee, ok := bash.ExecEnvEffect(a.Name, a.Value.Value, a.Value.Literal, a.Value.Taint); ok {
			effs = append(effs, ee)
			ders = append(ders, derive(ee, []engine.Atom{envVarAtom(a.Name, withFile(a.Pos, c.Pos.File))}, "code.exec"))
		}
	}
	return effs, ders
}

// envWrite is the effect of an environment assignment.
func envWrite(a EnvAssign) engine.Effect {
	return engine.Effect{
		Kind:       engine.KindEnvWrite,
		Target:     engine.ScopeOf(a.Name),
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      a.Value.Taint,
		Reversible: false,
	}
}

// topEffect is the conservative ⊤ effect: code execution over the any-target
// scope. Executing arbitrary code can do anything, so this is the sound
// stand-in for "the effects are unknown".
func topEffect(mode engine.EffectMode) engine.Effect {
	return engine.Effect{
		Kind:       engine.KindCodeExec,
		Target:     engine.ScopeTop(),
		Mode:       mode,
		Certainty:  engine.CertaintyCertain,
		Taint:      engine.TaintBottom(),
		Reversible: false,
	}
}

// intrinsicProcSpawn is the "this command ran" effect emitted for a resolved
// command whose invocation matched no parameter contributing an effect, so the
// report can never fail open to an empty benign result.
func intrinsicProcSpawn(name string, loc engine.SourceLoc) engine.Effect {
	return engine.Effect{
		Kind:       engine.KindProcSpawn,
		Target:     engine.ScopeOf(name),
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      engine.TaintBottom(),
		Reversible: false,
	}
}

// destructiveEntries resolves the matched (command, spec) pairs against the
// knowledge base's destructive-flags table, de-duplicated and sorted. A row
// gated on a resolved operand value (`value: suid`) applies only when the
// invocation satisfied that predicate.
func destructiveEntries(k *kb.KB, command string, specs []string, satisfied map[kb.ValuePredicate]bool) []kb.Destructive {
	if k == nil {
		return nil
	}
	seen := make(map[string]bool, len(specs))
	var out []kb.Destructive
	for _, s := range specs {
		d, ok := k.DestructiveFor(command, s)
		if !ok {
			continue
		}
		if d.Value != kb.ValueAlways && !satisfied[d.Value] {
			continue
		}
		key := d.Command + "|" + d.Spec
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Command != out[j].Command {
			return out[i].Command < out[j].Command
		}
		return out[i].Spec < out[j].Spec
	})
	return out
}

// normalizeResult merges effects by (kind, mode), folds the destructiveness of
// the effects together with that of the matched destructive entries, and sorts
// everything into its canonical, deterministic order.
func normalizeResult(r *Result) {
	rep := engine.NewReport()
	rep.Effects = r.Effects
	rep.Normalize()
	r.Effects = rep.Effects

	// The ⊤ shape (CodeExec over the any-target scope) and the conservative
	// flag must agree: a result that carries a ⊤ effect is conservative even if
	// resolution itself succeeded (e.g. a bounded command whose parameter
	// widened its target to ⊤).
	for _, e := range r.Effects {
		if e.Kind == engine.KindCodeExec && e.Target.IsTop() {
			r.Conservative = true
			break
		}
	}

	d := rep.Destructiveness
	for _, e := range r.Destructive {
		d = d.Join(e.Class.Severity())
	}
	r.Destructiveness = d
	sort.Strings(r.Notes)
}

func conservativeResult(style Style, note string, mode engine.EffectMode) *Result {
	r := &Result{
		Style:        style,
		Resolution:   Resolution{Kind: ResolveUnknown},
		Effects:      []engine.Effect{topEffect(mode)},
		Conservative: true,
		Notes:        []string{note},
	}
	normalizeResult(r)
	// Cite the (unknown) command so the ⊤ effect still carries a concrete atom.
	r.Derivations = []engine.Derivation{derive(r.Effects[0], []engine.Atom{commandAtom("", engine.SourceLoc{})}, "code.exec")}
	return r
}

// ===========================================================================
// bash frontend bridge
// ===========================================================================

// FromBash lowers a normalized bash command into a Call. prog supplies the
// declared functions and aliases; it may be nil.
func FromBash(cmd *bash.Command, prog *bash.Program) *Call {
	if cmd == nil {
		return &Call{Style: StyleBash}
	}
	c := &Call{
		Style:       StyleBash,
		Name:        cmd.Name,
		NameOK:      cmd.Name != "",
		NamePresent: cmd.Name != "" || cmd.NameWord != nil,
		Pos:         engine.SourceLoc{Line: cmd.Pos.Line, Col: cmd.Pos.Col},
		StdinTaint:  cmd.StdinTaint,
	}
	if prog != nil {
		c.Pos.File = prog.File
	}
	for _, w := range cmd.Args {
		c.Args = append(c.Args, wordArg(w))
	}
	for _, a := range cmd.Assigns {
		if a == nil {
			continue
		}
		ea := EnvAssign{Name: a.Name, Via: a.Via,
			Pos: engine.SourceLoc{Line: a.Pos.Line, Col: a.Pos.Col}}
		// A normalized assignment carries no Value when it assigns nothing:
		// `VAR=` binds the empty string and `declare VAR` leaves the variable
		// unset. Both execute nothing, so the value is known-empty rather than
		// unknown — the distinction the exec channel keys on (a cleared
		// LD_PRELOAD must not read as an unresolvable one).
		ea.Value.Literal = true
		if a.Value != nil {
			ea.Value = Arg{Value: a.Value.Value, Literal: a.Value.Literal, Taint: a.Value.Taint,
				Pos: engine.SourceLoc{Line: a.Value.Pos.Line, Col: a.Value.Pos.Col}}
		}
		c.Env = append(c.Env, ea)
	}
	for _, w := range cmd.Wrappers {
		if w == nil {
			continue
		}
		bw := Wrapper{Name: w.Name,
			Pos: engine.SourceLoc{Line: w.Pos.Line, Col: w.Pos.Col}}
		// The normalizer records a wrapper's literal option words; a
		// non-literal option value is replaced by a "@" placeholder (the
		// option stays unsatisfied, and the binder's re-pairing can never
		// glue a following word as the value), and the peel continues with
		// the following words, so every recorded option lowers as a literal
		// argument word.
		for _, o := range w.Options {
			bw.Options = append(bw.Options, Arg{Value: o, Literal: true})
		}
		c.Wrappers = append(c.Wrappers, bw)
	}
	if prog != nil {
		if len(prog.Funcs) > 0 {
			c.Funcs = make(map[string]bool, len(prog.Funcs))
			for n := range prog.Funcs {
				c.Funcs[n] = true
			}
		}
		if len(prog.Aliases) > 0 {
			c.Aliases = make(map[string]string, len(prog.Aliases))
			for n, a := range prog.Aliases {
				if a != nil {
					c.Aliases[n] = a.Value
				}
			}
		}
	}
	return c
}

// wordArg converts a normalized word into an Arg, carrying the word's source
// position (line/column) so the atom a matched parameter emits can be pinned
// back to the token. The file is filled in later from the enclosing call.
func wordArg(w *bash.Word) Arg {
	if w == nil {
		return Arg{}
	}
	return Arg{Value: w.Value, Literal: w.Literal, Dir: w.Dir, Taint: w.Taint, Root: w.Root,
		FromXargs: w.FromXargs,
		Pos:       engine.SourceLoc{Line: w.Pos.Line, Col: w.Pos.Col}}
}

// ===========================================================================
// Small helpers
// ===========================================================================

func callName(c *Call) string {
	if c == nil || c.Name == "" {
		return "<dynamic>"
	}
	return c.Name
}

func firstEnvName(c *Call) string {
	for _, a := range c.Env {
		if a.Name != "" {
			return a.Name
		}
	}
	return ""
}

func quote(s string) string { return "\"" + s + "\"" }

// isSignedNumber reports whether s is a negative integer literal (e.g. "-1",
// "-9"): a legitimate operand (a PID, a count) rather than a flag cluster.
func isSignedNumber(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func dedup(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(xs))
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}
