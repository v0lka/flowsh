// Package bind turns a normalized command invocation into the set of effects it
// implies, by resolving the invoked name and binding its flags and operands
// against the effect knowledge base.
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
	// outermost first.
	Wrappers []string `json:"wrappers,omitempty"`

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
func (b *Binder) Bind(c *Call) *Result {
	if c == nil {
		return conservativeResult(StyleBash, "nil call", engine.ModeDirect)
	}
	r := &Result{Style: c.Style}
	var raw []engine.Effect
	var ders []engine.Derivation

	// Environment assignments (VAR=x cmd, env VAR=x cmd) mutate the environment.
	for _, a := range c.Env {
		ew := envWrite(a)
		raw = append(raw, ew)
		ders = append(ders, derive(ew, []engine.Atom{envVarAtom(a.Name, withFile(a.Pos, c.Pos.File))}, "env.write"))
	}

	if b == nil || b.k == nil {
		r.Resolution = Resolution{Kind: ResolveUnknown, Invoked: callName(c)}
		te := topEffect(engine.ModeDirect)
		raw = append(raw, te)
		ders = append(ders, derive(te, []engine.Atom{commandAtom(callName(c), c.Pos)}, "code.exec"))
		r.Conservative = true
		r.Notes = append(r.Notes, "no knowledge base bound")
		r.Effects = raw
		r.Derivations = ders
		normalizeResult(r)
		return r
	}

	if !c.NamePresent {
		if len(c.Env) > 0 {
			r.Resolution = Resolution{Kind: ResolveAssignment, Name: firstEnvName(c)}
		} else {
			r.Resolution = Resolution{Kind: ResolveEmpty}
		}
	} else {
		res := b.resolve(c)
		r.Resolution = res.res
		if res.command != nil {
			eff, ds, ms, unknown := b.bindCommand(res.command, res.args, c.StdinTaint, c.Pos)
			if len(eff) == 0 {
				// The name resolved to a KB command, but its invocation matched
				// no parameter that contributes an effect (a flag-only entry
				// such as reboot/poweroff/halt/shutdown or date/id/sync).
				// Emitting nothing would fail open to an empty, benign result,
				// so contribute the command's intrinsic "it ran" effect
				// (ProcSpawn over the command's own scope).
				e := intrinsicProcSpawn(res.command.Name, c.Pos)
				eff = append(eff, e)
				ds = append(ds, derive(e, []engine.Atom{commandAtom(callName(c), c.Pos)}, "proc.spawn"))
			}
			raw = append(raw, eff...)
			ders = append(ders, ds...)
			r.Destructive = destructiveEntries(b.k, res.command.Name, ms)
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
// effect each matched parameter contributes. It returns the effects, the specs
// that matched (for the destructive table), and any unrecognized flag names.
func (b *Binder) bindCommand(cmd *kb.Command, argv []Arg, stdinTaint engine.Taint, callLoc engine.SourceLoc) ([]engine.Effect, []engine.Derivation, []string, []string) {
	if cmd == nil {
		return nil, nil, nil, nil
	}
	operands, matches, unknown := parseArgs(cmd, argv)

	var out []engine.Effect
	var ders []engine.Derivation
	var specs []string

	cmdAtom := commandAtom(cmd.Name, callLoc)
	file := callLoc.File

	// Assignment operands (dd of=FILE, if=FILE): a key=value operand whose key
	// matches a declared assign parameter. cmd.AssignParams is the command's
	// precomputed ParamAssign subset, so this match never scans the command's
	// whole parameter list.
	var rest []Arg
	assigns := cmd.AssignParams()
	for _, op := range operands {
		done := false
		if op.Literal {
			for _, p := range assigns {
				if strings.HasPrefix(op.Value, p.Spec) {
					val := Arg{Value: op.Value[len(p.Spec):], Literal: true, Pos: withFile(op.Pos, file)}
					group := []Arg{val}
					effs, ds := lowerParam(cmd, p, val, argsScope(group), argsTaint(group), stdinTaint, []engine.Atom{cmdAtom, operandAtom(op.Value, withFile(op.Pos, file))})
					out = append(out, effs...)
					ders = append(ders, ds...)
					specs = append(specs, p.Spec)
					done = true
					break
				}
			}
		}
		if !done {
			rest = append(rest, op)
		}
	}

	// Flags and options matched by name; their effect target defaults to the
	// operand set for valueFrom=args.
	operandScope, operandTaint := argsScope(rest), argsTaint(rest)
	for _, m := range matches {
		mv := m.value
		mv.Pos = withFile(mv.Pos, file)
		atoms := []engine.Atom{cmdAtom, flagAtom(m.param.Spec, withFile(m.pos, file))}
		if m.hasVal && mv.Value != "" {
			atoms = append(atoms, operandAtom(mv.Value, mv.Pos))
		}
		effs, ds := lowerParam(cmd, m.param, mv, operandScope, operandTaint, stdinTaint, atoms)
		out = append(out, effs...)
		ders = append(ders, ds...)
		specs = append(specs, m.param.Spec)
	}

	// Positional operands. A leading literal operand that names a declared
	// positional parameter is matched by value first (the KB models CLI
	// subcommands this way: 7z l ARCHIVE, git clone|clean, systemctl start|stop,
	// nft list|flush); the remaining positional parameters fall back to index
	// order for generic operands (SRC/DEST/FILE).
	ps := positionalParams(cmd)
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
	if len(rest) > 0 && rest[0].Literal {
		if pi, ok := idxBySpec[rest[0].Value]; ok {
			p := ps[pi]
			group := rest[1:]
			atoms := []engine.Atom{cmdAtom}
			for _, g := range group {
				atoms = append(atoms, operandAtom(g.Value, withFile(g.Pos, file)))
			}
			effs, ds := lowerParam(cmd, p, Arg{}, argsScope(group), argsTaint(group), stdinTaint, atoms)
			out = append(out, effs...)
			ders = append(ders, ds...)
			specs = append(specs, p.Spec)
			valueMatched = true
		}
	}
	if !valueMatched {
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
			atoms := []engine.Atom{cmdAtom}
			for _, g := range group {
				atoms = append(atoms, operandAtom(g.Value, withFile(g.Pos, file)))
			}
			effs, ds := lowerParam(cmd, p, Arg{}, argsScope(group), argsTaint(group), stdinTaint, atoms)
			out = append(out, effs...)
			ders = append(ders, ds...)
			specs = append(specs, p.Spec)
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
		effs, ds := lowerParam(cmd, p, Arg{}, engine.ScopeBottom(), engine.TaintBottom(), stdinTaint, []engine.Atom{cmdAtom})
		out = append(out, effs...)
		ders = append(ders, ds...)
		specs = append(specs, p.Spec)
	}

	return out, ders, specs, unknown
}

// parseArgs splits argv into positional operands, matched flags/options, and
// unrecognized flag names.
func parseArgs(cmd *kb.Command, argv []Arg) ([]Arg, []match, []string) {
	var (
		operands []Arg
		matches  []match
		unknown  []string
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
				unknown = append(unknown, name)
				continue
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
			cluster := v[1:]
			consumed := false
			// Dedupe by spec so a long cluster token (-rrrr…) contributes one
			// match per distinct flag, not one per byte: this bounds the memory
			// a single token can allocate (ADR-0006) without changing the
			// effects of a repeated flag.
			seenSpec := make(map[string]bool, len(cluster))
			unknownSeen := make(map[string]bool, len(cluster))
			for j := 0; j < len(cluster); j++ {
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
	return operands, matches, unknown
}

// lowerParam lowers one matched parameter into the effects it contributes. Most
// parameters contribute exactly one effect. A parameter marked fileRef whose
// value uses the @file convention additionally contributes the filesystem read
// of the named file — or, for `@-`, no read at all, because the content comes
// from standard input — and carries the payload's provenance into its own
// effect, so that a data-carrying flag becomes a tainted egress.
func lowerParam(cmd *kb.Command, p kb.Param, value Arg, argScope engine.Scope, argTaint, stdinTaint engine.Taint, atoms []engine.Atom) ([]engine.Effect, []engine.Derivation) {
	cert := certaintyOf(p.Effect.Mode)
	target := targetFor(cmd, p, value, argScope)
	taint := taintFor(p, value, argTaint, stdinTaint)
	path, fromStdin, fileRef := fileRefPath(value)

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
		filtered, keep := engine.FilterEgressTargets(target, lenientHostDialect(cmd))
		if !keep {
			return nil, nil
		}
		target = filtered
	}

	if !p.Effect.FileRef || !fileRef {
		e := p.Effect.EngineEffect(target, taint, cert)
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

// fileRefPath recognizes the @file convention in a parameter value: "@path"
// names a file, "@-" names standard input, and "name=@path" (curl's multipart
// form syntax) is accepted too. The boolean is false when the value does not
// use the convention.
func fileRefPath(value Arg) (path string, fromStdin, ok bool) {
	if !value.Literal || value.Value == "" {
		return "", false, false
	}
	v := value.Value
	if i := strings.IndexByte(v, '='); i >= 0 && i+1 < len(v) && v[i+1] == '@' {
		v = v[i+1:]
	}
	if !strings.HasPrefix(v, "@") {
		return "", false, false
	}
	rest := v[1:]
	switch rest {
	case "-":
		return "", true, true
	case "":
		return "", false, false
	default:
		return rest, false, true
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
		kb.DialectUtilLinux: // logger -n/--server: the flag value is the syslog server
		return true
	}
	return false
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
		// The target is derived from an environment variable's value, which the
		// analysis cannot pin down: ⊤ (unknown), never ⊥ (no target).
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
func argsScope(g []Arg) engine.Scope {
	if len(g) == 0 {
		return engine.ScopeBottom()
	}
	vals := make([]string, 0, len(g))
	for _, a := range g {
		if !a.Literal {
			if a.Dir != "" {
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
// knowledge base's destructive-flags table, de-duplicated and sorted.
func destructiveEntries(k *kb.KB, command string, specs []string) []kb.Destructive {
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
		if a.Value != nil {
			ea.Value = Arg{Value: a.Value.Value, Literal: a.Value.Literal, Taint: a.Value.Taint,
				Pos: engine.SourceLoc{Line: a.Value.Pos.Line, Col: a.Value.Pos.Col}}
		}
		c.Env = append(c.Env, ea)
	}
	for _, w := range cmd.Wrappers {
		c.Wrappers = append(c.Wrappers, w.Name)
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
	return Arg{Value: w.Value, Literal: w.Literal, Dir: w.Dir, Taint: w.Taint,
		Pos: engine.SourceLoc{Line: w.Pos.Line, Col: w.Pos.Col}}
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
