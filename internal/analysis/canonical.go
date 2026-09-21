// Per-command resolution and the effect-based canonical form.
//
// The aggregated Resolution answers "which command did the program name?" once
// per program. A signature that must recognize a retry of an already-judged
// invocation needs more: retries differ in FORM but not in EFFECT — the blocked
// `npx tsc -b` comes back as `./node_modules/.bin/tsc -b`, the blocked
// `sed … > staging && mv staging file` comes back as `sed -i … file` — so the
// report carries (a) a per-command view whose binary name is normalized
// (CommandCall), and (b) a canonical effect set whose staging-file lifecycle is
// folded onto the final target (Canonical). Both are additive report fields;
// the aggregated Resolution and the raw effects[] are unchanged.

package analysis

import (
	"sort"
	"strings"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/bash"
)

// CommandCall is one command invocation as the report surfaces it for
// effect-based comparison: the name exactly as written at the call site, the
// normalized binary it resolves to, its (non-empty) argument values, and the
// statement's resolved redirections. It is the per-command companion of the
// aggregated Resolution.
type CommandCall struct {
	// Invoked is the name exactly as written at the call site (the alias or
	// path form, before normalization).
	Invoked string `json:"invoked,omitempty"`
	// Resolved is the normalized binary the invocation resolves to: when the
	// binder resolved the invocation to a knowledge-base command, that command's
	// name; otherwise the basename of the resolved name (the alias target,
	// function name, or the invoked word) with any node_modules/.bin directory
	// segment stripped (and, for a package runner, of its first non-flag
	// operand).
	// npx tsc -b and ./node_modules/.bin/tsc -b both resolve to tsc, and npx
	// mvnw package, ./mvnw package and mvnw package all resolve to mvn (the
	// wrapper alias), so every spelling of one binary reports one resolved
	// identity.
	Resolved string `json:"resolved,omitempty"`
	// Args are the invocation's argument values after normalization: for a
	// package runner the runner's own words (flags and the binary operand) are
	// consumed, so npx --yes tsc -b leaves ["-b"]. Empty values are dropped —
	// they are the macOS optional-suffix form (sed -i '' …), not a comparable
	// token.
	Args []string `json:"args,omitempty"`
	// Redirs are the statement's resolved redirections (operator plus expanded
	// target text). They are the ordering witness the canonical staging fold
	// reads: a source written by a preceding call's redirect is a staging file.
	Redirs []CallRedirect `json:"redirs,omitempty"`
}

// CallRedirect is one resolved redirection of a command's statement.
type CallRedirect struct {
	// Op is the redirection operator verbatim (">", ">>", "<", "2>", "2>&1",
	// ">&", "<<" …).
	Op string `json:"op"`
	// Target is the expanded target text: a file path, an fd word for a stream
	// dupe, a host:port for the /dev/tcp pseudo-file; empty for heredocs.
	Target string `json:"target,omitempty"`
	// Known reports whether the target text is statically known. An unknown
	// target is the word's placeholder, not a boundable path.
	Known bool `json:"known"`
}

// Canonical is the effect-based canonical form of the analysed program: the
// report's effect set normalized for signature comparison, plus the
// deterministic key derived from it. Two invocations that differ in form but
// not in effect — a blocked command retried through an equivalent form — carry
// the same key.
//
// The normalizations are deliberately coarse, because a merge of two genuinely
// different commands is no worse than today's alternative (the split of every
// retry): staged temp files fold onto the destination the trailing mv names
// (sed … > tmp && mv tmp file ≡ sed -i … file), and targets that cannot be
// paths — the operands the knowledge base over-approximates as file targets,
// such as a sed script or a grep pattern — drop out. The raw effects[] and the
// decision they feed are untouched; only the comparable form is normalized.
type Canonical struct {
	// Effects is the normalized effect set: staging-folded and
	// path-shaped-filtered, merged and ordered by the core's canonical rules.
	Effects []engine.Effect `json:"effects"`
	// Key is the deterministic comparable string: the effects' frozen
	// Effect.Key() values, sorted and joined by ";". Empty when there are no
	// canonical effects.
	Key string `json:"key"`
}

// commandCallOf builds the per-command view of one resolved invocation: cmd is
// the frontend's normalized command (name, argument words, statement
// redirections), res the binder's name resolution for it.
func commandCallOf(cmd *bash.Command, res bind.Resolution) CommandCall {
	if cmd == nil {
		return CommandCall{}
	}
	name := res.Name
	if name == "" {
		name = cmd.Name
	}
	args := make([]string, 0, len(cmd.Args))
	for _, a := range cmd.Args {
		if a == nil || a.Value == "" {
			continue
		}
		args = append(args, a.Value)
	}
	// The package runner is the one INVOCATION-FORM normalization: its operand
	// names the executed binary, so the runner's own words must be consumed
	// from the word as written at the call site (npx tsc -b → tsc [-b]).
	// It applies only when the word really is the runner: a program alias or
	// function shadowing npx/bunx resolves through the binder instead — the
	// binder's resolved name stands and the call's own words are kept — and a
	// runner word the binder bound to a knowledge-base command of its own uses
	// that command's argv unchanged. (The bash frontend dispatches declared
	// functions itself, so the function case reaches the binder only through a
	// direct caller.)
	shadowed := res.Kind == bind.ResolveAlias || res.Kind == bind.ResolveFunction
	runnerBound := res.Kind == bind.ResolveCommand && res.Name == cmd.Name
	resolved, rest := bind.StripBinaryPath(name), args
	if !shadowed && !runnerBound && bind.IsPackageRunner(cmd.Name) {
		resolved, rest = normalizeBinary(cmd.Name, args)
	}
	// Whenever the binder resolved the invocation to a knowledge-base command,
	// that command's name is the one resolved identity every spelling of the
	// binary shares: ./mvnw, mvnw and npx mvnw all report mvn — the literal
	// form-level rule cannot see the alias.
	if res.Kind == bind.ResolveCommand && res.Name != "" {
		resolved = res.Name
	}
	redirs := make([]CallRedirect, 0, len(cmd.Redirs))
	for _, r := range cmd.Redirs {
		redirs = append(redirs, CallRedirect{Op: r.Op, Target: r.Target, Known: r.Known})
	}
	return CommandCall{
		Invoked:  cmd.Name,
		Resolved: resolved,
		Args:     rest,
		Redirs:   redirs,
	}
}

// normalizeBinary reduces a resolved command name, with its argument values, to
// the normalized binary plus the argument list that survives: the basename of
// the name with any node_modules/.bin segment stripped (./node_modules/.bin/tsc,
// node_modules/.bin/tsc and /abs/node_modules/.bin/tsc all reduce to tsc), or —
// for a package runner — the runner's first non-flag operand with the runner's
// own words consumed (npx --yes tsc -b → (tsc, [-b])). A runner that names no
// operand keeps the basename rule, so bare npx still reports itself.
//
// The implementation lives in bind (bind.NormalizeBinaryName) so the
// comparable form and the binder's resolution share one runner/path
// vocabulary. Both refuse the -c/--call shape: the binder declines to BIND it
// (⊤), and this form-level normalization likewise consumes no operand for it,
// so a runner that carries -c/--call keeps its own basename as the resolved
// binary (npx -c 'X' Y → resolved "npx") rather than reporting the shell
// string's word.
func normalizeBinary(name string, args []string) (string, []string) {
	return bind.NormalizeBinaryName(name, args)
}

// identity is a comparable key for a call: two abstract executions of the same
// call site (name, normalized binary, arguments, redirections) produce the same
// identity, so a repeated call — a loop body — contributes one report entry.
func (c CommandCall) identity() string {
	var b strings.Builder
	b.WriteString(c.Invoked)
	b.WriteByte(0)
	b.WriteString(c.Resolved)
	for _, a := range c.Args {
		b.WriteByte(0)
		b.WriteString(a)
	}
	for _, r := range c.Redirs {
		b.WriteByte(0)
		b.WriteString(r.Op)
		b.WriteByte('=')
		b.WriteString(r.Target)
	}
	return b.String()
}

// buildCanonical derives the canonical effect set from the report's effects and
// its per-command view: every mv whose source the same program writes first
// stages that source, so writes of a staged source fold onto the destination
// the mv names and the staged file's other lifecycle effects (creation
// metadata, transport read, unlink) drop; targets that cannot be paths drop.
// The effects are then merged and ordered by the core's canonical rules and
// keyed by their frozen Effect.Key().
func buildCanonical(effs []engine.Effect, calls []CommandCall) *Canonical {
	staged := stagingDestinations(calls)
	var out []engine.Effect
	for _, e := range effs {
		if e.Target.IsTop() || e.Target.IsBottom() {
			// ⊤ cannot be refined and ⊥ has no target to normalize; keep either
			// verbatim so the canonical form stays a faithful image of
			// effects[] and never drops an effect it carries.
			out = append(out, e)
			continue
		}
		for _, t := range e.Target.Targets() {
			t = canonicalTarget(t, e.Kind, staged)
			if t == "" {
				continue
			}
			ne := e
			ne.Target = engine.ScopeOf(t)
			out = append(out, ne)
		}
	}
	norm := normalizeEffects(out)
	return &Canonical{Effects: norm, Key: canonicalKey(norm)}
}

// stagingDestinations maps staged source → final destination: the sources of
// the program's mv calls that the same program writes first (the
// `cmd > tmp && mv tmp final` pattern). A source nothing writes is an ordinary
// rename, not a staging file, and is left alone.
func stagingDestinations(calls []CommandCall) map[string]string {
	if len(calls) == 0 {
		return nil
	}
	moves := make(map[string]string)
	// written is the set of paths a redirect has written *so far* in traversal
	// order: only a source written before its mv is a staging file, so the
	// "move the file aside, then rewrite it" idiom does not fold the later write
	// onto the backup path.
	written := make(map[string]bool)
	for _, c := range calls {
		if c.Resolved == "mv" {
			src, dst := mvOperands(c.Args)
			if src != "" && dst != "" && src != dst && written[src] {
				if _, dup := moves[src]; !dup {
					moves[src] = dst
				}
			}
		}
		for _, r := range c.Redirs {
			if writesFile(r.Op) && r.Target != "" {
				written[r.Target] = true
			}
		}
	}
	if len(moves) == 0 {
		return nil
	}
	return moves
}

// mvOperands returns the source and destination operands of an mv invocation,
// skipping option words (mv -f tmp final, mv -- tmp final). A -t/--target-
// directory invocation moves into a directory, which is not a staging fold, so
// it reports no operands.
func mvOperands(args []string) (string, string) {
	var ops []string
	for _, a := range args {
		if a == "--" {
			continue
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			if a == "-t" || a == "--target-directory" || strings.HasPrefix(a, "--target-directory=") {
				return "", ""
			}
			continue
		}
		ops = append(ops, a)
	}
	if len(ops) < 2 {
		return "", ""
	}
	return ops[0], ops[len(ops)-1]
}

// writesFile reports whether a redirection operator writes its target's file
// (a stream dupe or a read does not). A leading file-descriptor prefix (2>, 10>>)
// is stripped first, since the per-command view keeps it.
func writesFile(op string) bool {
	op = strings.TrimLeft(op, "0123456789")
	switch op {
	case ">", ">>", "&>", "&>>":
		return true
	}
	return false
}

// targetNoise lists bytes that essentially never occur in a path but routinely
// occur in the operands the knowledge base over-approximates as file targets:
// a sed script ("297d;328,1972d"), a grep pattern ("^<<<<<<<\\|^…"), an
// arithmetic range ("1,296p;…,$p"). A target carrying one cannot name the file
// the effect is really about, so it drops out of the canonical form.
const targetNoise = ";|<>^$"

// canonicalTarget maps one effect target onto its canonical form: a staged
// source folds onto its destination for writes and vanishes for every other
// kind (the staged file's lifecycle is transport, not durable effect); a
// target that cannot be a path drops. The empty string means "dropped".
func canonicalTarget(t string, kind engine.EffectKind, staged map[string]string) string {
	if dst, ok := staged[t]; ok {
		if kind == engine.KindFSWrite {
			// Validate the fold destination like any other target, so a
			// destination carrying noise bytes cannot slip in through the fold.
			return canonicalTarget(dst, kind, nil)
		}
		return ""
	}
	if kind == engine.KindNetEgress || kind == engine.KindNetIngress {
		// A network address is never a knowledge-base over-approximation of a
		// file operand: keep it verbatim, so the noise / leading-'-' heuristics
		// (meant for file-ish targets) can never erase a live egress from the
		// canonical form.
		return t
	}
	if t == "" || strings.HasPrefix(t, "-") || strings.ContainsAny(t, targetNoise) {
		return ""
	}
	return t
}

// canonicalKey renders the canonical effect set as one deterministic string:
// the effects' frozen keys, sorted and joined, so equal sets in any order
// produce equal keys.
func canonicalKey(effs []engine.Effect) string {
	if len(effs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(effs))
	for _, e := range effs {
		keys = append(keys, e.Key())
	}
	sort.Strings(keys)
	return strings.Join(keys, ";")
}
