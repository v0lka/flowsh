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
	// Resolved is the normalized binary the invocation resolves to: the
	// basename of the resolved name with any node_modules/.bin directory
	// segment stripped, and for a package runner (npx) the first non-flag
	// operand. npx tsc -b and ./node_modules/.bin/tsc -b both resolve to tsc.
	Resolved string `json:"resolved,omitempty"`
	// Args are the invocation's argument values after normalization: for a
	// package runner the runner's own words (flags and the binary operand) are
	// consumed, so npx --yes tsc -b leaves ["-b"]. Empty values are dropped —
	// they are the macOS optional-suffix form (sed -i '' …), not a comparable
	// token.
	Args []string `json:"args,omitempty"`
	// Redirs are the statement's resolved redirections (operator plus expanded
	// target text). They carry the staging writes the canonical form folds.
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

// packageRunners are the package runners whose first non-flag operand names the
// binary that actually executes. Their invocation form differs from the direct
// binary path while the executed binary — and its effect — is the same, so the
// canonical resolution consumes the runner.
var packageRunners = map[string]bool{
	"npx": true,
}

// nodeModulesBin is the directory segment every JavaScript project exposes its
// local tool binaries under; stripping it maps a project-local binary path onto
// the bare binary name.
const nodeModulesBin = "node_modules/.bin"

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
	resolved, rest := normalizeBinary(name, args)
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
func normalizeBinary(name string, args []string) (string, []string) {
	if name == "" {
		return "", args
	}
	if packageRunners[name] {
		for i, a := range args {
			if a == "" || strings.HasPrefix(a, "-") {
				continue
			}
			r, _ := normalizeBinary(a, nil)
			return r, args[i+1:]
		}
	}
	if i := strings.LastIndex(name, nodeModulesBin); i >= 0 {
		name = name[i+len(nodeModulesBin):]
	}
	if j := strings.LastIndexAny(name, `/\`); j >= 0 {
		name = name[j+1:]
	}
	return name, args
}

// buildCanonical derives the canonical effect set from the report's effects and
// its per-command view: every mv whose source the same program writes first
// stages that source, so writes of a staged source fold onto the destination
// the mv names and the staged file's other lifecycle effects (creation
// metadata, transport read, unlink) drop; targets that cannot be paths drop.
// The effects are then merged and ordered by the core's canonical rules and
// keyed by their frozen Effect.Key().
func buildCanonical(effs []engine.Effect, calls []CommandCall) *Canonical {
	staged := stagingDestinations(effs, calls)
	var out []engine.Effect
	for _, e := range effs {
		if e.Target.IsTop() {
			// ⊤ cannot be refined by target normalization; keep it as-is so
			// the canonical form stays exactly as bounded as the report.
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
func stagingDestinations(effs []engine.Effect, calls []CommandCall) map[string]string {
	if len(calls) == 0 {
		return nil
	}
	moves := make(map[string]string)
	for _, c := range calls {
		if c.Resolved != "mv" || len(c.Args) < 2 {
			continue
		}
		src, dst := c.Args[0], c.Args[len(c.Args)-1]
		if src == "" || dst == "" || src == dst {
			continue
		}
		if _, dup := moves[src]; !dup {
			moves[src] = dst
		}
	}
	if len(moves) == 0 {
		return nil
	}
	written := make(map[string]bool)
	for _, e := range effs {
		if e.Kind != engine.KindFSWrite || e.Target.IsTop() {
			continue
		}
		for _, t := range e.Target.Targets() {
			written[t] = true
		}
	}
	for src := range moves {
		if !written[src] {
			delete(moves, src)
		}
	}
	if len(moves) == 0 {
		return nil
	}
	return moves
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
			return dst
		}
		return ""
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
