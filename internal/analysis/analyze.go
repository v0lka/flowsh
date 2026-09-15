// Package analysis is the shared analysis facade behind the flowsh CLI and
// the regression harness. It is the single place that wires the two frontends
// (front/bash, front/ps), the knowledge-base binder (bind) and the frozen core
// (engine) into one deterministic, serialisable report.
//
// It lives under internal/ because it is not part of the public core: the core
// (engine) must stay frontend-free (see TestCoreDoesNotImportFrontends), so the
// composition of frontends + binder + engine can only live above them.
package analysis

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/bash"
	"github.com/v0lka/flowsh/front/ps"
)

const (
	// ToolName is the tool identifier stamped into every report.
	ToolName = "flowsh"
	// SchemaVersion tags the report's effect schema. It is the frozen core's
	// schema version, so a flowsh report is an engine report plus a little
	// CLI metadata.
	SchemaVersion = engine.SchemaVersion
	// ToolVersion is the semantic version of the report contract. It is bumped
	// when the shape of the CLI report changes; command-line additions that do
	// not alter the emitted document (such as --version) do not bump it. The
	// v2 contract added the additive report fields why, resolution, destructive
	// and root (see specs/contracts/report-json.md).
	ToolVersion = "flowsh/v1"

	// RootArgument and RootStdin are the source-name markers stamped into
	// Report.Root when the analysed command does not come from a file: it was
	// given as the positional argument, or read from standard input.
	RootArgument = "<argument>"
	RootStdin    = "<stdin>"
)

// Lang names the command-line dialect a source is written in. The values are
// exactly the ones the CLI accepts on --lang.
type Lang string

const (
	// LangBash is GNU bash argv with -flags and --options: the default dialect.
	LangBash Lang = "bash"
	// LangPOSIX is the POSIX shell (a.k.a. sh). It reuses the bash frontend but
	// parses and executes in the POSIX dialect, so bash-only constructs (e.g.
	// [[ … ]]) are not recognised as their bash special forms.
	LangPOSIX Lang = "posix"
	// LangPowerShell is PowerShell cmdlet syntax (named/positional parameters).
	// The canonical name is "posh", matching the CLI's --lang value.
	LangPowerShell Lang = "posh"
)

// Langs is every supported dialect, in canonical order.
var Langs = []Lang{LangBash, LangPOSIX, LangPowerShell}

// ParseLang maps a user-supplied language name onto a Lang, accepting the
// canonical spellings ("bash", "posix", "posh") plus their common aliases.
func ParseLang(s string) (Lang, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bash", "shell":
		return LangBash, nil
	case "posix", "sh":
		return LangPOSIX, nil
	case "posh", "ps", "pwsh", "powershell":
		return LangPowerShell, nil
	default:
		return "", fmt.Errorf("flowsh: unknown language %q (want bash|posix|posh)", s)
	}
}

// Report is the CLI's JSON contract: the frozen effect IR plus the composition
// score and the conservative/⊤ flags that tell a consumer whether the analysis
// could bound the input.
type Report struct {
	SchemaVersion string `json:"schemaVersion"`
	Tool          string `json:"tool"`
	ToolVersion   string `json:"toolVersion"`
	Lang          string `json:"lang"`
	Input         string `json:"input"`
	// Root names the source the input was read from: the path of the analysed
	// file, or a marker when it was not a file (RootArgument / RootStdin). It is
	// omitted when the caller did not name a source.
	Root            string                 `json:"root,omitempty"`
	Effects         []engine.Effect        `json:"effects"`
	Destructiveness engine.Destructiveness `json:"destructiveness"`
	Score           engine.Score           `json:"score"`
	Why             []engine.WhyTrace      `json:"why,omitempty"`
	Conservative    bool                   `json:"conservative"`
	Top             bool                   `json:"top"`
	Reason          string                 `json:"reason,omitempty"`
	Commands        int                    `json:"commands"`
	// Resolution is the aggregated name-resolution outcome across the program's
	// calls: which command the invocation(s) actually named. It is the zero
	// value (empty Kind) when no call reached the binder — e.g. on the
	// PowerShell path, which resolves through its own alias/cmdlet tables.
	Resolution bind.Resolution `json:"resolution"`
	// Destructive lists the destructive-flags entries the program's calls
	// matched, de-duplicated and sorted. It is omitted when no call matched one.
	Destructive []DestructiveFinding `json:"destructive,omitempty"`
	Notes       []string             `json:"notes,omitempty"`
}

// DestructiveFinding is one matched entry of the knowledge base's
// destructive-flags table, surfaced in the report. It mirrors the binder's
// destructive entries but is defined here so the report contract does not
// couple to the kb package.
type DestructiveFinding struct {
	// Command is the knowledge-base command the entry belongs to.
	Command string `json:"command"`
	// Spec is the parameter spec (flag/option/operand) that matched.
	Spec string `json:"spec"`
	// Class is the entry's severity class, A–E (A=None … E=Critical).
	Class string `json:"class"`
	// Reason is why the entry is destructive.
	Reason string `json:"reason"`
}

// aggregatedResolution folds the per-call Resolution objects of a program into a
// single report-level answer: the most informative resolution observed, so that
// a call that resolved through an alias, a function or to an external command is
// preferred over a bare builtin, an assignment, or an unresolved call.
type aggregatedResolution struct {
	set bool
	res bind.Resolution
}

// observe folds one call's resolution into the aggregate, keeping the
// highest-ranked kind seen (ties keep the first, so the outcome is stable).
func (a *aggregatedResolution) observe(r bind.Resolution) {
	if !a.set || resolutionRank(r.Kind) > resolutionRank(a.res.Kind) {
		a.res, a.set = r, true
	}
}

// resolution returns the aggregated resolution, or the zero value when no call
// was observed.
func (a *aggregatedResolution) resolution() bind.Resolution {
	if !a.set {
		return bind.Resolution{}
	}
	return a.res
}

// resolutionRank orders ResolveKind values by how much they tell a consumer
// about the intent behind a call: an alias/function/command name is more
// informative than a bare builtin, a bare assignment, an empty call, or ⊤.
func resolutionRank(k bind.ResolveKind) int {
	switch k {
	case bind.ResolveAlias:
		return 6
	case bind.ResolveFunction:
		return 5
	case bind.ResolveCommand:
		return 4
	case bind.ResolveBuiltin:
		return 3
	case bind.ResolveAssignment:
		return 2
	case bind.ResolveEmpty:
		return 1
	default: // ResolveUnknown and the zero kind
		return 0
	}
}

// normalizeDestructive de-duplicates destructive findings by (command, spec) and
// sorts them, so the report is deterministic. It returns nil when there are
// none, so the JSON omits the field.
func normalizeDestructive(xs []DestructiveFinding) []DestructiveFinding {
	if len(xs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(xs))
	out := make([]DestructiveFinding, 0, len(xs))
	for _, x := range xs {
		key := x.Command + "|" + x.Spec
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Command != out[j].Command {
			return out[i].Command < out[j].Command
		}
		return out[i].Spec < out[j].Spec
	})
	return out
}

// mergeNotes concatenates the frontend and binder note streams, dropping empty
// duplicates so a note repeated by both layers appears once. It returns nil when
// there are no notes, so the JSON omits the field.
func mergeNotes(frontend, binder []string) []string {
	if len(frontend) == 0 && len(binder) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(frontend)+len(binder))
	out := make([]string, 0, len(frontend)+len(binder))
	for _, group := range [][]string{frontend, binder} {
		for _, n := range group {
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// Validate reports whether the report is well-formed: it carries the schema
// version, a language, and only valid effects.
func (r *Report) Validate() error {
	if r == nil {
		return fmt.Errorf("flowsh: nil report")
	}
	if r.SchemaVersion == "" {
		return fmt.Errorf("flowsh: empty schemaVersion")
	}
	if r.Lang == "" {
		return fmt.Errorf("flowsh: empty lang")
	}
	for i := range r.Effects {
		if err := r.Effects[i].Validate(); err != nil {
			return fmt.Errorf("flowsh: effects[%d]: %w", i, err)
		}
	}
	return nil
}

// Encode validates the report and returns its canonical indented JSON.
func (r *Report) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(r, "", "  ")
}

// Covered reports the "no silent miss" invariant the GuardFall corpus checks:
// the analysis either produced at least one effect or degraded to ⊤. A report
// that is neither is a miss — the analyser failed to say anything about the
// command.
func (r *Report) Covered() bool {
	if r == nil {
		return false
	}
	return len(r.Effects) > 0 || r.Top || r.Conservative
}

// HasTop reports whether the report contains the ⊤ effect (CodeExec over the
// any-target scope).
func (r *Report) HasTop() bool {
	if r == nil {
		return false
	}
	for _, e := range r.Effects {
		if e.Kind == engine.KindCodeExec && e.Target.IsTop() {
			return true
		}
	}
	return false
}

// Analyzer holds the reusable state of an analysis — the command knowledge
// base — so that analysing many commands does not pay the one-time KB load on
// every call. It is safe for concurrent use.
type Analyzer struct {
	binder *bind.Binder
}

// NewAnalyzer returns an analyser over the embedded knowledge base.
func NewAnalyzer() (*Analyzer, error) {
	b, err := bind.NewDefault()
	if err != nil {
		return nil, fmt.Errorf("flowsh: load knowledge base: %w", err)
	}
	return &Analyzer{binder: b}, nil
}

// defaultAnalyzer memoises the process-wide analyser, so repeated calls from a
// CLI script or a benchmark reuse a single loaded knowledge base.
var defaultAnalyzer = sync.OnceValues(NewAnalyzer)

// Options tunes the composition analysis. The zero value reproduces the
// historical host-default behaviour, so callers that do not care about a
// specific provider configuration can pass Options{}.
type Options struct {
	// Windows forces the PowerShell Registry provider on (true) or off (false)
	// independently of the host OS. It defaults to nil, meaning "the host's
	// GOOS decides" — registry branches are active only on a Windows host, so
	// the default is unchanged from before this option existed.
	Windows *bool

	// Root names the source the input was read from: the path of the analysed
	// file, or a marker such as RootArgument / RootStdin. It is stamped into
	// Report.Root (and used as the source name positions are reported against).
	// Empty leaves the report's root unset, as for an in-memory analysis.
	Root string
}

// psOptions resolves o into the PowerShell frontend's provider options. When
// Windows is unset it falls back to the host default (registry active only on
// Windows), which is exactly what ps.Lower does.
func (o Options) psOptions() ps.Options {
	if o.Windows != nil {
		return ps.Options{Windows: *o.Windows}
	}
	return ps.Options{Windows: runtime.GOOS == "windows"}
}

// Bool returns a pointer to v. It is a convenience for setting the tri-state
// Options.Windows field: Options{Windows: Bool(true)} forces registry semantics
// on any host.
func Bool(v bool) *bool { return &v }

// Analyze runs the full pipeline for lang over src using the process-wide
// analyser and the host-default provider configuration.
func Analyze(lang Lang, src string) (*Report, error) {
	return AnalyzeWith(lang, src, Options{})
}

// AnalyzeWith is Analyze with explicit options. It is the entry point that lets
// a caller enable a frontend provider (today, the PowerShell Registry) on a
// host where it would otherwise be inactive; the zero Options is identical to
// Analyze.
func AnalyzeWith(lang Lang, src string, opts Options) (*Report, error) {
	a, err := defaultAnalyzer()
	if err != nil {
		return nil, err
	}
	return a.AnalyzeWith(lang, src, opts), nil
}

// Analyze runs the full pipeline for lang over src with the host-default
// provider configuration.
func (a *Analyzer) Analyze(lang Lang, src string) *Report {
	return a.AnalyzeWith(lang, src, Options{})
}

// AnalyzeWith runs the full pipeline for lang over src: for bash, parse and
// abstractly execute with the knowledge-base resolver; for PowerShell, parse
// and lower with the provider configuration opts selects. It is total and
// deterministic — the frontends degrade to ⊤ rather than fail — so the returned
// report is never nil.
func (a *Analyzer) AnalyzeWith(lang Lang, src string, opts Options) *Report {
	switch lang {
	case LangPowerShell:
		return analyzePS(src, opts.psOptions(), opts.Root)
	case LangPOSIX:
		return a.analyzeBash(bash.POSIX, LangPOSIX, src, opts.Root)
	default:
		return a.analyzeBash(bash.Bash, LangBash, src, opts.Root)
	}
}

// analyzeBash abstractly executes src as shell variant v and folds the
// aggregate effects into a report. The resolver is the knowledge-base binder;
// when the analyser holds no binder the shell's own intrinsic effects are still
// reported. lang is stamped into the report (LangBash or LangPOSIX), so it is
// kept distinct from the frontend variant v; root names the source (a file path
// or a stdin/argument marker).
func (a *Analyzer) analyzeBash(v bash.Variant, lang Lang, src, root string) *Report {
	var (
		res         *bash.ExecResult
		agg         aggregatedResolution
		destructive []DestructiveFinding
		binderNotes []string
		// kbDestruct is the join (max) of the destructiveness the binder
		// computed for every call. The binder already folds the matched
		// destructive-table entries' classes into it (bind.normalizeResult →
		// DestructiveClass.Severity), so this carries the KB class A–E into the
		// report. Joining it can only raise the severity derived from the
		// effects, never lower it — the D6 raise-only invariant.
		kbDestruct engine.Destructiveness
	)
	if a == nil || a.binder == nil {
		res = bash.Exec(v, sourceName(root, "script"), src, nil)
	} else {
		b := a.binder
		res = bash.Exec(v, sourceName(root, "script"), src, func(cmd *bash.Command, prog *bash.Program) bash.Resolution {
			br := b.BindBash(cmd, prog)
			agg.observe(br.Resolution)
			kbDestruct = kbDestruct.Join(br.Destructiveness)
			for _, d := range br.Destructive {
				destructive = append(destructive, DestructiveFinding{
					Command: d.Command,
					Spec:    d.Spec,
					Class:   string(d.Class),
					Reason:  d.Reason,
				})
			}
			binderNotes = append(binderNotes, br.Notes...)
			return bash.Resolution{Effects: br.Effects, Derivations: br.Derivations}
		})
	}

	rep := newReport(lang, src, root)
	rep.Effects = normalizeEffects(res.Effects)
	// The knowledge-base destructive class joins (max) the effect-derived
	// severity, so it can only raise the report's destructiveness (D6).
	rep.Destructiveness = engine.ComputeDestructiveness(rep.Effects).Join(kbDestruct)
	rep.Why = buildWhy(rep.Effects, res.Derivations, commandFallback(bashFallbackName(res.Cmds)))
	rep.Conservative = res.Conservative
	rep.Top = res.Top
	rep.Reason = res.Reason
	rep.Commands = len(res.Cmds)
	rep.Resolution = agg.resolution()
	rep.Destructive = normalizeDestructive(destructive)
	rep.Notes = mergeNotes(res.Notes, binderNotes)
	rep.Score = engine.ScoreEffects(rep.Effects, bashTokens(res.Cmds)...)
	// Carry the KB class severity into the score too, so the report's
	// destructiveness and composite grade agree and neither can sit below a
	// matched destructive class (raise-only, D6). Grade is the join of the
	// risk dimensions, so adding kbDestruct here is equivalent to feeding it in
	// as a destructiveness dimension.
	rep.Score.Destructiveness = rep.Score.Destructiveness.Join(kbDestruct)
	rep.Score.Grade = rep.Score.Grade.Join(kbDestruct)
	return rep
}

// analyzePS parses and lowers src as PowerShell with the given provider
// options (see Options.psOptions): LowerWith honours opts.Windows so the
// Registry branches can be enabled independently of the host OS. root names the
// source (a file path or a stdin/argument marker).
func analyzePS(src string, opts ps.Options, root string) *Report {
	prog := ps.Parse(sourceName(root, "flowsh"), src)
	res := ps.LowerWith(prog, opts)

	rep := newReport(LangPowerShell, src, root)
	rep.Effects = normalizeEffects(res.Effects)
	rep.Destructiveness = engine.ComputeDestructiveness(rep.Effects)
	rep.Why = buildWhy(rep.Effects, res.Derivations, commandFallback(psFallbackName(prog)))
	rep.Conservative = res.Conservative
	rep.Top = prog.Top
	rep.Reason = prog.Reason
	rep.Commands = psCommandCount(prog)
	rep.Notes = append(rep.Notes, res.Notes...)
	rep.Score = engine.ScoreEffects(rep.Effects, psTokens(prog)...)
	return rep
}

// newReport builds the report skeleton common to both dialects. root names the
// source the input came from (a file path or a stdin/argument marker); it is
// omitted when empty.
func newReport(lang Lang, src, root string) *Report {
	return &Report{
		SchemaVersion: SchemaVersion,
		Tool:          ToolName,
		ToolVersion:   ToolVersion,
		Lang:          string(lang),
		Input:         src,
		Root:          root,
		Effects:       []engine.Effect{},
	}
}

// sourceName picks the source name a frontend records positions against: the
// caller's root when set, else the historical default ("script" for bash,
// "flowsh" for PowerShell) so a rootless analysis is unchanged.
func sourceName(root, def string) string {
	if root == "" {
		return def
	}
	return root
}

// normalizeEffects merges effects by (kind, mode) and sorts them into the core's
// canonical order. The result is never nil, so the JSON carries [] not null.
func normalizeEffects(effs []engine.Effect) []engine.Effect {
	rep := engine.NewReport()
	rep.Effects = effs
	rep.Normalize()
	if rep.Effects == nil {
		rep.Effects = []engine.Effect{}
	}
	return rep.Effects
}

// ---------------------------------------------------------------------------
// Why-trace construction
// ---------------------------------------------------------------------------

// buildWhy maps the frontends' derivations onto the report's normalized effects
// and builds their why-traces. Derivations are keyed by (kind, mode) because
// normalization merges effects on exactly that pair, so a derivation recorded
// for a narrower target still explains the merged effect. Any effect left
// without a derivation is given a fallback citing the command atom, which makes
// the report's WhyGaps invariant — every non-empty effect explained by a
// concrete node/flag — hold for every input, including the ⊤ cases.
func buildWhy(effects []engine.Effect, ders []engine.Derivation, fallback engine.Atom) []engine.WhyTrace {
	if len(effects) == 0 {
		return nil
	}
	if fallback.Kind == "" {
		fallback.Kind = engine.AtomCommand
	}
	atoms := make(map[string][]engine.Atom, len(ders))
	rules := make(map[string][]string, len(ders))
	for _, d := range ders {
		k := whyKey(d.Effect)
		atoms[k] = append(atoms[k], d.Atoms...)
		rules[k] = append(rules[k], d.Rules...)
	}
	out := make([]engine.Derivation, 0, len(effects))
	for _, e := range effects {
		k := whyKey(e)
		a := dedupAtoms(atoms[k])
		rs := dedupStrings(rules[k])
		if len(a) == 0 {
			a = []engine.Atom{fallback}
			rs = []string{"effect.derive"}
		}
		out = append(out, engine.Derivation{Effect: e, Atoms: a, Rules: rs})
	}
	return engine.BuildWhy(out)
}

// whyKey is the (kind, mode) pair normalization merges on, the key under which
// derivations are matched to the merged effects.
func whyKey(e engine.Effect) string { return string(e.Kind) + "|" + string(e.Mode) }

// commandFallback builds the command atom used to explain an effect that arrived
// without a derivation.
func commandFallback(name string) engine.Atom {
	return engine.Atom{Kind: engine.AtomCommand, Text: name}
}

// bashFallbackName picks a representative command name for the bash fallback
// atom: the first resolved invocation, or "" when there is none.
func bashFallbackName(cmds []*bash.Command) string {
	for _, c := range cmds {
		if c != nil && c.Name != "" {
			return c.Name
		}
	}
	return ""
}

// psFallbackName picks a representative command name for the PowerShell fallback
// atom: the first lowered command, or "" when there is none.
func psFallbackName(p *ps.Program) string {
	if p == nil {
		return ""
	}
	for _, s := range p.Stmts {
		if s != nil && s.Kind == ps.KindCommand && s.Cmd != nil && s.Cmd.Name != "" {
			return s.Cmd.Name
		}
	}
	return ""
}

// dedupAtoms removes duplicate atoms (same kind and text), preserving order.
func dedupAtoms(xs []engine.Atom) []engine.Atom {
	if len(xs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(xs))
	out := make([]engine.Atom, 0, len(xs))
	for _, x := range xs {
		k := string(x.Kind) + "\x00" + x.Text
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, x)
	}
	return out
}

// dedupStrings removes duplicate strings, preserving order.
func dedupStrings(xs []string) []string {
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
	return out
}

// bashTokens returns the resolved invocation names, de-duplicated and sorted,
// for the score's irreversibility dimension.
func bashTokens(cmds []*bash.Command) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		if c != nil && c.Name != "" {
			out = append(out, c.Name)
		}
	}
	return dedupSorted(out)
}

// psCommandCount counts the lowered command statements.
func psCommandCount(p *ps.Program) int {
	if p == nil {
		return 0
	}
	n := 0
	for _, s := range p.Stmts {
		if s != nil && s.Kind == ps.KindCommand {
			n++
		}
	}
	return n
}

// psTokens returns the statically-known PowerShell command names.
func psTokens(p *ps.Program) []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, s := range p.Stmts {
		if s == nil || s.Kind != ps.KindCommand || s.Cmd == nil {
			continue
		}
		if s.Cmd.Name != "" {
			out = append(out, s.Cmd.Name)
		}
	}
	return dedupSorted(out)
}

func dedupSorted(xs []string) []string {
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
