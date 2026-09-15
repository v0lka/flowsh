package ps

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/v0lka/flowsh/engine"
)

// StylePS names the dialect the result was lowered from. It is the value the
// composition layer uses to tell a PowerShell result from a bash one.
const StylePS = "ps"

// Options tunes lowering. The zero value is a valid, non-Windows configuration;
// use Lower for the host-default behaviour.
type Options struct {
	// Windows enables the Registry provider. On non-Windows hosts the provider
	// does not exist, so registry paths contribute no effect (the task scopes
	// Registry to Windows). Lower defaults it to runtime.GOOS == "windows".
	Windows bool
}

// Result is the outcome of lowering one normalized PowerShell program into the
// effect IR. It mirrors the binder's Result so the two compose uniformly.
type Result struct {
	Style           string                 `json:"style"`
	Effects         []engine.Effect        `json:"effects"`
	Destructiveness engine.Destructiveness `json:"destructiveness"`
	// Derivations justifies every reported effect with the concrete source atoms
	// (command, operand, redirect, source, sink) it rests on. It is analysis
	// metadata for the why-trace, not part of the serialized result.
	Derivations []engine.Derivation `json:"-"`
	// Conservative is true when the outcome includes a ⊤ (CodeExec) effect
	// because a construct could not be bounded.
	Conservative bool     `json:"conservative"`
	Notes        []string `json:"notes,omitempty"`
}

// Encode returns the canonical indented JSON of the result.
func (r *Result) Encode() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// cmdletIndex maps a lower-cased cmdlet name onto its canonical spelling so
// lookups are case-insensitive, as PowerShell's are.
var cmdletIndex = func() map[string]string {
	m := make(map[string]string, len(Cmdlets))
	for k := range Cmdlets {
		m[strings.ToLower(k)] = k
	}
	return m
}()

// Lower lowers a parsed program into the effect IR, using the host's provider
// configuration.
func Lower(p *Program) *Result {
	return LowerWith(p, Options{Windows: runtime.GOOS == "windows"})
}

// LowerWith is Lower with explicit options.
func LowerWith(p *Program, opts Options) *Result {
	l := &lowerer{
		prog:    p,
		windows: opts.Windows,
	}
	r := &Result{Style: StylePS}
	if p == nil {
		l.top("nil program")
		l.finish(r)
		return r
	}
	if p.Top {
		reason := p.Reason
		if reason == "" {
			reason = "unparseable program"
		}
		l.top(reason)
		l.finish(r)
		return r
	}
	for _, s := range p.Stmts {
		if s == nil {
			continue
		}
		switch s.Kind {
		case KindCommand:
			l.command(s)
		case KindAssignment:
			l.assignment(s.Assign)
		case KindTop:
			l.top(s.Reason)
		}
	}
	l.finish(r)
	return r
}

// Analyze is the one-call convenience: parse src and lower it.
func Analyze(src string) *Result { return Lower(Parse("", src)) }

// ===========================================================================
// Lowering
// ===========================================================================

type lowerer struct {
	prog         *Program
	windows      bool
	effects      []engine.Effect
	ders         []engine.Derivation
	notes        []string
	conservative bool
	bump         engine.Destructiveness
}

func (l *lowerer) emit(e engine.Effect) {
	l.effects = append(l.effects, e)
}

// emitEff records one effect together with the derivation that justifies it,
// citing the concrete source atoms (command, operand, redirect, source, sink).
func (l *lowerer) emitEff(e engine.Effect, atoms ...engine.Atom) {
	l.effects = append(l.effects, e)
	l.ders = append(l.ders, engine.Derivation{Effect: e, Atoms: atoms, Rules: []string{ruleForKind(e.Kind)}})
}

func (l *lowerer) note(format string, args ...any) {
	l.notes = append(l.notes, fmt.Sprintf(format, args...))
}

// top records a ⊤ conclusion: a CodeExec effect over the any-target scope,
// flagged conservative, with the reason in the notes. Every path that cannot
// bound its input funnels through here.
func (l *lowerer) top(reason string) {
	l.emitEff(topEffect(engine.ModeDirect), atom(engine.AtomLiteral, reason, Pos{}))
	l.conservative = true
	l.note("⊤ %s → CodeExec(⊤)", reason)
}

// canonicalCmdlet returns the canonical spelling of name if it is a known
// cmdlet (case-insensitively).
func canonicalCmdlet(name string) (string, bool) {
	c, ok := cmdletIndex[strings.ToLower(name)]
	return c, ok
}

// resolve maps a command name to its canonical cmdlet spelling, following the
// script's own aliases and then the built-in alias table. viaAlias reports
// whether an alias was expanded.
func (l *lowerer) resolve(name string) (canonical string, viaAlias bool) {
	if c, ok := canonicalCmdlet(name); ok {
		return c, false
	}
	var declared map[string]string
	if l.prog != nil {
		declared = l.prog.Aliases
	}
	if target, ok := LookupAlias(name, declared); ok {
		if c, ok := canonicalCmdlet(target); ok {
			return c, true
		}
		return target, true
	}
	return name, false
}

func (l *lowerer) command(s *Stmt) {
	c := s.Cmd
	if c == nil {
		return
	}
	canonical, viaAlias := l.resolve(c.Name)

	if reason, ok := l.topReason(c, canonical); ok {
		l.emitEff(topEffect(engine.ModeDirect), atom(engine.AtomCommand, canonical, c.Pos))
		l.conservative = true
		l.note("⊤ %s → CodeExec(⊤): %s", cmdLabel(c, canonical), reason)
		l.redirs(c)
		return
	}
	if l.prog != nil && l.prog.Funcs[canonical] {
		l.emitEff(topEffect(engine.ModeTransitive), atom(engine.AtomCommand, canonical, c.Pos))
		l.conservative = true
		l.note("⊤ shell function %s → CodeExec(⊤, transitively): body is opaque", canonical)
		l.redirs(c)
		return
	}
	specs, known := Cmdlets[canonical]
	if !known {
		l.emitEff(topEffect(engine.ModeDirect), atom(engine.AtomCommand, canonical, c.Pos))
		l.conservative = true
		l.note("⊤ unknown command %q → CodeExec(⊤)", canonical)
		l.redirs(c)
		return
	}
	if viaAlias {
		l.note("alias %s → %s", c.Name, canonical)
	}
	if len(specs) == 0 {
		l.note("%s: no external effect", canonical)
		l.redirs(c)
		return
	}
	for _, sp := range specs {
		l.emitSpec(c, canonical, sp)
	}
	l.bumpFor(c, canonical)
	l.redirs(c)
}

// topReason reports whether a command must be lowered to ⊤ and why. It covers
// the constructs the task pins: Invoke-Expression, dot-sourcing, Add-Type,
// New-Object, [ScriptBlock]::Create (handled as a static invocation upstream),
// the call operator & with a computed name, and splatting.
func (l *lowerer) topReason(c *Command, canonical string) (string, bool) {
	switch strings.ToLower(canonical) {
	case "invoke-expression":
		return "Invoke-Expression evaluates data as code", true
	case "add-type":
		return "Add-Type compiles and loads arbitrary code", true
	case "new-object":
		return "New-Object instantiates an arbitrary .NET type", true
	}
	if c.DotSource {
		return "dot-sourcing runs an external script in the caller's scope", true
	}
	if c.CallOperator && (c.ComputedName || c.Name == "") {
		return "call operator & with a computed name", true
	}
	for _, a := range c.Args {
		if a.Splat {
			return "splatting " + a.Text + " hides the parameter set", true
		}
	}
	if c.ComputedName {
		return "computed command name", true
	}
	return "", false
}

// emitSpec lowers one cmdlet spec: it resolves the target set and emits the
// corresponding effect(s), handling the Env/Variable/Registry providers and
// credential-material detection for reads.
func (l *lowerer) emitSpec(c *Command, cmd string, sp Spec) {
	base := atom(engine.AtomCommand, cmd, c.Pos)
	targets := l.targetWords(c, sp.Target)
	cred := sp.Kind == engine.KindFSRead && isCredentialText(c.Text)
	if len(targets) == 0 {
		// A path/name/url effect with no operand is fed from the pipeline or a
		// default location: the target is unknown, so widen to ⊤ rather than
		// claim ⊥ (no target).
		switch sp.Target {
		case TargetPath, TargetURL, TargetName:
			e := effectOf(sp.Kind, engine.ScopeTop(), sp.Mode, sp.Reversible)
			l.emitEff(e, withSink([]engine.Atom{base}, e)...)
			l.note("%s: %s ⊤ (pipelines/default) → %s", cmd, sp.Op, sp.Kind)
			if cred {
				l.emitEff(effectOf(engine.KindCredAccess, engine.ScopeTop(), engine.ModeDirect, false),
					base, atom(engine.AtomSource, "credential", c.Pos))
				l.note("%s: credential material ⊤ → CredAccess", cmd)
			}
			return
		}
		l.emitOne(c, cmd, sp, "", cred)
		return
	}
	for _, t := range targets {
		l.emitOne(c, cmd, sp, t, cred)
	}
}

func (l *lowerer) emitOne(c *Command, cmd string, sp Spec, target string, cred bool) {
	base := []engine.Atom{atom(engine.AtomCommand, cmd, c.Pos)}
	if target != "" {
		base = append(base, atom(engine.AtomOperand, target, l.targetPos(c, target)))
	}
	switch driveOf(target) {
	case DriveEnv:
		en := envNameOf(target)
		kind := engine.KindEnvRead
		if sp.Kind == engine.KindFSWrite || sp.Kind == engine.KindFSMeta {
			kind = engine.KindEnvWrite
		}
		l.emitEff(effectOf(kind, scopeOf(en), sp.Mode, sp.Reversible), base...)
		l.note("%s: %s Env:%s → %s", cmd, sp.Op, en, kind)
		return

	case DriveVariable:
		l.note("%s: %s Variable: provider is session-local → no external effect", cmd, sp.Op)
		return

	case DriveRegistry:
		if !l.windows {
			l.note("%s: %s Registry: provider is Windows-only → skipped on this host", cmd, sp.Op)
			return
		}
		kind := sp.Kind
		if sp.Kind == engine.KindFSWrite || sp.Kind == engine.KindFSMeta || sp.Kind == engine.KindFSRead {
			kind = engine.KindPersist
		}
		l.emitEff(effectOf(kind, scopeOf(target), sp.Mode, sp.Reversible), base...)
		l.note("%s: %s %s → %s", cmd, sp.Op, target, kind)
		return
	}

	e := effectOf(sp.Kind, scopeOf(target), sp.Mode, sp.Reversible)
	l.emitEff(e, withSink(base, e)...)
	l.note("%s: %s %s → %s", cmd, sp.Op, quoteTarget(target), sp.Kind)
	if cred {
		l.emitEff(effectOf(engine.KindCredAccess, scopeOf(target), engine.ModeDirect, false),
			append(base, atom(engine.AtomSource, "credential", c.Pos))...)
		l.note("%s: credential material %s → CredAccess", cmd, quoteTarget(target))
	}
}

// targetWords resolves the target strings a spec applies to.
func (l *lowerer) targetWords(c *Command, k TargetKind) []string {
	switch k {
	case TargetNone:
		return nil
	case TargetSelf:
		if c.Name != "" {
			return []string{c.Name}
		}
		return nil
	case TargetCwd:
		return []string{"."}
	}
	var vals []string
	switch k {
	case TargetPath:
		for _, b := range c.Bindings {
			if b.Param != nil && pathParam(b.Param.Bare()) && b.Value != nil {
				vals = append(vals, b.Value.Text)
			}
		}
	case TargetURL:
		// A network target is carried by a URL-ish parameter (-Uri/-Url/
		// -ConnectionUri/-Proxy/-SmtpServer); a probe cmdlet may instead name its
		// peer with a host-style parameter (-ComputerName/-Name), so those are
		// consulted next. Only when neither is present is the URL the operand, as
		// in `Invoke-WebRequest https://…`. An explicit parameter deliberately
		// wins over any stray operand, so the egress is reported at the
		// parameter's endpoint rather than at a decoy operand.
		for _, b := range c.Bindings {
			if b.Param != nil && urlParam(b.Param.Bare()) && b.Value != nil {
				vals = append(vals, b.Value.Text)
			}
		}
		if len(vals) == 0 {
			for _, b := range c.Bindings {
				if b.Param != nil && nameParam(b.Param.Bare()) && b.Value != nil {
					vals = append(vals, b.Value.Text)
				}
			}
		}
	case TargetName:
		for _, b := range c.Bindings {
			if b.Param != nil && nameParam(b.Param.Bare()) && b.Value != nil {
				vals = append(vals, b.Value.Text)
			}
		}
	}
	if len(vals) == 0 {
		for _, a := range c.Args {
			vals = append(vals, a.Text)
		}
	}
	return vals
}

// targetPos returns the source position of the word that carries target: the
// binding value or positional argument it was read from. It falls back to the
// command's own position when the target is synthetic (".", the command name)
// or cannot be located, so the operand atom a why-trace cites points at the
// operand rather than the whole command.
func (l *lowerer) targetPos(c *Command, target string) Pos {
	if c == nil {
		return Pos{}
	}
	for _, b := range c.Bindings {
		if b != nil && b.Value != nil && b.Value.Text == target {
			return b.Value.Pos
		}
	}
	for _, a := range c.Args {
		if a != nil && a.Text == target {
			return a.Pos
		}
	}
	return c.Pos
}

// redirs lowers a command's redirections: > and >> write their target file.
func (l *lowerer) redirs(c *Command) {
	for _, r := range c.Redirs {
		if r.Word == nil || r.Word.Text == "" {
			l.emitEff(effectOf(engine.KindFSWrite, engine.ScopeTop(), engine.ModeDirect, false),
				atom(engine.AtomRedirect, r.Op, r.Pos))
			l.note("redirection %s → FSWrite(⊤)", r.Op)
			continue
		}
		l.emitEff(effectOf(engine.KindFSWrite, scopeOf(r.Word.Text), engine.ModeDirect, false),
			atom(engine.AtomCommand, c.Name, c.Pos), atom(engine.AtomRedirect, r.Word.Text, r.Word.Pos))
		l.note("redirection %s %s → FSWrite", r.Op, r.Word.Text)
	}
}

// bumpFor raises the destructiveness for confirmed destructive invocations.
func (l *lowerer) bumpFor(c *Command, cmd string) {
	if strings.EqualFold(cmd, "Remove-Item") && (c.HasParam("Recurse") || c.HasParam("Force")) {
		l.bump = l.bump.Join(engine.DestructCritical)
		l.note("Remove-Item with -Recurse/-Force: recursive/forced delete → Critical")
	}
}

// assignment lowers a variable/environment assignment.
func (l *lowerer) assignment(a *Assign) {
	if a == nil {
		return
	}
	switch a.Drive {
	case DriveEnv:
		if a.Name == "" {
			l.top("environment assignment with an unknown variable name")
			return
		}
		l.emitEff(effectOf(engine.KindEnvWrite, scopeOf(a.Name), engine.ModeDirect, false),
			atom(engine.AtomLiteral, a.Name, a.Pos))
		l.note("$env:%s = … → EnvWrite", a.Name)
	case DriveRegistry:
		if !l.windows {
			l.note("registry assignment %s: Windows-only → skipped", a.Name)
			return
		}
		l.emitEff(effectOf(engine.KindPersist, scopeOf(a.Name), engine.ModeDirect, false),
			atom(engine.AtomLiteral, a.Name, a.Pos))
		l.note("registry assignment %s → Persist", a.Name)
	default:
		l.note("session variable assignment %s: no external effect", a.TargetWord.Text)
	}
}

// finish normalises the collected effects into canonical order, folds the
// destructiveness, de-duplicates the notes and fills the result.
func (l *lowerer) finish(r *Result) {
	rep := engine.NewReport()
	rep.Effects = l.effects
	rep.Normalize()
	r.Effects = rep.Effects
	r.Destructiveness = rep.Destructiveness.Join(l.bump)
	l.stampFile()
	r.Derivations = l.ders
	r.Conservative = l.conservative
	r.Notes = dedupSorted(l.notes)
}

// stampFile fills in the source file of every why-trace atom from the program's
// file, so a position recorded with line/column alone still names its source.
func (l *lowerer) stampFile() {
	file := ""
	if l.prog != nil {
		file = l.prog.File
	}
	if file == "" {
		return
	}
	for i := range l.ders {
		for j := range l.ders[i].Atoms {
			a := &l.ders[i].Atoms[j]
			if a.Loc != nil && a.Loc.File == "" {
				a.Loc.File = file
			}
		}
	}
}

// ===========================================================================
// Why-trace atoms
// ===========================================================================

// atom builds a source atom for a why-trace, carrying the frontend position
// when one is known.
func atom(kind engine.AtomKind, text string, p Pos) engine.Atom {
	var loc *engine.SourceLoc
	if p.Line > 0 || p.Col > 0 {
		loc = &engine.SourceLoc{Line: p.Line, Col: p.Col}
	}
	return engine.Atom{Kind: kind, Text: text, Loc: loc}
}

// withSink appends the sink atom an egress effect must cite, so a data-carrying
// outbound request is explained by the network sink it reaches.
func withSink(atoms []engine.Atom, e engine.Effect) []engine.Atom {
	if e.Kind != engine.KindNetEgress {
		return atoms
	}
	return append(append([]engine.Atom{}, atoms...), engine.Atom{Kind: engine.AtomSink, Text: "NetEgress"})
}

// ruleForKind names the rule the lowerer fires for an effect kind; the names
// mirror the why-trace vocabulary (fs.read, net.egress, cred.access…).
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

// ===========================================================================
// Credential-material detection
// ===========================================================================

// credentialMarkers are substrings that, when present in a command's text,
// indicate it touches credential or secret material.
var credentialMarkers = []string{
	".ssh", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts",
	"authorized_keys", ".aws", "credentials", ".netrc", ".git-credentials",
	".pem", ".pfx", ".p12", ".pgpass", ".npmrc", ".htpasswd",
	"password", "passwd", "secret", "token", "apikey", "api_key",
	"kubeconfig", ".kube", ".azure", ".docker/config.json",
	"shadow", "ntds.dit", "sam.json",
}

// isCredentialText reports whether text mentions credential material.
func isCredentialText(text string) bool {
	if text == "" {
		return false
	}
	lower := strings.ToLower(text)
	for _, m := range credentialMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// ===========================================================================
// Small helpers
// ===========================================================================

// cmdLabel renders a command for a note: the raw name, and its canonical form
// when that differs.
func cmdLabel(c *Command, canonical string) string {
	if c == nil {
		return canonical
	}
	name := c.Name
	if name == "" && c.NameWord != nil {
		name = c.NameWord.Text
	}
	if name == "" {
		return canonical
	}
	if canonical != "" && !strings.EqualFold(name, canonical) {
		return name + "→" + canonical
	}
	return name
}

// quoteTarget renders a target for a note.
func quoteTarget(t string) string {
	if t == "" {
		return "∅"
	}
	return "\"" + t + "\""
}

// dedupSorted returns a sorted, duplicate-free copy of xs.
func dedupSorted(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	sort.Strings(xs)
	out := xs[:1]
	for _, x := range xs[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}
