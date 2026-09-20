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
		aliases: map[string]string{},
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
			// Record a declared alias only after it has been lowered, so it
			// affects the statements that follow it and nothing before.
			if name, value, ok := aliasDecl(s.Cmd); ok {
				l.aliases[strings.ToLower(name)] = value
			}
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
	// aliases holds the aliases declared by the source *before* the statement
	// currently being lowered, keyed by folded name. Resolution is therefore
	// order-aware: an alias only rewrites the calls that follow its declaration,
	// as in PowerShell (a later Set-Alias must not rewrite an earlier call).
	aliases map[string]string
	// gatedEgress records that the egress gate dropped a literal target during
	// the command currently being lowered, so the intrinsic ProcSpawn fallback
	// knows the command would otherwise contribute no effect.
	gatedEgress bool
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
//
// Resolution follows PowerShell's precedence alias > function > cmdlet: a
// script-declared alias shadows a built-in alias and a cmdlet of the same name.
// Only aliases declared *before* the current statement are consulted, so
// resolution follows source order.
func (l *lowerer) resolve(name string) (canonical string, viaAlias bool) {
	if l.aliases != nil {
		if target, ok := l.aliases[strings.ToLower(name)]; ok {
			if c, ok := canonicalCmdlet(target); ok {
				return c, true
			}
			return target, true
		}
	}
	if target, ok := LookupAlias(name, nil); ok {
		if c, ok := canonicalCmdlet(target); ok {
			return c, true
		}
		return target, true
	}
	if c, ok := canonicalCmdlet(name); ok {
		return c, false
	}
	return name, false
}

func (l *lowerer) command(s *Stmt) {
	c := s.Cmd
	if c == nil {
		return
	}
	// before records the effect count so the intrinsic ProcSpawn fallback can
	// tell whether this command (or its specs) contributed any effect at all.
	before := len(l.effects)
	l.gatedEgress = false
	if c.ArrayComma {
		// A comma-separated argument list (`Remove-Item x,y`) is not modelled:
		// the operand set cannot be bounded, so degrade to ⊤ rather than bind a
		// garbled target.
		l.emitEff(topEffect(engine.ModeDirect), atom(engine.AtomCommand, c.Name, c.Pos))
		l.conservative = true
		l.note("⊤ %s: comma-separated argument list is not modelled → CodeExec(⊤)", cmdLabel(c, c.Name))
		l.redirs(c)
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
	if l.prog != nil && l.prog.Funcs[strings.ToLower(canonical)] {
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
	l.dataFiles(c, canonical)
	l.bumpFor(c, canonical)
	// A command whose only effect was a gated-out egress target (a literal that
	// names no network address) must not leave the report empty: emit the
	// command's intrinsic "it ran" effect, as the bash binder does, so the
	// no-silent-miss invariant holds on this path too. Pure cmdlets that
	// contribute no external effect are intentionally left effect-free.
	l.ensureGatedEgressFallback(c, canonical, before)
	l.redirs(c)
}

// ensureGatedEgressFallback emits the command's intrinsic "it ran" effect when
// the egress gate dropped the command's only effect and nothing else replaced
// it. It is the PowerShell counterpart of the bash binder's intrinsicProcSpawn,
// closing the fail-open hole the gate would otherwise create for a command like
// Invoke-WebRequest -Uri ./local.html (a literal that names no network address).
func (l *lowerer) ensureGatedEgressFallback(c *Command, canonical string, before int) {
	if len(l.effects) != before || !l.gatedEgress || l.conservative {
		return
	}
	e := effectOf(engine.KindProcSpawn, scopeOf(canonical), engine.ModeDirect, false)
	l.emitEff(e, atom(engine.AtomCommand, canonical, c.Pos))
	l.note("%s: egress target gated out → ProcSpawn", cmdLabel(c, canonical))
}

// egressTargetUnresolved reports whether a lowering target is not a
// confidently-literal destination word: it references a variable ($), carries a
// backtick escape, or is a parenthesised sub-expression. Such a target's value
// is not known at analysis time, so its egress stays as unresolved (⊤) rather
// than being judged — and rejected — as a literal.
func egressTargetUnresolved(s string) bool {
	return strings.ContainsAny(s, "$`()")
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
	case "invoke-history":
		return "Invoke-History re-executes a previous command (arbitrary code)", true
	case "trace-command":
		return "Trace-Command evaluates an arbitrary expression string", true
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
			// Note: the effect's *target* is ⊤, but the effect is not the ⊤
			// shape (CodeExec over any), so the conservative flag is deliberately
			// NOT set here: the result contract ties Conservative to a genuine
			// CodeExec/⊤ effect, and a read/write with an unknown target is still
			// a bounded kind.
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

	case DriveFunction, DriveAlias:
		// Function:/Alias: name in-memory session state, which is not durable
		// off-process state: a write there has no external effect.
		l.note("%s: %s %s → %s: session-local provider, no external effect", cmd, sp.Op, target, driveOf(target))
		return

	case DriveWSMan:
		// WSMan: is durable host configuration (like the registry), so a write
		// lowers to Persist.
		l.emitEff(effectOf(engine.KindPersist, scopeOf(target), sp.Mode, sp.Reversible), base...)
		l.note("%s: %s %s → Persist (WSMan configuration)", cmd, sp.Op, target)
		return

	case DriveCert:
		// Cert: is the certificate store: reading it is credential access, while
		// installing/removing a certificate mutates persisted host state.
		kind := engine.KindCredAccess
		if sp.Kind == engine.KindFSWrite || sp.Kind == engine.KindFSMeta {
			kind = engine.KindPersist
		}
		l.emitEff(effectOf(kind, scopeOf(target), sp.Mode, sp.Reversible), base...)
		l.note("%s: %s %s → %s (certificate store)", cmd, sp.Op, target, kind)
		return
	}

	// Egress target gate: a NetEgress target must pass the host/URL grammar.
	// A target that references a variable or an expression is unresolved: the
	// egress stays, widened to ⊤ (the unresolved egress keeps participating in
	// the network controls). A literal that names no network address creates
	// no egress effect at all. Destination parameters (-Uri, -ComputerName)
	// name hosts by declaration, so the lenient grammar accepts single-label
	// computer names.
	scope := scopeOf(target)
	if sp.Kind == engine.KindNetEgress {
		switch {
		case target == "":
			// No target text (TargetNone/TargetSelf specs): the effect keeps
			// the ⊥ target it always had.
		case egressTargetUnresolved(target):
			// A target that references a variable, carries a backtick escape or
			// is a parenthesised sub-expression is not known at analysis time:
			// the egress stays, widened to ⊤ (the unresolved egress keeps
			// participating in the network controls).
			scope = engine.ScopeTop()
		case engine.HostShapedLenient(target):
		default:
			l.note("%s: %s %s names no network address → no egress", cmd, sp.Op, quoteTarget(target))
			l.gatedEgress = true
			return
		}
	}
	e := effectOf(sp.Kind, scope, sp.Mode, sp.Reversible)
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
				vals = append(vals, cleanTarget(b.Value))
			}
		}
		// A positional operand names the item the cmdlet acts on, so it is
		// combined with the named path parameters rather than being dropped when
		// one is present (`Move-Item C:\a -Destination C:\b` acts on both).
		vals = append(vals, l.operands(c)...)
		// A filesystem-selection parameter (-Include/-Exclude/-Filter) is not a
		// path and must not be recorded as the target: it only filters a query.
		// When no path parameter or operand names the location, no target is
		// contributed, so emitSpec widens it to ⊤ (a bounded effect kind over an
		// unknown target) rather than fabricating a path from the pattern.
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
				vals = append(vals, cleanTarget(b.Value))
			}
		}
		if len(vals) == 0 {
			for _, b := range c.Bindings {
				if b.Param != nil && nameParam(b.Param.Bare()) && b.Value != nil {
					vals = append(vals, cleanTarget(b.Value))
				}
			}
		}
		if len(vals) == 0 {
			vals = append(vals, l.operands(c)...)
		}
	case TargetName:
		for _, b := range c.Bindings {
			if b.Param != nil && nameParam(b.Param.Bare()) && b.Value != nil {
				vals = append(vals, cleanTarget(b.Value))
			}
		}
		if len(vals) == 0 {
			vals = append(vals, l.operands(c)...)
		}
	}
	return vals
}

// operands returns the positional operand texts of a command, with surrounding
// quotes stripped.
func (l *lowerer) operands(c *Command) []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Args))
	for _, a := range c.Args {
		if a == nil {
			continue
		}
		out = append(out, cleanTarget(a))
	}
	return out
}

// cleanTarget returns a word's target text with one matching pair of surrounding
// quotes stripped, so a quoted operand records the real path (`'C:\a'` →
// `C:\a`) rather than the quoted source spelling.
func cleanTarget(w *Word) string {
	if w == nil {
		return ""
	}
	return unquoteWord(w.Text)
}

// dataFiles lowers the data-file parameters of a cmdlet that is otherwise about
// something else (a network request, a mail message): -InFile and -Attachments
// name a file that is read, -OutFile names a file that is written, and the
// catalog output path is written by New-FileCatalog. Without this the file
// read/write would be lost.
func (l *lowerer) dataFiles(c *Command, cmd string) {
	for _, b := range c.Bindings {
		if b.Param == nil || b.Value == nil {
			continue
		}
		kind, ok := dataFileKind(cmd, b.Param.Bare())
		if !ok {
			continue
		}
		t := cleanTarget(b.Value)
		if t == "" {
			continue
		}
		e := effectOf(kind, scopeOf(t), engine.ModeDirect, kind == engine.KindFSRead)
		base := []engine.Atom{atom(engine.AtomCommand, cmd, c.Pos), atom(engine.AtomOperand, t, b.Value.Pos)}
		l.emitEff(e, withSink(base, e)...)
		l.note("%s: %s %s → %s", cmd, b.Param.Name, quoteTarget(t), kind)
		if kind == engine.KindFSRead && isCredentialText(t) {
			l.emitEff(effectOf(engine.KindCredAccess, scopeOf(t), engine.ModeDirect, false),
				atom(engine.AtomCommand, cmd, c.Pos), atom(engine.AtomSource, "credential", b.Value.Pos))
			l.note("%s: credential material %s → CredAccess", cmd, quoteTarget(t))
		}
	}
}

// dataFileKind classifies a parameter that names a data file read from or
// written to by a cmdlet: -InFile/-Attachments are reads; -OutFile is a write.
// The catalog output path is a write only for New-FileCatalog — Test-FileCatalog
// accepts the same parameter names but merely reads the catalog it verifies, so
// the classification is cmdlet-aware rather than global.
func dataFileKind(cmd, bare string) (engine.EffectKind, bool) {
	b := bareParam(bare)
	if inNames(readDataNames, b) {
		return engine.KindFSRead, true
	}
	if inNames(writeDataNames, b) {
		return engine.KindFSWrite, true
	}
	if strings.EqualFold(cmd, "New-FileCatalog") && inNames(catalogOutputNames, b) {
		return engine.KindFSWrite, true
	}
	return "", false
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
		if strings.Contains(r.Op, "&") {
			// A stream merge (2>&1, *>&1): the target is a file descriptor, not
			// a path, so no file is written.
			l.note("redirection %s → stream merge (no file)", r.Op)
			continue
		}
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
	if strings.EqualFold(cmd, "Remove-Item") {
		if c.HasParam("Recurse") || c.HasParam("Force") || hasSwitchCanon(c, "recurse") || hasSwitchCanon(c, "force") {
			l.bump = l.bump.Join(engine.DestructCritical)
			l.note("Remove-Item with -Recurse/-Force: recursive/forced delete → Critical")
		}
		return
	}
	// Disk-wiping Storage cmdlets destroy data irreversibly; escalate them to
	// Critical like the equivalent util-linux/fdisk operations.
	switch {
	case strings.EqualFold(cmd, "Clear-Disk"),
		strings.EqualFold(cmd, "Format-Volume"),
		strings.EqualFold(cmd, "Remove-Partition"):
		l.bump = l.bump.Join(engine.DestructCritical)
		l.note("%s: disk/volume destruction → Critical", cmd)
	}
}

// hasSwitchCanon reports whether the command carries a switch whose canonical
// name is canon, accepting PowerShell's parameter-name abbreviation (`-Rec` →
// recurse).
func hasSwitchCanon(c *Command, canon string) bool {
	if c == nil {
		return false
	}
	for _, p := range c.Params {
		if p == nil {
			continue
		}
		if got, ok := switchCanon(p.Bare()); ok && got == canon {
			return true
		}
	}
	return false
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
	l.markEgressTaint(r.Effects)
	r.Derivations = l.ders
	r.Conservative = l.conservative
	r.Notes = dedupSorted(l.notes)
}

// markEgressTaint pairs a secret read with an egress sink at the program level.
//
// The PowerShell frontend does not track dataflow, so provenance is never
// propagated from a credential read into the request that could carry it, and
// the exfiltration detector therefore never fires on a PowerShell input. As a
// conservative remedy, when the analysed program reads credential material and
// also reaches an egress sink, the sink is marked secret-bearing so DetectExfil
// can pair them. It over-approximates (the read need not feed the request), but
// it cannot miss an exfiltration the way the provenance-light path did.
func (l *lowerer) markEgressTaint(effs []engine.Effect) {
	secret := false
	for _, e := range effs {
		if engine.IsSecretRead(e) {
			secret = true
			break
		}
	}
	if !secret {
		return
	}
	for i := range effs {
		if effs[i].Kind == engine.KindNetEgress {
			effs[i].Taint = effs[i].Taint.Join(engine.TaintOf(engine.TaintSecret))
		}
	}
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
