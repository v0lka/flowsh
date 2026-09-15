// Package kb holds the effect knowledge base: a hand-verified dataset mapping
// command-line parameters to the effects they contribute, together with a
// dedicated destructive-flags table.
//
// The dataset is authored as YAML under kb/data/*.yaml, compiled into the
// binary with go:embed, and parsed at start-up without touching the filesystem.
// The document schema is frozen and versioned: every data file declares a
// `version`, and the loader refuses to load an unknown one.
//
// Dependency direction: kb lowers into the frozen core (package engine); the
// core never imports kb.
package kb

import (
	"errors"
	"fmt"
	"strings"

	"github.com/v0lka/flowsh/engine"
)

// SchemaVersion is the version of the knowledge-base document schema. Every
// data file must declare exactly this value in its top-level `version` field;
// the loader rejects missing or unknown versions with an explicit error.
//
// v2 added the per-parameter `fileRef` marker (the `@file` convention); a v1
// document cannot express it, so the schema version was bumped rather than
// extended in place.
const SchemaVersion = "effect-kb/v2"

// KnownVersions lists every schema version the loader accepts. Keeping this an
// explicit list (rather than an inline string comparison) makes version
// handling a checked decision that can be extended without a schema break.
var KnownVersions = []string{SchemaVersion}

// Known reports whether v is an accepted schema version.
func Known(v string) bool {
	for _, k := range KnownVersions {
		if k == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Dialect
// ---------------------------------------------------------------------------

// Dialect names the implementation family (the command tradition) a command's
// parameter set is documented against. A command belongs to exactly one family.
type Dialect string

const (
	DialectPOSIX     Dialect = "posix"      // POSIX.1-2017 utilities
	DialectGNU       Dialect = "gnu"        // GNU coreutils/extensions
	DialectBSD       Dialect = "bsd"        // BSD/macOS variants
	DialectUtilLinux Dialect = "util-linux" // util-linux
	DialectFindutils Dialect = "findutils"  // GNU findutils
	DialectTar       Dialect = "tar"        // GNU tar / bsdtar
	DialectNetTools  Dialect = "net-tools"  // net-tools (ifconfig, route, …)
	DialectCurl      Dialect = "curl"
	DialectWget      Dialect = "wget"
	DialectNetcat    Dialect = "netcat" // nc
	DialectOpenSSH   Dialect = "openssh"
	DialectRsync     Dialect = "rsync"
	DialectGit       Dialect = "git"
	DialectPkgmgr    Dialect = "pkgmgr"   // distribution package managers
	DialectBuild     Dialect = "build"    // compilers, linkers, build systems
	DialectProcps    Dialect = "procps"   // procps-ng process/system utilities
	DialectSystemd   Dialect = "systemd"  // systemd services and journal
	DialectArchive   Dialect = "archive"  // archive and compression tools
	DialectSecurity  Dialect = "security" // users, permissions, audit, crypto
	DialectVCS       Dialect = "vcs"      // version-control clients
	DialectBuiltin   Dialect = "builtin"  // shell builtins
)

// Dialects is every valid dialect, in canonical order.
var Dialects = []Dialect{
	DialectPOSIX, DialectGNU, DialectBSD, DialectUtilLinux, DialectFindutils,
	DialectTar, DialectNetTools, DialectCurl, DialectWget, DialectNetcat,
	DialectOpenSSH, DialectRsync, DialectGit,
	DialectPkgmgr, DialectBuild, DialectProcps, DialectSystemd,
	DialectArchive, DialectSecurity, DialectVCS,
	DialectBuiltin,
}

var dialectSet = setOf(Dialects)

// Valid reports whether d is a defined dialect.
func (d Dialect) Valid() bool { _, ok := dialectSet[d]; return ok }

// ---------------------------------------------------------------------------
// ParamKind
// ---------------------------------------------------------------------------

// ParamKind classifies how a parameter is written on the command line.
type ParamKind string

const (
	// ParamFlag is a boolean switch, e.g. `-r`, `--recursive`, `-delete`.
	ParamFlag ParamKind = "flag"
	// ParamOption is a parameter that takes a value, e.g. `-o FILE`,
	// `--output=FILE`, `-m 0755`.
	ParamOption ParamKind = "option"
	// ParamPositional is a positional operand, e.g. `rm FILE`, `cp SRC DEST`.
	ParamPositional ParamKind = "positional"
	// ParamAssign is a key=value operand, e.g. `dd of=FILE`, `if=FILE`.
	ParamAssign ParamKind = "assign"
)

// ParamKinds is every valid parameter kind, in canonical order.
var ParamKinds = []ParamKind{ParamFlag, ParamOption, ParamPositional, ParamAssign}

var paramKindSet = setOf(ParamKinds)

// Valid reports whether k is a defined parameter kind.
func (k ParamKind) Valid() bool { _, ok := paramKindSet[k]; return ok }

// ---------------------------------------------------------------------------
// ValueSource
// ---------------------------------------------------------------------------

// ValueSource names where the value an effect acts on comes from. It is the
// KB's answer to "effect on what?": the analysed command supplies the argument
// slice, the loader matches a parameter, and the source says which token of the
// invocation becomes the effect's target.
type ValueSource string

const (
	ValueArgs      ValueSource = "args"      // positional arguments of the invocation
	ValueFlagValue ValueSource = "flagValue" // the value attached to the matched flag/option
	ValueStdin     ValueSource = "stdin"     // standard input
	ValueEnv       ValueSource = "env"       // the process environment
	ValueCwd       ValueSource = "cwd"       // the current working directory
	ValueSelf      ValueSource = "self"      // the command's own binary/image
	ValueLiteral   ValueSource = "literal"   // a literal encoded in the flag value
)

// ValueSources is every valid value source, in canonical order.
var ValueSources = []ValueSource{
	ValueArgs, ValueFlagValue, ValueStdin, ValueEnv, ValueCwd, ValueSelf, ValueLiteral,
}

var valueSourceSet = setOf(ValueSources)

// Valid reports whether v is a defined value source.
func (v ValueSource) Valid() bool { _, ok := valueSourceSet[v]; return ok }

// ---------------------------------------------------------------------------
// Effect
// ---------------------------------------------------------------------------

// Effect is the effect a single parameter contributes. It reuses the core's
// closed EffectKind/EffectMode sets and adds the KB-specific value source that
// says which part of the invocation the effect acts on.
type Effect struct {
	Kind      engine.EffectKind `yaml:"kind" json:"kind"`
	Mode      engine.EffectMode `yaml:"mode" json:"mode"`
	ValueFrom ValueSource       `yaml:"valueFrom" json:"valueFrom"`

	// FileRef marks a parameter whose value follows the `@file` convention:
	// a value of the form `@path` names a file whose *content* the command
	// consumes (and `@-` names standard input). It is meaningful only for an
	// option whose value is read from the flag itself (valueFrom: flagValue);
	// the analysis then reads that content as an additional filesystem read and
	// carries its provenance into the parameter's own effect.
	FileRef bool `yaml:"fileRef,omitempty" json:"fileRef,omitempty"`
}

// Validate reports whether the effect is well-formed and expressed in terms the
// core understands.
func (e Effect) Validate() error {
	if !e.Kind.Valid() {
		return fmt.Errorf("invalid effect kind %q", string(e.Kind))
	}
	if !e.Mode.Valid() {
		return fmt.Errorf("invalid effect mode %q", string(e.Mode))
	}
	if !e.ValueFrom.Valid() {
		return fmt.Errorf("invalid valueFrom %q", string(e.ValueFrom))
	}
	if e.FileRef && e.ValueFrom != ValueFlagValue {
		return fmt.Errorf("fileRef requires valueFrom %q, got %q", string(ValueFlagValue), string(e.ValueFrom))
	}
	return nil
}

// EngineEffect lowers the KB effect into a core engine.Effect. The KB supplies
// kind and mode (and a conservative default for reversibility); the analysis
// supplies the concrete target scope, taint and certainty.
func (e Effect) EngineEffect(target engine.Scope, taint engine.Taint, c engine.Certainty) engine.Effect {
	return engine.Effect{
		Kind:       e.Kind,
		Mode:       e.Mode,
		Target:     target,
		Taint:      taint,
		Certainty:  c,
		Reversible: DefaultReversible(e.Kind),
	}
}

// DefaultReversible reports whether effects of kind k are reversible by
// default. Read-only and advisory effects are; anything that mutates state is
// conservatively treated as not reversible.
func DefaultReversible(k engine.EffectKind) bool {
	switch k {
	case engine.KindFSRead, engine.KindEnvRead, engine.KindNetIngress,
		engine.KindNetEgress, engine.KindStdio, engine.KindCredAccess:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Param / Command
// ---------------------------------------------------------------------------

// Param is one parameter of a command and the effect it contributes.
type Param struct {
	// Spec is the parameter as written in the dataset: a flag (`-r`), an
	// option (`-o`), a positional operand (`FILE`), or an assignment (`of=`).
	Spec string `yaml:"spec" json:"spec"`
	// Kind classifies the parameter's surface syntax.
	Kind ParamKind `yaml:"kind" json:"kind"`
	// Effect is the primary effect this parameter contributes.
	Effect Effect `yaml:"effect" json:"effect"`
}

// Validate reports whether the parameter is well-formed. The spec is also
// checked against the kind so that the two cannot drift apart silently.
func (p Param) Validate() error {
	if p.Spec == "" {
		return errors.New("empty spec")
	}
	if !p.Kind.Valid() {
		return fmt.Errorf("param %q: invalid kind %q", p.Spec, string(p.Kind))
	}
	switch p.Kind {
	case ParamFlag, ParamOption:
		if !strings.HasPrefix(p.Spec, "-") {
			return fmt.Errorf("param %q: kind %q requires a spec starting with '-'", p.Spec, string(p.Kind))
		}
	case ParamAssign:
		if !strings.HasSuffix(p.Spec, "=") {
			return fmt.Errorf("param %q: kind %q requires a spec ending with '='", p.Spec, string(p.Kind))
		}
	case ParamPositional:
		if strings.HasPrefix(p.Spec, "-") {
			return fmt.Errorf("param %q: positional spec must not start with '-'", p.Spec)
		}
	}
	if err := p.Effect.Validate(); err != nil {
		return fmt.Errorf("param %q: effect: %w", p.Spec, err)
	}
	return nil
}

// Command is one command in the knowledge base.
type Command struct {
	Name    string   `yaml:"name" json:"name"`
	Dialect Dialect  `yaml:"dialect" json:"dialect"`
	Aliases []string `yaml:"aliases,omitempty" json:"aliases,omitempty"`
	Params  []Param  `yaml:"params" json:"params"`

	// idx indexes Params by Spec so the binder's per-token flag/option lookup
	// (Command.Param / Command.HasParam) is an O(1) map hit instead of a linear
	// scan over the parameter list. It is built once, after the parameter lists
	// are final, by KB.build. A nil idx — a Command literal that never went
	// through build, e.g. in a unit test — falls back to a linear scan, so zero
	// values stay usable.
	idx *paramIndex
}

// paramIndex maps a parameter Spec to its position in Command.Params. It is the
// precomputed form of the name/flag match the binder performs for every token of
// a command line, so growing a command's parameter list can never turn that
// match into an accidental O(tokens x params) hot path.
type paramIndex struct {
	bySpec map[string]int
	// assigns holds the ParamAssign params, in declaration order, so the
	// binder's assignment-operand match iterates only the (few) assign specs
	// instead of the command's whole parameter list.
	assigns []Param
}

// buildIndex precomputes the Spec-to-position index. On a duplicate spec the
// first occurrence wins; Validate rejects duplicates, so this tie-break only
// matters for a Command that never reached Validate.
func (c *Command) buildIndex() {
	ix := &paramIndex{bySpec: make(map[string]int, len(c.Params))}
	for i, p := range c.Params {
		if _, dup := ix.bySpec[p.Spec]; !dup {
			ix.bySpec[p.Spec] = i
		}
		if p.Kind == ParamAssign {
			ix.assigns = append(ix.assigns, p)
		}
	}
	c.idx = ix
}

// AssignParams returns the command's ParamAssign params, in declaration order.
// It returns the precomputed slice when the command is indexed (no scan, no
// allocation) and otherwise filters Params on the fly, so a hand-built Command
// literal keeps working. The binder uses it to match dd-style key=value operands
// without scanning the command's whole parameter list.
func (c Command) AssignParams() []Param {
	if c.idx != nil {
		return c.idx.assigns
	}
	var out []Param
	for _, p := range c.Params {
		if p.Kind == ParamAssign {
			out = append(out, p)
		}
	}
	return out
}

// Validate reports whether the command is well-formed.
func (c Command) Validate() error {
	if c.Name == "" {
		return errors.New("empty name")
	}
	if !c.Dialect.Valid() {
		return fmt.Errorf("%s: invalid dialect %q", c.Name, string(c.Dialect))
	}
	if len(c.Params) == 0 {
		return fmt.Errorf("%s: no params", c.Name)
	}
	seen := make(map[string]bool, len(c.Params))
	for i, p := range c.Params {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("%s: params[%d]: %w", c.Name, i, err)
		}
		if seen[p.Spec] {
			return fmt.Errorf("%s: duplicate param spec %q", c.Name, p.Spec)
		}
		seen[p.Spec] = true
	}
	return nil
}

// HasParam reports whether the command declares a parameter with the given spec.
// It is O(1) once the command has been indexed by KB.build, and falls back to a
// linear scan for an unindexed Command literal.
func (c Command) HasParam(spec string) bool {
	if c.idx != nil {
		_, ok := c.idx.bySpec[spec]
		return ok
	}
	for _, p := range c.Params {
		if p.Spec == spec {
			return true
		}
	}
	return false
}

// Param returns the parameter with the given spec, if declared. It is O(1) once
// the command has been indexed by KB.build, and falls back to a linear scan for
// an unindexed Command literal.
func (c Command) Param(spec string) (Param, bool) {
	if c.idx != nil {
		if i, ok := c.idx.bySpec[spec]; ok {
			return c.Params[i], true
		}
		return Param{}, false
	}
	for _, p := range c.Params {
		if p.Spec == spec {
			return p, true
		}
	}
	return Param{}, false
}

// ---------------------------------------------------------------------------
// Destructive table
// ---------------------------------------------------------------------------

// DestructiveClass is the severity class of a destructive parameter. The
// classes are lettered A–E and line up with the core Destructiveness lattice
// (A↔None … E↔Critical), so that a class can be folded into a report without a
// second taxonomy.
type DestructiveClass string

const (
	ClassNone     DestructiveClass = "A" // None — no lasting impact
	ClassLow      DestructiveClass = "B" // Low — reversible / read-only
	ClassMedium   DestructiveClass = "C" // Medium — recoverable with effort
	ClassHigh     DestructiveClass = "D" // High — hard to reverse
	ClassCritical DestructiveClass = "E" // Critical — irreversible / trust-breaking
)

// DestructiveClasses is every valid class, in increasing severity.
var DestructiveClasses = []DestructiveClass{ClassNone, ClassLow, ClassMedium, ClassHigh, ClassCritical}

var destructiveClassSet = setOf(DestructiveClasses)

// Valid reports whether c is a defined class.
func (c DestructiveClass) Valid() bool { _, ok := destructiveClassSet[c]; return ok }

// Severity maps the class onto the core destructiveness lattice.
func (c DestructiveClass) Severity() engine.Destructiveness {
	switch c {
	case ClassLow:
		return engine.DestructLow
	case ClassMedium:
		return engine.DestructMedium
	case ClassHigh:
		return engine.DestructHigh
	case ClassCritical:
		return engine.DestructCritical
	default:
		return engine.DestructNone
	}
}

// Destructive is one entry of the destructive-flags table: a (command, spec)
// pair that is known to be destructive, its class, and why.
type Destructive struct {
	Command string           `yaml:"command" json:"command"`
	Spec    string           `yaml:"spec" json:"spec"`
	Class   DestructiveClass `yaml:"class" json:"class"`
	Reason  string           `yaml:"reason" json:"reason"`
}

// Validate reports whether the entry is well-formed (referential integrity
// against the command set is enforced by KB.Validate).
func (d Destructive) Validate() error {
	if d.Command == "" {
		return errors.New("empty command")
	}
	if d.Spec == "" {
		return errors.New("empty spec")
	}
	if !d.Class.Valid() {
		return fmt.Errorf("%s %s: invalid class %q", d.Command, d.Spec, string(d.Class))
	}
	if d.Reason == "" {
		return fmt.Errorf("%s %s: empty reason", d.Command, d.Spec)
	}
	return nil
}

// ---------------------------------------------------------------------------
// KB
// ---------------------------------------------------------------------------

// KB is a loaded knowledge base.
type KB struct {
	Version     string
	Commands    []Command     // sorted by Name
	Destructive []Destructive // sorted by (Command, Spec)

	byName  map[string]*Command
	byDestr map[string]*Destructive
}

// Command resolves a command by name or by any of its aliases.
func (k *KB) Command(name string) (*Command, bool) {
	c, ok := k.byName[name]
	return c, ok
}

// DestructiveFor resolves a destructive-table entry by command name/alias and
// parameter spec.
func (k *KB) DestructiveFor(command, spec string) (*Destructive, bool) {
	d, ok := k.byDestr[command+"|"+spec]
	return d, ok
}

// CommandNames returns the names of every command, in sorted order.
func (k *KB) CommandNames() []string {
	out := make([]string, len(k.Commands))
	for i := range k.Commands {
		out[i] = k.Commands[i].Name
	}
	return out
}

// Validate reports whether the knowledge base is internally consistent: a known
// schema version, every command well-formed, and every destructive entry
// referring to a declared parameter of a known command.
func (k *KB) Validate() error {
	if !Known(k.Version) {
		return fmt.Errorf("kb: unsupported schema version %q (known: %s)", k.Version, strings.Join(KnownVersions, ", "))
	}
	for i := range k.Commands {
		if err := k.Commands[i].Validate(); err != nil {
			return fmt.Errorf("kb: commands[%d]: %w", i, err)
		}
	}
	for i := range k.Destructive {
		d := &k.Destructive[i]
		if err := d.Validate(); err != nil {
			return fmt.Errorf("kb: destructive[%d]: %w", i, err)
		}
		cmd, ok := k.Command(d.Command)
		if !ok {
			return fmt.Errorf("kb: destructive[%d]: %s: unknown command", i, d.Command)
		}
		if !cmd.HasParam(d.Spec) {
			return fmt.Errorf("kb: destructive[%d]: %s: spec %q is not declared on the command", i, d.Command, d.Spec)
		}
	}
	return nil
}

// setOf builds a membership set from a slice of comparable values.
func setOf[T comparable](xs []T) map[T]struct{} {
	m := make(map[T]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}
