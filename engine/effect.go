// Package engine is the frontend-agnostic core of the effect-analysis IR.
//
// It freezes three things and nothing else:
//
//   - the effect IR: Effect, EffectKind, EffectMode;
//   - the value lattices: Certainty, Scope, Taint and Destructiveness; and
//   - the Report format, including its why-trace and destructiveness summary.
//
// Dependency direction is one-way: frontends (per-language parsers/lifters)
// import this package, never the other way around. The invariant is enforced by
// TestCoreDoesNotImportFrontends, which fails if the package gains any import
// that is neither the standard library nor another core package of this module.
package engine

import "fmt"

// EffectKind enumerates the kinds of observable effect representable by the IR.
// The set is closed: it is exactly the set of kinds a frontend may emit.
type EffectKind string

const (
	KindFSRead     EffectKind = "FSRead"     // read filesystem content
	KindFSWrite    EffectKind = "FSWrite"    // create/modify filesystem content
	KindFSMeta     EffectKind = "FSMeta"     // metadata ops (stat, chmod, rename, unlink)
	KindEnvRead    EffectKind = "EnvRead"    // read process environment
	KindEnvWrite   EffectKind = "EnvWrite"   // mutate process environment
	KindNetEgress  EffectKind = "NetEgress"  // outbound network traffic
	KindNetIngress EffectKind = "NetIngress" // inbound network traffic / listening
	KindProcSpawn  EffectKind = "ProcSpawn"  // start a child process
	KindProcSignal EffectKind = "ProcSignal" // signal a process
	KindIPC        EffectKind = "IPC"        // inter-process communication (sockets, pipes, shm)
	KindStdio      EffectKind = "Stdio"      // read/write standard streams
	KindPrivEsc    EffectKind = "PrivEsc"    // attempt privilege escalation
	KindPersist    EffectKind = "Persist"    // persist state beyond lifetime (services, cron, registry)
	KindCredAccess EffectKind = "CredAccess" // access credential/secret material
	KindCodeExec   EffectKind = "CodeExec"   // execute data as code (eval, dlopen, shell)
)

// EffectKinds is every valid EffectKind, in canonical order.
var EffectKinds = []EffectKind{
	KindFSRead, KindFSWrite, KindFSMeta,
	KindEnvRead, KindEnvWrite,
	KindNetEgress, KindNetIngress,
	KindProcSpawn, KindProcSignal, KindIPC, KindStdio,
	KindPrivEsc, KindPersist, KindCredAccess, KindCodeExec,
}

var effectKindSet = func() map[EffectKind]struct{} {
	m := make(map[EffectKind]struct{}, len(EffectKinds))
	for _, k := range EffectKinds {
		m[k] = struct{}{}
	}
	return m
}()

// Valid reports whether k is a defined effect kind.
func (k EffectKind) Valid() bool { _, ok := effectKindSet[k]; return ok }

// EffectMode describes how an effect is realized with respect to the analyzed
// unit. It is orthogonal to EffectKind, which says *what* happens.
type EffectMode string

const (
	ModeDirect      EffectMode = "Direct"      // performed by the analyzed unit itself
	ModeTransitive  EffectMode = "Transitive"  // performed by a callee or dependency
	ModeAmbient     EffectMode = "Ambient"     // implicit, via the runtime or host
	ModeConditional EffectMode = "Conditional" // occurs only under a runtime guard
)

// EffectModes is every valid EffectMode, in canonical order.
var EffectModes = []EffectMode{ModeDirect, ModeTransitive, ModeAmbient, ModeConditional}

var effectModeSet = func() map[EffectMode]struct{} {
	m := make(map[EffectMode]struct{}, len(EffectModes))
	for _, x := range EffectModes {
		m[x] = struct{}{}
	}
	return m
}()

// Valid reports whether m is a defined effect mode.
func (m EffectMode) Valid() bool { _, ok := effectModeSet[m]; return ok }

// Effect is the atom of the IR: a single observable effect of the analyzed
// program. The field set is frozen.
//
// Target is a Scope — the lattice of target sets — so that joining two effects
// of the same kind and mode unions their targets instead of dropping them.
type Effect struct {
	Kind       EffectKind `json:"kind"`
	Target     Scope      `json:"target"`
	Mode       EffectMode `json:"mode"`
	Certainty  Certainty  `json:"certainty"`
	Taint      Taint      `json:"taint"`
	Reversible bool       `json:"reversible"`
}

// Key returns a stable identity for the effect, used for deterministic sorting
// and for referencing effects from why-traces. It is a function of Kind, Mode
// and the canonical form of Target.
func (e Effect) Key() string {
	return string(e.Kind) + "|" + string(e.Mode) + "|" + e.Target.canonical()
}

// Join is the least upper bound of two effects that share a kind and a mode:
// targets and taint are unioned, certainty is joined, and the result is
// reversible only if both operands are. The boolean result is false when the
// kinds or modes differ (such effects are not comparable in this lattice).
func (e Effect) Join(o Effect) (Effect, bool) {
	if e.Kind != o.Kind || e.Mode != o.Mode {
		return Effect{}, false
	}
	return Effect{
		Kind:       e.Kind,
		Mode:       e.Mode,
		Target:     e.Target.Join(o.Target),
		Certainty:  e.Certainty.Join(o.Certainty),
		Taint:      e.Taint.Join(o.Taint),
		Reversible: e.Reversible && o.Reversible,
	}, true
}

// Validate reports whether the effect is well-formed.
func (e Effect) Validate() error {
	if !e.Kind.Valid() {
		return fmt.Errorf("invalid effect kind %q", string(e.Kind))
	}
	if !e.Mode.Valid() {
		return fmt.Errorf("invalid effect mode %q", string(e.Mode))
	}
	if !e.Certainty.Valid() {
		return fmt.Errorf("invalid certainty %d", int(e.Certainty))
	}
	return nil
}
