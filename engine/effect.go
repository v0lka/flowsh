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

// FlowRole names the network data-flow relation an effect is the sink of: the
// effect consumes content that arrived over the network. It is the flow
// evidence a report surfaces (cradleFlows / ingestFlows), so a consumer keys on
// an actual data flow rather than on the co-occurrence of a NetEgress and a
// sink somewhere in the same program.
type FlowRole string

const (
	// FlowNone is the zero role: the effect is not the sink of a network data
	// flow.
	FlowNone FlowRole = ""
	// FlowCradle marks a CodeExec reached by network content: the download
	// cradle. It covers a pipe to a shell/interpreter (curl … | sh), a
	// source/`.` of a fetched path (source <(curl …)) and a code-execution sink
	// invoked on a command substitution (sh -c "$(curl …)"). The exec of a path
	// a download wrote (chmod +x f && ./f) is not currently asserted: no
	// frontend establishes that flow.
	FlowCradle FlowRole = "cradle"
	// FlowIngest marks an FSWrite of downloaded content: a download client
	// writing the fetched body to a file (curl -o/-O, wget default/-O).
	FlowIngest FlowRole = "ingest"
)

// FlowRoles is every defined flow role, in canonical order.
var FlowRoles = []FlowRole{FlowNone, FlowCradle, FlowIngest}

var flowRoleSet = func() map[FlowRole]struct{} {
	m := make(map[FlowRole]struct{}, len(FlowRoles))
	for _, r := range FlowRoles {
		m[r] = struct{}{}
	}
	return m
}()

// Valid reports whether r is a defined flow role.
func (r FlowRole) Valid() bool { _, ok := flowRoleSet[r]; return ok }

// kind reports the effect kind a flow role marks, or "" when the role is not
// tied to a single kind. A cradle sink is code execution; an ingest sink is a
// filesystem write.
func (r FlowRole) kind() EffectKind {
	switch r {
	case FlowCradle:
		return KindCodeExec
	case FlowIngest:
		return KindFSWrite
	default:
		return ""
	}
}

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
	// NetFlow marks the effect as the sink of a network data-flow relation: it
	// consumes content that arrived over the network (FlowCradle for a code
	// execution, FlowIngest for a filesystem write). It is FlowNone for an
	// effect that is not such a sink, so a program with no network flow
	// serialises exactly as before.
	NetFlow FlowRole `json:"netFlow,omitempty"`
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
		NetFlow:    joinFlow(e.NetFlow, o.NetFlow),
	}, true
}

// joinFlow unions two flow roles: a tagged role survives a join with FlowNone,
// so an explicit Effect.Join of a tagged and an untagged effect of the same kind
// and mode keeps the flow evidence — dropping it would lose a flow the analysis
// did establish. Two distinct non-empty roles cannot collide here: each role
// fixes its effect kind (cradle → CodeExec, ingest → FSWrite), so effects that
// carry different roles never share a kind and never join.
//
// Report.Normalize never joins a tagged with an untagged effect: it keys the
// merge on (kind, mode, netFlow) precisely so the flow evidence of one effect
// cannot bleed onto the targets of another (see normalizeKey). This function is
// therefore reached only by a caller that joins such a pair itself, and it
// prefers an over-approximated sink target set over dropping the flow.
func joinFlow(a, b FlowRole) FlowRole {
	if a != FlowNone {
		return a
	}
	return b
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
	if !e.NetFlow.Valid() {
		return fmt.Errorf("invalid netFlow %q", string(e.NetFlow))
	}
	if k := e.NetFlow.kind(); k != "" && e.Kind != k {
		return fmt.Errorf("netFlow %q requires effect kind %q, got %q", string(e.NetFlow), string(k), string(e.Kind))
	}
	return nil
}
