# Effect IR

## Role

The effect IR is the frozen, frontend-agnostic vocabulary of the core: the `Effect` atom, its closed `EffectKind` and `EffectMode` sets, the `Report` container that carries a set of effects, and the `WhyTrace` structure that explains how an effect was derived.

## Key Files

- `engine/effect.go` — `Effect`, `EffectKind`, `EffectMode`, `EffectKinds`, `EffectModes`, and `Effect.Key`/`Join`/`Validate`.
- `engine/report.go` — `SchemaVersion`, `SourceLoc`, `WhyStep`, `WhyTrace`, `Report`, `NewReport`, and `Report.Normalize`/`Validate`/`Encode`/`Sort`.
- `engine/why.go` — `AtomKind`, `Atom`, `Derivation`: the source-level facts a why-trace cites, and the lowering that turns them into `WhyTrace`.
- `engine/testdata/effect.golden.json`, `engine/testdata/report.golden.json` — the pinned canonical JSON encodings.
- `engine/report_test.go` — golden, JSON round-trip, `Effect.Join` and validation tests.

## Behavior

### Effect

`Effect` is the atom of the IR: a single observable effect of the analyzed program. Its field set is frozen. `Target` is a `Scope` (the target-set lattice — see [lattices.md](lattices.md)), so joining two effects of the same kind and mode unions their targets instead of dropping them.

```go
type Effect struct {
	Kind       EffectKind `json:"kind"`
	Target     Scope      `json:"target"`
	Mode       EffectMode `json:"mode"`
	Certainty  Certainty  `json:"certainty"`
	Taint      Taint      `json:"taint"`
	Reversible bool       `json:"reversible"`
}
```

- `Key` returns a stable identity for the effect — `Kind|Mode|canonical(Target)` — used for deterministic sorting and for referencing effects from why-traces:

```go
func (e Effect) Key() string {
	return string(e.Kind) + "|" + string(e.Mode) + "|" + e.Target.canonical()
}
```

- `Join` is the least upper bound of two effects that share a kind and a mode: targets and taint are unioned (`Scope.Join`/`Taint.Join`), certainty is joined (max), and the result is reversible only if both operands are. The `ok` result is false when the kinds or modes differ.

```go
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
```

- `Validate` reports whether the effect is well-formed: `Kind.Valid()`, `Mode.Valid()` and `Certainty.Valid()` must all hold.

### EffectKind (closed set, 15 kinds)

`EffectKind` enumerates the kinds of observable effect representable by the IR. The set is exactly the set of kinds a frontend may emit; `EffectKinds` lists them in canonical order and `EffectKind.Valid` accepts exactly these.

| Constant | Value | Meaning |
| --- | --- | --- |
| `KindFSRead` | `FSRead` | read filesystem content |
| `KindFSWrite` | `FSWrite` | create/modify filesystem content |
| `KindFSMeta` | `FSMeta` | metadata ops (stat, chmod, rename, unlink) |
| `KindEnvRead` | `EnvRead` | read process environment |
| `KindEnvWrite` | `EnvWrite` | mutate process environment |
| `KindNetEgress` | `NetEgress` | outbound network traffic |
| `KindNetIngress` | `NetIngress` | inbound network traffic / listening |
| `KindProcSpawn` | `ProcSpawn` | start a child process |
| `KindProcSignal` | `ProcSignal` | signal a process |
| `KindIPC` | `IPC` | inter-process communication (sockets, pipes, shm) |
| `KindStdio` | `Stdio` | read/write standard streams |
| `KindPrivEsc` | `PrivEsc` | attempt privilege escalation |
| `KindPersist` | `Persist` | persist state beyond lifetime (services, cron, registry) |
| `KindCredAccess` | `CredAccess` | access credential/secret material |
| `KindCodeExec` | `CodeExec` | execute data as code (eval, dlopen, shell) |

### EffectMode (4 modes)

`EffectMode` describes how an effect is realized with respect to the analyzed unit; it is orthogonal to `EffectKind`, which says *what* happens. `EffectModes` lists them in canonical order.

| Constant | Value | Meaning |
| --- | --- | --- |
| `ModeDirect` | `Direct` | performed by the analyzed unit itself |
| `ModeTransitive` | `Transitive` | performed by a callee or dependency |
| `ModeAmbient` | `Ambient` | implicit, via the runtime or host |
| `ModeConditional` | `Conditional` | occurs only under a runtime guard |

### Report

`Report` is the frozen analysis output: plain data, serialisable to JSON, carrying no reference to any frontend type. `SchemaVersion` tags the frozen JSON schema and consumers/golden fixtures pin to it.

```go
const SchemaVersion = "effect-ir/v1"

type Report struct {
	SchemaVersion   string          `json:"schemaVersion"`
	Root            string          `json:"root,omitempty"`
	Effects         []Effect        `json:"effects"`
	Destructiveness Destructiveness `json:"destructiveness"`
	Why             []WhyTrace      `json:"why,omitempty"`
	Notes           []string        `json:"notes,omitempty"`
}
```

`SourceLoc` is a frontend-agnostic source location (a file/line/column triple, no frontend-specific node handle):

```go
type SourceLoc struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	Col  int    `json:"col,omitempty"`
}
```

Report lifecycle operators:

- `NewReport` returns an empty report stamped with the current schema version (`Effects: []Effect{}`).
- `Normalize` canonicalises the report: effects that share a `(Kind, Mode)` pair are merged with `Join`, `Destructiveness` is recomputed, and every slice is sorted. Two reports built from the same effects normalise to byte-identical JSON.
- `Sort` orders `Effects` by `Key`, `Why` by `(Effect, whyFingerprint)`, and `Notes` lexicographically — the canonical deterministic order.
- `Validate` reports whether the report is well-formed: a schema version is set, every effect is valid, and every why-trace references a non-empty effect key.
- `Encode` validates the report and returns its canonical indented JSON (`json.MarshalIndent` with a two-space indent).

### WhyTrace

A why-trace explains how a single effect was derived. `Effect` is the `Effect.Key()` of the explained effect; `Because` is the ordered chain of steps that produced it, closest step first. Each step names the rule that fired, the premises it consumed, an optional note, and an optional source location.

```go
type WhyStep struct {
	Rule     string     `json:"rule"`
	Premises []string   `json:"premises,omitempty"`
	Note     string     `json:"note,omitempty"`
	Loc      *SourceLoc `json:"loc,omitempty"`
}

type WhyTrace struct {
	Effect  string    `json:"effect"`
	Because []WhyStep `json:"because"`
}
```

Premises are free-form tokens the frontend defines (call ids, argument slices, other `Effect.Key()` values); the core only keeps them ordered and stable. `why.go` lowers a `Derivation` — an effect plus the concrete `Atom`s (nodes/flags) and `Rules` it rests on — into canonical, deduplicated `WhyTrace`s via `BuildWhy`. An effect derived without atoms still receives a trace carrying the synthetic `effect:<key>` premise, so `Report.Validate` passes while `WhyGaps` still reports it as unexplained (see [scoring.md](scoring.md)).

### Canonical JSON

`Effect` marshals as a JSON object; `Scope` and `Taint` marshal in canonical object form (`{"targets":[…],"arbitrary":bool}` and `{"labels":[…],"arbitrary":bool}`). The pinned fixtures are the reference:

```json
{
  "kind": "NetEgress",
  "target": { "targets": ["api.example.com:443"], "arbitrary": false },
  "mode": "Transitive",
  "certainty": "Likely",
  "taint": { "labels": ["network", "untrusted"], "arbitrary": false },
  "reversible": false
}
```

## Error Handling

- `Effect.Validate` returns a non-nil error naming the offending field and value for an unknown kind (`invalid effect kind %q`), an unknown mode (`invalid effect mode %q`), or an out-of-range certainty (`invalid certainty %d`).
- `Report.Validate` returns `engine: report schemaVersion is empty` when `SchemaVersion` is unset, wraps an effect error as `engine: effects[%d]: …`, and returns `engine: why[%d]: empty effect key` for a why-trace with no effect key.
- `Report.Encode` propagates any `Validate` error and returns the encoding error from `json.MarshalIndent`; it never returns partial output alongside an error.
- `Certainty`/`Destructiveness` reject invalid values on marshal (`cannot marshal invalid …`) and reject unknown names or out-of-range ordinals on unmarshal (`engine: unknown …`, `… ordinal out of range`). `Scope`/`Taint` unmarshal accept the canonical object form plus a bare string or array, and error with `engine: cannot decode set from …` on anything else.
- `WhyGaps` is the error-surfacing primitive for traces: it returns the effect keys a report fails to explain concretely, rather than failing construction.

## Invariants

- `Effect` has exactly the six frozen fields `Kind, Target, Mode, Certainty, Taint, Reversible`.
- `EffectKind.Valid` accepts exactly the 15 kinds in `EffectKinds`; `EffectMode.Valid` accepts exactly the 4 modes in `EffectModes`.
- `Effect.Join(a, b)` returns `ok == true` if and only if `a.Kind == b.Kind && a.Mode == b.Mode`.
- `Join` is commutative over matching kind/mode and unions targets and taint; reversibility is the logical AND of the operands'.
- `Effect.Key` is a function of `Kind`, `Mode` and the canonical target form only.
- `SchemaVersion` is the constant `"effect-ir/v1"` and every freshly built report carries it.
- `Report.Normalize` is idempotent and merges on `(Kind, Mode)`; two reports over the same effects normalise to byte-identical JSON.
- `Report.Encode` validates before encoding, so an invalid report never produces output.
- Why-trace `Effect` keys are non-empty and stable (`Effect.Key()` values).
- The IR carries no frontend-specific types: `Report`, `Effect`, `WhyTrace` and `SourceLoc` are plain serialisable data.

## Related Specs

- [Engine (Frozen Core)](README.md) — the domain overview, key files and cross-cutting invariants.
- [Lattices](lattices.md) — `Certainty`, `Scope`, `Taint` and the other value lattices referenced by `Effect`.
- [Scoring](scoring.md) — how `Report`/`Effect` sets are folded into a `Score`, and how why-trace gaps are reported.
- [Contract: Analyzer <-> CLI/CI (JSON Report)](../../contracts/report-json.md) — the frozen report JSON an `Effect`/`Report` encodes to.
- [ADR-0001: Freeze the effect IR](../../decisions/0001-frozen-effect-ir.md) — why the IR is closed and pinned to `effect-ir/v1`.
- [META.md](../../META.md) — spec formats and update rules.
