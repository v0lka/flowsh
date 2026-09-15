# Engine (Frozen Core)

## Purpose

The `engine` package is the frontend-agnostic core of the effect-analysis IR. It freezes exactly three things and nothing else: the effect IR (`Effect`, `EffectKind`, `EffectMode`), the value lattices (`Certainty`, `Scope`, `Taint`, `Destructiveness`), and the `Report` format including its why-trace and destructiveness summary. Dependency direction is one-way: per-language frontends and the binder import `engine`, never the reverse.

## Key Files

- `engine/effect.go` — the effect IR atoms: `EffectKind`, `EffectMode`, the `Effect` struct, and its `Key`, `Join`, `Validate` operations.
- `engine/lattice.go` — the value lattices: `Certainty`, `Destructiveness`, the shared `flatSet` shape, `Scope` and `Taint`, plus their join/meet/order operations.
- `engine/report.go` — the frozen `Report` container: `SchemaVersion`, `SourceLoc`, `WhyStep`, `WhyTrace`, `NewReport`, and `KindDestructiveness`/`ComputeDestructiveness`/`Sort`/`Normalize`/`Validate`/`Encode`.
- `engine/score.go` — the risk dimensions and composite score: `Breadth`, `Irreversibility`, `ConfidenceOf`, `Score`, `ScoreEffects`, `BreadthSeverity`, `IrreversibilityOf`.
- `engine/taint.go` — provenance and exfiltration: `SourceClass`, `Influence`, `Provenance`, `Flow`, `InfluenceOf`, `MaxInfluence`, `SecretPath`, `IsSecretRead`, `IsEgressSink`, `Exfil`, `DetectExfil`.
- `engine/why.go` — why-trace construction: `AtomKind`, `Atom`, `Derivation`, `BuildWhy`, `WhyStepsFor`, `WhyGaps`.
- `engine/report_test.go` — golden JSON, round-trip, lattice-law and import-direction tests.
- `engine/score_test.go` — fixtures and unit tests for every scoring dimension.
- `engine/bench_test.go` — external test package (`engine_test`): per-command latency and recall gates.
- `engine/testdata/report.golden.json`, `engine/testdata/effect.golden.json` — frozen canonical JSON the schema is pinned to.

## Core Types

The effect IR atom. `Target` is a `Scope` (a lattice), so joining two effects of the same kind and mode unions their targets instead of dropping them.

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

The closed kind set and the mode set:

```go
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

type EffectMode string

const (
	ModeDirect      EffectMode = "Direct"      // performed by the analyzed unit itself
	ModeTransitive  EffectMode = "Transitive"  // performed by a callee or dependency
	ModeAmbient     EffectMode = "Ambient"     // implicit, via the runtime or host
	ModeConditional EffectMode = "Conditional" // occurs only under a runtime guard
)
```

The frozen report container (see [effect-ir.md](effect-ir.md) for the full IR detail):

```go
type Report struct {
	SchemaVersion   string          `json:"schemaVersion"`
	Root            string          `json:"root,omitempty"`
	Effects         []Effect        `json:"effects"`
	Destructiveness Destructiveness `json:"destructiveness"`
	Why             []WhyTrace      `json:"why,omitempty"`
	Notes           []string        `json:"notes,omitempty"`
}
```

## Flow

The core is a pure function of `[]Effect`: it neither parses nor binds. Frontends lift source into `Effect`s and the binder resolves names against the knowledge base; the core normalises, scores and encodes.

```
source text ──front/bash, front/ps──▶ normalized call ──bind (kb + engine)──▶ []engine.Effect
                                                                                    │
                                          ┌─────────────────────────────────────────┘
                                          ▼
        Report{Effects} ──Normalize──▶ merge same (Kind,Mode) via Effect.Join
                        ──Normalize──▶ ComputeDestructiveness(Effects)   (max over effects)
                        ──Normalize──▶ Sort(Effects by Key, Why by fingerprint, Notes)
                        ──Encode────▶ canonical indented JSON  (Validate first)

        ScoreEffects(Effects, tokens...) ──▶ Score   (independent risk dimensions)
```

Two reports built from the same set of effects normalise to byte-identical JSON.

## Invariants

- The `EffectKind` set is closed and enumerated by `EffectKinds` in canonical order; `EffectKind.Valid` accepts exactly those 15 kinds.
- The `EffectMode` set is exactly `{Direct, Transitive, Ambient, Conditional}`; `EffectMode.Valid` accepts exactly those 4.
- `SchemaVersion` is the constant string `"effect-ir/v1"`; consumers and golden fixtures pin to this value.
- The `engine` package depends on the standard library only (plus other core packages of the same module); `TestCoreDoesNotImportFrontends` fails if the package gains any other import.
- `Effect.Join` succeeds if and only if both operands share a `Kind` and a `Mode`; it unions targets and taint, joins certainty, and is reversible only if both operands are.
- `Report.Normalize` merges every set of effects that share a kind and a mode, recomputes `Destructiveness`, and sorts every slice into canonical order.
- `Effect.Key` is a stable identity, a function of `Kind`, `Mode` and the canonical form of `Target`.
- Every non-empty effect has a why-trace citing a concrete node or flag; `WhyGaps` returns the empty set for a fully explained report.
- `Scope` and `Taint` are canonical: elements are kept sorted and unique, and each has a single JSON encoding.
- `Report.Encode` validates first: a report with an empty schema version, an invalid effect, or a why-trace with an empty effect key is rejected.
- `KindDestructiveness`, `Breadth.Severity`, `Irreversibility.Severity` and `Influence.Severity` map every dimension onto the shared `Destructiveness` scale, so all dimensions are comparable and orderable.

## Configuration

The core has no runtime configuration and no I/O. Its behaviour is fixed by compile-time constants and tables, which act as the configuration surface:

| Constant / table | Location | Value / role |
| --- | --- | --- |
| `SchemaVersion` | `engine/report.go` | `"effect-ir/v1"` — the frozen schema tag. |
| `EffectKinds` | `engine/effect.go` | the 15 canonical effect kinds, in canonical order. |
| `EffectModes` | `engine/effect.go` | `Direct, Transitive, Ambient, Conditional`. |
| Taint labels (`TaintUntrusted`, `TaintUserInput`, `TaintEnv`, `TaintNetwork`, `TaintSecret`, `TaintFileSystem`, `TaintProcess`) | `engine/lattice.go` | the labels the core recognises; the label universe is otherwise open. |
| `SourceClasses` | `engine/taint.go` | `UntrustedContent, Env, File, Literal` (most attacker-influenced first). |
| `secretPathMarkers` | `engine/taint.go` | substrings that mark credential/secret locations (case-insensitive, substring match). |
| `irreversibleTokens` | `engine/score.go` | command → `Irreversibility` table (`rm`, `dd`, `shred`, `mkfs*`, …). |
| Golden fixtures | `engine/testdata/*.golden.json` | pin the canonical JSON encoding of `Effect` and `Report`. |

## Extension Points

- **Add an effect kind** — extend the `const` block and `EffectKinds` in `engine/effect.go`, and add a case to `KindDestructiveness` in `engine/report.go`. Any frontend may then emit it; `EffectKind.Valid` picks it up automatically.
- **Add an effect mode** — extend the `const` block and `EffectModes` in `engine/effect.go`.
- **Add a taint label** — add a constant next to the existing canonical labels in `engine/lattice.go`; the `Taint` lattice already treats the label universe as open.
- **Add a source class** — add the constant plus entries in `SourceClass.Valid`, `SourceClass.Influence` and `SourceClass.Labels`, and register it in `SourceClasses` (`engine/taint.go`).
- **Add or tune a lattice** — new lattices follow the `flatSet`/ordinal shape in `engine/lattice.go`; each must provide `Join`, `Meet`, order, canonical encoding and — for scoring — a `Severity` mapping onto `Destructiveness`.
- **Add a why-trace atom kind** — extend the `const` block and `AtomKinds` in `engine/why.go`.
- **Integrate a new frontend** — implement a lifter that emits `engine.Effect` values (see `bind/bind.go`); the core needs no change, and the import-direction rule keeps the dependency pointing at the core.
- **Change risk policy** — adjust `KindDestructiveness`, `secretPathMarkers`, `irreversibleTokens`, or the weightings inside `ScoreEffects`; these are the tunable policy tables, not the structural IR.

## Related Specs

- [Effect IR](effect-ir.md) — `Effect`/`EffectKind`/`EffectMode`/`Report`/`WhyTrace`, `Join` and `Normalize`.
- [Lattices](lattices.md) — `Certainty`, `Scope`, `Taint`, `Destructiveness`, `Breadth`, `Irreversibility`, `Influence` and the lattice laws.
- [Scoring](scoring.md) — `ScoreEffects`, `ComputeDestructiveness`, `DetectExfil`, `BreadthSeverity`, `IrreversibilityOf`, `ConfidenceOf` and why-trace gaps.
- [Contract: Frontends <-> Engine](../../contracts/frontend-engine.md) — the engine's inbound boundary and import rule.
- [Contract: Analyzer <-> CLI/CI (JSON Report)](../../contracts/report-json.md) — the frozen report JSON consumed by the CLI/CI.
- [ADR-0001: Freeze the effect IR](../../decisions/0001-frozen-effect-ir.md) — why the kind/mode set is closed and the schema pinned.
- [ADR-0002: Keep the core one-way](../../decisions/0002-one-way-dependency.md) — the standard-library-only import rule.
- [META.md](../../META.md) — spec formats, naming and update protocol.
- [WORKFLOW.md](../../WORKFLOW.md) — spec-system usage and navigation.
