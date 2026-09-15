# Contract: Frontends <-> Engine

## Boundary Rule

A frontend (`front/bash`, `front/ps`) may import the core (`engine`) and lower its constructs into `engine.Effect`; the core never imports a frontend. Data crosses the boundary one way only: frontends produce effects, the core consumes them.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |
| `engine.Effect` | `engine` | both frontends | the atom a frontend emits |
| `engine.EffectKind`, `engine.EffectMode` | `engine` | both frontends | the closed kind/mode vocabulary |
| `engine.Scope`, `engine.Taint` | `engine` | both frontends | target and provenance lattices |
| `engine.Certainty` | `engine` | both frontends | belief strength |
| `engine.Report`, `Report.Normalize` | `engine` | frontends (bash `ExecResult` folds through it) | canonical effect aggregation |
| `engine.Derivation`, `engine.Atom` | `engine` | both frontends | the concrete source facts (nodes/flags) a reported effect rests on — the why-trace vocabulary |
| `bash.Resolver` (`func(*Command, *Program) bash.Resolution`) | `front/bash` | `bind`, via the facade | injected seam for ordinary-command effects and their `Derivation`s |
| `ps.Result` | `front/ps` | `internal/analysis` | lowering outcome (mirrors `bind.Result`) |

## Initialization

The core has no initialization. A frontend is constructed per analysis: `bash.ExecBash(src, resolver)` or `ps.Parse` + `ps.Lower(prog)`. The bash `Resolver` is supplied by the composition layer (the facade passes a closure that calls `binder.BindBash`); passing `nil` disables command binding while the shell's own intrinsic effects are still emitted.

## Data Flow Across Boundary

```
frontend internals (syntax tree, Σ, cmdlet tables)
        |  lower each construct
        v
[]engine.Effect   (Kind, Target=Scope, Mode, Certainty, Taint, Reversible)
        |
        v
engine.Report.Normalize  (merge equal kind|mode by Join, sort)
        |
        v
engine.ComputeDestructiveness / engine.ScoreEffects
```

Only `engine` types cross: no frontend type (AST node, `Command`, `State`) appears in the core. Capability flows the other way through the `Resolver` function value, not through an import.

## Error Propagation

Frontends never return Go errors for bad input; they fold failure into a ⊤ result (`Top=true`, a `Reason`, a `CodeExec`/⊤ effect) and preserve any effects discovered first. The core reports malformed data through return values (`Validate`, `Encode`, `Join`'s boolean) and never panics on a well-formed value.

## Breaking Change Checklist

If you change… | you MUST also update…
--- | ---
An `EffectKind`/`EffectMode` constant | `EffectKinds`/`EffectModes`, `KindDestructiveness` (`engine/report.go`), `kb.DefaultReversible`, the frontends that emit it, and the report contract
The `Effect` field set or its JSON tags | the golden fixtures (`engine/testdata/*.golden.json`) and the [Report Contract](report-json.md)
`Effect.Key()` | the frontends' effect construction and the why-trace reference scheme
The `Resolver` signature | `bind.BindBash` and the facade's resolver closure
`engine.SchemaVersion` | the [Report Contract](report-json.md) and every golden fixture
A frontend's emitted kinds | `DefaultReversible` and the corpus expectations

## Related Specs

- [Layer Architecture](../architecture/layers.md) — the import rules
- [Effect IR](../domains/engine/README.md) — the target vocabulary
- [bash Frontend](../domains/bash-frontend/README.md) — a producer
- [Report Contract](report-json.md) — the downstream boundary
