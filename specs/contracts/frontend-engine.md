# Contract: Frontends <-> Engine

## Boundary Rule

A frontend (`front/bash`, `front/ps`, `front/js`) may import the core (`engine`) and lower its constructs into `engine.Effect`; the core never imports a frontend. Data crosses the boundary one way only: frontends produce effects, the core consumes them.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |
| `engine.Effect` | `engine` | frontends | the atom a frontend emits |
| `engine.EffectKind`, `engine.EffectMode` | `engine` | frontends | the closed kind/mode vocabulary |
| `engine.Scope`, `engine.Taint` | `engine` | frontends | target and provenance lattices |
| `engine.Certainty` | `engine` | frontends | belief strength |
| `engine.Report`, `Report.Normalize` | `engine` | frontends (bash `ExecResult` folds through it) | canonical effect aggregation |
| `engine.Derivation`, `engine.Atom` | `engine` | frontends | the concrete source facts (nodes/flags) a reported effect rests on — the why-trace vocabulary |
| `bash.Resolver` (`func(*Command, *Program) bash.Resolution`) | `front/bash` | `bind`, via the facade | injected seam for ordinary-command effects and their `Derivation`s |
| `ps.Result` | `front/ps` | `internal/analysis` | lowering outcome (mirrors `bind.Result`) |
| `js.Resolver` (`func(js.Call) js.Resolution`) | `front/js` | composition/test models | injected typed call boundary; the facade currently passes nil |
| `js.Result` | `front/js` | `internal/analysis` | bounded JS effects/derivations and Top/Conservative/Reason |

## Initialization

The core has no initialization. A frontend is constructed per analysis: `bash.ExecBash(src, resolver)` or `ps.Parse` + `ps.Lower(prog)`. The bash `Resolver` is supplied by the composition layer (the facade passes a closure that calls `binder.BindBash`); passing `nil` disables command binding while the shell's own intrinsic effects are still emitted.

`js.AnalyzeWith(name, src, resolver)` parses and evaluates a bounded subset.
The facade passes nil for the resolver: calls and unsupported execution yield
`CodeExec(ScopeTop())`; understood pure programs may have no effects. Whole-unit
parse/budget failures set Top; local degradation sets Conservative. Derivations
carry source locations into the shared explanation builder. The typed
`js.Resolver` seam returns values/effects/derivations without a frontend import
of bind/KB; Node API models and invocation semantics remain later work.

## Data Flow Across Boundary

```
frontend internals (syntax tree, Σ, cmdlet tables)
        |  lower each construct
        v
[]engine.Effect   (Kind, Target=Scope, Mode, Certainty, Taint, Reversible, NetFlow)
        |
        v
engine.Report.Normalize  (merge equal kind|mode|netFlow by Join, sort)
        |
        v
engine.ComputeDestructiveness / engine.ScoreEffects
```

Only `engine` types cross: no frontend type (AST node, `Command`, `State`) appears in the core. The Bash binder capability flows through its `Resolver` function value, not through an import.

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
- [JavaScript Frontend](../domains/javascript-frontend.md) — the bounded source-dialect evaluator
- [Report Contract](report-json.md) — the downstream boundary
