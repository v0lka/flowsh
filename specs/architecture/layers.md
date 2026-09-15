# Layers and Dependency Direction

## Context

The repository is a single Go module (`github.com/v0lka/flowsh`, see `go.mod`)
that analyses a shell or PowerShell command and reports the observable effects
it implies. The value of the analysis rests on a hard structural guarantee: the
frontend-agnostic core must stay independent of every frontend and of every
command signature dataset. That guarantee is what lets a new shell frontend be
added without touching the core, and it is enforced mechanically by a test, not
by convention alone.

This document fixes the layer boundaries, the one-way import graph between
them, and the rules a change must respect to keep that graph intact.

## Layers

Each layer is a Go package or package tree. Responsibilities are exclusive:
a responsibility belongs to exactly one layer.

| Layer | Path | Imports (this module) | Responsibility |
| ----- | ---- | --------------------- | -------------- |
| Core | `engine/` | *(none)* | Freeze the effect IR, the value lattices, the report format, scoring and the why-trace. |
| Knowledge base | `kb/` | `engine` | Hold the hand-verified command/parameter→effect dataset and the destructive-flags table; lower a matched parameter to an `engine.Effect`. |
| Shell frontend | `front/bash/` | `engine` | Parse shell source and abstractly execute it, emitting the effects the shell itself contributes and delegating ordinary commands through a resolver seam. |
| PowerShell frontend | `front/ps/` | `engine` | Parse PowerShell source and lower it into the effect IR, using its own alias/cmdlet tables. |
| Binding | `bind/` | `engine`, `kb`, `front/bash` | Resolve an invoked name and bind its flags/operands against the knowledge base, producing `[]engine.Effect`. |
| Composition | `internal/analysis/` | `engine`, `bind`, `front/bash`, `front/ps` | Wire the two frontends, the binder and the core into one deterministic `Report`; the single facade behind the CLI, the embedding API and the corpus harness. |
| Public API | `api/` | `internal/analysis` | Re-export the facade as an embeddable Go API — type aliases, copied constants and forwarding functions only; holds no behaviour of its own ([ADR-0010](../decisions/0010-public-embedding-api.md)). |
| CLI | `cmd/flowsh/` | `api`, `engine` | Parse arguments, read the command, call the facade through `api`, and print a text summary or JSON report. |

The import edges above are derived from the package imports in
`engine/*.go`, `kb/*.go`, `front/bash/*.go`, `front/ps/*.go`, `bind/*.go`,
`internal/analysis/*.go`, `api/api.go` and `cmd/flowsh/main.go`.

## The one-way import graph

Imports point strictly downward; there are no cycles and no upward edges.

```
  ┌──────────────────────────┐
  │ cmd/flowsh               │
  │ binary: CLI + text       │
  └────────────┬─────────────┘
               │  imports api/ (and engine/)
               ▼
  ┌──────────────────────────┐
  │ api/                     │
  │ embedding: type aliases  │
  └────────────┬─────────────┘
               │  imports
               ▼
  ┌────────────────────────────────────────────────────┐
  │ internal/analysis        facade: Analyze → Report  │
  └───┬───────────────┬────────────────────┬───────────┘
      │               │                    │
      ▼               ▼                    ▼
 ┌──────────┐   ┌──────────┐        ┌──────────┐
 │front/bash│   │  bind    │        │ front/ps │
 └────┬─────┘   └──┬────┬──┘        └────┬─────┘
      │            │    │                │
      │            ▼    │                │
      │        ┌─────┐  │                │
      │        │ kb  │  │                │
      │        └──┬──┘  │                │
      │           │     │                │
      ▼           ▼     ▼                ▼
 ┌────────────────────────────────────────────────────┐
 │ engine   effect IR · lattices · report · score     │
 │          imports the standard library only         │
 └────────────────────────────────────────────────────┘
```

Key properties of the graph:

- `engine` is a sink: it imports nothing from this module. Its package doc
  (`engine/effect.go`) states "Dependency direction is one-way: frontends
  (per-language parsers/lifters) import this package, never the other way
  around", and `TestCoreDoesNotImportFrontends` (`engine/report_test.go`)
  fails if the package gains any import that is neither the standard library
  nor another core package of this module.
- `kb` lowers into `engine` and is never imported by it (`kb/schema.go` package
  doc: "the core never imports kb").
- `front/bash` and `front/ps` are siblings; neither imports the other, and
  neither imports `kb` or `bind`. The PowerShell frontend has "its own alias
  table and its own cmdlet→effect mapping" (`front/ps/parse.go`).
- `bind` is a sibling of `engine`, not part of it, precisely because it must
  import `front/bash` (`bind/bind.go`: "This is why the package is a sibling of
  engine rather than a file inside it").
- `internal/analysis` is the only package that imports both frontends, so the
  composition of frontends + binder + engine can only live above them
  (`internal/analysis/analyze.go`: "the composition of frontends + binder +
  engine can only live above them").
- `cmd/flowsh` reaches the facade through `api/` — it does not import
  `internal/analysis` directly — and imports `engine` for the frozen IR types it
  prints; `api`, in turn, imports only `internal/analysis`.

## The resolver seam

The shell frontend needs the binding layer to obtain the effects of ordinary
commands, but `bind` already imports `front/bash`, so the reverse import would
be a cycle. The dependency is inverted with a function-typed seam:

```go
// front/bash/exec.go (Resolution + Resolver)
type Resolution struct {
	Effects     []engine.Effect
	Derivations []engine.Derivation
}

type Resolver func(cmd *Command, prog *Program) Resolution
```

`bind` supplies the concrete resolver; `front/bash` only knows the type. The
two call sites are:

- `bind.BindBash` (`bind/bind.go`) adapts a frontend command into the
  binder's own normalized call; and
- `internal/analysis.analyzeBash` (`internal/analysis/analyze.go`) injects a
  closure that returns `b.BindBash(cmd, prog)` (a `Resolution{Effects,
  Derivations}`) as the resolver when it calls
  `bash.Exec(v, sourceName(root, "script"), src, resolver)`.

`Resolver` being nil disables command binding; the shell then reports only its
own intrinsic effects (`front/bash/exec.go`: "Passing nil disables command
binding").

## Invariants

- `engine` imports only the Go standard library; it imports no package of this
  module. The single, deliberate exception is the external test package
  `engine/bench_test.go` (`package engine_test`), which imports
  `internal/analysis` — including its internal corpus harness (`analysis.Case`,
  `analysis.LoadCorpus`, `analysis.CorpusDir`) — to benchmark the whole pipeline
  end to end; it adds no edge to the core package and introduces no cycle. The
  corpus harness it reaches stays internal and is not re-exported by `api/`.
- Every intra-module import edge points from a higher layer in the table above
  to a lower one; the import graph is acyclic.
- `front/bash` and `front/ps` import `engine` and (their external parser
  libraries) only; they import neither each other, nor `kb`, nor `bind`. The
  single, deliberate exception is the external test package
  `front/bash/exec_test.go` (`package bash_test`), which imports `bind` to wire
  a concrete resolver into the `Resolver` seam; it adds no edge to the
  `front/bash` package itself.
- `kb` imports `engine` and no other package of this module.
- `bind` is the only package that imports `front/bash` together with `kb`; it
  imports `engine`, `kb` and `front/bash`.
- `internal/analysis` is the only package that imports both `front/bash` and
  `front/ps`.
- The only channel by which the shell frontend receives command effects is the
  `Resolver` seam; `front/bash` holds no reference to `bind`, `kb` or the
  knowledge base.
- `cmd/flowsh` depends on the analysis only through `api`, which re-exports
  `internal/analysis`; it additionally imports `engine` (the frozen effect IR)
  and no other package below the facade.
- `api` imports `internal/analysis` and no other package of this module: its
  whole surface is a type-alias re-export of the facade, so the public embedding
  edge points strictly downward and adds no edge to any package below it
  ([ADR-0010](../decisions/0010-public-embedding-api.md)).
- `api` is the sole public entry point to the facade: `api` imports only
  `internal/analysis`, and `cmd/flowsh` reaches the analysis through `api`.
- `api` re-exports only the analyse-and-report surface (types, constants,
  functions); the corpus harness (`Case`, `LoadCorpus`, `CorpusDir`, `Filter`,
  the `Group*` constants, `GuardFallClasses`) is never part of it.

## Anti-Patterns

- **Importing a frontend from `engine`.** Adds an upward edge and breaks the
  core's frontend-agnosticism; `TestCoreDoesNotImportFrontends` fails. Put
  language-specific logic in the frontend instead.
- **Importing `kb` from `engine`.** `kb` already imports `engine`, so this is
  both a cycle and a core dependency on a signature dataset.
- **Folding `bind` into `engine`.** `bind` must import `front/bash`; doing this
  would drag a frontend into the core and instantiate the exact edge the
  dependency test forbids.
- **Having `front/bash` import `bind` to bind its own commands.** Would create
  a `bind ↔ front/bash` cycle; use the injected `Resolver` seam. (An external
  test package may import `bind` to inject the concrete resolver.)
- **Analysing through `internal/analysis` from a frontend.** Base packages must
  not depend on the composition layer; effects flow up, never down.
- **Giving `front/ps` the bash frontend's data.** The two dialects assign
  different meanings to the same tokens (`rm`, `curl`, `iex` differ between the
  two), so PowerShell resolution uses the PS alias/cmdlet tables and never the
  bash knowledge base.
- **Re-exporting the corpus harness from `api/`.** The corpus harness is an
  internal testing aid; placing `Case`, `LoadCorpus`, `CorpusDir`, `Filter` or
  the `Group*` constants on the public surface would freeze a testing API as an
  external contract. In-module tests reach it through `internal/analysis`
  instead ([ADR-0010](../decisions/0010-public-embedding-api.md)).

## Related Specs

- [data-flow.md](data-flow.md) — how a source flows through these layers.
- [conservatism.md](conservatism.md) — the ⊤ degradation each layer can emit.
