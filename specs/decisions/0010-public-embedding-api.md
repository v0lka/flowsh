# ADR-0010: Public embedding API as a first-class entry point

## Status

Accepted

> **Historical record.** This decision describes the embedding contract with the
> report-contract tag as `flowsh/v1`. The live tag is now `flowsh/v3` (see
> [`specs/contracts/report-json.md`](../contracts/report-json.md) and
> `analysis.ToolVersion`); the `flowsh/v1` spellings below are the tag as of
> this decision.

## Context

`SECURITY.md` and the `docs/` set already describe a library API. `SECURITY.md`
names "the `internal/analysis` library API" and its exported `engine`, `kb`,
`bind`, `front/bash`, `front/ps` packages as an attack surface consumed "by
other Go programs", and `docs/report-json.md` documents the `root` field as
"Omitted only when unset (library use)". But the composition facade lives at
`internal/analysis/`, and Go's `internal/` convention makes any path containing
an `internal` element unimportable by a module outside the
`github.com/v0lka/flowsh` subtree. An external consumer therefore cannot embed
the analyser at all: `import "github.com/v0lka/flowsh/internal/analysis"` from
another module is rejected by the compiler.

This contradicts the documented promise. The roadmap's item A9 (P2, "Публичная
точка входа (API для встраивания)") raised the question and contemplated a
public package; the instinct to publish only the CLI is inconsistent both with
those docs and with the architecture, because the CLI is itself just a thin
consumer of the facade — there is nothing CLI-specific about the
analyse-and-report operation. The question is where the public embedding surface
should live, and how it is versioned.

## Decision

Publish the analyser as a first-class Go embedding API in a new top-level
package tree `api/` (import path `github.com/v0lka/flowsh/api`). The package is
a **thin type-alias re-export** over `internal/analysis`:

- Every exported type (`Lang`, `Report`, `DestructiveFinding`, `Analyzer`,
  `Options`) is a type **alias** (`=`) of the corresponding `analysis` type, so
  the two are the same type at the boundary — no conversion, no duplicate
  definition.
- Every exported constant (`ToolName`, `SchemaVersion`, `ToolVersion`,
  `RootArgument`, `RootStdin`, `LangBash`, `LangPOSIX`, `LangPowerShell`) is a
  copy of the facade's, every exported variable (`Langs`) aliases the facade's,
  and every exported function (`ParseLang`, `Analyze`, `AnalyzeWith`,
  `NewAnalyzer`, `Bool`) is a one-line forwarder.
- The package adds **no behaviour of its own**, so an embedding caller sees
  exactly the report contract the CLI emits.

**CLI and API are equal first-class entry points.** Neither is the "real" one
and neither wraps the other: both are consumers of `internal/analysis` at the
same layer. The CLI is simply the **first consumer** of the surface — its
behaviour (argument/stdin reading, text/JSON rendering, exit codes) stays in
`cmd/flowsh` and does not leak into the API, and the API exposes only the
analyse → `*Report` operation, not the CLI's rendering.

The **corpus harness is deliberately not re-exported**: `Case`, `LoadCorpus`,
`CorpusDir`, `CorpusDirFrom`, `Filter`, the `Group*` constants and
`GuardFallClasses` remain internal testing aids. In-module tests (including the
external `engine_test` package) may still reach them through `internal/analysis`.

Versioning is unchanged and orthogonal: the embedding surface is pinned by the
two report-contract constants — `SchemaVersion` (`effect-ir/v1`) for the effect
IR shape and `ToolVersion` (`flowsh/v1`) for the document as a whole — not by
the module version or by the package's API shape.

## Consequences

- Positive: `internal/analysis` is embeddable from any external Go module
  without exposing the whole internal tree; the public surface is one small,
  auditable package that re-exports exactly the documented contract.
- Positive: the promise in `SECURITY.md` / `docs/report-json.md` becomes true,
  and CLI and embedding consumers exercise the same code path, so a corpus/CI
  gate that passes for the CLI also covers the API.
- Positive: consumers pin to `Report.SchemaVersion` / `Report.ToolVersion`
  (`effect-ir/v1` / `flowsh/v1`) rather than to a module revision, so the two
  independent version axes keep working across the boundary.
- Positive: the alias wrapper keeps a single definition of every type — there
  is no parallel "public" model to keep in sync.
- Negative: because every exported type is an **alias**, a change to an internal
  type in `internal/analysis` *is* a change to the public API — renaming or
  reshaping `analysis.Report` silently changes `api.Report`. The alias gives no
  encapsulation barrier; the contract is held by discipline and by the version
  constants, not by the type system.
- Negative: the corpus harness must be kept out of `api/` by review — the
  package boundary does not by itself prevent a future re-export of an internal
  testing aid.
- Negative: holding `internal/analysis` to a stable contract constrains
  refactoring there, since internal churn now propagates to external consumers.
- Negative: `api/` imports `internal/analysis`, which is legal (an `internal`
  package is importable by any package rooted at the parent of `internal/`), but
  it couples the public package to the facade's location — the facade cannot
  move to another module without relocating `api/` too.

## Alternatives Considered

- **Curated public types (a purpose-built public model mapping to and from the
  internal types).** Rejected: it duplicates the entire report type graph, forces
  a conversion layer on every call, and creates a second definition that can
  drift from `internal/analysis` — the exact "spec vs code" divergence the tool
  warns about. The alias wrapper is zero-cost and cannot drift.
- **Ship only the CLI; no library API.** Rejected: it contradicts `SECURITY.md`
  (which lists the library API as a supported entry point) and
  `docs/report-json.md` (which documents library use), and it ignores that the
  CLI is itself a thin consumer of the facade. A consumer wanting a CI gate or
  an agent runtime would be forced to shell out to the binary.
- **A separate Go module for the public API** (a `flowsh/api` module with its
  own `go.mod`). Rejected: it adds a second module, a `replace`/publish workflow
  and version skew against the analyser, for a surface that is a thin alias of
  code living in the main module. The single-module decision
  ([ADR-0008](0008-single-go-module.md)) holds; layering inside one module is
  enough.
- **Move the facade out of `internal/` and rename it public.** Rejected: it
  would expose the corpus harness and every helper the facade happens to hold,
  and it would make the composition layer itself the contract; the small `api/`
  alias package documents and freezes only the intended surface.

## Related Specs

- [Layer Architecture](../architecture/layers.md) — the layer table and import graph that gain the `api/` layer
- [Analysis Report](../domains/analysis-report.md) — the `internal/analysis` facade this package re-exports
- [Report Contract](../contracts/report-json.md) — the `flowsh/v1` envelope pinned across the boundary
- [ADR-0008: Single Go Module](0008-single-go-module.md) — the module this new package lives in
- [ADR-0009: Rename the project identity to flowsh](0009-rename-identity-to-flowsh.md) — the `flowsh/v1` tool version the API stamps
