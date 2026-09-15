# ADR-0008: Single Go Module with Layered Packages

## Status

Accepted

## Context

The analyser spans several concerns — a frontend-agnostic effect model, two language frontends, a knowledge base, a binder, a composition facade, and a CLI. These could be split across multiple modules/repositories or kept in one module with internal layering. The core must stay frontend-free, and the frontends must not import each other.

## Decision

Keep everything in one Go module (`github.com/v0lka/flowsh`) with packages that mirror the layers: `engine` (core), `front/bash` and `front/ps` (frontends), `kb` (knowledge base), `bind` (binder), `internal/cmdscope` (composition facade), `cmd/cmdscope` (binary). The facade lives under `internal/` precisely because it must import the frontends while the core must not.

## Consequences

- A single `go build ./...` and `go test ./...` cover the whole system; CI stays simple.
- The frontend-agnostic guarantee is enforceable in-module by a test (`TestCoreDoesNotImportFrontends`) that inspects `engine`'s imports.
- `internal/cmdscope` gets compile-time privacy from external consumers, which is what keeps the core frontend-free.
- A change to a shared internal type requires updating every layer in lockstep within one commit (no versioned boundary).
- Consumers who want only the core must depend on the whole module.

## Alternatives Considered

- **Multiple modules (core, frontends, cli).** Rejected: adds `go.mod`/version churn and a publish/replace workflow for a small, fast-moving tool, with no external consumer needing an independent core release.
- **One flat package.** Rejected: the frontend-agnostic invariant and the injectable resolver seam require package boundaries; a flat package would allow `engine` to reach into a frontend.
- **Frontends in separate repositories.** Rejected: the two frontends share the core IR and their integration is exercised by one corpus; splitting them would fragment the conformance harness.

## Related Specs

- [Layer Architecture](../architecture/layers.md) — the layering this decision fixes
- [ADR-0001: Freeze the Effect IR](0001-frozen-effect-ir.md) — the interface the layering protects
