# ADR-0009: Rename the project identity to flowsh

## Status

Accepted

## Context

The analyser was first built under the internal working name `cmdscope` — the
composition facade at `internal/cmdscope`, the binary at `cmd/cmdscope`, and
the report tagged `cmdscope/v2`. That name was a title of
convenience rather than a product identity: it named the *tool* after one of its
outputs (the effect scope of a command) and it did not match how the project is
published.

The repository is now published publicly as `v0lka/flowsh`. Every artefact a
consumer sees — the import path, the binary, the package layout and the wire tag
— must present that one identity, so the legacy `cmdscope` name has to be
eliminated from the public surface. The question was what the new identity is
called at each layer, and how the rename interacts with the report contract
versioning.

## Decision

Adopt `flowsh` as the single project identity, at every layer:

- **Module path**: `github.com/v0lka/flowsh`, matching the published repository.
- **Binary**: `flowsh`, built from `cmd/flowsh` and installed as `flowsh` (was
  `cmd/cmdscope`).
- **Composition facade**: the `internal/analysis` package (was the `cmdscope`
  facade at `internal/cmdscope`).
- **Public report contract tag**: `flowsh/v1` (was `cmdscope/v2`). The tool
  stamps the envelope with `analysis.ToolName = "flowsh"` and
  `analysis.ToolVersion = "flowsh/v1"`, and `--version` prints `flowsh/v1`
  followed by the frozen core tag `effect-ir/v1`.

Every documented artefact, error prefix (`flowsh: …`) and source label uses the
new name.

The rename is an *identity* change, not a *shape* change: `flowsh/v1` is the
starting public report contract and already includes every field (`why`,
`resolution`, `destructive`, …), so the tag starts at `v1` rather than
continuing the legacy `v2` line. The two independent version axes are untouched
by this decision:

- `engine.SchemaVersion = "effect-ir/v1"` — versions the frozen effect IR.
- `kb.SchemaVersion = "effect-kb/v2"` — versions the knowledge-base document
  schema.

They version their own payloads, not the project identity, and stay decoupled
from it.

## Consequences

- Positive: one name spans the module path, binary, packages, wire tag,
  documentation and specs; a consumer imports and invokes a single identity that
  matches the published `v0lka/flowsh` repository.
- Positive: the three version axes remain orthogonal — project identity
  (`flowsh/v1`), effect IR (`effect-ir/v1`) and KB document schema
  (`effect-kb/v2`) can each evolve independently.
- Positive: `internal/analysis` names what the package does (compose the
  analysis), which is what a package name should convey.
- Negative: this is a breaking rename — the module path, every import path, the
  binary name and the report tag all change, so a consumer pinned to
  legacy import path or to `cmdscope/v2` must migrate.
- Negative: references to `cmdscope` survive only inside this record and the
  other accepted ADRs, where they are immutable history rather than live
  identity.

## Alternatives Considered

- **Keep `cmdscope` and publish it under `v0lka/flowsh`** — rejected: the module
  path, binary and wire tag would disagree with the published repository name,
  and the tool would carry a name its own distribution never uses.
- **Rename the binary but keep the module path** — rejected: the import path is
  the most visible public surface; splitting the identity across two names keeps
  the legacy name alive in every `go get`.
- **Continue the wire tag as `flowsh/v2`** — rejected: the rename changes the
  *identity* fields (`tool`, `toolVersion`), not the *shape* of the report.
  `flowsh/v1` is the starting public contract and already carries every field, so
  a fresh `v1` — not a `v2` — is the honest label; a `v2` would falsely imply an
  earlier shipped `flowsh/v1` with fewer fields.
- **Reuse the `cmdscope` name for the facade package** — rejected: `internal/analysis`
  describes the package's role (it composes the two frontends, the binder and
  the core), whereas `cmdscope` named an output, not the package.

## Related Specs

- [Report Contract](../contracts/report-json.md) — the `flowsh/v1` envelope this decision fixes
- [Analysis Report](../domains/analysis-report.md) — the `internal/analysis` facade
- [CLI](../domains/cli.md) — the `cmd/flowsh` binary
- [ADR-0008: Single Go Module](0008-single-go-module.md) — the module this rename applies to
