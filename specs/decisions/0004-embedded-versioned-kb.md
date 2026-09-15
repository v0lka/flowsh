# ADR-0004: Embed and version the knowledge base

## Status

Superseded by [0011](./0011-ci-tolerant-load-budget.md) for the load-latency acceptance threshold only; the embed-and-version decision stands.

## Context

The knowledge base maps command parameters to the effects they contribute
(`kb/data/*.yaml`). Three requirements pull in different directions: it must be
available **with no external files** and be correct regardless of the working
directory; it must load **fast**, because analysis runs per invocation; and it
must **evolve** without a reader silently misinterpreting a document written for
a different schema.

## Decision

The dataset is authored as YAML under `kb/data/*.yaml` and compiled into the
binary with `//go:embed data/*.yaml`, exposed as `var dataFS embed.FS`
(`kb/loader.go`). `Load()` reads **only** from the embedded
filesystem — "no files on disk at run time" — so it works from any working
directory; `EmbeddedFiles()` exposes the document names.

The document schema is **frozen and versioned**: `SchemaVersion =
"effect-kb/v2"` (`kb/schema.go`), with an explicit
`KnownVersions` list and a `Known()` gate. The loader rejects a missing or
unknown version and refuses to merge documents that disagree on it
(`kb/loader.go`). v2 *added* the per-parameter `fileRef` marker
(the `@file` convention), which a v1 document cannot express — hence the version
was **bumped rather than extended in place**.

Performance is an acceptance criterion, not an aspiration: `TestLoadUnderBudget`
asserts that `Load()` completes in **under 5 ms with no external files**
(`kb/loader_test.go`).

## Consequences

- Positive: zero-config, hermetic and fast (no disk I/O on the hot path);
  version-checked so schema drift is a loud error not a silent misread; the
  loader is testable against an in-memory filesystem (`loadFS`), which is how
  bad-version and conflict cases are covered; `KB.Validate` additionally checks
  referential integrity of destructive entries.
- Negative: changing the dataset requires recompiling the binary; every schema
  extension needs a new `effect-kb/vN` and a loader decision about which
  versions to accept; a given binary pins exactly one known version.

## Alternatives Considered

- **Ship the YAML next to the binary / read it from disk at runtime** —
  rejected: violates "no external files" and CWD-independence, and adds I/O to a
  latency-sensitive path.
- **Embed the data without a version field** — rejected: silent schema drift; a
  reader could mis-interpret an older/newer document with no signal.
- **Extend `effect-kb/v1` in place to add `fileRef`** — rejected: a v1 reader
  would misread the new field, so the schema version was bumped instead.
- **Derive the KB from man pages / `--help` at runtime** — rejected:
  non-deterministic, slow, and unavailable in a hermetic binary.
