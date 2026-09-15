# ADR-0001: Freeze the effect IR — closed kinds/modes and a pinned schema version

## Status

Accepted

## Context

The analyzer is consumed from several directions at once: two frontends
(`front/bash`, `front/ps`) emit effects, a binder (`bind`) and knowledge base
(`kb`) lower into the same types, and a composition facade
(`internal/cmdscope`) plus a CLI (`cmd/cmdscope`) and golden fixtures read the
result. If the effect vocabulary or the JSON envelope were open — each frontend
free to invent tokens — then join semantics would be ambiguous, consumers could
not rely on a stable shape, and golden fixtures would drift silently.

The core needs one contract that (a) fixes *what* an effect can say, (b) fixes
*how* effects combine, and (c) is pinned so that it can evolve deliberately
rather than by accident.

## Decision

The `engine` package freezes exactly three things and nothing else — stated in
the package doc of `engine/effect.go`:

- the effect IR — `Effect`, `EffectKind`, `EffectMode`;
- the value lattices — `Certainty`, `Scope`, `Taint`, `Destructiveness`; and
- the `Report` format, including its why-trace and destructiveness summary.

`EffectKind` is a **closed** set of 15 values (`EffectKinds`, gated by
`EffectKind.Valid()`), documented as "exactly the set of kinds a frontend may
emit". `EffectMode` is a closed set of 4 (`Direct`, `Transitive`, `Ambient`,
`Conditional`). The `Effect` struct field set is frozen, and `Effect.Join` is
defined only for two effects that share both kind and mode (unioning targets and
taint, joining certainty; reversible only if both are).

The serialised schema is tagged by a single constant — `SchemaVersion =
"effect-ir/v1"` in `engine/report.go` — which "consumers and
golden fixtures pin to". `Report.Validate`/`Encode` refuse to emit a malformed
report, and `Report.Normalize` canonicalises so that two reports built from the
same effects encode to byte-identical JSON. `kb.SchemaVersion` and
`cmdscope.SchemaVersion` are derived from `engine.SchemaVersion`, so one bump
propagates to every layer.

## Consequences

- Positive: a single, shared vocabulary; deterministic, byte-identical output;
  a version string that golden fixtures and downstream tools can pin to; `Join`
  has well-defined behaviour precisely because kind and mode are closed.
- Negative: adding a kind or a mode is a schema-change event — it requires a
  deliberate edit of `EffectKinds`/`EffectModes`, their membership maps, the
  docs, and a decision about whether `SchemaVersion` must bump. The closed set
  can lag the real world, so a frontend facing behaviour it cannot name must
  fall back to the top element ⊤ (see [ADR-0003](0003-conservative-top.md))
  rather than adding an ad-hoc kind.

## Alternatives Considered

- **Open string kinds with no `Valid()` gate** — rejected: there would be no way
  to reject a typo, `Join`/fixtures would be unbounded, and closure (the very
  thing that makes the lattice safe) would be lost.
- **Frontend-specific effect types** — rejected: the `Report` must be
  frontend-agnostic; `engine/report.go` states it "carries no
  reference to any frontend type". Per-frontend types would couple every
  consumer to a frontend.
- **No schema version, trust consumers to adapt** — rejected: golden fixtures
  and the CLI need a stable pin; a versionless schema makes drift invisible and
  un-greppable.
