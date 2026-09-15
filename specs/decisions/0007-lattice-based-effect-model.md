# ADR-0007: Model Effects with Bounded Lattices

## Status

Accepted

## Context

An effect's properties are imprecise and must be combined when effects are merged (pipeline stages, branches, a whole script): how certain the analysis is, how destructive, how broad the target set, how attacker-influenced. Combining must be total, order-independent, and stable so that identical inputs encode identically. A naive scalar or ad-hoc merge rule loses information (e.g. drops one of two targets) or depends on order.

## Decision

Model each axis as an element of a bounded lattice with an explicit join (⊔). Use chains (`Certainty`, `Destructiveness`, `Breadth`, `Irreversibility`, `Influence`) where join is `max`, and a shared powerset lattice (`flatSet`) for `Scope` (targets) and `Taint` (labels) whose join is set union with a single top element `arbitrary`. `Effect.Join` combines two effects that share a kind and mode by joining every axis and ANDing reversibility. Set elements are stored sorted and unique so every representation is canonical.

## Consequences

- Merging is idempotent, commutative, associative, and order-independent (`TestLatticeLaws`), so results are deterministic.
- Joining two same-kind effects unions their targets and taint instead of dropping either — no silent loss.
- The `arbitrary` top element expresses "any target / any taint" without enumerating a universe, and keeps unions closed.
- Every axis maps onto the shared `Destructiveness` scale via a `Severity()` method, so a single comparable `Grade` is possible.
- `Effect.Join` is a partial operation (only same kind+mode), so callers must handle the `false` result; this is expressed in the type system rather than as a panic.

## Alternatives Considered

- **Scalar severity per effect with max-merge.** Rejected: loses target/label sets and cannot express "these two targets", breaking exfil and breadth reasoning.
- **Order-dependent set merge (first-wins or last-wins).** Rejected: non-deterministic output and silent information loss.
- **Full boolean-algebra sets without a top element.** Rejected: target and label universes are open, so closed union needs an explicit top (`arbitrary`).
- **Probability/weights instead of lattices.** Rejected: the analysis is sound-but-imprecise, not probabilistic; a lattice matches the join-based merge exactly.

## Related Specs

- [Lattices](../domains/engine/lattices.md) — the specific lattices
- [Scoring](../domains/engine/scoring.md) — how lattices fold into a score
- [ADR-0001: Freeze the Effect IR](0001-frozen-effect-ir.md) — the model this shapes
