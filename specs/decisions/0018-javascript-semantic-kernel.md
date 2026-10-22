# ADR-0018: Bounded JavaScript semantic kernel

## Status

Accepted

## Context

The JavaScript dialect foundation accepts source but treats every input as opaque. Issue #28 requires values and control flow before Node API effects land. The PowerShell parity audit shows that opaque function architecture, lost provenance, hardcoded API knowledge, and report gaps are costly to retrofit. Issue #34 separately owns function invocation and module/closure semantics.

## Decision

Use the JavaScript grammar embedded in the already pinned pure-Go gotreesitter dependency. Normalize into frontend-owned, position-preserving nodes under explicit source/node/depth limits; discard the parser tree after normalization. Parse failures degrade to the existing top representation.

Keep a typed value lattice and case-sensitive lexical state inside `front/js`, outside the frozen engine. Carry `engine.Taint` independently of knownness. Use immutable object/array snapshots, bounded state cloning/joins, and separate normal/break/continue/return/throw completion paths. Charge expressions, statements, iterations, joins, and expansion against a deterministic 50,000-step budget. Preserve earlier effects when bounds stop evaluation.

Retain function bodies and make the same statement evaluator usable for bodies in isolated state. Declaration is not invocation. Keep calls conservative until #34 adds parameters, return propagation, recursion, closures, module aliases, and callbacks. This boundary implements #28 without claiming that #34 has landed.

Provide a function-valued, typed call-resolution seam, injected above the frontend. The facade currently passes nil, so all calls, constructors, and external module initialization remain conservative. Later Node API knowledge belongs to the YAML/binder milestone, not frontend Go tables. The frontend imports neither `bind`, `kb`, nor sibling frontends.

Choose no console stdout folding. Awaited primitive values use sequential semantics; unknown thenables degrade. Event-loop scheduling stays out of scope.

Preserve the existing wire contract and policy behavior: understood pure programs may yield valid empty-effect reports, with `Covered()==false` and policy `uncovered_report` denial. Local unknown execution sets Conservative with canonical top; parse/budget/internal failures additionally set Top. No artificial effect or coverage flag is introduced.

## Consequences

- Values and control flow are testable directly, so blanket top coverage cannot stand in for semantic support.
- Source-located derivations use the existing shared why/scoring pipeline without changing the frozen engine or report schema.
- #34 and the Node effect families remain separate tracked work, with bodies and a typed seam available for extension.
- Coarse mutation, unknown coercion, external initialization, and unsupported constructs lose precision conservatively.
- Existing stub-specific API/CLI/policy tests and documentation must distinguish pure programs from unsupported execution.

## Alternatives Considered

- A new parser dependency or JavaScript runtime: the pinned grammar already supplies parsing; executing source violates the analysis-only boundary.
- A handwritten JavaScript parser: duplicates lexical/grammar complexity and risks silently dropping executable syntax.
- A permanent opaque function representation: repeats the PowerShell #4 trap. Retain bodies now, implement invocation under #34.
- Combining #28 and #34: imports parameter, closure, recursion, and module scope into a values/control-flow milestone.
- Keeping unconditional top or changing Covered for pure programs: hides missing evaluation or changes a shared consumer contract unnecessarily.

## Related Specs

- [JavaScript Frontend](../domains/javascript-frontend.md) — supported subset and degrade table.
- [Analysis Report](../domains/analysis-report.md) — facade and report behavior.
- [Frontend/Engine Contract](../contracts/frontend-engine.md) — dependency boundary.
- [Conservatism](../architecture/conservatism.md) — shared top representation.
