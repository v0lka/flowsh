# ADR-0014: PowerShell variable state — a Σ interpreter inside the frontend

## Status

Accepted

## Context

The PowerShell frontend lowered effects directly from the parse tree without
tracking values. Three consequences followed:

1. **Fabricated literal targets.** A word like `$dir/file.txt` landed in an
   effect's scope as the *raw text* `$dir/file.txt` with `certainty=Certain` —
   a fake concrete path that contradicts [ADR-0003](0003-conservative-top.md)
   (degrade to ⊤, never guess) and that could never correlate with a real path.
2. **Lost egress endpoints.** Any `$` in a URL widened the whole egress to ⊤,
   discarding a perfectly literal host (`http://evil.example/$lines`).
3. **No dataflow exfiltration.** Secret-tainted values never flowed to a sink;
   the exfil detector ran on a program-level co-occurrence heuristic
   (`markEgressTaint`), pairing any credential read with any egress.

The bash frontend already models variables as an abstract state Σ
(`front/bash/expand.go`). The PowerShell frontend deliberately has no binder
and no knowledge base ([ADR-0005](0005-two-separate-frontends.md)), and the
engine is frozen ([ADR-0001](0001-frozen-effect-ir.md)), so the bash
interpreter cannot be reused directly: its state is bound to the mvdan/sh AST
and its `Resolver` seam assumes a knowledge base.

## Decision

Give `front/ps` its own bounded abstract variable state Σ, mirroring the bash
model at the frontend's own layer:

- **State** (`front/ps/state.go`): `Var{Value, Set, Known, Taint, Hash}` keyed
  by the lower-cased name (PowerShell names are case-insensitive); scope
  qualifiers (`$global:`/`$script:`/`$local:`/`$private:`) flatten into the
  bare name — one session scope is a sound over-approximation for one script
  file. Automatic variables (`$pid`, `$args`, `$input`, `$_`, `$PSItem`,
  `$matches`, `$error`) are seeded set-but-unknown. `JoinStates` is the least
  upper bound: a value survives only when every path agrees.
- **Word evaluation** (`front/ps/wordeval.go`): words are split into parts
  (literal runs, `$var`, `${var}`, scope/env/using qualifiers, `$(…)`,
  member/index access, backtick escapes) and combined — the word is known only
  when every part is, and its taint is the join of its parts. `$env:` values
  the script itself wrote resolve through Σ; foreign ones stay unknown and
  report an `EnvRead`. Member/index punctuation marks member access **only in
  bare argument mode** (inside a quoted string, `"$h.example"` interpolates `$h`
  and keeps `.example` literal). An unquoted `(` in a bare argument is an
  executing sub-expression: unknown + untrusted.
- **Unset reads degrade to ⊤**, not to the empty string: a profile or session
  may seed a variable the script never mentions, so "unset in the script" is
  not "unset at run time". This matches the bash frontend and ADR-0003.
- **Structured control flow** (`front/ps/parse.go`): `if/elseif…/else`,
  `foreach`, `for`, `while`, `do` and `try/catch…/finally` are normalized into
  structured statements whose bodies are walked into side lists (like an
  assignment's RHS), so nothing lowers twice and the lowerer can fork Σ per
  branch. `switch`, function bodies, classes, traps and `param` blocks stay
  opaque (⊤). A literal-decidable condition (`$true`, `$false`, `0`) picks the
  executed branch; otherwise every non-false arm runs in a cloned Σ and the
  results join. A `foreach` over a literal list iterates exactly; every other
  loop runs its body once. `break`/`continue`/`return`/`exit`/`throw` are
  control-flow keywords, not unknown commands.
- **Session-state cmdlets**: `Set-Location`/`cd` moves `$pwd`,
  `Pop-Location` marks it unknown, `Set-Variable`/`New-Variable` and
  `Set-Item Variable:` bind values, `Clear-Variable`/`Remove-Item Variable:`
  unset them. The state never reads the host environment or filesystem
  (SECURITY.md).
- **Fake literals are gone**: an effect target is the evaluated value when the
  word is known, ⊤ when it is not. An unresolved egress target stays a ⊤
  egress — scoped to the literal host when one prefixes the dynamic tail — and
  the word's provenance (including `secret`) flows onto the egress effect, so
  `DetectExfil` pairs on real per-command dataflow. `markEgressTaint` remains
  as a program-level backstop.
- **Splat expansion**: `@{…}` literals parse into entries
  (`Assign.Hash`, `Var.Hash`); `Get-Content @p` with a fully-known `$p`
  expands into its parameter bindings (switch entries included), so
  destructiveness escalations survive splatting. An unknown splat keeps its ⊤.
- **Budget**: lowering gains a deterministic step counter
  (`defaultBudget = 50000`, ADR-0006's bash order); exhaustion or any internal
  panic unwinds to ⊤ with the effects discovered so far preserved. The budget
  is a counter, not a wall clock, so it needs no race-detector special case
  (unlike the parse timeout of ADR-0012/0013).

## Consequences

- Positive: PowerShell reports gain concrete targets, host-scoped egress,
  dataflow-based exfiltration, branch-accurate values and exact literal-list
  iteration — parity with the bash frontend's precision on the constructs PS
  scripts actually use. Every unresolved construct still degrades to ⊤, so the
  no-silent-miss invariant only strengthens (fake literals became ⊤).
- Negative: the frontend now maintains an interpreter's worth of code
  (state, word evaluation, structured lowering); report shapes change where
  fabricated literals existed before (corpus re-pinned, expectations updated
  consciously); truthiness over strings (`"0"` is falsy, `"False"` is false)
  is an approximation of PowerShell's richer type system.

## Alternatives Considered

- **Reuse the bash interpreter over a converted AST** — rejected: different
  ASTs and semantics, and it would drag the binder seam into a frontend that
  is defined not to have one (ADR-0005).
- **Treat unset reads as the empty string (faithful PS string semantics)** —
  rejected as the default: weaker under the threat model (profiles seed
  variables) and inconsistent with the bash reference.
- **Keep raw-text targets and only add value propagation** — rejected: it
  would preserve confidently-wrong `Certain` targets, the exact failure the
  work set out to remove.

## Related

- [ADR-0003](0003-conservative-top.md) — degrade-to-⊤, which the Σ model
  operationalizes for PowerShell values.
- [ADR-0005](0005-two-separate-frontends.md) — why the state lives in the
  frontend instead of a shared binder.
- [ADR-0006](0006-bounded-abstract-execution.md) — the bounded-execution
  pattern this budget follows.
- [PowerShell Frontend](../domains/powershell-frontend.md) — the domain spec
  describing the implementation.
