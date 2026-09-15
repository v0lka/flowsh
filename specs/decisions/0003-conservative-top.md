# ADR-0003: Degrade to ⊤, never guess

## Status

Accepted

## Context

This is a security analysis tool, so the cost of the two error directions is
asymmetric: a false negative — a real effect that is silently dropped — is far
worse than a false positive. Frontends inevitably meet inputs they cannot fully
understand: unknown or dynamically-named programs, encoded payloads, parser
errors, exhausted budgets, internal failures. The design question is *what to
report when understanding fails*, and the two tempting answers ("guess the most
likely effect" and "report no effect") are both unsound.

## Decision

Where the analysis cannot see, it degrades to the **top element ⊤** — realised
as `CodeExec` over the any-target `Scope` — rather than guessing or reporting
"no effect". Every layer implements the same rule:

- The shell abstract-execution layer documents that when it cannot finish it
  "degrades to ⊤ rather than diverge"; a wholly degraded analysis is an
  `ExecResult` with `Top` set and a `Reason`, and a ⊤ effect inside an otherwise
  analysed program is flagged `Conservative`
  (`front/bash/exec.go`).
- The binder states it plainly: a call whose name is not statically known, or
  that matches no builtin/function/alias/KB command, "degrades to the top
  element ⊤ ... never to 'no effect'"
  (`bind/bind.go`).
- The PowerShell frontend folds *every* unrecoverable failure — unknown
  construct, parser timeout, internal panic — into `Program.Top=true` with a
  human-readable `Reason`, so that `Lower` emits ⊤ and nothing else
  (`front/ps/parse.go`).
- The regression corpus codifies it as guard-evasion class **E**:
  "unbounded/opaque work that must degrade to ⊤ (budget exhaustion, unknown)"
  (`internal/cmdscope/corpus.go`).

⊤ is a lattice element (`ScopeTop`, `TaintTop`; `CodeExec` maps to
`DestructCritical`), so it joins as the absorbing element and propagates
soundly.

## Consequences

- Positive: sound by default — unknown behaviour is never silently dropped;
  degradation is deterministic and representable as data, so it is testable and
  reproducible.
- Negative: a precision cost — any program containing an opaque construct
  reports a ⊤ effect and is therefore over-approximated; because ⊤ is absorbing
  under join, a single opaque construct can dominate an entire aggregate. The
  `Conservative`/`Top` flags exist so consumers can tell an over-approximation
  from a precise result.

## Alternatives Considered

- **Best-effort "most likely" effect** — rejected: a guess can be wrong in
  either direction and is indistinguishable from a bug; it is not sound.
- **Report nothing when unsure** — rejected: this is the worst failure mode for
  a security analyzer — a silent false negative.
- **Return a Go error / abort the analysis** — rejected: the tool must always
  produce a report, so failure is folded into the *data* (`Top` + `Reason`)
  rather than expressed as control flow.
- **Add a bespoke "unknown" effect kind** — rejected: it would breach the closed
  kind set of [ADR-0001](0001-frozen-effect-ir.md); ⊤ already carries
  "anything" semantics through `CodeExec` over the any-target scope.
