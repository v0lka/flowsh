# ADR-0006: Bound abstract execution — a step budget and a parse timeout

## Status

Accepted

## Context

Abstract execution runs over an unbounded domain: loops, recursion, expansions
and pipelines can diverge (a literal `while true`) or grow state without limit,
and a pathological or hostile input can keep the *parser* busy for a long time.
The tool must always terminate with bounded wall-clock cost, while remaining
sound in the sense of [ADR-0003](0003-conservative-top.md) (a bound must never
turn into a wrong-but-confident answer).

## Decision

Bound **both** layers, and make exhaustion a *data* outcome rather than a crash.

- **Bash abstract execution — a step budget.** The interpreter charges one unit
  per interpreted step (redirections, statements, loop iterations and function
  calls all draw on it) against `defaultBudget = 50000`. Supporting bounds cap
  the other unbounded dimensions: `maxFuncDepth = 64`, `maxAliasDepth = 32`, and
  `maxRecorded = 1024` (so a non-terminating loop cannot grow the recorded lists
  before the budget stops it). When the budget runs out the interpreter unwinds
  via `budgetError` and the result degrades to ⊤ — "which is what makes `while
  true` cheap" (`front/bash/exec.go`).
- **PowerShell parsing — a wall-clock timeout.** A single parse runs under
  `DefaultTimeoutMicros = 250_000` (250 ms per source; the whole analysis is
  budgeted hundreds of milliseconds), applied via `parser.SetTimeoutMicros`. A
  parse that stops early, times out, or panics becomes a ⊤ program —
  `Program.Top=true` with a `Reason` — via `topProgram`
  (`front/ps/parse.go`).

In both layers, hitting a bound yields `Top` plus an explanatory `Reason`; it is
never an error the caller must recover from.

## Consequences

- Positive: guaranteed termination and bounded cost even for adversarial input;
  degradation is deterministic and lands on ⊤, so it stays sound; the bounds are
  simple named constants that are easy to audit and tune.
- Negative: a legitimate but very large program can exceed a bound and be
  reported as ⊤, i.e. over-approximated; the constants encode a
  precision/robustness trade-off (too low loses precision, too high risks time),
  so they are a maintenance surface.

## Alternatives Considered

- **Unbounded interpretation with an external watchdog / goroutine kill** —
  rejected: Go cannot cleanly interrupt arbitrary code, and a wall-clock kill is
  non-deterministic; the step budget gives a reproducible bound.
- **Iterate loops a fixed number of times each** — rejected: still unbounded in
  aggregate across nested/recursive constructs; one shared budget bounds
  everything at once.
- **No parser timeout** — rejected: a pathological source could stall the
  analysis; the code notes a zero timeout is "not recommended for untrusted
  input".
- **Return an error on exhaustion** — rejected: the tool must always emit a
  report, so exhaustion is folded into ⊤ with a `Reason`.
