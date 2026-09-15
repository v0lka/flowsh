# ADR-0012: The PowerShell parse budget is advisory under the race detector

## Status

Accepted

## Context

[ADR-0006](0006-bounded-abstract-execution.md) bounds a PowerShell parse with a
wall-clock timeout — `DefaultTimeoutMicros = 250_000`, applied via
`parser.SetTimeoutMicros` (`front/ps/parse.go`) — so a pathological source
degrades to ⊤ instead of stalling the analysis. That is a *safety* bound, but it
is also, unavoidably, a *correctness input*: a parse that trips it becomes ⊤, and
whether it trips depends on how much wall-clock time the host gives the
goroutine, not on the source.

The concurrent embedding test (`api/api_test.go`,
`TestAnalyzeConcurrentMatchesSequential`) pins the documented invariant that the
analysis is deterministic: 32 goroutines analyse the same inputs and every
result must be byte-identical to the sequential run. Under the race detector on
the shared 2 vCPU Linux runner the 250 ms budget stopped firing on pathological
input and started firing on the *runner*. `-race` instruments every memory
access and inflates the parse several-fold, and the one-time knowledge-base load
(`sync.OnceValues`) allocates ~7 MB per call, so its GC pressure stalls other
goroutines mid-parse. 4–6 of 768 parses exceeded 250 ms of wall clock and
flipped a benign `Get-Content ~/.aws/credentials` / `Set-Content x y` to
`⊤ … parse stopped early (timeout)`, failing the race gate with a real
non-determinism (reproduced locally by running the gate under `-race` with
`GOGC=1` and a saturated host).

The CI already declares wall-clock budgets meaningless under the race detector —
the per-command latency gate and the KB load-budget gate skip under `-race`
(`engine/norace_test.go`, `kb/norace_test.go`) — but the *production* parse
budget carried no such exemption.

## Decision

Make the per-parse wall-clock budget advisory under the race detector. `Parse`
takes its budget from a build-tagged constant:

- `front/ps/budget_norace.go` — ordinary build: `parseBudgetMicros =
  DefaultTimeoutMicros` (250 ms), unchanged;
- `front/ps/budget_race.go` — `-race` build: `parseBudgetMicros = 0`, which
  disables the deadline check.

`ParseTimeout` still takes an explicit budget in every build, so a caller that
wants to pin one can. Termination under `-race` is still guaranteed:
gotreesitter bounds every parse with deterministic, source-length-scaled limits
(max iterations, max nodes, max stack depth) that do not depend on the host's
speed or load, so an adversarial source still degrades to ⊤ — on those limits
rather than on a wall clock. The one wall-clock *test* ceiling that had relied
on the production budget (`front/ps/fuzz_test.go`,
`TestAdversarialInputsAreBounded`) is guarded with `raceDetectorEnabled`, exactly
like the other wall-clock gates, while its non-timing assertions still run.

## Consequences

- Positive: under the race detector the analysis is deterministic again, so the
  concurrency gate tests what it claims; a race-instrumented run no longer
  reports a benign source as ⊤ merely because of scheduling or GC.
- Positive: the ordinary build is unchanged — `Parse` still returns ⊤ on a
  250 ms timeout, so ADR-0006's DoS bound holds in every shipped binary.
- Negative: a race-instrumented binary no longer has the wall-clock backstop for
  a pathological source and relies on the parser's deterministic limits. This is
  acceptable because `-race` is a diagnostic build and those limits still bound
  the parse.
- Negative: `Parse`'s default budget now varies with the build mode — a second
  axis to keep in mind, documented in `front/ps/parse.go` and the build-tagged
  files.

## Alternatives Considered

- **Raise `DefaultTimeoutMicros` (e.g. 250 ms → 2 s).** Rejected: a larger
  wall-clock budget only lowers the probability of a spurious trip; it does not
  remove the dependence on host load, so the determinism gate stays flaky, and
  it weakens the DoS bound in every build.
- **Remove the wall-clock budget entirely, in all builds.** Rejected: it
  discards the DoS backstop from shipped binaries (ADR-0006), and a race-built
  adversarial parse (`unbalanced-quotes`, 16 KB) still takes ~9 s, so it would
  need the same test exemption without keeping the protection.
- **Scale the budget by input size / drop it only for small sources.** Reasonable
  but rejected as more machinery for the same result: it would add a size
  threshold where the race detector is the documented, existing reason wall-clock
  budgets are not meaningful.
- **Warm the analyser up before the concurrent phase in the test.** Rejected: it
  would hide the transient KB-load/GC stall rather than fix it, and a shared
  analyser must be deterministic for an *external* embedder under any load, not
  only under this test's schedule.

## Related Specs

- [PowerShell Frontend](../domains/powershell-frontend.md) — the parse budget
- [ADR-0006](0006-bounded-abstract-execution.md) — the parse timeout and the step budget
- [Conservatism](../architecture/conservatism.md) — the ⊤ degradation table
