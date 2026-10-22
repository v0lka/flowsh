# ADR-0018: The determinism gate tolerates a parse-budget ⊤

## Status

Accepted

## Context

[ADR-0006](0006-bounded-abstract-execution.md) bounds one PowerShell parse with a
wall clock — `DefaultTimeoutMicros = 250_000` — and a parse that trips it becomes
⊤ (the sound direction, [ADR-0003](0003-conservative-top.md)). The bound is
therefore, unavoidably, an input to the report: whether it fires is a property of
how much wall-clock time the host gives the parse goroutine, not of the source.

The concurrent embedding gate (`api/api_test.go`,
`TestAnalyzeConcurrentMatchesSequential`) pins the determinism claim: 32
goroutines analyse the probe set four times over the process-wide analyser, and
every one of the 768 results must be byte-identical to the sequential reference.
[ADR-0012](0012-race-advisory-parse-budget.md) made the budget advisory under the
race detector after that gate failed under `-race` on a shared 2 vCPU runner.

The gate also runs in an **ordinary** build on all three CI operating systems
(`go test ./... -count=1`). On 2026-10-22 the macOS job of run `39803827370`
failed with 3/768 results differing — two `posh write` and one `posh secret
read`, each a `⊤ … parse exceeded its 250000 µs budget` — while the Linux and
Windows jobs of the same run passed. Reproduced locally by oversubscribing a
16-core host six times over (96 spinning goroutines): 4/4 runs failed with 3–12
trips.

The mechanism is not a defect in the analyser. The probe sources are 15 and 31
bytes and parse in microseconds, so a 250 ms trip means the goroutine was simply
not scheduled for a quarter of a second — the runner was busy with the other test
binaries of the same `go test ./...` invocation. The gate asserted a property the
design cannot guarantee in a build where a wall-clock bound is live, and a
wall-clock threshold the slowest runner cannot meet is a false alarm rather than
a real regression (the principle of
[ADR-0011](0011-ci-tolerant-load-budget.md)).

The fix cannot be on the production side: the parse budget is a security
contract, and `SECURITY.md` forbids removing, raising or bypassing the analysis
bounds (including as a test convenience).

## Decision

The gate classifies a mismatch before failing:

- A result that is ⊤ **because the parse budget expired** (the reason carries the
  production wording) while the sequential reference is concrete is a *candidate*
  host-load artifact. The gate re-analyses that input sequentially, up to four
  attempts (a lone analysis competes with no other goroutine, so the budget is
  expected to hold on the first attempt):
  - the reference is reproduced → **tolerated trip**: counted, logged with the
    counts in the test output, and the run continues;
  - every attempt trips too → the host cannot give a benign source its budget at
    all, so the byte-identity half of the claim is unmeasurable there →
    `t.Skip` with that message;
  - a concrete report that differs, a failure, or a ⊤ for **any other** reason
    (a panic, a grammar failure, an unresolved source) → **real mismatch**, fatal
    exactly as before.
- Nothing is tolerated for the other dialects: bash and posix run under no
  wall-clock budget, so their results must always match byte for byte.

The classifier keys on the fragment `µs budget` of the reason `front/ps` emits
(`parse exceeded its %d µs budget: treating source as ⊤`). That wording is pinned
from the producing side by `front/ps` `TestParseTimeoutYieldsTop`, and the
classifier's negative direction — a ⊤ from a panic, a grammar failure or no
reason at all is *not* tolerated — by `api` `TestRetrySequentiallyClassification`.
Matching a fragment keeps the gate fail-closed: if the wording changes, a budget
trip is reported as nondeterminism instead of being silently tolerated.

No production behaviour changes. `Parse` keeps `DefaultTimeoutMicros`, a trip
still reports ⊤/conservative, and the shipped binary's DoS backstop is untouched.

## Consequences

- Positive: the gate stops failing a CI run because the runner was busy, on the
  OS whose runner is the slowest of the matrix.
- Positive: the strict byte-identity claim is unchanged wherever it is
  measurable — under `-race` (budget disabled, ADR-0012) it is unconditional, and
  on an unloaded host it is exactly what the gate has always enforced.
- Positive: the tolerance is narrow. It requires the *budget* reason **and** a
  sequential reproduction of the reference, so a real divergence cannot hide
  behind it.
- Negative: on a loaded ordinary build, a systematic nondeterminism that could
  only ever manifest as a parse-budget ⊤ would be tolerated. That defect class is
  still caught by the `-race` gate on Linux, where the budget cannot fire.
- Negative: the gate now depends on production diagnostic wording. That is
  deliberate (fail-closed), but it is a second place to update when the reason
  text changes — pinned by a test rather than by memory.
- Negative: the test output distinguishes "all byte-identical" from "N trips,
  each reproduced sequentially", so a reader of a green run can see which claim
  was actually demonstrated.

## Alternatives Considered

- **Raise `DefaultTimeoutMicros`.** Rejected: `SECURITY.md` forbids raising an
  analysis bound, and ADR-0012 already rejected a larger budget as a flakiness
  fix — it lowers the probability without removing the dependence on host load.
- **Disable the budget for test builds.** Rejected: a test-only escape hatch in
  the production parse path is a DoS bypass by another name, and Go has no
  "test" build tag to scope it.
- **Warm up the analyser and the grammar before the concurrent phase.** Rejected
  by ADR-0012 and insufficient here: the observed failures are sustained
  starvation (4/4 runs under 6× oversubscription), not one-time initialisation.
- **Drop the posh probes from the gate.** Rejected: it would silently stop
  testing the only dialect that has a wall-clock budget — the place the defect
  class actually lives.
- **Tolerate any ⊤ result.** Rejected: it would hide real degradations (a panic,
  a grammar failure) that the gate exists to catch.
- **Serialise the CI test step (`go test -p 1`).** Rejected: slower on every
  platform, and it only lowers the probability of the trip rather than deciding
  what the gate may claim.
- **Assert only that the report is *covered* (effect, ⊤ or conservative).**
  Rejected as too weak: it would pass a run where every concurrent analysis
  degraded, which is exactly the signal the gate should surface.

## Related Specs

- [Analysis Facade and Report](../domains/analysis-report.md) — the `api/` surface and the invariants this gate checks
- [PowerShell Frontend](../domains/powershell-frontend.md) — the parse budget and its ⊤ reason
- [ADR-0003](0003-conservative-top.md) — why ⊤ is the sound answer
- [ADR-0006](0006-bounded-abstract-execution.md) — the parse timeout itself
- [ADR-0011](0011-ci-tolerant-load-budget.md) — CI-tolerant wall-clock constants
- [ADR-0012](0012-race-advisory-parse-budget.md) — the budget under the race detector
