# ADR-0015: A per-host reference for the per-command latency gate

## Status

Accepted

## Context

`TestPerCommandLatencyBudget` (`engine/bench_test.go`) enforces two properties
over the whole corpus: an **absolute** per-command p95 budget (`budgetMs: 100`,
every command must stay under it) and a **regression tripwire**
(`baselineP95Ms x toleranceFactor` = `12 x 6` = `72 ms`, the worst command must
stay under it). Both numbers live in `engine/testdata/latency_baseline.json`.

The worst command is always the same case: `gf-bash-e-loop`, the input
`while true; do :; done`. It is a *budget-exhaustion* case — it deliberately runs
the bash interpreter to its `defaultBudget = 50000` steps before the analysis
degrades to ⊤ ([ADR-0006](0006-bounded-abstract-execution.md)). Its wall-clock
cost is therefore pure CPU: `50000 x per-step-cost`, with the per-step cost set
by the host's single-core speed.

The reference was calibrated on a developer machine (darwin/arm64), where that
case measures ~12 ms. On the Windows CI runner it does not:

```
--- FAIL: TestPerCommandLatencyBudget (37.65s)
  latency over 170 commands: worst p95 86.120 ms (gf-bash-e-loop);
  budget 100.0 ms; baseline 12.000 ms x6.0 = 72.000 ms
  latency regression: worst p95 86.120 ms exceeds the baseline ceiling 72.000 ms
```

`windows-latest` (2 vCPU) is ~7x slower than darwin/arm64 on this CPU-bound
case: 86.12 ms against a 72 ms ceiling — a **false alarm**, not a code
regression. The absolute budget (100 ms) still passed, and the darwin timing was
unchanged by the commit under test (12.2 ms vs the 12.0 ms reference), so no
code got slower. This is the same class of problem [ADR-0013](0013-windows-clock-tick-parse-budget.md)
ruled on for the Windows monotonic clock and [ADR-0011](0011-ci-tolerant-load-budget.md)
ruled on for the knowledge-base load budget: a wall-clock threshold the slowest
supported runner cannot meet tests the runner, not the code.

A single shared constant cannot fix it. The ceiling is `baseline x tolerance`,
and it must (a) exceed the observed Windows p95 to stop the false alarm, while
(b) staying below the budget so the tripwire can still fire first. With
`baseline = 12` that forces `7.2 < tolerance < 8.3`: at most an ~8x tolerance,
leaving under 12% headroom over the already-observed 86 ms — too thin for shared
runners. And every value in that window also loosens the tripwire on the hosts
we *can* measure (darwin/linux) from 72 ms to ~96 ms. Raising the budget to buy
headroom instead loosens the absolute net on every host. There is no single
constant that accommodates the slowest runner and keeps a meaningful tripwire on
the fastest.

## Decision

Make the reference **per host**. `latency_baseline.json` gains an optional
`hostOverrides` map keyed by `runtime.GOOS`; each entry may replace `budgetMs`,
`baselineP95Ms` and `toleranceFactor`, and any field it omits keeps the shared
value. `TestPerCommandLatencyBudget` resolves the numbers with
`loadBaseline(t).forHost(runtime.GOOS)` and compares each host against its own
reference. A host therefore names its own numbers instead of inflating the
constants every host shares.

Only `windows` needs an entry, calibrated from the observed CI failure:

| Host | budgetMs | baselineP95Ms | toleranceFactor | tripwire |
| ---- | -------- | ------------- | --------------- | -------- |
| shared (darwin/arm64, linux) | 100 | 12 | 6 | 72 ms |
| windows | 350 | 90 | 3 | 270 ms |

The Windows entry keeps the two properties a host needs: its reference (90 ms)
sits just above the observed worst (86.12 ms, rounded up with a small margin),
and its tripwire (270 ms) stays well below its budget (350 ms), so a real
slowdown — a regression that no host-speed difference explains — still fails. A
new host whose CPU is not covered by the shared reference adds its own entry the
same way.

`TestLatencyBaselineHostOverride` pins the resolution on every host: an
overridden host uses its entry, an unlisted host keeps the shared numbers, and
no host's tripwire crosses its own budget.

## Consequences

- Positive: the gate is green on all three CI OSes without weakening the
  regression tripwire on the hosts whose CPU the shared reference describes —
  the outcome ADR-0011 and ADR-0013 both aimed for.
- Positive: the per-command reference now states *which host* each set of
  numbers describes, so the Windows behaviour is documented rather than
  rediscovered as a CI failure.
- Positive: adding a runner whose CPU the shared reference does not cover is a
  reviewable data edit, not a code change.
- Negative: the gate carries more than one set of numbers, so a change to the
  corpus or the interpreter must be re-checked against the host it is measured
  on; the shared constants no longer describe every host.
- Negative: the Windows tripwire (3x its reference) is looser than the shared
  one (6x), so a moderate regression on Windows would pass — the same
  precision-for-CI-stability trade ADR-0011 accepted for the load budget.

## Alternatives Considered

- **Raise the shared `toleranceFactor` (and budget) so Windows passes.**
  Rejected: as shown in the Context, a shared tolerance large enough for the
  ~7x-slower Windows runner either leaves <12% headroom (a latent flake) or
  pushes the ceiling past the budget, where the tripwire can never fire; and it
  loosens the tripwire on darwin/linux for no reason.
- **A per-host multiplier applied to the shared reference.** Rejected: it
  double-counts, because the tolerance already absorbs host speed. A x8 host
  factor on the shared `12 x 6` gives a 576 ms ceiling, far above the 100 ms
  budget — the budget would fire first and the tripwire would be dead.
- **Normalise the measurement with a runtime speed-calibration probe.** Rejected
  as needless machinery ([ADR-0011](0011-ci-tolerant-load-budget.md) rejected the
  same idea for the load budget): the probe would itself be measured on the
  coarse/slow host, and a fixed per-host constant is simpler and reviewable.
- **Skip the tripwire on the slow host.** Rejected: ADR-0011 and ADR-0013 both
  kept their gates live on every platform; here only the *numbers* need to
  differ, so the gate can stay live with a host reference.
- **Exclude the budget-exhaustion case from the tripwire.** Rejected: that case
  is the worst on every host and the gate's whole point is to bound the worst,
  so dropping it would hide real slowdowns in the interpreter's step loop.
- **Reduce `defaultBudget` so the worst case is cheaper on every host.**
  Rejected: `50000` is a deliberate precision/robustness bound (ADR-0006), not a
  performance knob; changing it to fit a CI runner would trade correctness for a
  test threshold.

## Related Specs

- [Engine domain](../domains/engine/README.md) — the latency and recall gates
- [ADR-0006](0006-bounded-abstract-execution.md) — the step budget the worst case exhausts
- [ADR-0011](0011-ci-tolerant-load-budget.md) — the same false-alarm class for the load budget
- [ADR-0013](0013-windows-clock-tick-parse-budget.md) — the same false-alarm class for the parse budget
- [Conservatism](../architecture/conservatism.md) — the ⊤ degradation table
