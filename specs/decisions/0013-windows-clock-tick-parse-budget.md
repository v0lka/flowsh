# ADR-0013: A sub-millisecond parse budget is unobservable on the Windows monotonic clock

## Status

Accepted

## Context

`TestParseTimeoutYieldsTop` (`front/ps/lower_test.go`) is acceptance criterion 4
for the PowerShell frontend: a parse that times out must degrade to ⊤ with a
`Reason`, validate, and lower to a conservative `CodeExec`. It drove that
condition with `ParseTimeout(src, 1)` — a **1 µs** budget — over three sources:
`Get-Content x` (13 B), a 5000-statement repeat (75 KB) and `if($true){rm -Force
x}` (22 B). The comment asserted that "1 µs is far below the cost of even a tiny
parse, so the timeout trips deterministically".

That premise holds on Linux and macOS but not on Windows, where the test failed
on CI:

```
--- FAIL: TestParseTimeoutYieldsTop (0.00s)
    lower_test.go:244: "Get-Content x": expected ⊤ on timeout, got a parsed program
```

gotreesitter trips its deadline when a parse-loop poll reads `time.Now()` at or
past `start + timeoutMicros` (`activeParseStopReason`, `parser_timeout.go`), and
the fresh full-parse loop polls on **every** iteration (`parser.go`). The loop
therefore only stops once the *monotonic clock has advanced past the deadline*,
not merely once the budget has "elapsed" — the two differ when the clock cannot
resolve the interval.

On Windows they differ by orders of magnitude. `runtime.nanotime` is not
`clock_gettime`: `runtime.nanotime1` reads the OS **interrupt time**
(`runtime/sys_windows_amd64.s`, `_arm64.s`, `_386.s` — `_INTERRUPT_TIME` × 100 ns),
which the kernel advances only on the system timer tick. Go asks for a 1 ms floor
via `timeBeginPeriod` **only** when the platform has no high-resolution timer
(`osRelax`/`haveHighResTimer`, `runtime/os_windows.go`); otherwise the tick is the
default **15.6 ms** (64 Hz). Either way the granularity is ≥ 1 ms — at least a
thousand times the 1 µs budget.

So on Windows every poll during a short parse reads the *same value as `start`*,
which is still `Before(start+1 µs)`, and the deadline is never observed. A source
whose whole parse fits inside one tick (`Get-Content x` parses its loop in well
under 1 ms; measured ~270 µs here with a 1 ms budget that did **not** trip) can
never trip a sub-tick budget, however often the parser polls. The 15.6 ms tick
also explains why the tiny source fails deterministically rather than flakily.

This is the same class of problem ADR-0012 already ruled on for the race
detector — a wall-clock budget is not meaningful where the host cannot measure it
— but on a different axis: not instrumentation, but clock resolution.

## Decision

Keep the test running on every platform, and assert the 1 µs deadline only where
the clock can resolve it; cover the timeout→⊤ path everywhere with a source that
spans many ticks.

- `front/ps/lower_test.go` gains `coarseMonotonicClock` (`runtime.GOOS ==
  "windows"`) and marks the two sources whose entire parse fits inside one tick
  (`Get-Content x`, `if($true){rm -Force x}`) as `shortParse`. A `shortParse` case
  is skipped **with a logged reason** on a coarse-clock host and asserted on a
  fine-grained one, so Linux and macOS keep the exact coverage they had.
- The repeated-statement source is widened from 5000 to **20000** statements
  (`~300 KB`). Its parse is ~254 ms with the deadline disabled on a developer
  machine, ~16x the coarsest default Windows tick, so it is guaranteed to cross a
  tick and trip on every host — keeping the timeout→⊤, reason, validate and
  conservative-lowering assertions live on Windows. Widening is nearly free: with
  a 1 µs budget the parse stops at the first tick boundary (≤ 15.6 ms on Windows,
  ~1.6 ms here), long before it has read the whole source.

The production budget is untouched: `DefaultTimeoutMicros = 250_000` is far above
any clock tick, so `Parse` still bounds a pathological source at ⊤ on Windows
exactly as before (ADR-0006/ADR-0012).

## Consequences

- Positive: the gate is green on all three CI OSes without dropping the
  acceptance criterion. Linux/macOS keep the full three-source coverage; Windows
  still exercises the real timeout→⊤ path through the repeated-statement source.
- Positive: the test now states *why* a sub-tick budget is unobservable, so the
  Windows behaviour is documented rather than discovered as a CI failure.
- Negative: Windows no longer pins a timeout on a trivially small source. That
  scenario is physically unobservable there — the tick, not the test, is the
  limit — so it cannot be asserted without a different mechanism.
- Negative: the coverage split depends on the assumption that Windows is the only
  supported host with a coarse monotonic clock. A new coarse-clock target would
  need the same treatment.

## Alternatives Considered

- **Skip the whole test on Windows.** Rejected: only the sub-tick cases are
  unobservable, and the large source still validates the timeout→⊤ contract on
  Windows — the same reasoning ADR-0011 used to reject skipping a timing gate
  outright.
- **Raise the budget above a tick (e.g. 1 ms).** Rejected: it does not help. The
  deadline is observed only at the *next tick boundary* (≤ 15.6 ms on Windows),
  which a sub-tick parse never reaches no matter how small the budget, so a tiny
  source still cannot trip.
- **Make `ParseTimeout` enforce the budget itself (self-timed elapsed check or a
  goroutine watchdog).** Rejected: a self-measured elapsed check reads the same
  coarse clock and still sees 0 for a sub-tick parse, and ADR-0006 already
  rejects a watchdog kill as non-deterministic.
- **Detect the clock granularity at runtime in the test and skip on that basis.**
  Rejected: a regression that stopped the deadline firing *everywhere* would make
  the probe conclude "coarse" and silently skip, masking the failure. The
  `runtime.GOOS` guard cannot be fooled by the code under test.
- **Keep the original 5000-statement source.** Rejected: its ~6x margin over a
  15.6 ms tick is thinner than the 20000-statement source's ~16x, and the larger
  source costs nothing on a fine-grained clock because the parse stops early.

## Related Specs

- [PowerShell Frontend](../domains/powershell-frontend.md) — the parse budget
- [ADR-0006](0006-bounded-abstract-execution.md) — the parse timeout and the step budget
- [ADR-0012](0012-race-advisory-parse-budget.md) — the other axis on which a wall-clock budget is not meaningful
- [Conservatism](../architecture/conservatism.md) — the ⊤ degradation table
