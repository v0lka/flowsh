# ADR-0011: Widen the knowledge-base load-latency budget for shared CI runners

## Status

Superseded by [0016](0016-kb-load-budget-release-headroom.md) for the load-latency budget value only; the CI-tolerant-constant decision stands.

## Context

ADR-0004 made the embedded knowledge base's load time an acceptance criterion:
`TestLoadUnderBudget` (`kb/loader_test.go`) asserted that `Load()` completes in
**under 5 ms**. That threshold was calibrated on a developer machine, where
`Load()` is stable at min ≈ 2.7 ms and avg ≈ 3.3 ms.

`Load()` is not a steady-state call: it re-parses the whole dataset on every
invocation and allocates ~7 MB across ~70k objects (measured with
`go test -benchmem`). The gate calls `Load()` 50 times and checks both the
fastest run and the average. On the shared GitHub-hosted runners (2 vCPU) the
same binary measured min = 8.86 ms and avg = 20.1 ms: the CPU is roughly 3x
slower, and the per-run allocations trigger GC that inflates the average well
past the fastest run. The step `corpus + latency/recall gates` therefore went red
on Linux and macOS for changes that did not touch the loader.

A wall-clock threshold that the slowest supported runner cannot meet is a false
alarm, not a real slowdown.

## Decision

Raise the `TestLoadUnderBudget` budget from 5 ms to **50 ms** — enough headroom
for the slowest runner on the CI matrix (observed worst avg 20.1 ms) while still
failing an order-of-magnitude regression or any accidental disk I/O. This mirrors
the composition-level latency gate, which pairs a generous absolute budget
(`budgetMs: 100`) with a separate regression tripwire
(`engine/testdata/latency_baseline.json`).

ADR-0004's decision — embed the dataset with `//go:embed` and version the schema
— is unaffected and stands.

## Consequences

- Positive: the gate tests the property it claims to (a hermetic, in-memory load)
  and no longer fails a CI run merely because the runner is slower than a
  developer machine, on all three matrix OSes.
- Negative: the budget is looser, so a moderate (2–5x) load-time regression would
  now pass. The `-benchmem` figures and the `bench smoke` CI step remain the
  tools for tracking load cost over time.

## Alternatives Considered

- **Warm up and gate the best-of-N run** — rejected in favour of one simple,
  CI-tolerant constant; a warm-up would not have rescued the observed 8.86 ms
  minimum anyway.
- **Skip the assertion under CI** — rejected: the budget is a genuine acceptance
  criterion and should run on every platform, just with a realistic value.
- **Optimise `Load()` so 5 ms holds on CI** — rejected as insufficient: the
  ~7 MB / ~70k allocations per call are inherent to building the KB and the
  average is GC-bound on the runner, so a reliable 2x speed-up is not available.
- **Scale the budget by a CI-detected factor** — rejected as needless machinery;
  a single reviewable constant is clearer.
