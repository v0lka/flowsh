# ADR-0016: Raise the knowledge-base load budget again for the release runner

## Status

Accepted

## Context

[ADR-0011](0011-ci-tolerant-load-budget.md) raised the `TestLoadUnderBudget`
budget (`kb/loader_test.go`) from 5 ms to **50 ms** after the shared CI runners
measured the hermetic, in-memory load several times slower than a developer
machine (observed worst average 20.1 ms) — roughly 2.5x headroom over that
observation.

The tagged-commit release gate (`.github/workflows/release.yml`, the `gates`
step — `go test ./... -count=1`, identical to the CI `corpus + latency/recall
gates` step) then failed on `ubuntu-latest`:

```
--- FAIL: TestLoadUnderBudget (2.61s)
  loader_test.go:124: Load(): min=34.236913ms avg=52.280404ms over 50 runs (budget 50ms)
  loader_test.go:129: average Load() = 52.280404ms, want < 50ms
```

Only the **average** check tripped; the fastest run (34.2 ms) stayed under the
budget, and the **same OS** (`ubuntu-latest`) had passed the identical step in
CI. So no code got slower: the release runner was simply slower or busier than
the runner ADR-0011 calibrated against (worst average 20.1 ms → 52.3 ms).

`Load()` re-parses the whole dataset and allocates ~7 MB across ~70k objects on
every call, so its per-run cost is CPU- and GC-bound and the average over 50
runs is the noisiest statistic the gate reads. This is the same class of problem
[ADR-0013](0013-windows-clock-tick-parse-budget.md) ruled on for the Windows
monotonic clock and [ADR-0015](0015-per-host-latency-reference.md) ruled on for
the per-command latency gate: a wall-clock threshold the slowest supported runner
cannot meet tests the runner, not the code.

Unlike the per-command gate, a per-`GOOS` reference (ADR-0015) does **not** help
here: the host that failed is `linux`, the same `GOOS` that passes in CI, so the
spread is *within* a host (load and GC), not *across* operating systems.

## Decision

Raise the shared `TestLoadUnderBudget` budget from 50 ms to **150 ms** — one
reviewable constant, as ADR-0011 chose. The value carries ~2.9x headroom over the
worst average now observed on a shared runner (52.28 ms) and ~4.4x over its
fastest run (34.2 ms), matching the ~3x margin the per-command gate grants its
own slow host (ADR-0015). It still fails an order-of-magnitude regression of the
load relative to what any supported runner measures, and any accidental disk I/O.

The `-race` exemption is unchanged: the test still skips under the race detector,
where a wall-clock measurement is not meaningful ([ADR-0012](0012-race-advisory-parse-budget.md)).

## Consequences

- Positive: the release gate no longer rejects a tagged commit for a runner that
  is merely slower than the one ADR-0011 measured, on any of the three CI OSes.
- Negative: the budget is looser again, so a moderate (3–10x) load-time
  regression would now pass on a fast host. Tracking load cost over time remains
  the job of the `-benchmem` figures and the `bench smoke` CI step, as ADR-0011
  already noted.
- Negative: the number must be re-checked if the knowledge base grows
  substantially — `Load()` cost scales with the dataset, so a much larger KB
  lowers the headroom this budget leaves.

## Alternatives Considered

- **Convert the KB gate to the per-host reference of ADR-0015.** Rejected: the
  failing run and the passing CI run share `GOOS=linux`, so a per-`GOOS` entry
  cannot express the difference — there is no OS family to key on.
- **Gate the fastest run only (drop the average check).** Considered: the fastest
  run is the least GC/contention-affected sample, and 34.2 ms would have passed
  the existing 50 ms budget. Rejected because the mean is exactly what surfaces a
  GC/allocation pathology — a load that allocates far more per call — which is
  the regression the gate most wants to catch, and the fastest run on a loaded
  runner is not contention-free either.
- **Normalise the measurement with a runtime speed-calibration probe.** Rejected
  for the same reason ADR-0011 and ADR-0015 rejected it: needless machinery, and
  the probe would itself be measured on the slow host.
- **Scale the budget by a CI-detected factor.** Rejected in ADR-0011 and still
  rejected: a single reviewable constant is clearer.

## Related Specs

- [Knowledge Base](../domains/knowledge-base.md) — the loader this budget bounds
- [ADR-0011](0011-ci-tolerant-load-budget.md) — the CI-tolerant constant this value supersedes
- [ADR-0015](0015-per-host-latency-reference.md) — the per-host reference for the per-command gate
- [ADR-0013](0013-windows-clock-tick-parse-budget.md) — the same false-alarm class for the parse budget
- [ADR-0004](0004-embedded-versioned-kb.md) — the embed-and-version decision
