//go:build race

package ps

// raceDetectorEnabled reports whether this binary was built with the race
// detector (-race). The race detector instruments every memory access, which
// inflates wall-clock time several-fold, so a wall-clock bound is not a
// meaningful one: it fires on scheduling and GC stalls rather than on
// genuinely pathological input, and the same source then parses to a different
// result on different runs. See parseBudgetMicros.
const raceDetectorEnabled = true

// parseBudgetMicros is the per-parse wall-clock budget Parse hands to the
// parser. Under the race detector it is 0, which disables the deadline check
// entirely: a wall-clock budget is not a meaningful bound for a
// race-instrumented binary (see raceDetectorEnabled above), and letting it fire
// would break the "analysis is total and deterministic" invariant the
// concurrent embedding API test pins — a benign source would flip to ⊤ merely
// because another goroutine was scheduled or the GC ran.
//
// Termination is still guaranteed: gotreesitter bounds every parse with
// deterministic, source-length-scaled limits (max iterations, max nodes, max
// stack depth) that do not depend on the host's speed or load, so an
// adversarial source still degrades to ⊤ — just on those limits rather than on
// a wall clock.
const parseBudgetMicros uint64 = 0
