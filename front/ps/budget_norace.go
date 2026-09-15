//go:build !race

package ps

// raceDetectorEnabled is false in an ordinary (non-race) build; see
// budget_race.go for the -race counterpart.
const raceDetectorEnabled = false

// parseBudgetMicros is the per-parse wall-clock budget Parse hands to the
// parser in an ordinary build: DefaultTimeoutMicros (250 ms), the bound ADR-0006
// chooses so a pathological source stops at the top element ⊤ instead of
// stalling the analysis. See budget_race.go for why the budget is disabled
// under the race detector.
const parseBudgetMicros = DefaultTimeoutMicros
