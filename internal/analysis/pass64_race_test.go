//go:build race

package analysis

// raceBuild reports that this test binary is instrumented by the race detector.
// The PowerShell parse budget is disabled in that build (front/ps/budget_race.go),
// so a wall-clock assertion would measure instrumentation overhead rather than
// the analyser's bound.
const raceBuild = true
