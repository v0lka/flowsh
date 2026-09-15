//go:build race

package engine_test

// raceDetectorEnabled reports whether this test binary was built with the race
// detector (-race). The race detector instruments every memory access, which
// inflates wall-clock time several-fold, so the timing gate in this package
// skips when it is on. That gate still runs — and still enforces the latency
// budget — in the ordinary (non-race) test step on every OS.
const raceDetectorEnabled = true
