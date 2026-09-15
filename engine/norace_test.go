//go:build !race

package engine_test

// raceDetectorEnabled is false in an ordinary (non-race) build; see
// race_test.go for the -race counterpart.
const raceDetectorEnabled = false
