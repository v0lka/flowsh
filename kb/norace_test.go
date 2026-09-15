//go:build !race

package kb

// raceDetectorEnabled is false in an ordinary (non-race) build; see
// race_test.go for the -race counterpart.
const raceDetectorEnabled = false
