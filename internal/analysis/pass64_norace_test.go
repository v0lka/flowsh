//go:build !race

package analysis

// raceBuild reports that this test binary is not instrumented by the race
// detector, so the PowerShell parse deadline is the one the product uses.
const raceBuild = false
