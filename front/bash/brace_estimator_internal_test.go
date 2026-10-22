package bash

import "testing"

// TestFinding046BraceCountCountsEveryRangeField is the mechanism-level pin for
// Finding 46. The analysis-level test
// (TestFinding046BraceEstimator) only proves the *verdict* is bounded — and a
// pre-fix tree produced that same ⊤ verdict, just after materialising the
// expansion and allocating gigabytes. This pin asserts the estimator's own
// arithmetic, so it fails unless every character and stepped range is counted
// as the number of fields it really expands to:
//
//   - a character range (`{a..z}`) is 26 fields, not one;
//   - a stepped range (`{1..5000..1}`) is 5000 fields, not one;
//   - the product of several groups (`{a..z}{a..z}…`) is multiplied, so the
//     five-group payload is recognised as an overflow BEFORE materialising.
//
// On the pre-fix estimator each of these returned 1, so braceExpansionOverflow
// reported false and the expansion was built in memory; every assertion below
// then fails.
func TestFinding046BraceCountCountsEveryRangeField(t *testing.T) {
	cases := []struct {
		in   string
		want int // minimum field count; overflow cases are capped at max+1
	}{
		// Character ranges: 26 and 10 fields.
		{"{a..z}", 26},
		{"{a..j}", 10},
		// Stepped ranges: the span divided by the step, plus one.
		{"{1..10..2}", 5},
		{"{a..z..5}", 6},
		// Ascending/descending spellings are both real ranges.
		{"{z..a}", 26},
		{"{10..1}", 10},
		// A range over the cap is reported as an overflow, never under-counted.
		{"{1..5000}", maxExpandedFields + 1},
		{"{1..5000..1}", maxExpandedFields + 1},
		{"{a..z}{a..z}{a..z}{a..z}{a..z}", maxExpandedFields + 1},
		// The product of two smaller groups is multiplied (10^4 = 10000).
		{"{a..j}{a..j}{a..j}{a..j}", 10000},
	}
	for _, c := range cases {
		n, ok := braceCount(c.in, 0)
		if !ok {
			t.Fatalf("%q: estimate reported uncomputable", c.in)
		}
		if n < c.want {
			t.Errorf("%q: counted %d fields, want at least %d (a range fell through to the one-field literal count)", c.in, n, c.want)
		}
		if n > maxExpandedFields && !braceExpansionOverflow(c.in) {
			t.Errorf("%q: counted %d fields yet reports no overflow", c.in, n)
		}
	}

	// A word with no range must not be reported as an overflow: the estimator
	// may only degrade real expansions.
	for _, s := range []string{"plain", "{a,b}", "{a,b,c}", "x{1}y"} {
		if braceExpansionOverflow(s) {
			t.Errorf("%q: false overflow for a bounded word", s)
		}
	}
}
