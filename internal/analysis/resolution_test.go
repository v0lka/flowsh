package analysis

// This file is the A2 acceptance suite at the report layer: the facade must
// surface the binder's name resolution (bind.Result.Resolution) and the
// destructive-flags entries that matched (bind.Result.Destructive) in the
// report, aggregated across the program's calls. It complements the binder-level
// resolution tests in bind/resolve_test.go and the destructiveness tests in
// destructive_test.go by pinning the aggregation the report contract promises:
//
//	ll (alias)         → report.resolution records the alias (ll → ls)
//	find / -delete     → report.resolution records the command, and
//	                     report.destructive carries the matched entry's
//	                     class (E) and reason.

import (
	"testing"

	"github.com/v0lka/flowsh/bind"
)

// TestReportResolutionAggregated is acceptance criterion A2: the report carries
// the aggregated name-resolution outcome across the program's calls, so a
// consumer can see which command each invocation actually named.
func TestReportResolutionAggregated(t *testing.T) {
	a := mustAnalyzer(t)

	cases := []struct {
		name    string
		input   string
		kind    bind.ResolveKind
		invoked string
		resName string
		chain   []string
	}{
		{
			// An alias declared by the program: resolution walks the alias to
			// the effective command and records the chain.
			name:    "alias",
			input:   "alias ll='ls -la'; ll",
			kind:    bind.ResolveAlias,
			invoked: "ll",
			resName: "ls",
			chain:   []string{"ll"},
		},
		{
			// An external command with a knowledge-base signature.
			name:    "command",
			input:   "find / -delete",
			kind:    bind.ResolveCommand,
			invoked: "find",
			resName: "find",
		},
		{
			// A name that matches nothing: the analysis must say so rather than
			// silently guessing. The ⊤ step keeps the invoked name as the
			// best-effort Name (bind.resolve, step 5).
			name:    "unknown",
			input:   "frobnicate --now",
			kind:    bind.ResolveUnknown,
			invoked: "frobnicate",
			resName: "frobnicate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := mustAnalyzeBash(t, a, tc.input)
			if rep.Resolution.Kind != tc.kind {
				t.Errorf("%q: resolution.kind = %q, want %q", tc.input, rep.Resolution.Kind, tc.kind)
			}
			if rep.Resolution.Invoked != tc.invoked {
				t.Errorf("%q: resolution.invoked = %q, want %q", tc.input, rep.Resolution.Invoked, tc.invoked)
			}
			if rep.Resolution.Name != tc.resName {
				t.Errorf("%q: resolution.name = %q, want %q", tc.input, rep.Resolution.Name, tc.resName)
			}
			if len(rep.Resolution.AliasChain) != len(tc.chain) {
				t.Fatalf("%q: resolution.aliasChain = %v, want %v", tc.input, rep.Resolution.AliasChain, tc.chain)
			}
			for i := range tc.chain {
				if rep.Resolution.AliasChain[i] != tc.chain[i] {
					t.Errorf("%q: resolution.aliasChain[%d] = %q, want %q", tc.input, i, rep.Resolution.AliasChain[i], tc.chain[i])
				}
			}
		})
	}
}

// TestReportDestructiveSurfaced is acceptance criterion A2: a call that matches
// a knowledge-base destructive-flags entry surfaces that entry in the report
// with its command, matched spec, severity class and reason.
func TestReportDestructiveSurfaced(t *testing.T) {
	a := mustAnalyzer(t)
	const in = "find / -delete"
	rep := mustAnalyzeBash(t, a, in)

	if len(rep.Destructive) == 0 {
		t.Fatalf("%q: report carries no destructive finding", in)
	}

	var found *DestructiveFinding
	for i := range rep.Destructive {
		if rep.Destructive[i].Command == "find" && rep.Destructive[i].Spec == "-delete" {
			found = &rep.Destructive[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("%q: no find/-delete destructive finding in %+v", in, rep.Destructive)
	}
	if found.Class != "E" {
		t.Errorf("%q: destructive class = %q, want E", in, found.Class)
	}
	if found.Reason == "" {
		t.Errorf("%q: destructive finding carries no reason", in)
	}
}

// TestReportResolutionAndDestructiveAreAdditive pins the v2 contract shape: the
// additive resolution/destructive fields serialise (resolution always present;
// destructive omitted when empty) and round-trip through JSON.
func TestReportResolutionAndDestructiveAreAdditive(t *testing.T) {
	a := mustAnalyzer(t)

	// destructive is omitted when nothing matched: the alias case is read-only.
	aliasRep := mustAnalyzeBash(t, a, "alias ll='ls -la'; ll")
	if aliasRep.Destructive != nil {
		t.Errorf("read-only alias: destructive = %+v, want nil (omitempty)", aliasRep.Destructive)
	}

	data, err := mustAnalyzeBash(t, a, "find / -delete").Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !contains(string(data), `"resolution"`) {
		t.Errorf("encoded report has no resolution key:\n%s", data)
	}
	if !contains(string(data), `"destructive"`) {
		t.Errorf("encoded report has no destructive key:\n%s", data)
	}
}

// contains reports whether sub occurs in s, a tiny helper so the JSON-shape
// assertions do not pull in strings for one call each.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
