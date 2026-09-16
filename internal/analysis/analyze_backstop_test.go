package analysis

import "testing"

// TestZeroAnalyzerBackstop pins the nil-binder fail-open protection at the
// facade. A zero-value Analyzer{} holds no binder, so a command name cannot be
// resolved to its declared effects; any source that has at least one command
// statement must therefore degrade to Conservative (⊤) rather than emit an
// empty, fail-open report. The guard is "≥1 command statement, builtins
// included": res.Cmds counts every invocation, so `true` trips it just as
// `rm -rf /tmp/x` does. A source with no command statement at all — empty
// input, or a lone redirection — carries nothing to resolve and is left
// untouched.
//
// api.Analyzer is a type alias of this Analyzer, so this exercises the same
// zero-value misuse the embedding API exposes.
func TestZeroAnalyzerBackstop(t *testing.T) {
	var a Analyzer // zero value: no knowledge-base binder bound

	cases := []struct {
		src  string
		want bool
	}{
		{"", false},             // no command statement
		{"> /tmp/f", false},     // a lone redirection: no command statement
		{"true", true},          // a pure shell-state builtin still counts as a command
		{"rm -rf /tmp/x", true}, // an ordinary command
	}
	for _, tc := range cases {
		rep := a.Analyze(LangBash, tc.src)
		if rep.Conservative != tc.want {
			t.Errorf("Analyze(%q).Conservative = %t, want %t", tc.src, rep.Conservative, tc.want)
		}
		if tc.want && !rep.Covered() {
			t.Errorf("Analyze(%q) is Conservative but not Covered (no-silent-miss)", tc.src)
		}
		if tc.want && rep.Reason == "" {
			t.Errorf("Analyze(%q) is Conservative but carries no reason", tc.src)
		}
	}
}
