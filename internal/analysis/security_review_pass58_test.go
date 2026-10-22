package analysis

// Regression tests for the findings recorded in security-review.md, pass 58.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding090PathRebindsResolution pins F90: an assignment to PATH (or to
// BASH_CMDS, the command-hash table as an array) re-binds which binary a later
// command word runs, exactly as `hash -p` does — but the assignment was
// modelled as an ordinary EnvWrite, so the report described the *name's* row.
// Measured before the fix: `PATH=/tmp/evil:$PATH; cat -rf -- /root/data`
// reported EnvWrite+FSRead{/root/data}/Medium, bounded and covered, while the
// `hash -p /usr/bin/rm cat` spelling of the same rebinding reported
// CodeExec{⊤}/conservative/Critical and was denied by every strict policy.
func TestFinding090PathRebindsResolution(t *testing.T) {
	a := mustAnalyzer(t)

	// Every channel that changes the search path or the hash table degrades to
	// ⊤ instead of binding the name's knowledge-base row.
	for _, src := range []string{
		`PATH=/tmp/evil:$PATH; cat -rf -- /root/data`,
		`export PATH=/tmp/evil:$PATH; cat -rf -- /root/data`,
		`PATH=/tmp/evil:$PATH cat -rf -- /root/data`,
		`env PATH=/tmp/evil:$PATH cat -rf -- /root/data`,
		`PATH=/tmp/evil:$PATH; cat /etc/hostname`,
		`BASH_CMDS[cat]=/tmp/evil; cat -rf -- /root/data`,
		`BASH_CMDS[cat]=/usr/bin/rm; cat -rf -- /root/data`,
		`BASH_CMDS[cat]=/bin/sh; cat -c 'rm -rf /root/data'`,
		`BASH_CMDS[cat]=/tmp/evil; cat /etc/hostname`,
		`PATH=$HOME/bin:$PATH; cat /etc/hostname`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: missing CodeExec (effects=%v)", src, rep.Effects)
		}
		if !rep.Conservative && !rep.Top {
			t.Errorf("%q: resolution still claimed bounded (effects=%v)", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
		if effectOn(rep, engine.KindFSRead, "/root/data") {
			t.Errorf("%q: still bound the name's own row (effects=%v)", src, rep.Effects)
		}
	}

	// Parity with the spelling Finding 76 fixed: the three channels reach the
	// same verdict shape when the rebound binary is not provable (an
	// unresolvable hash path is the hash-spelling twin of a caller-chosen
	// PATH entry).
	hashRep := a.Analyze(LangBash, `hash -p /tmp/evil cat; cat -rf -- /root/data`)
	for _, src := range []string{
		`PATH=/tmp/evil:$PATH; cat -rf -- /root/data`,
		`BASH_CMDS[cat]=/tmp/evil; cat -rf -- /root/data`,
	} {
		rep := a.Analyze(LangBash, src)
		if rep.Conservative != hashRep.Conservative || rep.Score.Grade != hashRep.Score.Grade {
			t.Errorf("%q: verdict %s/conservative=%v differs from the hash spelling %s/conservative=%v",
				src, rep.Score.Grade, rep.Conservative, hashRep.Score.Grade, hashRep.Conservative)
		}
	}

	// Precision controls: a path that only appends, or whose leading entry is a
	// fixed system directory, keeps every name bound to the documented binary.
	for _, src := range []string{
		`export PATH=/usr/bin:$PATH; cat /etc/hostname`,
		`PATH=/usr/bin:/bin; cat /etc/hostname`,
		`PATH=$PATH:/opt/tool/bin; cat /etc/hostname`,
		`export PATH="$PATH:$HOME/bin"; cat /etc/hostname`,
		`BASH_CMDS=; cat /etc/hostname`,
	} {
		rep := a.Analyze(LangBash, src)
		if rep.Conservative || rep.Top {
			t.Errorf("%q: fabricated ⊤ (effects=%v reason=%s)", src, rep.Effects, rep.Reason)
		}
		if hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: fabricated CodeExec (effects=%v)", src, rep.Effects)
		}
		mustEffect(t, rep, engine.KindFSRead, "/etc/hostname", src)
	}
}
