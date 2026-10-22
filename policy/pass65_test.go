package policy_test

// ===========================================================================
// Pass 65 decisions: Finding 100
// ===========================================================================

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

// TestFinding100SetuidModeIsDenied pins the decision level of F100: every
// spelling of a mode that sets the set-user-ID bit must be denied by a policy
// that denies privilege escalation, and by a policy that denies Critical
// grades, while an ordinary mode stays allowed — the two directions together
// are what makes the fix a fix rather than a blanket over-report.
func TestFinding100SetuidModeIsDenied(t *testing.T) {
	privDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindPrivEsc: policy.Deny,
	}}
	gradeDeny := policy.Config{Grades: map[engine.Destructiveness]policy.Action{
		engine.DestructCritical: policy.Deny,
	}}

	for _, src := range []string{
		`chmod 4755 /tmp/evil`,
		`chmod u+s /bin/bash`,
		`chmod 2755 /tmp/evil`,
		`chmod --reference=/usr/bin/passwd /tmp/evil`,
		`chmod --ref=/usr/bin/passwd /tmp/evil`,
		`chmod "$M" /tmp/evil`,
		`install -m 4755 /tmp/payload /tmp/evil`,
		`install -m4755 /tmp/payload /tmp/evil`,
		`install -vm 4755 /tmp/payload /tmp/evil`,
		`install --mode 4755 /tmp/payload /tmp/evil`,
		`install --mode=4755 /tmp/payload /tmp/evil`,
		`install --mod=4755 /tmp/payload /tmp/evil`,
		`install -m 755 --mode=4755 /tmp/payload /tmp/evil`,
		`install -m 4755 -t /tmp/bin /tmp/payload`,
		`install -m "$M" /tmp/payload /tmp/evil`,
	} {
		mustDecide(t, privDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (PrivEsc deny)")
		mustDecide(t, gradeDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (Critical deny)")
	}

	// Precision: a mode that sets no identity bit is not an escalation, so the
	// same policies allow the ordinary spelling.
	for _, src := range []string{
		`chmod 755 /tmp/x`,
		`chmod u-s /tmp/x`,
		`chmod o+s /tmp/x`,
		`install -m 755 /tmp/payload /tmp/evil`,
		`install --mode=0644 /tmp/payload /tmp/evil`,
		`install -m 4755 -m 755 /tmp/payload /tmp/evil`,
	} {
		mustDecide(t, privDeny, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (control)")
	}
}
