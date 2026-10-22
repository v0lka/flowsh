package policy_test

// ===========================================================================
// Pass 58 decisions: Findings 90 and the F45 environment-channel extension
// ===========================================================================

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

// TestFinding090CodeExecDenyCatchesPathRebinding pins the decision level of
// Finding 90: the control the finding defeats is a policy that denies code
// execution, and it admitted a name rebound through PATH or BASH_CMDS while the
// `hash -p` spelling of the same rebinding was refused. Every channel now
// reaches the unresolved (⊤) resolution verdict, so the deny rule fires.
func TestFinding090CodeExecDenyCatchesPathRebinding(t *testing.T) {
	codeExecDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindCodeExec: policy.Deny,
	}}
	for _, src := range []string{
		`hash -p /tmp/evil cat; cat -rf -- /root/data`,
		`PATH=/tmp/evil:$PATH; cat -rf -- /root/data`,
		`export PATH=/tmp/evil:$PATH; cat -rf -- /root/data`,
		`PATH=/tmp/evil:$PATH cat -rf -- /root/data`,
		`env PATH=/tmp/evil:$PATH cat -rf -- /root/data`,
		`BASH_CMDS[cat]=/tmp/evil; cat -rf -- /root/data`,
	} {
		mustDecide(t, codeExecDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (CodeExec deny)")
	}

	// The F45 extension: the helper-program channels reach the same decision.
	f45 := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindCodeExec: policy.Deny,
	}}
	for _, src := range []string{
		`GIT_SEQUENCE_EDITOR='sh -c id' git rebase -i HEAD~2`,
		`GIT_ASKPASS=/tmp/evil git fetch`,
		`SUDO_ASKPASS=/tmp/evil sudo -A id`,
		`SYSTEMD_EDITOR=/tmp/evil systemctl edit foo`,
		`KUBECTL_EXTERNAL_DIFF=/tmp/evil kubectl diff`,
		`TAR_OPTIONS='--checkpoint-action=exec=sh' tar cf /tmp/a.tar /tmp/x`,
		`GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager GIT_CONFIG_VALUE_0='sh -c id' git log`,
	} {
		mustDecide(t, f45, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (CodeExec deny)")
	}

	// Precision: a search path that only appends, or whose leading entry is a
	// fixed system directory, keeps the binding and is allowed by the same
	// control — the fix must not become a blanket denial.
	for _, src := range []string{
		`export PATH=/usr/bin:$PATH; cat /etc/hostname`,
		`PATH=$PATH:/opt/tool/bin; cat /etc/hostname`,
		`TAR_OPTIONS=-z tar cf /tmp/a.tar /tmp/x`,
		`GIT_SEQUENCE_EDITOR= git rebase -i HEAD~2`,
	} {
		mustDecide(t, codeExecDeny, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (control)")
	}
}
