package policy_test

// ===========================================================================
// Pass 61 decisions: Findings 95 and 96
// ===========================================================================

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

// TestFinding095ScriptFileIsDenied pins the decision level of F95: a policy that
// denies code execution admitted `psql -f /tmp/q.sql`, whose script can run a
// shell command (`\!`), because the row bound the script file as a plain read
// and reported no CodeExec at all. `sqlite3 -init` and `gdb -x` reported a
// *bounded* CodeExec, so the same policy did deny them — but a policy keyed on
// writes did not, because a bounded effect set claims the invocation performs
// nothing else.
func TestFinding095ScriptFileIsDenied(t *testing.T) {
	execDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindCodeExec: policy.Deny,
	}}
	writeDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindFSWrite: policy.Deny,
	}}

	scripts := []string{
		`psql -f /tmp/q.sql`,
		`psql --file=/tmp/q.sql`,
		`sqlite3 -init /tmp/x /tmp/db`,
		`gdb -x /tmp/cmds /bin/true`,
		`redis-cli --eval /tmp/x.lua`,
	}
	for _, src := range scripts {
		mustDecide(t, execDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (exec deny)")
		mustDecide(t, writeDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (write deny, ⊤ via unknown)")
		// The default configuration denies through its `unknown` rule: a ⊤
		// report is exactly the "the analysis could not bound this" signal.
		mustDecide(t, policy.Config{}, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (default policy)")
	}

	// Precision: the inline spellings carry visible text, stay bounded, and the
	// default policy allows them.
	for _, src := range []string{
		`psql -c 'select 1'`,
		`gdb -ex 'shell id'`,
		`sqlite3 /tmp/db`,
		`sqlite3 -cmd '.tables' /tmp/db`,
	} {
		mustDecide(t, policy.Config{}, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (control)")
	}
}

// TestFinding096ResponseFileIsDenied pins the decision level of F96: a policy
// that denies code execution, and the default policy, both admitted
// `gcc @/tmp/args.rsp` because the response file was bound as an ordinary
// source operand — the report carried a write to the working directory and
// nothing else, while the file's content can name `-wrapper /tmp/evil,` or
// `-fplugin=/tmp/e.so`.
func TestFinding096ResponseFileIsDenied(t *testing.T) {
	execDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindCodeExec: policy.Deny,
	}}

	for _, src := range []string{
		`gcc @/tmp/args.rsp`,
		`clang @/tmp/args.rsp`,
		`ld @/tmp/args`,
		`as @/tmp/args`,
		`strip @/tmp/args`,
		`javac @/tmp/args`,
	} {
		mustDecide(t, execDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (exec deny)")
		mustDecide(t, policy.Config{}, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (default policy)")
	}

	// Precision: a normal compile is allowed by the default policy, and an
	// `@payload` of a data-taking client is not a response file.
	for _, src := range []string{
		`gcc -o /tmp/x hello.c`,
		`javac -d /tmp/out Hello.java`,
		`curl -d @/tmp/data http://a.example`,
	} {
		mustDecide(t, policy.Config{}, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (control)")
	}
}
