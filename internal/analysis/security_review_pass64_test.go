package analysis

// Regression tests for the findings recorded in security-review.md, pass 64.
//
// Pass 64 closed the two findings the previous verification round opened:
//
//   - F100 — a `chmod` mode that sets the set-user-ID / set-group-ID bit was
//     graded Medium with only an FSMeta effect, while the same operation
//     spelled `install -m 4755` was Critical with a PrivEsc effect. The KB
//     doctrine names the mode as the escalation, so the escalation is decided
//     from the (literal) mode operand.
//   - F101 — the PowerShell parse budget was not effective: the grammar's cost
//     is super-linear in bracket nesting and in single-line length, and the
//     deadline is only polled by the parse loop, so a 16 KB source could hold
//     the guard for 20+ seconds and still report a *parsed* (non-⊤) program.
//     The frontend now refuses those shapes deterministically before parsing
//     and enforces the deadline from outside the parser.

import (
	"strings"
	"testing"
	"time"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding100ChmodSuidIsPrivEsc pins F100: every spelling that sets the
// SUID/SGID bit is a privilege-escalation claim, at the same grade as the
// `install -m 4755` spelling of the same operation.
func TestFinding100ChmodSuidIsPrivEsc(t *testing.T) {
	a := mustAnalyzer(t)
	// The escalation is a property of the *target file*, not of the mode text:
	// a consumer that filters effects by path must see the file that becomes
	// set-user-ID, so each case names the file it writes.
	for _, tc := range []struct{ src, target string }{
		{`chmod 4755 /tmp/evil`, "/tmp/evil"},                    // octal SUID
		{`chmod 04755 /tmp/evil`, "/tmp/evil"},                   // octal SUID with a leading zero
		{`chmod 2755 /tmp/evil`, "/tmp/evil"},                    // octal SGID
		{`chmod 6755 /tmp/evil`, "/tmp/evil"},                    // SUID+SGID
		{`chmod u+s /bin/bash`, "/bin/bash"},                     // symbolic SUID
		{`chmod g+s /usr/local/bin/tool`, "/usr/local/bin/tool"}, // symbolic SGID
		{`chmod a+s /tmp/evil`, "/tmp/evil"},                     // symbolic, all
		{`chmod +s /tmp/evil`, "/tmp/evil"},                      // symbolic, who-less
		{`chmod =s /tmp/evil`, "/tmp/evil"},                      // symbolic, who-less with '='
		{`chmod u=rwxs /tmp/evil`, "/tmp/evil"},                  // 's' among the permissions
		{`chmod u+s,g+s /tmp/evil`, "/tmp/evil"},                 // several clauses
		{`chmod 4755,644 /tmp/evil`, "/tmp/evil"},                // octal list
	} {
		rep := a.Analyze(LangBash, tc.src)
		mustEffect(t, rep, engine.KindPrivEsc, tc.target, tc.src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, tc.src)
	}

	// Parity: the twin spelling of the same operation reports the same claim,
	// over the file it installs — every spelling the option resolver accepts,
	// including a short cluster (`-vm 4755`) and a unique long-option prefix
	// (`--mod=4755`). Both are documented getopt spellings, and reading the raw
	// words instead of the bound option dropped the escalation for them.
	for _, src := range []string{
		`install -m 4755 /tmp/payload /tmp/evil`,
		`install -m4755 /tmp/payload /tmp/evil`,
		`install -vm 4755 /tmp/payload /tmp/evil`,
		`install --mode 4755 /tmp/payload /tmp/evil`,
		`install --mode=4755 /tmp/payload /tmp/evil`,
		`install --mod=4755 /tmp/payload /tmp/evil`,
		`install -m 2755 /tmp/payload /tmp/evil`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindPrivEsc, "/tmp/evil", src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}

	// `install -t DIR SRC…` writes the directory, so the escalation names it —
	// including the attached and long-prefix spellings of `-t`.
	for _, src := range []string{
		`install -m 4755 -t /tmp/bin /tmp/payload`,
		`install -m 4755 -t/tmp/bin /tmp/payload`,
		`install -m 4755 --target-directory=/tmp/bin /tmp/payload`,
		`install -m 4755 --target-dir=/tmp/bin /tmp/payload`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindPrivEsc, "/tmp/bin", src)
	}

	// Repeated occurrences resolve to the last one, which is what getopt does:
	// `install -m 755 --mode=4755` installs a set-user-ID program (verified
	// against coreutils), `install -m 4755 -m 755` does not.
	for _, src := range []string{
		`install -m 755 --mode=4755 /tmp/payload /tmp/evil`,
		`install --mode=0755 -m 4755 /tmp/payload /tmp/evil`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindPrivEsc, "/tmp/evil", src)
	}
	for _, src := range []string{
		`install -m 4755 -m 755 /tmp/payload /tmp/evil`,
		`install -m 4755 --mode=0755 /tmp/payload /tmp/evil`,
	} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindPrivEsc) {
			t.Errorf("%s: claimed an escalation the last (winning) mode does not set (effects=%v)", src, rep.Effects)
		}
	}

	// The option terminator is honoured: after `--` the word `-m` is an operand
	// (a file name), not the mode option, so no escalation is claimed.
	rep := a.Analyze(LangBash, `install -- -m 4755 /tmp/p`)
	if hasKind(rep, engine.KindPrivEsc) {
		t.Errorf("install -- -m …: claimed an escalation for an operand (effects=%v)", rep.Effects)
	}
}

// TestFinding100UnknownModeIsEscalation pins the ⊤ side of F100: a mode the
// analysis cannot read may carry the identity bit, so the escalation is
// asserted over the destination rather than assumed absent.
func TestFinding100UnknownModeIsEscalation(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`chmod "$M" /tmp/evil`,
		`install -m "$M" /tmp/payload /tmp/evil`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindPrivEsc, "/tmp/evil", src)
	}
}

// TestFinding100ChmodNonEscalatingModes pins the other side of F100: a mode
// that grants no identity bit is not an escalation, so an ordinary permission
// change keeps its Medium grade. The bit-sharing sticky mode, the removal
// spelling and the meaningless `o+s` are all non-escalating.
func TestFinding100ChmodNonEscalatingModes(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`chmod 755 /tmp/x`,
		`chmod 0644 /tmp/x`,
		`chmod 1755 /tmp/x`, // sticky, not SUID/SGID
		`chmod u-s /tmp/x`,  // removal
		`chmod o+s /tmp/x`,  // the 's' bit has no meaning for others
		`chmod u+w /tmp/x`,
		`chmod +t /tmp/x`,
		// install's twin: an ordinary mode is a metadata change, not an
		// escalation (the KB row used to assert PrivEsc for *any* -m value).
		`install -m 755 a /tmp/x`,
		`install --mode=0644 a /tmp/x`,
		`install -m u-s a /tmp/x`,
	} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindPrivEsc) {
			t.Errorf("%q: claimed privilege escalation for a non-escalating mode (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Grade >= engine.DestructCritical {
			t.Errorf("%q: grade %s, want below Critical", src, rep.Score.Grade)
		}
	}
}

// TestFinding100ChmodReferenceMode pins the spelling that copies the mode from
// another file: the analysis does not read files, so the mode is unknown and
// the escalation is reported over ⊤ rather than assumed absent.
func TestFinding100ChmodReferenceMode(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`chmod --reference=/usr/bin/passwd /tmp/evil`,
		`chmod --reference /usr/bin/passwd /tmp/evil`,
		// the unique-prefix spelling getopt_long accepts
		`chmod --ref=/usr/bin/passwd /tmp/evil`,
		`chmod --ref /usr/bin/passwd /tmp/evil`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindPrivEsc, "/tmp/evil", src)
	}
}

// TestFinding101PSParseBound pins F101 for every shape that made the parser
// cost super-linear: the frontend must refuse them deterministically — ⊤ with a
// reason — instead of spending seconds on them.
func TestFinding101PSParseBound(t *testing.T) {
	a := mustAnalyzer(t)
	cases := map[string]string{
		// bracket nesting: parse and walk are O(depth²)
		"nesting-parens":    strings.Repeat("(", 4000) + "1" + strings.Repeat(")", 4000),
		"nesting-subexpr":   strings.Repeat("$(", 2000) + "1" + strings.Repeat(")", 2000),
		"nesting-array":     strings.Repeat("@(", 2000) + "1" + strings.Repeat(")", 2000),
		"nesting-scriptblk": strings.Repeat("&{", 1500) + "1" + strings.Repeat("}", 1500),
		"nesting-if":        strings.Repeat("if($true){", 1500) + "}",
		// single-line length: the super-linear shapes were all one long line
		"line-member": "$x = $a" + strings.Repeat(".a", 16000),
		"line-binop":  "$x = 1" + strings.Repeat("+1", 8000),
		"line-quotes": strings.Repeat("'\"", 8000),
		"line-pipe":   strings.Repeat("Get-ChildItem | ", 2000) + "Out-Null",
		"line-concat": "$x = 'a'" + strings.Repeat("+'a'", 4000),
		// total size
		"size-hex":     strings.Repeat("Write-Output hello\n", 4000),
		"size-onebyte": strings.Repeat("1\n", 80000),
	}
	for name, src := range cases {
		start := time.Now()
		rep := a.Analyze(LangPowerShell, src)
		elapsed := time.Since(start)
		if !rep.Top || !rep.Conservative {
			t.Errorf("%s (%d bytes): not degraded to ⊤ (top=%v conservative=%v effects=%d)",
				name, len(src), rep.Top, rep.Conservative, len(rep.Effects))
		}
		if rep.Reason == "" {
			t.Errorf("%s: ⊤ without a reason", name)
		}
		// The refusal is a linear scan, so it must be immediate even on a slow
		// host. 2 s is a generous ceiling that still catches a return to the
		// multi-second parses F101 recorded.
		if elapsed > 2*time.Second {
			t.Errorf("%s: took %s, want the structural bound to refuse it immediately", name, elapsed)
		}
	}
}

// TestFinding101PSParsePrecision pins the other side of F101: ordinary
// PowerShell — including pipelines, script blocks, hashtables and arrays nested
// well inside the bounds — still parses and produces its effect set.
func TestFinding101PSParsePrecision(t *testing.T) {
	a := mustAnalyzer(t)
	cases := map[string]string{
		"cmdlet":   `Get-Content C:\Users\me\Documents\notes.txt`,
		"pipeline": `Get-ChildItem C:\tmp | Where-Object Length -gt 10 | Remove-Item`,
		// A statement-initial `ForEach-Object` is refused by the grammar
		// (it lexes `foreach` as a keyword and leaves an ERROR node), so the
		// frontend correctly degrades it to ⊤; the pipeline form is the one
		// the grammar parses and is the precision case here.
		"scriptblock":  `1..3 | ForEach-Object -Process { Remove-Item C:\tmp\x }`,
		"hashtable":    `$h = @{ a = 1; b = 2 }`,
		"array":        `$a = @(1, 2, 3)`,
		"nested-dozen": strings.Repeat("if($true){", 12) + `Remove-Item C:\tmp\x` + strings.Repeat("}", 12),
		"long-line-3k": `Write-Output '` + strings.Repeat("a", 3000) + `'`,
		"wide-script":  strings.Repeat("Write-Output ok\n", 2000),
	}
	for name, src := range cases {
		rep := a.Analyze(LangPowerShell, src)
		if rep.Top {
			t.Errorf("%s: ordinary source degraded to ⊤ (%s)", name, rep.Reason)
		}
	}
	// The destructive ordinary case keeps its effect: precision, not just
	// non-⊤.
	rep := a.Analyze(LangPowerShell, `Remove-Item C:\tmp\x`)
	mustEffect(t, rep, engine.KindFSWrite, `C:\tmp\x`, `Remove-Item C:\tmp\x`)
}

// TestFinding101PSParseDeadlineEnforced pins the second half of F101: a source
// inside the structural bounds whose parse still overruns the budget is cut by
// the analyser's own deadline, so the call returns instead of stalling. The
// shape below (many maximal-length member chains) is the worst case inside the
// bounds.
func TestFinding101PSParseDeadlineEnforced(t *testing.T) {
	a := mustAnalyzer(t)
	// Each line pairs the costliest single-line shape (a maximal member chain)
	// with a command that carries an effect, so the report is non-empty whether
	// the deadline fires (⊤) or the parse completes.
	line := "$x = $a" + strings.Repeat(".a", 2000) + "\nRemove-Item C:\\tmp\\x\n"
	src := strings.Repeat(line, 8) // ~32 KB of the costliest line shape
	start := time.Now()
	rep := a.Analyze(LangPowerShell, src)
	elapsed := time.Since(start)
	// The deadline this case pins is the product's own parse budget. The race
	// build deliberately disables it (front/ps/budget_race.go: a wall clock is
	// not a meaningful bound for an instrumented binary), and the structural
	// bounds above still hold there, so only the wall-clock assertion is
	// conditioned on the build.
	if !raceBuild && elapsed > 2*time.Second {
		t.Fatalf("parse not bounded: %s for %d bytes", elapsed, len(src))
	}
	// Either outcome is sound (parsed, or ⊤ when the deadline fired), but a
	// report must always come back — never a hang, never a miss.
	if !rep.Covered() {
		t.Fatalf("report is a miss: effects=%v top=%v conservative=%v", rep.Effects, rep.Top, rep.Conservative)
	}
}
