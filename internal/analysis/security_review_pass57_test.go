package analysis

// Regression tests for the findings recorded in security-review.md, pass 57.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding088AliasBodyEnvEffects pins F88: an alias body's environment
// assignments carry the same effects as a directly written invocation. Before
// the fix the rewritten command's assigns reached only the binder, whose
// EnvWrite is skipped on dispatch's early-return paths and which has no view of
// the exec-bearing variable set, so `alias x='env LD_PRELOAD=…'; x` reported
// EnvWrite only (allowed by a CodeExec-denying policy) and
// `alias x='A=1 true'; x` reported no effect at all (grade None,
// Covered()==false).
func TestFinding088AliasBodyEnvEffects(t *testing.T) {
	a := mustAnalyzer(t)

	// The exec-bearing assignment is a CodeExec sink in the alias spelling,
	// exactly as in the direct spelling.
	for _, src := range []string{
		`env LD_PRELOAD=/tmp/e.so cat /etc/hostname`,
		`alias x='env LD_PRELOAD=/tmp/e.so cat /etc/hostname'; x`,
		`LD_PRELOAD=/tmp/e.so cat /etc/hostname`,
		`alias x='LD_PRELOAD=/tmp/e.so cat /etc/hostname'; x`,
		`alias x='env GIT_SSH_COMMAND=rm git fetch'; x`,
		`alias x='env RSYNC_RSH=rm rsync a b:/x'; x`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: missing CodeExec (effects=%v)", src, rep.Effects)
		}
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}

	// A body whose only effect is a plain environment assignment still reports
	// that assignment instead of an empty, uncovered report.
	for _, src := range []string{
		`A=1 true`,
		`alias x='A=1 true'; x`,
		`env A=1 true`,
		`alias x='env A=1 true'; x`,
		`alias x='env A=1 echo hi'; x`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindEnvWrite, "A", src)
		if !rep.Covered() {
			t.Errorf("%q: report is not covered (effects=%v grade=%s)", src, rep.Effects, rep.Score.Grade)
		}
	}

	// Controls: an ordinary body keeps its declared effect and gains no
	// fabricated CodeExec, and a wrapper chain still elevates.
	rep := a.Analyze(LangBash, `alias x='cat /etc/hostname'; x`)
	mustEffect(t, rep, engine.KindFSRead, "/etc/hostname", `alias x='cat /etc/hostname'; x`)
	if hasKind(rep, engine.KindCodeExec) {
		t.Errorf("plain alias body fabricated CodeExec: %v", rep.Effects)
	}
	rep = a.Analyze(LangBash, `alias s='sudo id'; s`)
	if !hasKind(rep, engine.KindPrivEsc) {
		t.Errorf("alias wrapper chain lost PrivEsc: %v", rep.Effects)
	}
}
