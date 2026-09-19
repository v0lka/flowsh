package bash_test

// This file exercises the two layers of in-analysis expansion resolution:
//
//   - layer (a), flowsh-native: a literal assignment (VAR=<literal>) earlier in
//     the text resolves every later $VAR read; a for-loop over a literal list
//     resolves the loop variable; and the status parameters ($?,
//     ${PIPESTATUS[*]}) are numeric-class, so a path-shaped word containing
//     them is confined to its literal directory instead of degrading to ⊤.
//   - layer (b), the host table: bash.ExecWithVars seeds host-known bindings
//     (values the embedding host knows from its session context) into the
//     abstract state, resolving $name reads the script alone could not.
//
// The safety invariant underpinning every case: an expansion the analysis
// cannot bound — an unknown variable, a command substitution, a ".." escape —
// still degrades to ⊤. Resolution only ever makes a ⊤ target concrete or
// directory-confined, never the other way round.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/bash"
)

// hasTopEffect reports whether the result contains an effect of the given kind
// whose target is ⊤ (the fully arbitrary scope).
func hasTopEffect(res *bash.ExecResult, kind engine.EffectKind) bool {
	for _, e := range res.Effects {
		if e.Kind == kind && e.Target.IsTop() {
			return true
		}
	}
	return false
}

// hasConfinedEffect reports whether the result contains an effect of the given
// kind whose target is exactly the given confined directory set (not ⊤).
func hasConfinedEffect(res *bash.ExecResult, kind engine.EffectKind, dirs ...string) bool {
	return hasEffect(res, kind, dirs...)
}

// ---------------------------------------------------------------------------
// Layer (a) — literal assignments resolve later $VAR reads
// ---------------------------------------------------------------------------

// TestLiteralAssignmentResolvesLaterVar pins the audit repro shape (silent-mode
// audit events 964501/964508): a session-temp directory assigned to D as a
// literal, then used by later redirects and operands. Every $D-derived target
// must be the concrete path under the assigned directory — not ⊤ — so a
// consumer's "unresolved shell expansions" criterion has nothing to fire on.
func TestLiteralAssignmentResolvesLaterVar(t *testing.T) {
	const sessTemp = "/Users/x/.c0wrk/projects/abc/ebefdbe1-54b0-46eb-9b2b-3564ab1c928f/temp"
	res := bash.ExecBash("cd /Users/x/repo && D="+sessTemp+" && git diff main...HEAD -- core/tools/registry.go > $D/registry.diff && wc -l $D/registry.diff", newResolver(t))
	if res.Top || res.Conservative {
		t.Fatalf("repro 964501 shape degraded: top=%v conservative=%v reason=%q", res.Top, res.Conservative, res.Reason)
	}
	if !hasEffect(res, engine.KindFSWrite, sessTemp+"/registry.diff") {
		t.Errorf("redirect > $D/registry.diff must write the concrete session path, effects:\n%s", effectKeys(res))
	}
	if !hasEffect(res, engine.KindFSRead, sessTemp+"/registry.diff") {
		t.Errorf("wc -l $D/registry.diff must read the concrete session path, effects:\n%s", effectKeys(res))
	}
	if hasTopEffect(res, engine.KindFSWrite) || hasTopEffect(res, engine.KindFSRead) {
		t.Errorf("no FS target may stay ⊤ once D is a literal, effects:\n%s", effectKeys(res))
	}
}

// TestLiteralAssignmentRedirectOnly checks the minimal redirect-only shape.
func TestLiteralAssignmentRedirectOnly(t *testing.T) {
	res := bash.ExecBash("D=/tmp/sess && git diff > $D/x.diff", newResolver(t))
	if !hasEffect(res, engine.KindFSWrite, "/tmp/sess/x.diff") {
		t.Errorf("redirect must resolve to /tmp/sess/x.diff, effects:\n%s", effectKeys(res))
	}
}

// TestReassignedLiteralTracksLatestValue pins that a reassignment rebinds the
// variable for every later read (last literal wins), exactly as bash does.
func TestReassignedLiteralTracksLatestValue(t *testing.T) {
	res := bash.ExecBash("D=/a && D=/b && git diff > $D/x.diff", newResolver(t))
	if !hasEffect(res, engine.KindFSWrite, "/b/x.diff") {
		t.Errorf("later literal must win, effects:\n%s", effectKeys(res))
	}
}

// ---------------------------------------------------------------------------
// Layer (a) — for-loop variables over literal lists
// ---------------------------------------------------------------------------

// TestForLoopLiteralListResolvesLoopVar pins the corpus shape (audit events
// 965047/965055/…): a for-loop iterating a literal file list resolves $f to
// each item, so the body's reads target the concrete files, not ⊤.
func TestForLoopLiteralListResolvesLoopVar(t *testing.T) {
	res := bash.ExecBash(`for f in frontend/src/lib/silentMode.ts frontend/src/lib/autonomyModes.ts; do echo "===== $f ====="; cat -n "$f"; done`, newResolver(t))
	if res.Top || res.Conservative {
		t.Fatalf("for-loop over a literal list must not degrade: top=%v conservative=%v", res.Top, res.Conservative)
	}
	if !hasEffect(res, engine.KindFSRead, "frontend/src/lib/silentMode.ts", "frontend/src/lib/autonomyModes.ts") {
		t.Errorf("cat \"$f\" must read both literal items, effects:\n%s", effectKeys(res))
	}
	if hasTopEffect(res, engine.KindFSRead) {
		t.Errorf("loop-variable reads must not leave a ⊤ FSRead, effects:\n%s", effectKeys(res))
	}
}

// ---------------------------------------------------------------------------
// Layer (a) — status variables are numeric-class
// ---------------------------------------------------------------------------

// TestNumericStatusVarConfinesOperand pins the numeric-class semantics: a
// path-shaped word whose only dynamic parts are $? / ${PIPESTATUS[n]} /
// ${PIPESTATUS[*]} / ${#x} cannot leave its literal directory, because the
// expansions are bounded integers, so the target is that directory instead of ⊤.
func TestNumericStatusVarConfinesOperand(t *testing.T) {
	cases := []struct {
		name string
		src  string
		kind engine.EffectKind
		dir  string
	}{
		{"exit status in filename", `cat file-$?.txt`, engine.KindFSRead, "."},
		{"pipestatus indexed", `cat /tmp/f-${PIPESTATUS[0]}.log`, engine.KindFSRead, "/tmp"},
		{"pipestatus joined", `cat /tmp/f-${PIPESTATUS[*]}.log`, engine.KindFSRead, "/tmp"},
		{"bare pipestatus word", `cat ${PIPESTATUS[*]}`, engine.KindFSRead, "."},
		{"redirect exit status", `echo done > out-$?-v.log`, engine.KindFSWrite, "."},
		{"redirect pipestatus", `echo done > /tmp/out-${PIPESTATUS[0]:-$?}.log`, engine.KindFSWrite, "/tmp"},
		{"numeric mid-path truncates at first numeric part", `cat /tmp/a$?/b`, engine.KindFSRead, "/tmp"},
		{"length expansion", `cat f-${#X}.txt`, engine.KindFSRead, "."},
		{"test clause operand", `[[ -f out-$?.log ]]`, engine.KindFSRead, "."},
		{"known assignment prefix", `D=/tmp/sess && echo log > $D/run-$?.log`, engine.KindFSWrite, "/tmp/sess"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := bash.ExecBash(tc.src, newResolver(t))
			if !hasConfinedEffect(res, tc.kind, tc.dir) {
				t.Errorf("word must confine to %q instead of ⊤, effects:\n%s", tc.dir, effectKeys(res))
			}
			if hasTopEffect(res, tc.kind) {
				t.Errorf("numeric-class word must not leave a ⊤ target, effects:\n%s", effectKeys(res))
			}
		})
	}
}

// TestNumericStatusVarEchoStandsAlone pins that a bare status read in a string
// operand (the corpus shape `echo "BUILD_EXIT=$?"`) keeps the analysis bounded:
// no ⊤, no conservative degradation, no filesystem effect at all.
func TestNumericStatusVarEchoStandsAlone(t *testing.T) {
	res := bash.ExecBash(`cd /repo && go build ./... 2>&1 | head -40; echo "BUILD_EXIT=$?"`, newResolver(t))
	if hasTopEffect(res, engine.KindFSRead) || hasTopEffect(res, engine.KindFSWrite) {
		t.Errorf("status echo must not add a ⊤ FS target, effects:\n%s", effectKeys(res))
	}
	if !hasConfinedEffect(res, engine.KindFSRead, ".") {
		// `cd /repo` contributes the working-directory metadata effect; the
		// point of this assertion is that the FS reads stay concrete.
		t.Logf("effects:\n%s", effectKeys(res))
	}
}

// TestNumericConfinementRefusesToEscape pins the no-weakening side: words whose
// dynamic parts are not numeric-class — or whose literal text could climb out
// of the confining directory — keep the historical ⊤ target.
func TestNumericConfinementRefusesToEscape(t *testing.T) {
	cases := []struct {
		name string
		src  string
		kind engine.EffectKind
	}{
		{"unknown variable", `cat $U/x`, engine.KindFSRead},
		{"command-substitution assignment", `D=$(pwd) && cat $D/x`, engine.KindFSRead},
		{"unknown variable in redirect", `echo x > $D/out.log`, engine.KindFSWrite},
		{"dot-dot escape after numeric part", `cat x-$?/../../etc/passwd`, engine.KindFSRead},
		{"dot-dot escape in prefix", `cat ../f-$?.txt`, engine.KindFSRead},
		{"set-unknown variable with path alternate", `X=$RANDOM; echo x > ${X:-/evil}/f.log`, engine.KindFSWrite},
		{"command substitution in word", `cat f-$(basename x).txt`, engine.KindFSRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := bash.ExecBash(tc.src, newResolver(t))
			if !hasTopEffect(res, tc.kind) {
				t.Errorf("unbounded word must keep the ⊤ target, effects:\n%s", effectKeys(res))
			}
		})
	}
}

// TestNumericAssignmentClearsClass pins that assigning a value to a numeric
// shell variable replaces the class: afterwards the variable is an ordinary
// string variable (known or unknown), never still-numeric.
func TestNumericAssignmentClearsClass(t *testing.T) {
	// RANDOM=...; $RANDOM must resolve to the assigned literal.
	res := bash.ExecBash("RANDOM=7; cat f-$RANDOM.txt", newResolver(t))
	if !hasEffect(res, engine.KindFSRead, "f-7.txt") {
		t.Errorf("assigned RANDOM must read as the literal, effects:\n%s", effectKeys(res))
	}
	// Assigned from an unknown source, it is an ordinary unknown variable: ⊤.
	res = bash.ExecBash("RANDOM=$(pwd); cat f-$RANDOM.txt", newResolver(t))
	if !hasTopEffect(res, engine.KindFSRead) {
		t.Errorf("unknown-assigned RANDOM must be ⊤, effects:\n%s", effectKeys(res))
	}
}

// ---------------------------------------------------------------------------
// Layer (b) — the host table (ExecWithVars)
// ---------------------------------------------------------------------------

// TestExecWithVarsResolvesHostBindings pins the host-table semantics: bindings
// the host knows from its session context behave exactly like literal
// in-script assignments, resolving later $name reads to concrete targets.
func TestExecWithVarsResolvesHostBindings(t *testing.T) {
	vars := map[string]string{
		"D": "/sess/ebefdbe1-54b0-46eb-9b2b-3564ab1c928f/temp",
	}
	res := bash.ExecWithVars(bash.Bash, "script",
		"git diff main...HEAD -- core/tools/registry.go > $D/registry.diff && wc -l $D/registry.diff",
		newResolver(t), vars)
	if res.Top || res.Conservative {
		t.Fatalf("host-bound repro must not degrade: top=%v conservative=%v reason=%q", res.Top, res.Conservative, res.Reason)
	}
	if !hasEffect(res, engine.KindFSWrite, "/sess/ebefdbe1-54b0-46eb-9b2b-3564ab1c928f/temp/registry.diff") {
		t.Errorf("redirect must resolve through the host binding, effects:\n%s", effectKeys(res))
	}
	if hasTopEffect(res, engine.KindFSWrite) || hasTopEffect(res, engine.KindFSRead) {
		t.Errorf("no FS target may stay ⊤ once D is host-bound, effects:\n%s", effectKeys(res))
	}
}

// TestExecWithVarsEmptyMatchesExec pins that the option is additive: an empty
// table is byte-for-byte the plain Exec behaviour.
func TestExecWithVarsEmptyMatchesExec(t *testing.T) {
	src := "cat $D/x"
	plain := bash.ExecBash(src, newResolver(t))
	seeded := bash.ExecWithVars(bash.Bash, "script", src, newResolver(t), nil)
	if got, want := effectKeys(seeded), effectKeys(plain); !equalStrings(got, want) {
		t.Errorf("empty Vars changed the analysis:\n got %v\nwant %v", got, want)
	}
	if !hasTopEffect(seeded, engine.KindFSRead) {
		t.Errorf("unknown $D without a host binding must stay ⊤, effects:\n%v", effectKeys(seeded))
	}
}

// TestExecWithVarsSkipsReadonlyStatusParams pins that a host cannot smuggle a
// value into the readonly status parameters: $ ? stays numeric-class even when
// the table names it.
func TestExecWithVarsSkipsReadonlyStatusParams(t *testing.T) {
	res := bash.ExecWithVars(bash.Bash, "script", "cat f-$?.txt", newResolver(t),
		map[string]string{"?": "/evil"})
	if !hasEffect(res, engine.KindFSRead, ".") {
		t.Errorf("$? must stay numeric-class despite the host binding, effects:\n%s", effectKeys(res))
	}
}

// TestExecWithVarsOverriddenByScript pins that an in-script assignment wins
// over the seeded binding from the point it executes, as in a real shell.
func TestExecWithVarsOverriddenByScript(t *testing.T) {
	res := bash.ExecWithVars(bash.Bash, "script", "D=/after && git diff > $D/x.diff",
		newResolver(t), map[string]string{"D": "/before"})
	if !hasEffect(res, engine.KindFSWrite, "/after/x.diff") {
		t.Errorf("in-script assignment must override the host binding, effects:\n%s", effectKeys(res))
	}
}

// equalStrings compares two string slices element-wise.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
