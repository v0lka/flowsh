package analysis

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// This file pins the host-table option end to end at the facade:
// Options.Vars seeds host-known variable bindings (values the embedding host
// knows from its session context — a session temp directory, a workspace root)
// into the shell's abstract state, where they behave exactly like literal
// in-script assignments. The repro shapes are the silent-mode audit events
// 964501/964508: a redirect through $D must land on the concrete session-root
// path instead of an unresolved ⊤ target.

// hasTarget reports whether the report contains an effect of the given kind
// whose target set is exactly the given paths.
func hasTarget(r *Report, kind engine.EffectKind, paths ...string) bool {
	want := engine.ScopeOf(paths...)
	for _, e := range r.Effects {
		if e.Kind == kind && e.Target.Equal(want) {
			return true
		}
	}
	return false
}

// hasTopTarget reports whether the report contains an effect of the given kind
// whose target is ⊤.
func hasTopTarget(r *Report, kind engine.EffectKind) bool {
	for _, e := range r.Effects {
		if e.Kind == kind && e.Target.IsTop() {
			return true
		}
	}
	return false
}

// TestAnalyzeWithOptionsVarsResolvesRepro runs the audit repro 964501 shape
// with the session-temp binding supplied by the host: every $D-derived target
// resolves inside the session roots, the report stays bounded, and no FS target
// remains ⊤.
func TestAnalyzeWithOptionsVarsResolvesRepro(t *testing.T) {
	const sessTemp = "/Users/x/.c0wrk/projects/abc/ebefdbe1-54b0-46eb-9b2b-3564ab1c928f/temp"
	rep, err := AnalyzeWith(LangBash,
		"cd /Users/x/repo && git diff main...HEAD -- core/tools/registry.go > $D/registry.diff && git diff main...HEAD -- backend/config/config.go > $D/backend.diff && wc -l $D/registry.diff $D/backend.diff",
		Options{Vars: map[string]string{"D": sessTemp}})
	if err != nil {
		t.Fatalf("AnalyzeWith: %v", err)
	}
	if rep.Top || rep.Conservative {
		t.Fatalf("host-bound repro must stay bounded: top=%v conservative=%v reason=%q", rep.Top, rep.Conservative, rep.Reason)
	}
	if !hasTarget(rep, engine.KindFSWrite, sessTemp+"/backend.diff", sessTemp+"/registry.diff") {
		t.Errorf("both redirects must resolve to the session paths (one merged write effect)")
	}
	if !hasTarget(rep, engine.KindFSRead, sessTemp+"/registry.diff", sessTemp+"/backend.diff") {
		t.Errorf("wc operands must resolve to the session paths")
	}
	if hasTopTarget(rep, engine.KindFSRead) || hasTopTarget(rep, engine.KindFSWrite) {
		t.Errorf("no FS target may stay ⊤ once D is host-bound")
	}
}

// TestAnalyzeWithOptionsVarsForLoopSeeded runs a for-loop whose list words read
// a host-bound variable: the items resolve through the binding, and the loop
// body's reads target the concrete files.
func TestAnalyzeWithOptionsVarsForLoopSeeded(t *testing.T) {
	rep, err := AnalyzeWith(LangBash,
		`for f in $D/a.diff $D/b.diff; do cat "$f"; done`,
		Options{Vars: map[string]string{"D": "/sess/temp"}})
	if err != nil {
		t.Fatalf("AnalyzeWith: %v", err)
	}
	if rep.Top || rep.Conservative {
		t.Fatalf("seeded loop must stay bounded: top=%v conservative=%v", rep.Top, rep.Conservative)
	}
	if !hasTarget(rep, engine.KindFSRead, "/sess/temp/a.diff", "/sess/temp/b.diff") {
		t.Errorf("loop reads must resolve through the host binding")
	}
}

// TestAnalyzeWithoutVarsStaysTop pins the no-weakening side: the same repro
// without the host table keeps the unresolved ⊤ targets — the option adds
// resolution, it never loosens the default.
func TestAnalyzeWithoutVarsStaysTop(t *testing.T) {
	rep, err := Analyze(LangBash, "git diff main...HEAD -- core/tools/registry.go > $D/registry.diff")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !hasTopTarget(rep, engine.KindFSWrite) {
		t.Errorf("unknown $D without a host binding must keep the ⊤ write target")
	}
}

// TestAnalyzeWithOptionsVarsNumericStatus pins that the numeric-class statuses
// and the host table compose: $? confines to the literal directory, and a
// host-bound $D resolves to its concrete value, in one report.
func TestAnalyzeWithOptionsVarsNumericStatus(t *testing.T) {
	rep, err := AnalyzeWith(LangBash,
		`gofmt -l "$D" 2>&1 | head -5; echo "gofmt exit: $?"; echo log > $D/run-$?.log`,
		Options{Vars: map[string]string{"D": "/sess/temp"}})
	if err != nil {
		t.Fatalf("AnalyzeWith: %v", err)
	}
	if !hasTarget(rep, engine.KindFSWrite, "/sess/temp") {
		t.Errorf("status-named redirect must be confined to the host-bound directory")
	}
	if hasTopTarget(rep, engine.KindFSWrite) {
		t.Errorf("no write target may stay ⊤: $D is bound and $? is numeric-class")
	}
}

// TestOptionsVarsZeroValueIsNeutral pins that Options{Vars: nil} reproduces the
// historical Analyze behaviour on a status-var command (bounded, confined to
// the working directory).
func TestOptionsVarsZeroValueIsNeutral(t *testing.T) {
	src := `cat file-$?.txt`
	withNil, err := AnalyzeWith(LangBash, src, Options{})
	if err != nil {
		t.Fatalf("AnalyzeWith: %v", err)
	}
	plain, err := Analyze(LangBash, src)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if withNil.Top != plain.Top || withNil.Conservative != plain.Conservative || len(withNil.Effects) != len(plain.Effects) {
		t.Errorf("zero Options must be identical to Analyze")
	}
	if !hasTarget(withNil, engine.KindFSRead, ".") {
		t.Errorf("numeric-class status read must confine to the working directory")
	}
}
