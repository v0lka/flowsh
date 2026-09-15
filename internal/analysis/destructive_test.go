package analysis

// This file is the A3 acceptance suite: the knowledge base's destructive class
// (A–E) is carried into the report and can only raise its destructiveness /
// score. The facade joins bind.Result.Destructiveness (which already folds each
// matched destructive entry's class via kb.DestructiveClass.Severity) with the
// effect-derived severity using engine.Destructiveness.Join (max) — the D6
// raise-only invariant.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/kb"
)

// classSeverity maps a destructive finding's class letter back onto the core
// destructiveness lattice. It fails the test on an unknown class, so a typo in
// the knowledge base cannot pass silently.
func classSeverity(t *testing.T, class string) engine.Destructiveness {
	t.Helper()
	c := kb.DestructiveClass(class)
	if !c.Valid() {
		t.Fatalf("unknown destructive class %q", class)
	}
	return c.Severity()
}

// maxClassSeverity folds the severity of every matched destructive finding of a
// report with join (max), mirroring the class contribution the binder already
// carries in bind.Result.Destructiveness.
func maxClassSeverity(t *testing.T, findings []DestructiveFinding) engine.Destructiveness {
	t.Helper()
	d := engine.DestructBottom()
	for _, f := range findings {
		d = d.Join(classSeverity(t, f.Class))
	}
	return d
}

// reportHasClass reports whether the report matched a destructive finding of the
// given class.
func reportHasClass(rep *Report, class string) bool {
	for _, f := range rep.Destructive {
		if f.Class == class {
			return true
		}
	}
	return false
}

// mustAnalyzeBash analyses in as bash and fails on a nil report.
func mustAnalyzeBash(t *testing.T, a *Analyzer, in string) *Report {
	t.Helper()
	rep := a.Analyze(LangBash, in)
	if rep == nil {
		t.Fatalf("Analyze(bash, %q) returned a nil report", in)
	}
	return rep
}

// TestKBClassERaisesToCritical is acceptance criterion A3.1: a case whose
// destructive entry is class E (Critical) yields a destructiveness and grade not
// below Critical even though its effects alone are milder. Each input's
// effect-derived severity is strictly below Critical, so the report reaching
// Critical is attributable to the knowledge-base class and not to the effects.
func TestKBClassERaisesToCritical(t *testing.T) {
	a := mustAnalyzer(t)
	inputs := []string{
		"sed -i s/a/b/ f.txt",    // FSWrite → High from effects
		"truncate -s 0 f.txt",    // FSWrite → High
		"tar -x",                 // FSWrite → High
		"rsync --delete src dst", // FSRead + FSWrite → High
		"wipefs -a /dev/sda",     // FSWrite → High
		"find . -delete",         // FSRead + FSWrite → High
	}

	for _, in := range inputs {
		rep := mustAnalyzeBash(t, a, in)
		if !reportHasClass(rep, "E") {
			t.Errorf("%q: no class-E destructive finding matched (%+v)", in, rep.Destructive)
			continue
		}

		derived := engine.ComputeDestructiveness(rep.Effects)
		if derived >= engine.DestructCritical {
			t.Errorf("%q: effect-derived severity %s is already Critical; the case does not isolate the KB class", in, derived)
			continue
		}

		if rep.Destructiveness < engine.DestructCritical {
			t.Errorf("%q: destructiveness %s < Critical (class E)", in, rep.Destructiveness)
		}
		if rep.Score.Destructiveness < engine.DestructCritical {
			t.Errorf("%q: score.destructiveness %s < Critical (class E)", in, rep.Score.Destructiveness)
		}
		if rep.Score.Grade < engine.DestructCritical {
			t.Errorf("%q: score.grade %s < Critical (class E)", in, rep.Score.Grade)
		}
	}
}

// TestKBClassCannotLowerSeverity is acceptance criterion A3.2: the KB class is
// joined with the effect-derived severity, so it can raise it but never lower
// it. The table mixes a class above the effects (which must lift the report) and
// classes below the effects (which must not pull it down).
func TestKBClassCannotLowerSeverity(t *testing.T) {
	a := mustAnalyzer(t)
	inputs := []string{
		"truncate -s 0 f.txt", // class E raises High → Critical
		"cp -f a b",           // class C under a High effect: must stay High
		"tee f",               // class C under a High effect: must stay High
		"curl -o f http://x",  // class C under a High effect: must stay High
		"sed -f s",            // class B over a Low effect: stays Low
		"crontab -l",          // class B over a Low effect: stays Low
	}

	var raised, classBelowEffects bool
	for _, in := range inputs {
		rep := mustAnalyzeBash(t, a, in)
		derived := engine.ComputeDestructiveness(rep.Effects)
		classes := maxClassSeverity(t, rep.Destructive)
		want := derived.Join(classes)

		if rep.Destructiveness != want {
			t.Errorf("%q: destructiveness = %s, want join(effects=%s, classes=%s) = %s",
				in, rep.Destructiveness, derived, classes, want)
		}
		if rep.Destructiveness < derived {
			t.Errorf("%q: KB class lowered destructiveness below the effects: %s < %s", in, rep.Destructiveness, derived)
		}
		if rep.Score.Destructiveness != rep.Destructiveness {
			t.Errorf("%q: score.destructiveness %s != report destructiveness %s", in, rep.Score.Destructiveness, rep.Destructiveness)
		}
		if rep.Score.Grade < rep.Destructiveness {
			t.Errorf("%q: score.grade %s < destructiveness %s", in, rep.Score.Grade, rep.Destructiveness)
		}

		if rep.Destructiveness > derived {
			raised = true
		}
		if classes < derived {
			classBelowEffects = true
		}
	}

	if !raised {
		t.Error("no input exercised a class that raises the effect-derived severity")
	}
	if !classBelowEffects {
		t.Error("no input exercised a class below the effect-derived severity (the no-lowering case)")
	}
}

// TestDestructiveFlagWithoutEffectTrail is acceptance criterion A3.3: a
// destructive flag whose modelled effect trail contains no filesystem write
// still forces the report to the class's severity. install -m matches a class-E
// entry but is modelled as a mode change plus a conditional privilege
// escalation — there is no FSWrite effect to "explain" the severity — yet the
// report must still reach Critical.
func TestDestructiveFlagWithoutEffectTrail(t *testing.T) {
	a := mustAnalyzer(t)
	const in = "install -m 4755 x y"
	rep := mustAnalyzeBash(t, a, in)

	if !reportHasClass(rep, "E") {
		t.Fatalf("%q: no class-E destructive finding matched (%+v)", in, rep.Destructive)
	}
	for _, e := range rep.Effects {
		if e.Kind == engine.KindFSWrite {
			t.Fatalf("%q: expected no FSWrite effect trail, got %v", in, e)
		}
	}
	if got := maxClassSeverity(t, rep.Destructive); got != engine.DestructCritical {
		t.Fatalf("%q: matched class severity %s, want Critical", in, got)
	}
	if rep.Destructiveness < engine.DestructCritical {
		t.Errorf("%q: destructiveness %s < Critical (class E, no FSWrite trail)", in, rep.Destructiveness)
	}
	if rep.Score.Grade < engine.DestructCritical {
		t.Errorf("%q: score.grade %s < Critical (class E, no FSWrite trail)", in, rep.Score.Grade)
	}
}
