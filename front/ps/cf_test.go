package ps

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// noWrites reports whether the result carries no FSWrite at all.
func noWrites(r *Result) bool { return len(effectsOfKind(r, engine.KindFSWrite)) == 0 }

func TestIfKnownTrueRunsTakenBranchOnly(t *testing.T) {
	r := lowerOK(t, "if ($true) { Remove-Item a.txt } else { Remove-Item b.txt }")
	if !targetHas(r, engine.KindFSWrite, "a.txt") {
		t.Fatalf("the taken branch must run; effects=%+v", r.Effects)
	}
	if targetHas(r, engine.KindFSWrite, "b.txt") {
		t.Fatalf("the skipped branch must not run; effects=%+v", r.Effects)
	}
}

func TestIfUnknownRunsBothBranches(t *testing.T) {
	r := lowerOK(t, "if ($x) { Remove-Item a.txt } else { Remove-Item b.txt }")
	if !targetHas(r, engine.KindFSWrite, "a.txt") || !targetHas(r, engine.KindFSWrite, "b.txt") {
		t.Fatalf("an unresolved condition must run both branches; effects=%+v", r.Effects)
	}
}

func TestWhileKnownFalseSkipsBody(t *testing.T) {
	r := lowerOK(t, "while ($false) { Remove-Item z.txt }")
	if !noWrites(r) {
		t.Fatalf("a known-false loop must not run its body; effects=%+v", r.Effects)
	}
}

func TestBranchJoinDisagree(t *testing.T) {
	r := lowerOK(t, "if ($x) { $v = 'a.txt' } else { $v = 'b.txt' }\nRemove-Item $v")
	if !hasTopTarget(t, r, engine.KindFSWrite) {
		t.Fatalf("disagreeing branch values must degrade the target to ⊤; effects=%+v", r.Effects)
	}
}

func TestBranchJoinAgree(t *testing.T) {
	r := lowerOK(t, "if ($x) { $v = 'same.txt' } else { $v = 'same.txt' }\nRemove-Item $v")
	if !targetHas(r, engine.KindFSWrite, "same.txt") {
		t.Fatalf("agreeing branch values must keep the target; effects=%+v", r.Effects)
	}
	if hasTopTarget(t, r, engine.KindFSWrite) {
		t.Fatalf("agreeing branch values must not degrade; effects=%+v", r.Effects)
	}
}

func TestForeachLiteralIteratesExactly(t *testing.T) {
	r := lowerOK(t, "foreach ($i in 'a.txt', 'b.txt') { Get-Content $i }")
	if !targetHas(r, engine.KindFSRead, "a.txt") || !targetHas(r, engine.KindFSRead, "b.txt") {
		t.Fatalf("a literal iterable must iterate exactly; effects=%+v", r.Effects)
	}
	if hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("a literal iterable must not produce ⊤ reads; effects=%+v", r.Effects)
	}
}

func TestForeachUnknownSingleIteration(t *testing.T) {
	r := lowerOK(t, "foreach ($i in (Get-Content list.txt)) { Get-Content $i.log }")
	// The iterable command must be lowered. Its concrete read merges with the
	// body's ⊤ read (FSRead{list.txt} ⊔ FSRead{⊤} = ⊤), so an effect-level
	// Contains is satisfied by the ⊤ scope alone — the vacuity finding #22
	// reports. The per-command notes pin the iterable's own read instead, and
	// they cannot be satisfied by a ⊤ effect.
	if !notesContain(r, `read "list.txt" → FSRead`) {
		t.Fatalf("the iterable command must be lowered; notes=%v", r.Notes)
	}
	if hasKind(r, engine.KindFSWrite) {
		t.Fatalf("this program writes nothing; effects=%+v", r.Effects)
	}
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("an unknown loop variable must degrade the body's target; effects=%+v", r.Effects)
	}

	// With the body writing instead of reading, the iterable's concrete read
	// survives the merge and is asserted on the effect directly.
	r2 := lowerOK(t, `foreach ($i in (Get-Content list.txt)) { Remove-Item "$i.txt" }`)
	if !targetHasExact(r2, engine.KindFSRead, "list.txt") {
		t.Fatalf("the iterable command must be lowered concretely; effects=%+v notes=%v", r2.Effects, r2.Notes)
	}
	if !hasTopTarget(t, r2, engine.KindFSWrite) {
		t.Fatalf("an unknown loop variable must degrade the body's target; effects=%+v", r2.Effects)
	}
}

func TestSwitchStaysTop(t *testing.T) {
	r := lowerOK(t, "switch ($x) { 'a' { Remove-Item a.txt } }")
	if !hasKind(r, engine.KindCodeExec) || !r.Conservative {
		t.Fatalf("a switch must degrade to ⊤; effects=%+v", r.Effects)
	}
}

func TestTryConservativeSuperset(t *testing.T) {
	r := lowerOK(t, "try { Get-Content f.txt } catch { Remove-Item g.txt } finally { Get-Content h.txt }")
	if !targetHas(r, engine.KindFSRead, "f.txt") || !targetHas(r, engine.KindFSWrite, "g.txt") || !targetHas(r, engine.KindFSRead, "h.txt") {
		t.Fatalf("try/catch/finally must all be lowered; effects=%+v", r.Effects)
	}
}

func TestControlFlowKeywordsNoTop(t *testing.T) {
	r := lowerOK(t, "foreach ($i in 'a.txt', 'b.txt') { if ($i -eq 'a.txt') { continue }\nGet-Content $i }")
	if r.Conservative {
		t.Fatalf("control-flow keywords must not degrade the loop to ⊤; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if !targetHas(r, engine.KindFSRead, "b.txt") {
		t.Fatalf("the loop body must run; effects=%+v", r.Effects)
	}
}

func TestFunctionBodyStaysOpaque(t *testing.T) {
	r := lowerOK(t, "function f { Remove-Item q.txt }\nf")
	if !hasKind(r, engine.KindCodeExec) {
		t.Fatalf("a function call must stay opaque (⊤); effects=%+v", r.Effects)
	}
}
