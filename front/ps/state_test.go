package ps

import (
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// ---------------------------------------------------------------------------
// State: set/get/unset, cloning, seeding
// ---------------------------------------------------------------------------

func TestStateSetGetCaseInsensitive(t *testing.T) {
	s := NewState()
	s.Set("Dir", "/tmp/target", engine.TaintBottom())
	v := s.Get("dir")
	if v == nil || !v.Known || v.Value != "/tmp/target" {
		t.Fatalf("Get(dir) = %+v, want known /tmp/target (PS names are case-insensitive)", v)
	}
	if s.Get("DIR") == nil {
		t.Fatal("Get(DIR) = nil, want the same variable")
	}
}

func TestStateCloneIndependence(t *testing.T) {
	s := NewState()
	s.Set("a", "1", engine.TaintBottom())
	c := s.Clone()
	c.Set("a", "2", engine.TaintBottom())
	c.SetUnknown("b", engine.TaintOf(engine.TaintUntrusted))
	if s.Get("a").Value != "1" {
		t.Fatalf("clone mutated the origin: $a = %q", s.Get("a").Value)
	}
	if s.Get("b") != nil {
		t.Fatal("clone added a variable to the origin")
	}
}

func TestNewStateSeedsAutomatics(t *testing.T) {
	s := NewState()
	for _, n := range []string{"args", "input", "_", "psitem", "matches", "error", "pid"} {
		v := s.Get(n)
		if v == nil || !v.Set || v.Known {
			t.Fatalf("automatic $%s = %+v, want set-but-unknown", n, v)
		}
	}
	if s.Get("home") != nil {
		t.Fatal("$home must not be seeded: its value is not determined by the script text")
	}
}

func TestSetUnknownReplacesKnown(t *testing.T) {
	s := NewState()
	s.Set("x", "lit", engine.TaintBottom())
	s.SetUnknown("x", engine.TaintOf(engine.TaintUntrusted))
	v := s.Get("x")
	if v == nil || !v.Set || v.Known {
		t.Fatalf("SetUnknown did not replace a known value: %+v", v)
	}
	if !v.Taint.Contains(engine.TaintUntrusted) {
		t.Fatalf("taint lost on SetUnknown: %v", v.Taint)
	}
}

func TestStateUnset(t *testing.T) {
	s := NewState()
	s.Set("x", "1", engine.TaintBottom())
	s.Unset("X")
	if s.Get("x") != nil {
		t.Fatal("Unset is case-insensitive and must remove the variable")
	}
}

// ---------------------------------------------------------------------------
// JoinStates: the least upper bound of two branches
// ---------------------------------------------------------------------------

func TestJoinStatesAgree(t *testing.T) {
	a, b := NewState(), NewState()
	a.Set("v", "same", engine.TaintBottom())
	b.Set("v", "same", engine.TaintOf(engine.TaintUntrusted))
	out := JoinStates(a, b)
	v := out.Get("v")
	if v == nil || !v.Known || v.Value != "same" {
		t.Fatalf("agreeing branches must keep the value: %+v", v)
	}
	if !v.Taint.Contains(engine.TaintUntrusted) {
		t.Fatalf("taint must join even when values agree: %v", v.Taint)
	}
}

func TestJoinStatesDisagree(t *testing.T) {
	a, b := NewState(), NewState()
	a.Set("v", "a", engine.TaintBottom())
	b.Set("v", "b", engine.TaintBottom())
	out := JoinStates(a, b)
	v := out.Get("v")
	if v == nil || !v.Set || v.Known {
		t.Fatalf("disagreeing values must degrade to set-but-unknown: %+v", v)
	}
}

func TestJoinStatesOneSideDropped(t *testing.T) {
	a, b := NewState(), NewState()
	a.Set("v", "a", engine.TaintBottom())
	out := JoinStates(a, b)
	if out.Get("v") != nil {
		t.Fatal("a variable assigned on one branch only is not surely set")
	}
}

func TestJoinStatesNilSide(t *testing.T) {
	s := NewState()
	s.Set("v", "a", engine.TaintBottom())
	if out := JoinStates(nil, s); out.Get("v") == nil {
		t.Fatal("joining a nil state must return the other state unchanged")
	}
	if out := JoinStates(s, nil); out.Get("v") == nil {
		t.Fatal("joining a nil state must return the other state unchanged")
	}
}

// ---------------------------------------------------------------------------
// Analysis budget
// ---------------------------------------------------------------------------

func TestStepPanicsWhenExhausted(t *testing.T) {
	l := &lowerer{budget: 0}
	defer func() {
		rec := recover()
		if _, ok := rec.(budgetError); !ok {
			t.Fatalf("step() on an exhausted budget panicked with %v, want budgetError", rec)
		}
	}()
	l.step()
	t.Fatal("step() on an exhausted budget must panic")
}

// TestLowerBudgetExhaustion drives the whole LowerWith recovery path: a script
// with more statements than the budget charges step() past the limit, and the
// panic is converted into a ⊤ conclusion that keeps the conservative flag.
func TestLowerBudgetExhaustion(t *testing.T) {
	var b strings.Builder
	b.WriteString("$seed = 'lit'\n")
	for i := 0; i < defaultBudget+2000; i++ {
		b.WriteString("$x = 1\n")
	}
	p := ParseTimeout("t", b.String(), 0) // disable the parse budget: this test targets the lowering budget
	if p.Top {
		t.Fatalf("parse unexpectedly top: %s", p.Reason)
	}
	r := LowerWith(p, Options{})
	if !r.Conservative {
		t.Fatal("an exhausted lowering budget must set Conservative")
	}
	if !hasKind(r, engine.KindCodeExec) {
		t.Fatal("an exhausted lowering budget must record a ⊤ CodeExec effect")
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "budget exhausted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the ⊤ reason must mention the budget; notes: %v", r.Notes)
	}
}
