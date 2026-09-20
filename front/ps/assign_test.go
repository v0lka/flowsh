package ps

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// firstAssign returns the program's first assignment statement.
func firstAssign(t *testing.T, src string) *Assign {
	t.Helper()
	p := parseOK(t, src)
	for _, s := range p.Stmts {
		if s.Kind == KindAssignment && s.Assign != nil {
			return s.Assign
		}
	}
	t.Fatalf("no assignment statement in %q", src)
	return nil
}

func TestParseAssignmentMultiTarget(t *testing.T) {
	a := firstAssign(t, "$a, $b = 1, 2")
	if len(a.Targets) != 2 {
		t.Fatalf("Targets = %d, want 2 ($a,$b)", len(a.Targets))
	}
	if a.TargetWord == nil || a.TargetWord.Text != "$a" {
		t.Fatalf("TargetWord = %v, want $a", a.TargetWord)
	}
	for i, want := range []string{"$a", "$b"} {
		if a.Targets[i].Text != want {
			t.Errorf("Targets[%d] = %q, want %q", i, a.Targets[i].Text, want)
		}
	}
}

func TestParseAssignmentScopePrefix(t *testing.T) {
	for _, tc := range []struct{ src, wantName string }{
		{"$global:x = 'v'", "x"},
		{"$script:x = 'v'", "x"},
		{"$local:x = 'v'", "x"},
		{"$private:x = 'v'", "x"},
		{"$x = 'v'", "x"},
	} {
		a := firstAssign(t, tc.src)
		if a.Drive != DriveVariable || a.Name != tc.wantName {
			t.Errorf("classifyVar(%q) = (%q, %q), want (Variable, %q)", tc.src, a.Drive, a.Name, tc.wantName)
		}
	}
}

func TestParseAssignmentEnvTarget(t *testing.T) {
	a := firstAssign(t, "$env:FOO = 'bar'")
	if a.Drive != DriveEnv || a.Name != "FOO" {
		t.Fatalf("= (%q, %q), want (Env, FOO)", a.Drive, a.Name)
	}
}

func TestParseAssignmentRHSPipeline(t *testing.T) {
	a := firstAssign(t, "$lines = Get-Content /etc/passwd")
	if a.Value == nil || a.Value.Text != "Get-Content /etc/passwd" {
		t.Fatalf("Value = %+v, want the raw pipeline text", a.Value)
	}
	if len(a.RHS) != 1 || a.RHS[0].Kind != KindCommand {
		t.Fatalf("RHS = %+v, want one command statement", a.RHS)
	}
}

func TestParseAssignmentRHSSubexpressionInString(t *testing.T) {
	a := firstAssign(t, `$x = "pre$(Get-Date)post"`)
	if len(a.RHS) != 1 {
		t.Fatalf("RHS = %+v, want the interpolated subexpression's command", a.RHS)
	}
}

func TestParseAssignmentPureLiteralNoRHS(t *testing.T) {
	a := firstAssign(t, "$dir = '/tmp/target'")
	if len(a.RHS) != 0 {
		t.Fatalf("RHS = %+v, want nil for a pure literal value", a.RHS)
	}
	if a.Value == nil || !a.Value.Literal {
		t.Fatalf("Value = %+v, want a literal word", a.Value)
	}
}

// TestLowerAssignmentRHSLoweredOnce pins the no-duplicate invariant: the RHS
// command's effects appear exactly once, even though the RHS is reached
// through the assignment.
func TestLowerAssignmentRHSLoweredOnce(t *testing.T) {
	r := lowerOK(t, "$lines = Get-Content /etc/passwd")
	if n := len(effectsOfKind(r, engine.KindFSRead)); n != 1 {
		t.Fatalf("FSRead effects = %d, want exactly 1", n)
	}
	if !targetHas(r, engine.KindFSRead, "/etc/passwd") {
		t.Fatal("the RHS read target is missing")
	}
}

// TestLowerNestedAssignmentInArgument keeps the transparent-descent behavior:
// an assignable expression inside a command argument still produces its own
// lowered statements.
func TestLowerNestedAssignmentInArgument(t *testing.T) {
	r := lowerOK(t, "Remove-Item ($x = Get-Content /etc/passwd)")
	if n := len(effectsOfKind(r, engine.KindFSRead)); n != 1 {
		t.Fatalf("FSRead effects = %d, want exactly 1", n)
	}
}
