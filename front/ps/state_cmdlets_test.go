package ps

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

func TestSetLocationTracksPwd(t *testing.T) {
	r := lowerOK(t, "Set-Location /tmp\nGet-Content $pwd/log.txt")
	if !targetHas(r, engine.KindFSRead, "/tmp/log.txt") {
		t.Fatalf("$pwd must track Set-Location; effects=%+v", r.Effects)
	}
}

func TestCdAliasTracksPwd(t *testing.T) {
	r := lowerOK(t, "cd /var\nGet-Content $pwd/adm.log")
	if !targetHas(r, engine.KindFSRead, "/var/adm.log") {
		t.Fatalf("the cd alias must move $pwd; effects=%+v", r.Effects)
	}
}

func TestPopLocationUnknownsPwd(t *testing.T) {
	r := lowerOK(t, "Push-Location /tmp\nPop-Location\nGet-Content $pwd/where.txt")
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("a popped location is unknowable: effects=%+v", r.Effects)
	}
}

func TestSetVariableBindsValue(t *testing.T) {
	r := lowerOK(t, "Set-Variable -Name x -Value 'v.txt'\nGet-Content $x")
	if hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("the bound value must resolve concretely; effects=%+v", r.Effects)
	}
	if !targetHas(r, engine.KindFSRead, "v.txt") {
		t.Fatalf("Set-Variable must bind the value for later reads; effects=%+v", r.Effects)
	}
}

func TestNewVariableAliasBindsValue(t *testing.T) {
	r := lowerOK(t, "nv -Name x -Value 'v.txt'\nGet-Content $x")
	if hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("the bound value must resolve concretely; effects=%+v", r.Effects)
	}
	if !targetHas(r, engine.KindFSRead, "v.txt") {
		t.Fatalf("nv must bind like New-Variable; effects=%+v", r.Effects)
	}
}

func TestClearVariableUnsets(t *testing.T) {
	r := lowerOK(t, "$x = 'known.txt'\nClear-Variable -Name x\nGet-Content $x")
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("a cleared variable must read as unknown; effects=%+v", r.Effects)
	}
}

func TestAutomaticsAreUnknownNotUnset(t *testing.T) {
	// $pid is seeded set-but-unknown: a read degrades the target to ⊤ without
	// any ⊤ CodeExec conclusion.
	r := lowerOK(t, "Get-Content log-$pid.txt")
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("$pid must degrade the target; effects=%+v", r.Effects)
	}
	if r.Conservative {
		t.Fatalf("an automatic variable read must not flip the program to ⊤; effects=%+v", r.Effects)
	}
}
