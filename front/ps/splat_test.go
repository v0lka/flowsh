package ps

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

func TestSplatKnownHashtableExpands(t *testing.T) {
	r := lowerOK(t, "$p = @{Path = '/etc/x.txt'}\nGet-Content @p")
	if !targetHas(r, engine.KindFSRead, "/etc/x.txt") {
		t.Fatalf("a known splat must expand to its bindings; effects=%+v", r.Effects)
	}
	if hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("a fully-known splat must not degrade; effects=%+v", r.Effects)
	}
	if r.Conservative {
		t.Fatalf("splatting a known hashtable must not flip the program to ⊤; notes=%v", r.Notes)
	}
}

func TestSplatUnknownStaysTop(t *testing.T) {
	r := lowerOK(t, "$p = Get-SplatDefaults\nGet-Content @p")
	if !hasKind(r, engine.KindCodeExec) || !r.Conservative {
		t.Fatalf("an unknown splat must stay ⊤; effects=%+v", r.Effects)
	}
}

func TestSplatKnownEntriesWithSwitch(t *testing.T) {
	r := lowerOK(t, "$p = @{Path = 'd.txt'; Recurse = $true}\nRemove-Item @p")
	if !targetHas(r, engine.KindFSWrite, "d.txt") {
		t.Fatalf("the splatted path must bind; effects=%+v", r.Effects)
	}
	// The Recurse switch must survive expansion so destructiveness escalates.
	if r.Destructiveness != engine.DestructCritical {
		t.Fatalf("the splatted -Recurse must escalate destructiveness: %v", r.Destructiveness)
	}
}

func TestSplatEntryWithUnknownValueKeepsTop(t *testing.T) {
	r := lowerOK(t, "$p = @{Path = $env:UNSET_PATH}\nGet-Content @p")
	if !hasKind(r, engine.KindCodeExec) || !r.Conservative {
		t.Fatalf("a splat with an unknown entry must stay ⊤; effects=%+v", r.Effects)
	}
}
