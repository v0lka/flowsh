package analysis

import (
	"runtime"
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// registrySrc is a PowerShell command whose only effect is a registry write; it
// exercises the Windows-only Registry provider.
const registrySrc = `Set-ItemProperty -Path HKCU:\Software\x -Name y -Value z`

// reportHasKind reports whether r carries an effect of kind k.
func reportHasKind(r *Report, k engine.EffectKind) bool {
	if r == nil {
		return false
	}
	for _, e := range r.Effects {
		if e.Kind == k {
			return true
		}
	}
	return false
}

// reportNotesContain reports whether any note of r contains sub.
func reportNotesContain(r *Report, sub string) bool {
	if r == nil {
		return false
	}
	for _, n := range r.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// TestPSWindowsOptionEnablesRegistry is acceptance criterion 1 for the facade:
// the Registry branch (a Windows-only provider) can be forced on independently
// of the host OS. With it on a registry command persists state; with it off the
// same command is skipped and contributes no effect.
func TestPSWindowsOptionEnablesRegistry(t *testing.T) {
	a := mustAnalyzer(t)

	on := a.AnalyzeWith(LangPowerShell, registrySrc, Options{Windows: Bool(true)})
	if !reportHasKind(on, engine.KindPersist) {
		t.Fatalf("--windows on: want a Persist effect, got %+v (notes=%v)", on.Effects, on.Notes)
	}

	off := a.AnalyzeWith(LangPowerShell, registrySrc, Options{Windows: Bool(false)})
	if reportHasKind(off, engine.KindPersist) {
		t.Fatalf("--windows off: registry must contribute no effect, got %+v", off.Effects)
	}
	if len(off.Effects) != 0 {
		t.Fatalf("--windows off: want no effects, got %+v", off.Effects)
	}
	if !reportNotesContain(off, "Windows-only") {
		t.Fatalf("--windows off: want a skipped note, got %v", off.Notes)
	}
}

// TestPSWindowsDefaultMatchesHost is acceptance criterion 2: the zero Options
// reproduces the historical host default, so behaviour on a Windows host is
// unchanged. The default resolves to runtime.GOOS == "windows" — exactly what
// ps.Lower does — and the default analysis routes through that same value.
func TestPSWindowsDefaultMatchesHost(t *testing.T) {
	hostIsWindows := runtime.GOOS == "windows"

	if got := (Options{}).psOptions().Windows; got != hostIsWindows {
		t.Fatalf("zero Options resolves Windows=%v, want host default %v", got, hostIsWindows)
	}
	if got := (Options{Windows: Bool(true)}).psOptions().Windows; !got {
		t.Fatalf("Options{Windows: true} lost the override")
	}
	if got := (Options{Windows: Bool(false)}).psOptions().Windows; got {
		t.Fatalf("Options{Windows: false} lost the override")
	}

	a := mustAnalyzer(t)
	def := a.Analyze(LangPowerShell, registrySrc)
	if got := reportHasKind(def, engine.KindPersist); got != hostIsWindows {
		t.Fatalf("default registry effect present=%v, want (host is Windows)=%v", got, hostIsWindows)
	}
	// The default must equal the explicitly-host-defaulted path.
	explicit := a.AnalyzeWith(LangPowerShell, registrySrc, Options{})
	if reportHasKind(def, engine.KindPersist) != reportHasKind(explicit, engine.KindPersist) {
		t.Fatalf("Analyze and AnalyzeWith(Options{}) disagree on the registry effect")
	}
}
