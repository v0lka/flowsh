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
// of the host OS. F22: a registry write is *persistence* wherever the analysis
// runs — a non-Windows control plane dispatching to Windows endpoints must not
// see a clean report — so both settings report Persist and the option only
// selects the provider's note.
func TestPSWindowsOptionEnablesRegistry(t *testing.T) {
	a := mustAnalyzer(t)

	on := a.AnalyzeWith(LangPowerShell, registrySrc, Options{Windows: Bool(true)})
	if !reportHasKind(on, engine.KindPersist) {
		t.Fatalf("--windows on: want a Persist effect, got %+v (notes=%v)", on.Effects, on.Notes)
	}

	off := a.AnalyzeWith(LangPowerShell, registrySrc, Options{Windows: Bool(false)})
	if !reportHasKind(off, engine.KindPersist) {
		t.Fatalf("--windows off: registry persistence must survive, got %+v", off.Effects)
	}
	if !repHasTarget(off, engine.KindPersist, `HKCU:\Software\x`) {
		t.Fatalf("--windows off: want Persist on the registry path, got %+v", off.Effects)
	}
	if !reportNotesContain(off, "host-agnostic") {
		t.Fatalf("--windows off: want a host-agnostic note, got %v", off.Notes)
	}
}

// repHasTarget reports whether rep carries kind k on the literal target want.
func repHasTarget(rep *Report, k engine.EffectKind, want string) bool {
	for _, e := range rep.Effects {
		if e.Kind != k {
			continue
		}
		for _, t := range e.Target.Targets() {
			if t == want {
				return true
			}
		}
	}
	return false
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
	// F22: the report is host-agnostic for persistence, so a registry write is
	// reported on every host.
	if !reportHasKind(def, engine.KindPersist) {
		t.Fatalf("default: want a Persist effect on every host, got %+v", def.Effects)
	}
	// The default must equal the explicitly-host-defaulted path.
	explicit := a.AnalyzeWith(LangPowerShell, registrySrc, Options{})
	if reportHasKind(def, engine.KindPersist) != reportHasKind(explicit, engine.KindPersist) {
		t.Fatalf("Analyze and AnalyzeWith(Options{}) disagree on the registry effect")
	}
}
