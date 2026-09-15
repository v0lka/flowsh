package ps

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func parseOK(t *testing.T, src string) *Program {
	t.Helper()
	p := Parse("t", src)
	if p.Top {
		t.Fatalf("Parse(%q) unexpectedly top: %s", src, p.Reason)
	}
	return p
}

func lowerOK(t *testing.T, src string) *Result {
	t.Helper()
	return Lower(parseOK(t, src))
}

// effectsOfKind returns the effects of r with the given kind.
func effectsOfKind(r *Result, k engine.EffectKind) []engine.Effect {
	var out []engine.Effect
	for _, e := range r.Effects {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

func hasKind(r *Result, k engine.EffectKind) bool { return len(effectsOfKind(r, k)) > 0 }

// targetHas reports whether any effect of kind k targets the given string.
func targetHas(r *Result, k engine.EffectKind, want string) bool {
	for _, e := range effectsOfKind(r, k) {
		if e.Target.Contains(want) {
			return true
		}
	}
	return false
}

func notesContain(r *Result, sub string) bool {
	for _, n := range r.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// onlyKinds asserts the result has exactly the given effect kinds (order-free).
func onlyKinds(t *testing.T, r *Result, kinds ...engine.EffectKind) {
	t.Helper()
	want := map[engine.EffectKind]int{}
	for _, k := range kinds {
		want[k]++
	}
	got := map[engine.EffectKind]int{}
	for _, e := range r.Effects {
		got[e.Kind]++
	}
	if len(got) != len(want) {
		t.Fatalf("effect kinds: got %v want %v (effects: %+v, notes: %v)", got, want, r.Effects, r.Notes)
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("effect kind %s: got %d want %d (effects: %+v, notes: %v)", k, got[k], n, r.Effects, r.Notes)
		}
	}
}

// ---------------------------------------------------------------------------
// AC 1: rm -Recurse -Force $HOME (PS) → FSWrite(delete,$HOME…), NOT bash effects
// ---------------------------------------------------------------------------

func TestRmRecurseForceIsPSNotBash(t *testing.T) {
	const src = `rm -Recurse -Force $HOME`
	p := parseOK(t, src)

	// The statement must parse as a command named rm, with the PowerShell
	// parameters -Recurse and -Force — not as anything bash-shaped.
	if len(p.Stmts) != 1 || p.Stmts[0].Kind != KindCommand || p.Stmts[0].Cmd == nil {
		t.Fatalf("expected one command statement, got %+v", p.Stmts)
	}
	c := p.Stmts[0].Cmd
	if c.Name != "rm" {
		t.Fatalf("command name: got %q want rm", c.Name)
	}
	if !c.HasParam("Recurse") || !c.HasParam("Force") {
		t.Fatalf("expected -Recurse and -Force parameters, got %+v", c.Params)
	}

	r := Lower(p)
	if r.Style != StylePS {
		t.Fatalf("style: got %q want %q", r.Style, StylePS)
	}
	if r.Conservative {
		t.Fatalf("rm should not be conservative; notes=%v", r.Notes)
	}
	// Exactly one effect: FSWrite. Crucially no bash-style effect and no ⊤.
	onlyKinds(t, r, engine.KindFSWrite)
	if !targetHas(r, engine.KindFSWrite, "$HOME") {
		t.Fatalf("FSWrite target must contain $HOME; effects=%+v", r.Effects)
	}
	// PS semantics: rm was resolved through the PowerShell alias table to
	// Remove-Item (a name that does not exist in bash), and the deletion verb is
	// recorded. This is what distinguishes this from bash effects.
	if !notesContain(r, "Remove-Item") {
		t.Fatalf("expected the PS alias rm → Remove-Item to be recorded; notes=%v", r.Notes)
	}
	if !notesContain(r, "delete") {
		t.Fatalf("expected a delete operation note; notes=%v", r.Notes)
	}
	if r.Destructiveness != engine.DestructCritical {
		t.Fatalf("destructiveness: got %s want Critical", r.Destructiveness)
	}
}

// TestRmIsNotBashRemove proves the alias table, not the bash binding, decides
// the effect: the same token lowers to Remove-Item here.
func TestRmAliasResolvesToRemoveItem(t *testing.T) {
	if got, ok := LookupAlias("rm", nil); !ok || got != "Remove-Item" {
		t.Fatalf("LookupAlias(rm): got %q ok=%v", got, ok)
	}
	if got, ok := LookupAlias("RM", nil); !ok || got != "Remove-Item" {
		t.Fatalf("alias lookup must be case-insensitive: got %q ok=%v", got, ok)
	}
}

// ---------------------------------------------------------------------------
// AC 2: $env:FOO='x' → EnvWrite(FOO); Get-Content …\.ssh\id_rsa → CredAccess+FSRead
// ---------------------------------------------------------------------------

func TestEnvAssignmentIsEnvWrite(t *testing.T) {
	r := lowerOK(t, `$env:FOO='x'`)
	if r.Conservative {
		t.Fatalf("unexpected ⊤: %v", r.Notes)
	}
	onlyKinds(t, r, engine.KindEnvWrite)
	if !targetHas(r, engine.KindEnvWrite, "FOO") {
		t.Fatalf("EnvWrite target must be FOO; effects=%+v", r.Effects)
	}
}

func TestCredentialReadGivesCredAccessAndFSRead(t *testing.T) {
	const src = `Get-Content $env:USERPROFILE\.ssh\id_rsa`
	p := Parse("t", src)
	// The PowerShell grammar flags the backslash as an ERROR, but the frontend
	// must still lower best-effort rather than degrade to ⊤.
	if p.Top {
		t.Fatalf("unexpected ⊤ on a recoverable parse: %s", p.Reason)
	}
	if !p.Errors {
		t.Fatalf("expected the tree to record parse errors (recovered), got none")
	}

	r := Lower(p)
	onlyKinds(t, r, engine.KindFSRead, engine.KindCredAccess)
	if !hasKind(r, engine.KindFSRead) {
		t.Fatalf("expected FSRead; effects=%+v", r.Effects)
	}
	if !hasKind(r, engine.KindCredAccess) {
		t.Fatalf("expected CredAccess for the .ssh path; effects=%+v", r.Effects)
	}
}

// ---------------------------------------------------------------------------
// AC 3: Invoke-Expression $x / iex $x → ⊤/CodeExec; plus the other ⊤ constructs
// ---------------------------------------------------------------------------

func TestInvokeExpressionIsTop(t *testing.T) {
	for _, src := range []string{
		`Invoke-Expression $x`,
		`iex $x`,
		`$x | Invoke-Expression`,
	} {
		r := lowerOK(t, src)
		onlyKinds(t, r, engine.KindCodeExec)
		if !r.Conservative {
			t.Errorf("%q: expected conservative=true", src)
		}
		e := r.Effects[0]
		if !e.Target.IsTop() {
			t.Errorf("%q: expected ⊤ target, got %s", src, e.Target)
		}
		if !notesContain(r, "⊤") {
			t.Errorf("%q: expected a ⊤ note; notes=%v", src, r.Notes)
		}
	}
}

func TestOpaqueConstructsAreTop(t *testing.T) {
	cases := []struct {
		src    string
		reason string
	}{
		{`. ./script.ps1`, "dot-sourc"},
		{`Add-Type -TypeDefinition $x`, "Add-Type"},
		{`New-Object System.Net.WebClient`, "New-Object"},
		{`[ScriptBlock]::Create($x)`, "static .NET"},
		{`$sb = [ScriptBlock]::Create($x)`, "static .NET"},
		{`& $cmd arg`, "computed name"},
		{`Get-Content @args`, "splatting"},
		{`frobnicate --wat /y`, "unknown command"},
	}
	for _, tc := range cases {
		r := lowerOK(t, tc.src)
		onlyKinds(t, r, engine.KindCodeExec)
		if !r.Conservative {
			t.Errorf("%q: expected conservative=true", tc.src)
		}
		if !notesContain(r, tc.reason) {
			t.Errorf("%q: expected note containing %q; notes=%v", tc.src, tc.reason, r.Notes)
		}
	}
}

// ---------------------------------------------------------------------------
// AC 4: a parse timeout yields ⊤ without error or panic
// ---------------------------------------------------------------------------

// coarseMonotonicClock reports whether this host's monotonic clock is coarser
// than the sub-millisecond parse budget the test below pins.
//
// Parse trips its deadline only when a poll reads time.Now() at or past
// start+budget. Linux and macOS resolve the monotonic clock to nanoseconds, so
// a 1 µs budget trips on even a one-line source. Windows does not:
// runtime.nanotime reads the OS interrupt time (runtime/sys_windows_*.s), a
// value the kernel advances only on the system timer tick — 1 ms at best, 15.6
// ms by default — so every poll inside one tick reads the same value as start
// and a source whose whole parse fits inside a tick can never trip, however
// often the parser polls. This is the same "a wall-clock budget is not
// meaningful on this host" rule ADR-0012 applies to the race detector, here
// applied to a coarse clock; see ADR-0013.
const coarseMonotonicClock = runtime.GOOS == "windows"

func TestParseTimeoutYieldsTop(t *testing.T) {
	// 1 µs is far below the cost of even a tiny parse, so where the host clock
	// can resolve it the deadline trips deterministically.
	const budgetMicros = 1

	// shortParse marks a source whose entire parse is shorter than one clock
	// tick: it can pin the 1 µs deadline only where the clock resolves the
	// budget (see coarseMonotonicClock). The repeated-statement source spans
	// many ticks on every host — its parse is ~250 ms on a developer machine,
	// ~16x the coarsest default Windows tick — so the timeout→⊤ path is still
	// exercised end to end on Windows.
	cases := []struct {
		src        string
		shortParse bool
	}{
		{`Get-Content x`, true},
		{strings.Repeat("Get-Content a; ", 20000), false},
		{`if($true){rm -Force x}`, true},
	}
	for _, tc := range cases {
		if tc.shortParse && coarseMonotonicClock {
			t.Logf("%q: skipped — a sub-tick parse cannot observe a %d µs budget on a host whose monotonic clock ticks at ≥1 ms",
				trim(tc.src), budgetMicros)
			continue
		}
		src := tc.src
		p := ParseTimeout("t", src, budgetMicros)
		if !p.Top {
			t.Fatalf("%q: expected ⊤ on timeout, got a parsed program", trim(src))
		}
		if p.Reason == "" {
			t.Fatalf("%q: ⊤ program must carry a reason", trim(src))
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("%q: ⊤ program must validate: %v", trim(src), err)
		}
		r := Lower(p)
		onlyKinds(t, r, engine.KindCodeExec)
		if !r.Conservative {
			t.Fatalf("%q: timed-out program must be conservative", trim(src))
		}
	}
}

// TestParseGenerousTimeoutParses: a normal budget must not trip.
func TestParseGenerousTimeoutParses(t *testing.T) {
	p := ParseTimeout("t", `Get-Content x`, DefaultTimeoutMicros)
	if p.Top {
		t.Fatalf("generous timeout unexpectedly top: %s", p.Reason)
	}
}

// TestParseNeverPanics exercises inputs that stress the parser and asserts the
// frontend always returns a usable Program.
func TestParseNeverPanics(t *testing.T) {
	inputs := []string{
		"",
		"   \n\t\n",
		"# just a comment",
		`"unterminated`,
		"$((",
		strings.Repeat("(", 200),
		"`",
		"@{}",
		"\x00\x01\x02",
		strings.Repeat("Get-Content x | ", 200),
	}
	for _, src := range inputs {
		p := Parse("t", src)
		if p == nil {
			t.Fatalf("Parse(%q) returned nil", trim(src))
		}
		if p.Top && p.Reason == "" {
			t.Fatalf("Parse(%q): ⊤ without a reason", trim(src))
		}
	}
}

// ---------------------------------------------------------------------------
// Supporting behaviour
// ---------------------------------------------------------------------------

func TestRedirectionWritesFile(t *testing.T) {
	r := lowerOK(t, `Get-Content a.txt > out.txt`)
	onlyKinds(t, r, engine.KindFSRead, engine.KindFSWrite)
	if !targetHas(r, engine.KindFSRead, "a.txt") {
		t.Fatalf("expected FSRead a.txt: %+v", r.Effects)
	}
	if !targetHas(r, engine.KindFSWrite, "out.txt") {
		t.Fatalf("expected FSWrite out.txt: %+v", r.Effects)
	}

	r2 := lowerOK(t, `echo hi >> log.txt`)
	onlyKinds(t, r2, engine.KindFSWrite)
	if !targetHas(r2, engine.KindFSWrite, "log.txt") {
		t.Fatalf("expected FSWrite log.txt: %+v", r2.Effects)
	}
}

func TestAliasLoweringMatchesPowerShell(t *testing.T) {
	// curl → Invoke-WebRequest (network egress), NOT bash curl.
	r := lowerOK(t, `curl https://evil.example/x`)
	onlyKinds(t, r, engine.KindNetEgress)
	if !targetHas(r, engine.KindNetEgress, "https://evil.example/x") {
		t.Fatalf("expected NetEgress to the URL: %+v", r.Effects)
	}
	if !notesContain(r, "Invoke-WebRequest") {
		t.Fatalf("expected curl → Invoke-WebRequest note; notes=%v", r.Notes)
	}
}

func TestEnvDriveReadAndWrite(t *testing.T) {
	r := lowerOK(t, `Get-Content Env:PATH`)
	onlyKinds(t, r, engine.KindEnvRead)
	if !targetHas(r, engine.KindEnvRead, "PATH") {
		t.Fatalf("expected EnvRead PATH: %+v", r.Effects)
	}

	r2 := lowerOK(t, `Set-Content Env:FOO bar`)
	if !targetHas(r2, engine.KindEnvWrite, "FOO") {
		t.Fatalf("expected EnvWrite FOO: %+v", r2.Effects)
	}
}

func TestRegistryOnlyOnWindows(t *testing.T) {
	const src = `Set-ItemProperty -Path HKCU:\x -Name y -Value z`
	p := parseOK(t, src)

	nonWin := LowerWith(p, Options{Windows: false})
	if len(nonWin.Effects) != 0 {
		t.Fatalf("registry must contribute no effect off Windows; got %+v", nonWin.Effects)
	}
	if !notesContain(nonWin, "Windows-only") {
		t.Fatalf("expected a Windows-only note; notes=%v", nonWin.Notes)
	}

	win := LowerWith(p, Options{Windows: true})
	onlyKinds(t, win, engine.KindPersist)
	if !targetHas(win, engine.KindPersist, "HKCU:\\x") {
		t.Fatalf("expected Persist on the registry path; %+v", win.Effects)
	}
}

func TestHashtableArgIsNotSplat(t *testing.T) {
	// @{} is a hashtable literal, not splatting: it must not force ⊤.
	r := lowerOK(t, `Get-Content @{a=1}`)
	if r.Conservative {
		t.Fatalf("hashtable argument must not be treated as splatting; notes=%v", r.Notes)
	}
	if !hasKind(r, engine.KindFSRead) {
		t.Fatalf("expected FSRead; effects=%+v", r.Effects)
	}
}

func TestUnknownCommandIsTopDirect(t *testing.T) {
	r := lowerOK(t, `frobnicate --wat /y`)
	onlyKinds(t, r, engine.KindCodeExec)
	if !r.Conservative {
		t.Fatalf("unknown command must be conservative")
	}
	if r.Effects[0].Mode != engine.ModeDirect {
		t.Fatalf("unknown command ⊤ mode: got %s want Direct", r.Effects[0].Mode)
	}
}

func TestSessionAssignmentHasNoExternalEffect(t *testing.T) {
	r := lowerOK(t, `$x = "rm -rf /"`)
	if len(r.Effects) != 0 {
		t.Fatalf("session variable assignment must have no effect; got %+v", r.Effects)
	}
}

func TestFunctionCallIsOpaque(t *testing.T) {
	r := lowerOK(t, "function f { Remove-Item -Force z }\nf y")
	onlyKinds(t, r, engine.KindCodeExec)
	if !r.Conservative {
		t.Fatalf("calling a shell function must be conservative")
	}
	if r.Effects[0].Mode != engine.ModeTransitive {
		t.Fatalf("function ⊤ mode: got %s want Transitive", r.Effects[0].Mode)
	}
	// The function body must NOT have been lowered as executed code.
	if hasKind(r, engine.KindFSWrite) {
		t.Fatalf("function body must stay opaque; effects=%+v", r.Effects)
	}
}

func TestDeclaredAliasIsHonoured(t *testing.T) {
	r := lowerOK(t, "Set-Alias -Name zz -Value Remove-Item\nzz -Force a")
	if !targetHas(r, engine.KindFSWrite, "a") {
		t.Fatalf("declared alias zz → Remove-Item not honoured; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

func TestDeterministicEncoding(t *testing.T) {
	const src = `rm -Recurse -Force $HOME; curl https://x; Get-Content a > b`
	p := parseOK(t, src)
	a, err := Lower(p).Encode()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Lower(Parse("t", src)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("lowering is not deterministic:\n%s\n%s", a, b)
	}
}

func TestProgramValidate(t *testing.T) {
	if err := parseOK(t, `Get-Content x`).Validate(); err != nil {
		t.Fatalf("valid program rejected: %v", err)
	}
	// A ⊤ program carrying statements is malformed.
	bad := &Program{Top: true, Reason: "x", Stmts: []*Stmt{{Kind: KindCommand}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected validation error for ⊤ program with statements")
	}
	// A ⊤ program without a reason is malformed.
	if err := (&Program{Top: true}).Validate(); err == nil {
		t.Fatal("expected validation error for ⊤ program without a reason")
	}
}

func TestEffectValidate(t *testing.T) {
	r := lowerOK(t, `rm -Recurse -Force $HOME`)
	for _, e := range r.Effects {
		if err := e.Validate(); err != nil {
			t.Fatalf("invalid effect %+v: %v", e, err)
		}
	}
}

// ---------------------------------------------------------------------------
// B13: parameter / target recognition (isSwitch / pathParam / nameParam / urlParam)
// ---------------------------------------------------------------------------

// TestSwitchNamesRecognised pins the switch table: a switch takes no value, so
// the token after it is an operand — and an operand is frequently the effect
// target.
func TestSwitchNamesRecognised(t *testing.T) {
	want := []string{
		// pre-existing
		"Recurse", "Force", "WhatIf", "Confirm", "Verbose", "PassThru",
		// B13 additions
		"NoNewline", "Container", "Append", "Compress", "AsByteStream",
		"UseBasicParsing", "UseDefaultCredentials", "SkipCertificateCheck",
		"NoTypeInformation",
	}
	for _, name := range want {
		if !isSwitch(name) {
			t.Errorf("isSwitch(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"Path", "Name", "Value", "Uri", "Url", "Method", "OutFile", ""} {
		if isSwitch(name) {
			t.Errorf("isSwitch(%q) = true, want false (it takes a value)", name)
		}
	}
}

// TestPathParamNamesRecognised pins the filesystem-target table.
func TestPathParamNamesRecognised(t *testing.T) {
	want := []string{
		"Path", "LiteralPath", "PSPath", "Destination", "FilePath", "OutFile",
		"Target", "Source", "FullName", "Filter", "Include", "Exclude",
	}
	for _, name := range want {
		if !pathParam(name) {
			t.Errorf("pathParam(%q) = false, want true", name)
		}
	}
	// -Name/-Value are not filesystem targets: classifying them as such would
	// fabricate an extra target for Set-ItemProperty -Path … -Name … -Value ….
	for _, name := range []string{"Name", "Value", "Uri", "Url", "Method", ""} {
		if pathParam(name) {
			t.Errorf("pathParam(%q) = true, want false", name)
		}
	}
}

// TestNameParamNamesRecognised pins the named-target (computer/process/service/
// task/session) table.
func TestNameParamNamesRecognised(t *testing.T) {
	want := []string{
		"Name", "Id", "TaskName", "ComputerName", "ProcessName", "ServiceName",
		"CN", "Query", "Computer", "HostName", "ServerName", "MachineName",
		"Session", "SessionName",
	}
	for _, name := range want {
		if !nameParam(name) {
			t.Errorf("nameParam(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"Path", "Value", "Uri", "Url", "Method", ""} {
		if nameParam(name) {
			t.Errorf("nameParam(%q) = true, want false", name)
		}
	}
}

// TestURLParamRecognised pins the network-target table (B13): -Uri/-Url are the
// TargetURL source.
func TestURLParamRecognised(t *testing.T) {
	for _, name := range []string{"Uri", "uri", "URL", "Url", "ConnectionUri", "Proxy"} {
		if !urlParam(name) {
			t.Errorf("urlParam(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"Path", "Name", "Value", "Method", "OutFile", "Headers", "Body", ""} {
		if urlParam(name) {
			t.Errorf("urlParam(%q) = true, want false", name)
		}
	}
}

// TestSwitchKeepsURLAsOperand: an unrecognised switch would swallow the URL into
// a binding, leaving the TargetURL cmdlet without an operand and widening to ⊤.
// Recognising -UseBasicParsing keeps the URL an operand, so the egress is
// reported against it.
func TestSwitchKeepsURLAsOperand(t *testing.T) {
	r := lowerOK(t, `Invoke-WebRequest -UseBasicParsing https://example.com/p.ps1`)
	if r.Conservative {
		t.Fatalf("URL after a switch must stay an operand, not widen to ⊤: %v", r.Notes)
	}
	onlyKinds(t, r, engine.KindNetEgress)
	if !targetHas(r, engine.KindNetEgress, "https://example.com/p.ps1") {
		t.Fatalf("expected NetEgress to the URL operand; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

// TestURLTargetFromUriParam: a cmdlet fed by -Uri takes its egress target from
// the parameter value, not from the operands.
func TestURLTargetFromUriParam(t *testing.T) {
	r := lowerOK(t, `Invoke-WebRequest -Uri https://good.example/x https://decoy.example/y`)
	if r.Conservative {
		t.Fatalf("-Uri must bound the target; got ⊤: %v", r.Notes)
	}
	onlyKinds(t, r, engine.KindNetEgress)
	if !targetHas(r, engine.KindNetEgress, "https://good.example/x") {
		t.Fatalf("expected NetEgress to the -Uri value; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if targetHas(r, engine.KindNetEgress, "https://decoy.example/y") {
		t.Fatalf("-Uri must not be overridden by an operand; effects=%+v", r.Effects)
	}
}

// TestURLTargetFromUriParamNotTop is the B13 regression: an explicit -Uri value
// is a concrete target, so the cmdlet must not degrade to ⊤ (previously the URL
// was only read from operands, and `-Uri http://evil` alone yielded ⊤).
func TestURLTargetFromUriParamNotTop(t *testing.T) {
	r := lowerOK(t, `Invoke-WebRequest -Uri http://evil -Method Post`)
	if r.Conservative {
		t.Fatalf("-Uri gives a concrete target; unexpected ⊤: %v", r.Notes)
	}
	onlyKinds(t, r, engine.KindNetEgress)
	if !targetHas(r, engine.KindNetEgress, "http://evil") {
		t.Fatalf("expected NetEgress http://evil; effects=%+v", r.Effects)
	}
}

// TestURLTargetFallsBackToOperand: with no URL parameter the URL is the operand.
func TestURLTargetFallsBackToOperand(t *testing.T) {
	r := lowerOK(t, `Invoke-RestMethod https://api.example/v1`)
	onlyKinds(t, r, engine.KindNetEgress)
	if !targetHas(r, engine.KindNetEgress, "https://api.example/v1") {
		t.Fatalf("expected NetEgress to the operand URL; effects=%+v", r.Effects)
	}
}

// TestPathParamTarget: -FilePath carries the filesystem target.
func TestPathParamTarget(t *testing.T) {
	r := lowerOK(t, `Out-File -FilePath out.txt`)
	onlyKinds(t, r, engine.KindFSWrite)
	if !targetHas(r, engine.KindFSWrite, "out.txt") {
		t.Fatalf("expected FSWrite out.txt from -FilePath; effects=%+v", r.Effects)
	}
}

// TestPathPatternParamsAvoidFalseTop: a filesystem-selection parameter
// (-Filter/-Include/-Exclude) that is not recognised would leave the cmdlet with
// no operand and widen it to ⊤. Recognising it keeps a concrete filesystem
// target even when no -Path is given.
func TestPathPatternParamsAvoidFalseTop(t *testing.T) {
	r := lowerOK(t, `Get-ChildItem -Path /tmp -Filter *.log`)
	if r.Conservative {
		t.Fatalf("unexpected ⊤: %v", r.Notes)
	}
	if !hasKind(r, engine.KindFSRead) {
		t.Fatalf("expected FSRead; effects=%+v", r.Effects)
	}
	if !targetHas(r, engine.KindFSRead, "/tmp") {
		t.Fatalf("expected FSRead on -Path /tmp; effects=%+v", r.Effects)
	}
	// The pattern parameter is part of the filesystem target set, so the cmdlet
	// keeps a target (and is not widened to ⊤) even without -Path.
	r2 := lowerOK(t, `Get-ChildItem -Include *.ps1`)
	if r2.Conservative {
		t.Fatalf("-Include alone must keep a target, not widen to ⊤: %v", r2.Notes)
	}
	if !hasKind(r2, engine.KindFSRead) {
		t.Fatalf("expected FSRead from -Include; effects=%+v", r2.Effects)
	}
}

// ---------------------------------------------------------------------------
// misc
// ---------------------------------------------------------------------------

func trim(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// sanity: the canonical alias targets the task pins.
func TestPinnedAliases(t *testing.T) {
	want := map[string]string{
		"rm":   "Remove-Item",
		"curl": "Invoke-WebRequest",
		"iex":  "Invoke-Expression",
	}
	for alias, target := range want {
		got, ok := LookupAlias(alias, nil)
		if !ok || got != target {
			t.Errorf("alias %s: got %q ok=%v want %q", alias, got, ok, target)
		}
	}
	// Encoding sanity: a Result marshals to JSON without error.
	if _, err := json.Marshal(lowerOK(t, `rm -Force x`)); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// B12: alias-table integrity over the expanded default PowerShell 7 set
// ---------------------------------------------------------------------------

// TestEveryAliasResolvesToKnownCmdlet enforces the B12 invariant: every entry
// of the built-in alias table resolves to a cmdlet the lowering table knows, so
// no default alias silently degrades to ⊤. The one documented exception is the
// ⊤ cmdlets, which lower.go intercepts in topReason before Cmdlets is consulted
// (see the comment on Cmdlets) — Invoke-Expression is the only one an alias
// points at (iex).
func TestEveryAliasResolvesToKnownCmdlet(t *testing.T) {
	deliberateTop := map[string]bool{"Invoke-Expression": true}
	for alias, target := range Aliases {
		// The public lookup path must round-trip the table.
		got, ok := LookupAlias(alias, nil)
		if !ok || got != target {
			t.Errorf("LookupAlias(%q, nil) = %q,%v; want %q,true", alias, got, ok, target)
		}
		// The target must be a known cmdlet (or the deliberate-⊤ set).
		if _, known := canonicalCmdlet(target); known || deliberateTop[target] {
			continue
		}
		t.Errorf("alias %q → %q: target is neither a known cmdlet nor a deliberate ⊤ cmdlet", alias, target)
	}
}

// TestDefaultAliasSetSpotChecks lowers a sample of the aliases added for the
// default PowerShell 7 set to confirm they reach the intended cmdlet.
func TestDefaultAliasSetSpotChecks(t *testing.T) {
	// sls → Select-String: a filesystem read of the operand.
	sls := lowerOK(t, `sls app.log`)
	if !hasKind(sls, engine.KindFSRead) || !targetHas(sls, engine.KindFSRead, "app.log") {
		t.Fatalf("sls: expected FSRead app.log, got %+v (notes %v)", sls.Effects, sls.Notes)
	}

	// cnsn → Connect-PSSession: opens a remote session (egress + IPC), like
	// New-PSSession.
	r := lowerOK(t, `cnsn -ComputerName host`)
	if !hasKind(r, engine.KindNetEgress) || !hasKind(r, engine.KindIPC) {
		t.Fatalf("cnsn: expected NetEgress+IPC, got %+v (notes %v)", r.Effects, r.Notes)
	}

	// iex stays ⊤: the pinned alias resolves to the deliberately-absent
	// Invoke-Expression, so lowering must remain conservative.
	if iex := lowerOK(t, `iex 'Write-Output 1'`); !iex.Conservative {
		t.Fatalf("iex must lower to a conservative (⊤) result: %+v", iex)
	}
}

// TestRemainingDefaultAliasesResolve covers the rest of the default PowerShell 7
// alias set added for B12 (part 2): the snap-in aliases and `md`→mkdir are
// deliberately omitted (their targets are a snap-in cmdlet / a session
// function), so every alias here must resolve to a registered cmdlet.
func TestRemainingDefaultAliasesResolve(t *testing.T) {
	want := map[string]string{
		"ise":   "powershell_ise.exe",
		"ipmo":  "Import-Module",
		"ihy":   "Invoke-History",
		"r":     "Invoke-History",
		"gdr":   "Get-PSDrive",
		"ndr":   "New-PSDrive",
		"rdr":   "Remove-PSDrive",
		"mount": "New-PSDrive",
		"npssc": "New-PSSessionConfigurationFile",
		"iwmi":  "Invoke-WMIMethod",
		"swmi":  "Set-WMIInstance",
		"rwmi":  "Remove-WMIObject",
		"rujb":  "Resume-Job",
		"sujb":  "Suspend-Job",
	}
	for alias, target := range want {
		got, ok := LookupAlias(alias, nil)
		if !ok || got != target {
			t.Errorf("LookupAlias(%q) = %q,%v; want %q,true", alias, got, ok, target)
		}
	}
}

// TestNewAliasesLowerWithoutTop is the behavioural counterpart: the added
// aliases must never degrade to ⊤.
func TestNewAliasesLowerWithoutTop(t *testing.T) {
	for _, src := range []string{
		`ipmo Pester`, `ihy`, `r`, `gdr`, `ise`,
		`ndr -Name X -Root /tmp`, `mount -Name X -Root /tmp`,
		`npssc -Path /tmp/c.pssc`, `iwmi -ClassName Win32_Process`,
		`rwmi -Class Win32_Process`, `rujb`, `sujb`, `rdr -Name X`,
	} {
		r := lowerOK(t, src)
		if r.Conservative {
			t.Errorf("%q degraded to ⊤: %v", src, r.Notes)
		}
	}
}

// TestIseAliasSpawnsProcess: `ise` names the ISE executable, not a cmdlet, so it
// is registered as a process spawn rather than widening to ⊤.
func TestIseAliasSpawnsProcess(t *testing.T) {
	onlyKinds(t, lowerOK(t, `ise`), engine.KindProcSpawn)
}

// ---------------------------------------------------------------------------
// B13 (part 2): the standard parameter names the B11 module cmdlets take as
// their target. An unrecognised *switch* swallows the operand that follows it,
// and an unrecognised *target parameter* leaves the cmdlet with no target at
// all — either way an ordinary invocation widens to ⊤.
// ---------------------------------------------------------------------------

// TestB13SwitchNamesRecognised pins the additional no-value switches.
func TestB13SwitchNamesRecognised(t *testing.T) {
	for _, name := range []string{
		"Raw", "File", "Directory", "NoClobber", "UseMaximumSize",
		"CaseSensitive", "SimpleMatch", "NotMatch", "AllMatches",
		"AutoSize", "Wrap", "NoNewWindow", "UseCulture", "NoEnumerate",
	} {
		if !isSwitch(name) {
			t.Errorf("isSwitch(%q) = false, want true", name)
		}
	}
}

// TestB13NameParamNamesRecognised pins the additional named-target parameters
// of the CimCmdlets/NetTCPIP/Storage/LocalAccounts/WSMan cmdlets.
func TestB13NameParamNamesRecognised(t *testing.T) {
	for _, name := range []string{
		"ClassName", "MethodName", "Class", "DriveLetter", "Number",
		"DiskNumber", "PartitionNumber", "LocalPort", "DisplayName",
		"IPAddress", "InterfaceAlias", "InterfaceIndex", "ResourceURI",
		"Role", "LogName", "Group", "Member", "Account", "PoolName",
	} {
		if !nameParam(name) {
			t.Errorf("nameParam(%q) = false, want true", name)
		}
	}
}

// TestB13PathAndURLParamNamesRecognised pins the two remaining sources added for
// B13: -DestinationPath (a filesystem target) and -SmtpServer (a network sink).
func TestB13PathAndURLParamNamesRecognised(t *testing.T) {
	if !pathParam("DestinationPath") {
		t.Error(`pathParam("DestinationPath") = false, want true`)
	}
	if !urlParam("SmtpServer") {
		t.Error(`urlParam("SmtpServer") = false, want true`)
	}
}

// TestB13NoFalseTopOnModuleCmdlets is the acceptance check: an ordinary
// invocation of any B11 module cmdlet must not widen to ⊤ once its standard
// parameters are recognised.
func TestB13NoFalseTopOnModuleCmdlets(t *testing.T) {
	srcs := []string{
		// A switch followed by the operand carrying the target.
		`Get-Content -Raw app.log`,
		`Get-ChildItem -File /tmp`,
		`Get-ChildItem -Directory /tmp`,
		`New-Partition -DiskNumber 1 -UseMaximumSize`,
		// Named targets of the B11 modules.
		`Get-CimInstance -ClassName Win32_Process`,
		`Invoke-CimMethod -ClassName Win32_Process -MethodName Create`,
		`Get-NetTCPConnection -LocalPort 443`,
		`New-NetFirewallRule -DisplayName r -Direction Inbound`,
		`New-NetIPAddress -IPAddress 10.0.0.1 -InterfaceAlias eth0`,
		`Get-Volume -DriveLetter C`,
		`Get-Disk -Number 0`,
		`Get-Partition -DiskNumber 1`,
		`Remove-Partition -DiskNumber 1 -PartitionNumber 2`,
		`Format-Volume -DriveLetter D`,
		`Clear-Disk -Number 0 -RemoveData`,
		`Add-LocalGroupMember -Group Administrators -Member bob`,
		`Get-WSManInstance -ResourceURI winrm/config`,
		`Enable-WSManCredSSP -Role Client`,
		// Network probes whose peer is a host-style parameter, not a URL.
		`Test-NetConnection -ComputerName example.com`,
		`Resolve-DnsName -Name example.com`,
		`Send-MailMessage -SmtpServer mail.example.com`,
	}
	for _, src := range srcs {
		r := lowerOK(t, src)
		if r.Conservative {
			t.Errorf("%q degraded to ⊤: %v", src, r.Notes)
			continue
		}
		if len(r.Effects) == 0 {
			t.Errorf("%q produced no effect", src)
		}
		for _, e := range r.Effects {
			if e.Target.IsTop() {
				t.Errorf("%q: target widened to ⊤ (effects=%+v)", src, r.Effects)
			}
		}
	}
}

// TestB13DestinationPathIsTarget: -DestinationPath carries the filesystem target
// of the Archive cmdlets, so the extraction destination is reported.
func TestB13DestinationPathIsTarget(t *testing.T) {
	r := lowerOK(t, `Expand-Archive -Path a.zip -DestinationPath /tmp/out -Force`)
	if !targetHas(r, engine.KindFSWrite, "/tmp/out") {
		t.Fatalf("expected FSWrite on -DestinationPath; effects=%+v", r.Effects)
	}
}

// TestB13URLTargetFromHostParam: a probe cmdlet that names its peer with
// -ComputerName/-Name still yields a concrete network target.
func TestB13URLTargetFromHostParam(t *testing.T) {
	r := lowerOK(t, `Test-NetConnection -ComputerName example.com`)
	onlyKinds(t, r, engine.KindNetEgress)
	if !targetHas(r, engine.KindNetEgress, "example.com") {
		t.Fatalf("expected NetEgress to -ComputerName; effects=%+v", r.Effects)
	}

	r2 := lowerOK(t, `Resolve-DnsName -Name example.com`)
	if !targetHas(r2, engine.KindNetEgress, "example.com") {
		t.Fatalf("expected NetEgress to -Name; effects=%+v", r2.Effects)
	}
}

// TestB13SwitchBeforeOperandKeepsTarget is the regression for the false ⊤ an
// unrecognised switch caused: `Get-Content -Raw app.log` bound app.log to -Raw,
// leaving the read with no target.
func TestB13SwitchBeforeOperandKeepsTarget(t *testing.T) {
	r := lowerOK(t, `Get-Content -Raw app.log`)
	if r.Conservative {
		t.Fatalf("unexpected ⊤: %v", r.Notes)
	}
	if !targetHas(r, engine.KindFSRead, "app.log") {
		t.Fatalf("expected FSRead app.log; effects=%+v", r.Effects)
	}
}
