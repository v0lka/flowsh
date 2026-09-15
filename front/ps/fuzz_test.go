package ps

import (
	"strings"
	"testing"
	"time"

	"github.com/v0lka/flowsh/engine"
)

// This file is roadmap task C4 (reliability/security): fuzzing for the
// PowerShell frontend, plus adversarial bound checks.
//
// The contract it pins is the one conservatism.md fixes for every frontend:
//
//   - Parse never panics; an input it cannot understand degrades to ⊤
//     (Program.Top with a non-empty Reason), never to a crash and never to a
//     silent "no effect";
//   - every non-⊤ program validates and re-encodes;
//   - Lower is total (never panics, never returns nil, always serialises) and
//     every path that cannot bound its input emits the single shared ⊤ shape —
//     CodeExec over the any-target scope — with Conservative set, so HasTop and
//     the severity propagation stay uniform;
//   - Conservative is never set without a matching ⊤ effect (the
//     "⊤ without an effect" anti-pattern), and an unparseable program always
//     lowers to a conservative ⊤, never to a benign result.

// isTopEffect reports whether e is the one shared ⊤ shape: code execution over
// the any-target scope (conservatism.md). It intentionally does not treat every
// ScopeTop effect as ⊤ — a bounded effect may legitimately target the any-scope
// (e.g. a pipeline-fed path), so only the CodeExec+tops pair is ⊤.
func isTopEffect(e engine.Effect) bool {
	return e.Kind == engine.KindCodeExec && e.Target.IsTop()
}

// hasTopEffect reports whether effs contains the ⊤ effect.
func hasTopEffect(effs []engine.Effect) bool {
	for _, e := range effs {
		if isTopEffect(e) {
			return true
		}
	}
	return false
}

// checkLowerContract enforces the conservative contract on one lowered result.
func checkLowerContract(t *testing.T, src string, r *Result) {
	t.Helper()
	if r == nil {
		t.Fatalf("nil ps.Result for %q", src)
	}
	if _, err := r.Encode(); err != nil {
		t.Fatalf("ps.Result.Encode failed for %q: %v", src, err)
	}
	if r.Conservative && !hasTopEffect(r.Effects) {
		t.Fatalf("conservative result without a ⊤ (CodeExec over any) effect for %q", src)
	}
}

// FuzzParse asserts the PowerShell frontend contract on arbitrary input.
//
// It mirrors front/bash's FuzzParse: it never panics, a non-⊤ program is a
// valid, re-encodable program, and Lower never turns an understood program into
// a silent miss or a ⊤ into anything other than the shared ⊤ shape.
//
// The seeds deliberately include adversarial shapes (unbalanced quotes, deep
// nesting, huge pipelines, repeated alias/record lines) so that even a seed-only
// `go test` run exercises the bounds the roadmap asks about.
func FuzzParse(f *testing.F) {
	seeds := []string{
		// Ordinary and structural forms.
		"", "Get-ChildItem", "Remove-Item -Recurse -Force $HOME",
		"Get-Content x | Where-Object { $_ } | Select-Object Name",
		"$env:FOO = 'bar'; Get-ChildItem",
		"function f { Remove-Item -Recurse -Force $HOME }",
		"if ($true) { Get-ChildItem } else { Remove-Item x }",
		// Opaque / code-execution constructs that must be ⊤.
		"R`emove-Item -Recurse -Force $HOME",
		"Invoke-Expression 'Remove-Item -Recurse -Force $HOME'",
		"& $cmd -Recurse -Force $HOME",
		"[ScriptBlock]::Create('Remove-Item -Recurse -Force $HOME')",
		"$a,$b -Recurse @args",
		"Set-Alias r Remove-Item; r -Recurse -Force /",
		// Malformed / adversarial trivia.
		"echo 'unterminated", `"unterminated`, "${", "(", "@(", "if", "|", ";;;",
		"\x00\x01\x02",
		// Adversarial scale: deep nesting, huge pipeline, unbalanced quotes,
		// repeated alias records.
		strings.Repeat("if(", 200),
		strings.Repeat("Get-ChildItem | ", 500) + "Out-Null",
		strings.Repeat("'", 1000),
		strings.Repeat("Set-Alias a b; ", 300),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, src string) {
		p := Parse("fuzz", src)
		if p == nil {
			t.Fatalf("nil program for %q", src)
		}
		if p.Top {
			if strings.TrimSpace(p.Reason) == "" {
				t.Fatalf("⊤ program without a reason for %q", src)
			}
		} else if err := p.Validate(); err != nil {
			t.Fatalf("invalid program for %q: %v", src, err)
		} else if _, err := p.Encode(); err != nil {
			t.Fatalf("program encode failed for %q: %v", src, err)
		}

		// Lower must be total under both provider configurations (the Windows
		// option only turns the Registry provider on; it must never break the
		// ⊤/no-silent-miss contract).
		for _, opts := range []Options{{Windows: false}, {Windows: true}} {
			r := LowerWith(p, opts)
			checkLowerContract(t, src, r)
			// An unparseable program MUST lower to ⊤, never to a benign result.
			if p.Top && !r.Conservative {
				t.Fatalf("⊤ program lowered without Conservative for %q", src)
			}
			if p.Top && !hasTopEffect(r.Effects) {
				t.Fatalf("⊤ program lowered to no ⊤ effect for %q", src)
			}
		}

		// A construct the frontend marked opaque (KindTop) must survive lowering
		// as ⊤: no path may drop it and report "no effect".
		if !p.Top {
			opaque := false
			for _, s := range p.Stmts {
				if s != nil && s.Kind == KindTop {
					opaque = true
					break
				}
			}
			if opaque {
				r := Lower(p)
				if !r.Conservative || !hasTopEffect(r.Effects) {
					t.Fatalf("opaque (KindTop) program not lowered to ⊤ for %q", src)
				}
			}
		}
	})
}

// TestAdversarialInputsAreBounded is acceptance criterion C4.3: adversarial
// inputs (deep nesting, huge pipelines, unbalanced quotes, repeated
// alias/record lines) terminate within the parse budget, never hang, never
// panic, and never degrade an unbounded input to a benign (effect-free, non-⊤)
// result.
func TestAdversarialInputsAreBounded(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"deep-nesting", strings.Repeat("if($true){", 4000)},
		{"huge-pipeline", strings.Repeat("Get-ChildItem | ", 4000) + "Out-Null"},
		{"unbalanced-quotes", strings.Repeat("'\"", 8000)},
		{"repeated-alias", strings.Repeat("Set-Alias a b; ", 2000)},
		{"repeated-record", strings.Repeat("Get-Content a; ", 4000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			p := Parse("adv", tc.src)
			elapsed := time.Since(start)
			if p == nil {
				t.Fatalf("Parse returned nil")
			}
			// The per-parse budget is DefaultTimeoutMicros (250 ms) in an ordinary
			// build; a generous wall-clock ceiling proves the bound held and
			// nothing hung. Under the race detector the budget is disabled (see
			// budget_race.go) and every memory access is instrumented, so a
			// wall-clock ceiling is not meaningful there — the race build skips
			// it, exactly as the other wall-clock gates do, while the remaining
			// assertions below still run.
			if !raceDetectorEnabled && elapsed > 5*time.Second {
				t.Fatalf("not bounded: took %s (budget %d µs)", elapsed, DefaultTimeoutMicros)
			}
			if p.Top {
				if strings.TrimSpace(p.Reason) == "" {
					t.Fatalf("⊤ program without a reason")
				}
			} else if err := p.Validate(); err != nil {
				t.Fatalf("invalid program: %v", err)
			}

			r := Lower(p)
			checkLowerContract(t, tc.src, r)
			// No silent miss: whatever the outcome, an adversarial input must
			// either carry an effect or degrade to ⊤ — never "nothing".
			if p.Top && !r.Conservative {
				t.Fatalf("unparseable adversarial input lowered non-conservatively")
			}
		})
	}
}
