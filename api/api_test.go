// Package api_test is an EXTERNAL test package for the embedding surface. It
// imports the public api package through its module path — exactly as an
// external Go module would — and touches only exported symbols (Analyze,
// AnalyzeWith, ParseLang, Options, Report.Encode, …). If a symbol the embedding
// caller needs were unexported, this file would not compile.
package api_test

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
)

// probe is one effect-producing invocation per dialect. Every source was chosen
// so the analysis yields at least one effect (a benign no-op such as bare `ls`
// would produce none), which keeps the "non-empty effects" assertion
// meaningful rather than vacuous.
var probe = []struct {
	name string
	lang api.Lang
	src  string
}{
	{"bash write", api.LangBash, `echo hi > /tmp/flowsh-api-out`},
	{"bash read", api.LangBash, `cat /etc/passwd`},
	{"posix remove", api.LangPOSIX, `rm -rf /tmp/flowsh-api-check`},
	{"posix read", api.LangPOSIX, `cat /etc/passwd`},
	{"posh secret read", api.LangPowerShell, `Get-Content ~/.aws/credentials`},
	{"posh write", api.LangPowerShell, `Set-Content x y`},
}

// TestExportedSurfaceAnalyze drives Analyze for bash, posix and posh through the
// public package and pins the report contract an embedder relies on: non-empty
// effects, the tool/schema versions, the stamped language, and canonical valid
// JSON that round-trips through api.Report.
func TestExportedSurfaceAnalyze(t *testing.T) {
	for _, p := range probe {
		t.Run(p.name, func(t *testing.T) {
			rep, err := api.Analyze(p.lang, p.src)
			if err != nil {
				t.Fatalf("Analyze(%s, %q): %v", p.lang, p.src, err)
			}
			if rep == nil {
				t.Fatalf("Analyze(%s, %q): nil report", p.lang, p.src)
			}

			// Non-empty effects: the analysis said something concrete.
			if len(rep.Effects) == 0 {
				t.Fatalf("Analyze(%s, %q): no effects (want >= 1)", p.lang, p.src)
			}
			if !rep.Covered() {
				t.Fatalf("Analyze(%s, %q): report not covered", p.lang, p.src)
			}

			// Report-contract versions, both against the exported constant and
			// against the literal the contract pins.
			if rep.ToolVersion != api.ToolVersion {
				t.Errorf("ToolVersion = %q, want api.ToolVersion %q", rep.ToolVersion, api.ToolVersion)
			}
			if rep.ToolVersion != "flowsh/v2" {
				t.Errorf("ToolVersion = %q, want %q", rep.ToolVersion, "flowsh/v2")
			}
			if rep.SchemaVersion != api.SchemaVersion {
				t.Errorf("SchemaVersion = %q, want api.SchemaVersion %q", rep.SchemaVersion, api.SchemaVersion)
			}
			if rep.Tool != api.ToolName {
				t.Errorf("Tool = %q, want api.ToolName %q", rep.Tool, api.ToolName)
			}
			if rep.Lang != string(p.lang) {
				t.Errorf("Lang = %q, want %q", rep.Lang, string(p.lang))
			}

			// Encode validates and returns canonical valid JSON.
			data, err := rep.Encode()
			if err != nil {
				t.Fatalf("Encode(): %v", err)
			}
			if !json.Valid(data) {
				t.Fatalf("Encode() produced invalid JSON: %s", data)
			}

			// It round-trips back into the exported report type.
			var back api.Report
			if err := json.Unmarshal(data, &back); err != nil {
				t.Fatalf("Unmarshal(Encode()): %v", err)
			}
			if back.ToolVersion != rep.ToolVersion || back.Lang != rep.Lang {
				t.Errorf("round-trip header mismatch: got (%q,%q), want (%q,%q)",
					back.ToolVersion, back.Lang, rep.ToolVersion, rep.Lang)
			}
			if len(back.Effects) != len(rep.Effects) {
				t.Errorf("round-trip effects: got %d, want %d", len(back.Effects), len(rep.Effects))
			}
		})
	}
}

// TestExportedParseLang pins the public language mapping: the canonical
// spellings plus their aliases, case-insensitively and trimmed, while an
// unknown name is rejected.
func TestExportedParseLang(t *testing.T) {
	want := map[string]api.Lang{
		"bash":       api.LangBash,
		"SHELL":      api.LangBash,
		"  Bash  ":   api.LangBash,
		"posix":      api.LangPOSIX,
		"sh":         api.LangPOSIX,
		"posh":       api.LangPowerShell,
		"ps":         api.LangPowerShell,
		"pwsh":       api.LangPowerShell,
		"PowerShell": api.LangPowerShell,
	}
	for in, exp := range want {
		got, err := api.ParseLang(in)
		if err != nil {
			t.Errorf("ParseLang(%q): unexpected error %v", in, err)
			continue
		}
		if got != exp {
			t.Errorf("ParseLang(%q) = %q, want %q", in, got, exp)
		}
	}
	if _, err := api.ParseLang("fish"); err == nil {
		t.Errorf("ParseLang(\"fish\") returned no error, want one")
	}

	// Every advertised dialect must round-trip through ParseLang.
	if len(api.Langs) == 0 {
		t.Fatal("api.Langs is empty")
	}
	for _, l := range api.Langs {
		got, err := api.ParseLang(string(l))
		if err != nil {
			t.Errorf("ParseLang(%q) (from api.Langs): %v", l, err)
			continue
		}
		if got != l {
			t.Errorf("ParseLang(%q) = %q, want %q", l, got, l)
		}
	}
}

// TestExportedAnalyzeWithOptions exercises the Options surface: Root is stamped
// into the report, the zero Options matches Analyze, and the tri-state Windows
// provider is honoured through Bool.
func TestExportedAnalyzeWithOptions(t *testing.T) {
	const src = `cat /etc/passwd`

	arg, err := api.AnalyzeWith(api.LangBash, src, api.Options{Root: api.RootArgument})
	if err != nil {
		t.Fatalf("AnalyzeWith(Root=argument): %v", err)
	}
	if arg.Root != api.RootArgument {
		t.Errorf("Root = %q, want api.RootArgument %q", arg.Root, api.RootArgument)
	}

	stdin, err := api.AnalyzeWith(api.LangBash, src, api.Options{Root: api.RootStdin})
	if err != nil {
		t.Fatalf("AnalyzeWith(Root=stdin): %v", err)
	}
	if stdin.Root != api.RootStdin {
		t.Errorf("Root = %q, want api.RootStdin %q", stdin.Root, api.RootStdin)
	}

	// The zero Options reproduces Analyze exactly.
	zero, err := api.AnalyzeWith(api.LangBash, src, api.Options{})
	if err != nil {
		t.Fatalf("AnalyzeWith(zero Options): %v", err)
	}
	plain, err := api.Analyze(api.LangBash, src)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	zb, err := zero.Encode()
	if err != nil {
		t.Fatalf("Encode(zero Options): %v", err)
	}
	pb, err := plain.Encode()
	if err != nil {
		t.Fatalf("Encode(Analyze): %v", err)
	}
	if string(zb) != string(pb) {
		t.Errorf("AnalyzeWith(Options{}) differs from Analyze:\n got=%s\nwant=%s", zb, pb)
	}

	// The Windows option toggles the host-independent Registry provider: forced
	// on it persists state, forced off it contributes nothing.
	const reg = `Set-ItemProperty -Path HKCU:\Software\x -Name y -Value z`
	on, err := api.AnalyzeWith(api.LangPowerShell, reg, api.Options{Windows: api.Bool(true)})
	if err != nil {
		t.Fatalf("AnalyzeWith(Windows=true): %v", err)
	}
	if len(on.Effects) == 0 {
		t.Errorf("AnalyzeWith(Windows=true): want >=1 effect, got none")
	}
	off, err := api.AnalyzeWith(api.LangPowerShell, reg, api.Options{Windows: api.Bool(false)})
	if err != nil {
		t.Fatalf("AnalyzeWith(Windows=false): %v", err)
	}
	if len(off.Effects) != 0 {
		t.Errorf("AnalyzeWith(Windows=false): want 0 effects, got %d", len(off.Effects))
	}
}

// TestExportedAnalyzeWithOptionsVars drives the host-table option through the
// public embedding surface: Options.Vars seeds host-known bindings (a session
// temp directory) that resolve later $name reads, turning an unresolved ⊤
// redirect target into the concrete session-root path. Without the table the
// same input keeps ⊤ — the option resolves, it never loosens.
func TestExportedAnalyzeWithOptionsVars(t *testing.T) {
	const sessTemp = "/sess/ebefdbe1-54b0-46eb-9b2b-3564ab1c928f/temp"
	const src = `git diff main...HEAD -- core/tools/registry.go > $D/registry.diff`

	bound, err := api.AnalyzeWith(api.LangBash, src, api.Options{Vars: map[string]string{"D": sessTemp}})
	if err != nil {
		t.Fatalf("AnalyzeWith(Vars): %v", err)
	}
	if bound.Top || bound.Conservative {
		t.Fatalf("host-bound input must stay bounded: top=%v conservative=%v", bound.Top, bound.Conservative)
	}
	found := false
	for _, e := range bound.Effects {
		if e.Kind != engine.KindFSWrite {
			continue
		}
		if targets := e.Target.Targets(); len(targets) == 1 && targets[0] == sessTemp+"/registry.diff" {
			found = true
		}
	}
	if !found {
		t.Errorf("Vars-bound redirect must write %s/registry.diff", sessTemp)
	}

	plain, err := api.Analyze(api.LangBash, src)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, e := range plain.Effects {
		if e.Kind == engine.KindFSWrite && !e.Target.IsTop() {
			t.Errorf("unbound $D must leave the write target ⊤, got %v", e.Target)
		}
	}
}

// TestAnalyzeConcurrentMatchesSequential is the load-bearing test for the race
// step: many goroutines call api.Analyze (which reaches the process-wide
// sync.OnceValues analyser singleton) concurrently, and every result must be a
// byte-for-byte match of the same input analysed sequentially. It is declared
// first in this file so it is also the first caller of api.Analyze in the test
// binary, making the goroutines race the one-time knowledge-base load as well as
// the subsequent concurrent use of the shared analyser.
//
// Run it under -race for the gate: `go test -race ./...`.
func TestAnalyzeConcurrentMatchesSequential(t *testing.T) {
	const (
		goroutines = 32
		rounds     = 4
	)

	// Phase 1: hammer the shared analyser concurrently. Each goroutine records
	// the canonical JSON of every (round, case) result; they are released
	// together by closing the gate to maximise real overlap.
	batches := make([][]string, goroutines)
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			out := make([]string, 0, rounds*len(probe))
			<-gate
			for r := 0; r < rounds; r++ {
				for _, p := range probe {
					rep, err := api.Analyze(p.lang, p.src)
					if err != nil {
						out = append(out, fmt.Sprintf("analyze error: %v", err))
						continue
					}
					data, err := rep.Encode()
					if err != nil {
						out = append(out, fmt.Sprintf("encode error: %v", err))
						continue
					}
					out = append(out, string(data))
				}
			}
			batches[g] = out
		}(g)
	}
	close(gate)
	wg.Wait()

	// Phase 2: the sequential reference for the same inputs.
	want := make([]string, len(probe))
	for i, p := range probe {
		rep, err := api.Analyze(p.lang, p.src)
		if err != nil {
			t.Fatalf("sequential Analyze(%s, %q): %v", p.lang, p.src, err)
		}
		if len(rep.Effects) == 0 {
			t.Fatalf("sequential Analyze(%s, %q): no effects (want >= 1)", p.lang, p.src)
		}
		if rep.ToolVersion != "flowsh/v2" {
			t.Fatalf("sequential Analyze(%s, %q): ToolVersion = %q, want flowsh/v2", p.lang, p.src, rep.ToolVersion)
		}
		data, err := rep.Encode()
		if err != nil {
			t.Fatalf("sequential Encode(%s, %q): %v", p.lang, p.src, err)
		}
		want[i] = string(data)
	}

	// Phase 3: every concurrent result must equal its sequential counterpart.
	mismatches := 0
	for g, out := range batches {
		if len(out) != rounds*len(probe) {
			t.Errorf("goroutine %d produced %d results, want %d", g, len(out), rounds*len(probe))
			continue
		}
		for r := 0; r < rounds; r++ {
			for i, p := range probe {
				got := out[r*len(probe)+i]
				if got != want[i] {
					mismatches++
					if mismatches <= 5 {
						t.Errorf("goroutine %d round %d case %q: concurrent result != sequential\n got=%s\nwant=%s",
							g, r, p.name, got, want[i])
					}
				}
			}
		}
	}
	if mismatches > 0 {
		t.Fatalf("concurrent analysis is nondeterministic: %d/%d results differed from the sequential run",
			mismatches, goroutines*rounds*len(probe))
	}
	t.Logf("concurrency: %d goroutines x %d rounds x %d cases = %d analyses, all byte-identical to sequential",
		goroutines, rounds, len(probe), goroutines*rounds*len(probe))
}

// TestExportedAnalyzerReuse drives the documented NewAnalyzer entry point — the
// second workflow in docs/embedding.md ("reuse the analyser to amortise the KB
// load"). It pins that NewAnalyzer returns a usable analyser whose report is
// byte-identical to the package-level Analyze for the same input (they run the
// same pipeline) and that a single analyzer may be reused across analyses.
func TestExportedAnalyzerReuse(t *testing.T) {
	a, err := api.NewAnalyzer()
	if err != nil {
		t.Fatalf("NewAnalyzer(): %v", err)
	}
	if a == nil {
		t.Fatal("NewAnalyzer() returned a nil analyzer")
	}

	for _, p := range probe {
		t.Run(p.name, func(t *testing.T) {
			reused := a.Analyze(p.lang, p.src)
			if reused == nil {
				t.Fatalf("Analyzer.Analyze(%s, %q): nil report", p.lang, p.src)
			}
			plain, err := api.Analyze(p.lang, p.src)
			if err != nil {
				t.Fatalf("Analyze(%s, %q): %v", p.lang, p.src, err)
			}
			rb, err := reused.Encode()
			if err != nil {
				t.Fatalf("Encode(NewAnalyzer report): %v", err)
			}
			pb, err := plain.Encode()
			if err != nil {
				t.Fatalf("Encode(Analyze report): %v", err)
			}
			if string(rb) != string(pb) {
				t.Errorf("NewAnalyzer report differs from Analyze for %q:\n got=%s\nwant=%s", p.src, rb, pb)
			}
		})
	}
}
