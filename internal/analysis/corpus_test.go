package analysis

import (
	"encoding/json"
	"testing"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
)

// mustCorpus loads the repository corpus or fails the test.
func mustCorpus(t *testing.T) []Case {
	t.Helper()
	dir, err := CorpusDir()
	if err != nil {
		t.Fatalf("CorpusDir: %v", err)
	}
	cases, err := LoadCorpus(dir)
	if err != nil {
		t.Fatalf("LoadCorpus(%s): %v", dir, err)
	}
	if len(cases) == 0 {
		t.Fatal("corpus is empty")
	}
	return cases
}

// mustAnalyzer builds an analyser over the embedded knowledge base.
func mustAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	a, err := NewAnalyzer()
	if err != nil {
		t.Fatalf("NewAnalyzer: %v", err)
	}
	return a
}

// analyzeCase analyses one corpus case.
func analyzeCase(t *testing.T, a *Analyzer, c Case) *Report {
	t.Helper()
	lang, err := c.Dialect()
	if err != nil {
		t.Fatalf("case %s: %v", c.ID, err)
	}
	rep := a.Analyze(lang, c.Input)
	if rep == nil {
		t.Fatalf("case %s: nil report", c.ID)
	}
	return rep
}

// TestGuardFallCoverage is acceptance criterion 2: every GuardFall case of
// classes A-E, in both dialects, is classified as "effect present or ⊤" — there
// are zero silent misses. It also pins that each dialect actually exercises
// every class A-E, so the suite cannot pass vacuously.
func TestGuardFallCoverage(t *testing.T) {
	a := mustAnalyzer(t)
	cases := Filter(mustCorpus(t), GroupGuardFall)
	if len(cases) == 0 {
		t.Fatal("no guardfall cases in the corpus")
	}

	seen := make(map[string]map[string]bool)
	for _, c := range cases {
		lang, _ := c.Dialect()
		if seen[string(lang)] == nil {
			seen[string(lang)] = make(map[string]bool)
		}
		seen[string(lang)][c.Category] = true
	}
	for _, lang := range Langs {
		for _, cls := range GuardFallClasses {
			if !seen[string(lang)][cls] {
				t.Errorf("guardfall: dialect %s does not exercise class %s", lang, cls)
			}
		}
	}

	misses := 0
	for _, c := range cases {
		rep := analyzeCase(t, a, c)
		if !rep.Covered() {
			misses++
			t.Errorf("guardfall MISS %s (%s/%s): %q → neither an effect nor ⊤", c.ID, c.Lang, c.Category, c.Input)
		}
	}
	if misses != 0 {
		t.Fatalf("guardfall coverage: %d/%d misses (want 0)", misses, len(cases))
	}
	t.Logf("guardfall: %d cases across %d dialects, 0 misses", len(cases), len(Langs))
}

// TestDestructiveCoverage checks the canonical destructive commands are all
// covered and reach at least the Medium grade.
func TestDestructiveCoverage(t *testing.T) {
	a := mustAnalyzer(t)
	cases := Filter(mustCorpus(t), GroupDestructive)
	if len(cases) == 0 {
		t.Fatal("no destructive cases in the corpus")
	}
	for _, c := range cases {
		rep := analyzeCase(t, a, c)
		if !rep.Covered() {
			t.Errorf("destructive MISS %s: %q → neither an effect nor ⊤", c.ID, c.Input)
			continue
		}
		if rep.Score.Grade < engine.DestructMedium {
			t.Errorf("destructive %s: grade %s < Medium (%q)", c.ID, rep.Score.Grade, c.Input)
		}
	}
}

// TestPowerShellCorpusCoverage checks the PowerShell-specific recall cases are
// all covered.
func TestPowerShellCorpusCoverage(t *testing.T) {
	a := mustAnalyzer(t)
	cases := Filter(mustCorpus(t), GroupPS)
	if len(cases) == 0 {
		t.Fatal("no PowerShell cases in the corpus")
	}
	for _, c := range cases {
		rep := analyzeCase(t, a, c)
		if !rep.Covered() {
			t.Errorf("ps MISS %s: %q → neither an effect nor ⊤", c.ID, c.Input)
		}
	}
}

// TestBenignPrecision is the precision control: ordinary commands must not be
// escalated to ⊤.
func TestBenignPrecision(t *testing.T) {
	a := mustAnalyzer(t)
	cases := Filter(mustCorpus(t), GroupBenign)
	if len(cases) == 0 {
		t.Fatal("no benign cases in the corpus")
	}
	for _, c := range cases {
		rep := analyzeCase(t, a, c)
		if rep.Top || rep.Conservative || rep.HasTop() {
			t.Errorf("benign %s raised ⊤/conservative: %q (reason %q)", c.ID, c.Input, rep.Reason)
		}
	}
}

// TestCorpusReportsAreValidJSON is acceptance criterion 1 across the whole
// corpus: every report validates and round-trips through JSON.
func TestCorpusReportsAreValidJSON(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range mustCorpus(t) {
		rep := analyzeCase(t, a, c)
		if err := rep.Validate(); err != nil {
			t.Errorf("%s: Validate: %v", c.ID, err)
			continue
		}
		data, err := rep.Encode()
		if err != nil {
			t.Errorf("%s: Encode: %v", c.ID, err)
			continue
		}
		if !json.Valid(data) {
			t.Errorf("%s: Encode produced invalid JSON", c.ID)
			continue
		}
		var back Report
		if err := json.Unmarshal(data, &back); err != nil {
			t.Errorf("%s: JSON does not round-trip: %v", c.ID, err)
			continue
		}
		if back.Effects == nil {
			t.Errorf("%s: effects serialise as null, want []", c.ID)
		}
		if back.Lang != rep.Lang || back.SchemaVersion != rep.SchemaVersion {
			t.Errorf("%s: header round-trip mismatch", c.ID)
		}
	}
}

// TestCorpusShape pins the corpus to a minimum shape, so shrinking it to a
// trivially-passing set is itself a test failure.
func TestCorpusShape(t *testing.T) {
	cases := mustCorpus(t)
	byGroup := make(map[string]int)
	for _, c := range cases {
		byGroup[c.Group]++
	}
	for _, want := range []struct {
		group string
		min   int
	}{
		{GroupGuardFall, 2 * len(GuardFallClasses)},
		{GroupDestructive, 10},
		{GroupBenign, 5},
		{GroupPS, 5},
		{GroupResolution, 5},
	} {
		if byGroup[want.group] < want.min {
			t.Errorf("corpus group %q has %d cases, want >= %d", want.group, byGroup[want.group], want.min)
		}
	}
}

// TestWhyCoverage is the why-trace gate: across the whole corpus, every reported
// effect must be explained by a why-trace citing a concrete node/flag, so that
// engine.WhyGaps returns the empty set. Any effect left without a concrete
// justification fails, and a non-empty effect set must carry a non-empty why.
func TestWhyCoverage(t *testing.T) {
	a := mustAnalyzer(t)
	cases := mustCorpus(t)
	for _, c := range cases {
		rep := analyzeCase(t, a, c)
		if gaps := engine.WhyGaps(rep.Effects, rep.Why); len(gaps) != 0 {
			t.Errorf("why MISS %s (%s/%s): unexplained effects: %v (input %q)", c.ID, c.Lang, c.Category, gaps, c.Input)
		}
		if len(rep.Effects) > 0 && len(rep.Why) == 0 {
			t.Errorf("why MISS %s: %d effects but empty why (input %q)", c.ID, len(rep.Effects), c.Input)
		}
	}
	t.Logf("why: %d corpus cases, every effect explained", len(cases))
}

// TestResolutionCoverage is acceptance criterion A2 over the corpus: every
// resolution case must expose which command its invocation actually named, and
// the group must exercise the decisive kinds (alias, builtin, command, unknown)
// so the gate cannot pass vacuously. Alias cases must carry their expansion
// chain, and at least one case must resolve through more than one alias.
func TestResolutionCoverage(t *testing.T) {
	a := mustAnalyzer(t)
	cases := Filter(mustCorpus(t), GroupResolution)
	if len(cases) == 0 {
		t.Fatal("no resolution cases in the corpus")
	}

	kinds := make(map[bind.ResolveKind]int)
	longestChain := 0
	for _, c := range cases {
		rep := analyzeCase(t, a, c)
		if !rep.Covered() {
			t.Errorf("resolution MISS %s (%s): %q → neither an effect nor ⊤", c.ID, c.Lang, c.Input)
		}
		k := rep.Resolution.Kind
		if k == "" {
			t.Errorf("resolution %s: report carries no resolution kind (%q)", c.ID, c.Input)
			continue
		}
		kinds[k]++
		if k == bind.ResolveAlias && len(rep.Resolution.AliasChain) == 0 {
			t.Errorf("resolution %s: alias kind but empty alias chain (%q)", c.ID, c.Input)
		}
		if len(rep.Resolution.AliasChain) > longestChain {
			longestChain = len(rep.Resolution.AliasChain)
		}
	}

	for _, want := range []bind.ResolveKind{bind.ResolveAlias, bind.ResolveBuiltin, bind.ResolveCommand, bind.ResolveUnknown} {
		if kinds[want] == 0 {
			t.Errorf("resolution corpus exercises no %q case", want)
		}
	}
	if longestChain < 2 {
		t.Errorf("resolution corpus has no alias chain longer than 1 (max %d)", longestChain)
	}
	t.Logf("resolution: %d cases, kinds %v, longest alias chain %d", len(cases), kinds, longestChain)
}

// TestPOSIXVariantCoverage is acceptance criterion A6 over the corpus: every
// case declared in the POSIX dialect is analysed in the POSIX variant (the
// report's lang is stamped "posix") and is covered, and the corpus actually
// contains such cases so the gate cannot pass vacuously.
func TestPOSIXVariantCoverage(t *testing.T) {
	a := mustAnalyzer(t)
	n := 0
	for _, c := range mustCorpus(t) {
		if c.Lang != string(LangPOSIX) {
			continue
		}
		n++
		rep := analyzeCase(t, a, c)
		if rep.Lang != string(LangPOSIX) {
			t.Errorf("posix %s: report lang %q, want %q", c.ID, rep.Lang, LangPOSIX)
		}
		if !rep.Covered() {
			t.Errorf("posix MISS %s: %q → neither an effect nor ⊤", c.ID, c.Input)
		}
	}
	if n == 0 {
		t.Fatal("no POSIX cases in the corpus")
	}
	t.Logf("posix: %d cases analysed in the POSIX variant", n)
}

// TestDestructiveClassCorpus is acceptance criterion A3 over the corpus: every
// destructive case that matches a knowledge-base destructive entry must expose
// that entry (a non-empty class and reason) and must not report a
// destructiveness below the matched class — in either the report or the score.
// The corpus must contain at least one such case, so the gate cannot pass
// vacuously.
func TestDestructiveClassCorpus(t *testing.T) {
	a := mustAnalyzer(t)
	cases := Filter(mustCorpus(t), GroupDestructive)
	matched := 0
	for _, c := range cases {
		rep := analyzeCase(t, a, c)
		if len(rep.Destructive) == 0 {
			continue
		}
		matched++
		want := maxClassSeverity(t, rep.Destructive)
		for _, f := range rep.Destructive {
			if f.Class == "" {
				t.Errorf("destructive %s: finding without a class: %+v", c.ID, f)
			}
			if f.Reason == "" {
				t.Errorf("destructive %s: finding without a reason: %+v", c.ID, f)
			}
		}
		if rep.Destructiveness < want {
			t.Errorf("destructive %s: destructiveness %s < matched class %s (%q)", c.ID, rep.Destructiveness, want, c.Input)
		}
		if rep.Score.Destructiveness < want {
			t.Errorf("destructive %s: score.destructiveness %s < matched class %s (%q)", c.ID, rep.Score.Destructiveness, want, c.Input)
		}
	}
	if matched == 0 {
		t.Fatal("no destructive corpus case matched a knowledge-base destructive entry")
	}
	t.Logf("destructive class: %d/%d cases matched a KB destructive entry", matched, len(cases))
}
