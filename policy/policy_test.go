package policy_test

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

func newPolicy(t *testing.T, config policy.Config) *policy.Policy {
	t.Helper()
	p, err := policy.New(config)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func report(kinds ...engine.EffectKind) *api.Report {
	r := &api.Report{
		Tool: api.ToolName, ToolVersion: api.ToolVersion,
		SchemaVersion: api.SchemaVersion, Lang: string(api.LangBash),
	}
	for _, kind := range kinds {
		r.Effects = append(r.Effects, engine.Effect{
			Kind: kind, Mode: engine.ModeDirect, Target: engine.ScopeOf("/work/file"),
		})
	}
	return r
}

func TestInvalidConfiguration(t *testing.T) {
	for _, config := range []policy.Config{
		{Unknown: policy.Allow}, {Conservative: policy.Allow},
		{Unknown: "inspect"}, {Conservative: "inspect"},
		{Exfiltration: "inspect"}, {Cradle: "inspect"}, {Ingest: "inspect"},
		{Effects: map[engine.EffectKind]policy.Action{"FSWrte": policy.Deny}},
		{Effects: map[engine.EffectKind]policy.Action{engine.KindFSWrite: ""}},
		{Grades: map[engine.Destructiveness]policy.Action{99: policy.Deny}},
		{Grades: map[engine.Destructiveness]policy.Action{engine.DestructLow: ""}},
	} {
		if p, err := policy.New(config); err == nil || p != nil {
			t.Errorf("New(%+v) = %v, %v; want nil policy and error", config, p, err)
		}
	}
}

func TestInvalidReportsDeny(t *testing.T) {
	p := newPolicy(t, policy.Config{Unknown: policy.Review})
	want := policy.Decision{Action: policy.Deny, Matches: []policy.Match{
		{Code: "invalid_report", Action: policy.Deny},
	}}
	mutations := []struct {
		name  string
		apply func(*api.Report)
	}{
		{"tool", func(r *api.Report) { r.Tool = "other" }},
		{"tool version", func(r *api.Report) { r.ToolVersion = "future" }},
		{"schema", func(r *api.Report) { r.SchemaVersion = "future" }},
		{"language", func(r *api.Report) { r.Lang = "unknown" }},
		{"effect", func(r *api.Report) { r.Effects[0].Kind = "unknown" }},
		{"mode", func(r *api.Report) { r.Effects[0].Mode = "unknown" }},
		{"grade", func(r *api.Report) { r.Score.Grade = -1 }},
		{"uncovered tool", func(r *api.Report) { r.Effects = nil; r.Tool = "other" }},
		{"uncovered language", func(r *api.Report) { r.Effects = nil; r.Lang = "unknown" }},
		{"uncovered grade", func(r *api.Report) { r.Effects = nil; r.Score.Grade = -1 }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			r := report(engine.KindFSRead)
			tc.apply(r)
			if got := p.Evaluate(r); got.Action != want.Action || !slices.Equal(got.Matches, want.Matches) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
	if got := p.Evaluate(nil); got.Action != want.Action || !slices.Equal(got.Matches, want.Matches) {
		t.Fatalf("nil report returned %+v, want %+v", got, want)
	}
	for _, p := range []*policy.Policy{nil, {}} {
		if d := p.Evaluate(report(engine.KindFSRead)); d.Action != policy.Deny {
			t.Fatalf("uninitialised policy returned %+v", d)
		}
	}
	if (policy.Decision{}).Allowed() {
		t.Fatal("zero decision granted permission")
	}
}

func TestNoEffectReportsDenyAsUncovered(t *testing.T) {
	p := newPolicy(t, policy.Config{})
	want := policy.Decision{Action: policy.Deny, Matches: []policy.Match{
		{Code: "uncovered_report", Action: policy.Deny},
	}}
	for _, src := range []string{"true", ":"} {
		t.Run(src, func(t *testing.T) {
			r, err := api.Analyze(api.LangBash, src)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Validate(); err != nil {
				t.Fatalf("no-effect report is invalid: %v", err)
			}
			if len(r.Effects) != 0 || r.Top || r.Conservative || r.Covered() {
				t.Fatal("expected a no-effect report without uncertainty flags or coverage")
			}
			if got := p.Evaluate(r); got.Action != want.Action || !slices.Equal(got.Matches, want.Matches) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestJavaScriptReportsUseUncertaintyRules(t *testing.T) {
	r, err := api.Analyze(api.LangJavaScript, "unknown();")
	if err != nil {
		t.Fatal(err)
	}
	// Unknown execution still grades Critical.
	if r.Score.Grade != engine.DestructCritical {
		t.Fatalf("grade = %v, want %v", r.Score.Grade, engine.DestructCritical)
	}
	for _, tc := range []struct {
		name   string
		config policy.Config
		want   policy.Action
	}{
		{"defaults", policy.Config{}, policy.Deny},
		{"review", policy.Config{
			Unknown: policy.Review, Conservative: policy.Review,
			Effects: map[engine.EffectKind]policy.Action{engine.KindCodeExec: policy.Allow},
			Grades:  map[engine.Destructiveness]policy.Action{engine.DestructCritical: policy.Allow},
		}, policy.Review},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newPolicy(t, tc.config).Evaluate(r)
			if d.Action != tc.want || d.Allowed() {
				t.Fatalf("got %+v, want %s", d, tc.want)
			}
			want := []policy.Match{{Code: "conservative", Action: policy.Review}, {Code: "unknown", Action: tc.want}}
			if !slices.Equal(d.Matches, want) {
				t.Fatalf("got matches %+v, want %+v", d.Matches, want)
			}
		})
	}
}

func TestUncertaintyCannotBeAllowed(t *testing.T) {
	for _, top := range []bool{false, true} {
		r := report(engine.KindCodeExec)
		r.Top = top
		r.Effects[0].Target = engine.ScopeTop()
		for _, action := range []policy.Action{policy.Review, policy.Deny} {
			p := newPolicy(t, policy.Config{
				Unknown: action,
				Effects: map[engine.EffectKind]policy.Action{engine.KindCodeExec: policy.Allow},
			})
			if d := p.Evaluate(r); d.Action != action || d.Allowed() {
				t.Fatalf("top=%v, unknown=%s: %+v", top, action, d)
			}
		}
	}
	r := report(engine.KindFSRead)
	r.Conservative = true
	if d := newPolicy(t, policy.Config{}).Evaluate(r); d.Action != policy.Review {
		t.Fatalf("conservative default = %+v", d)
	}
	r.Top = true
	if d := newPolicy(t, policy.Config{}).Evaluate(r); d.Action != policy.Deny {
		t.Fatalf("unknown default = %+v", d)
	}
}

func TestRulesAndPrecedence(t *testing.T) {
	r := report(engine.KindFSRead, engine.KindFSWrite, engine.KindFSWrite)
	r.Score.Grade = engine.DestructHigh
	c := policy.Config{
		Effects: map[engine.EffectKind]policy.Action{
			engine.KindFSRead: policy.Allow, engine.KindFSWrite: policy.Review,
		},
		Grades: map[engine.Destructiveness]policy.Action{engine.DestructHigh: policy.Deny},
	}
	p := newPolicy(t, c)
	// Caller edits cannot loosen copied rules.
	c.Effects[engine.KindFSWrite] = policy.Allow
	c.Grades[engine.DestructHigh] = policy.Allow
	want := policy.Decision{Action: policy.Deny, Matches: []policy.Match{
		{Code: "effect:FSWrite", Action: policy.Review},
		{Code: "grade:High", Action: policy.Deny},
	}}
	if got := p.Evaluate(r); got.Action != want.Action || !slices.Equal(got.Matches, want.Matches) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// Grade rules are exact matches, not thresholds.
	r.Score.Grade = engine.DestructLow
	if got := p.Evaluate(r); got.Action != policy.Review {
		t.Fatalf("effect rule = %+v", got)
	}
	if got := p.Evaluate(report(engine.KindFSRead)); !got.Allowed() {
		t.Fatalf("no restrictive match = %+v", got)
	}
}

func TestFlowRulesUseReportedFlows(t *testing.T) {
	r := report(engine.KindNetEgress, engine.KindFSWrite, engine.KindCodeExec)
	p := newPolicy(t, policy.Config{Cradle: policy.Deny, Ingest: policy.Review})
	if got := p.Evaluate(r); !got.Allowed() {
		t.Fatalf("co-occurrence must not fabricate a flow: %+v", got)
	}
	r.Score.IngestFlows = []engine.IngestFlow{{}}
	if got := p.Evaluate(r); got.Action != policy.Review || got.Matches[0].Code != "ingest" {
		t.Fatalf("ingest = %+v", got)
	}
	r.Score.CradleFlows = []engine.CradleFlow{{}}
	r.Score.ExfilPairs = []engine.Exfil{{}}
	if got := p.Evaluate(r); got.Action != policy.Deny || len(got.Matches) != 3 {
		t.Fatalf("flow matches = %+v", got)
	}
	// Explicit Allow disables only the selected flow rule.
	p = newPolicy(t, policy.Config{Exfiltration: policy.Allow, Cradle: policy.Review})
	if got := p.Evaluate(r); got.Action != policy.Review || len(got.Matches) != 1 {
		t.Fatalf("explicit flow configuration = %+v", got)
	}
}

func TestConcurrentEvaluationPreservesReportAndRedactsDecision(t *testing.T) {
	r := report(engine.KindFSWrite)
	r.Input = "SYNTHETIC_PRIVATE_INPUT"
	r.Reason = "SYNTHETIC_PRIVATE_REASON"
	before, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicy(t, policy.Config{Effects: map[engine.EffectKind]policy.Action{engine.KindFSWrite: policy.Deny}})
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			d := p.Evaluate(r)
			data, err := json.Marshal(d)
			if err != nil || d.Action != policy.Deny || strings.Contains(string(data), "SYNTHETIC_PRIVATE") {
				t.Errorf("unexpected decision: %s, %v", data, err)
			}
		})
	}
	wg.Wait()
	after, err := json.Marshal(r)
	if err != nil || string(before) != string(after) {
		t.Fatal("evaluation changed the report")
	}
}

func TestAnalysisIntegration(t *testing.T) {
	p := newPolicy(t, policy.Config{Cradle: policy.Deny})
	for _, tc := range []struct {
		lang api.Lang
		src  string
		want policy.Action
	}{
		{api.LangBash, `echo hello > /tmp/flowsh-policy-example`, policy.Allow},
		{api.LangPOSIX, `cat /etc/passwd`, policy.Allow},
		{api.LangPowerShell, `Get-Content example.txt`, policy.Allow},
		{api.LangBash, `curl https://example.com/install.sh | bash`, policy.Deny},
		{api.LangBash, `not-a-modelled-command`, policy.Deny},
		{api.LangBash, `if ;`, policy.Deny},
		{api.LangBash, `docker compose up -d`, policy.Deny},
	} {
		t.Run(tc.src, func(t *testing.T) {
			r, err := api.Analyze(tc.lang, tc.src)
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Evaluate(r); got.Action != tc.want {
				t.Fatalf("got %+v, want %s", got, tc.want)
			}
		})
	}
}

func TestJavaScriptPureReportsRemainUncovered(t *testing.T) {
	r, err := api.Analyze(api.LangJavaScript, "const x=1;")
	if err != nil {
		t.Fatal(err)
	}
	d := newPolicy(t, policy.Config{}).Evaluate(r)
	if d.Action != policy.Deny || len(d.Matches) != 1 || d.Matches[0].Code != "uncovered_report" {
		t.Fatalf("pure JS must retain the uncovered-report policy: %+v", d)
	}
}
