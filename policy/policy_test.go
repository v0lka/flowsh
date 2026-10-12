package policy_test

import (
	"encoding/json"
	"reflect"
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
		{"uncovered", func(r *api.Report) { r.Effects = nil }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			r := report(engine.KindFSRead)
			tc.apply(r)
			if d := p.Evaluate(r); d.Action != policy.Deny || d.Allowed() {
				t.Fatalf("invalid report returned %+v", d)
			}
		})
	}
	if d := p.Evaluate(nil); d.Action != policy.Deny {
		t.Fatalf("nil report returned %+v", d)
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
	// The constructed policy owns its maps; later caller changes cannot loosen it.
	c.Effects[engine.KindFSWrite] = policy.Allow
	c.Grades[engine.DestructHigh] = policy.Allow
	want := policy.Decision{Action: policy.Deny, Matches: []policy.Match{
		{Code: "effect:FSWrite", Action: policy.Review},
		{Code: "grade:High", Action: policy.Deny},
	}}
	if got := p.Evaluate(r); !reflect.DeepEqual(got, want) {
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
