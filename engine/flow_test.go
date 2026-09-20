package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFlowRoleValid(t *testing.T) {
	for _, r := range FlowRoles {
		if !r.Valid() {
			t.Errorf("%q: Valid() = false, want true", string(r))
		}
	}
	if FlowRole("bogus").Valid() {
		t.Errorf("an unknown flow role reported valid")
	}
	if got, want := FlowCradle.kind(), KindCodeExec; got != want {
		t.Errorf("FlowCradle.kind() = %q, want %q", string(got), string(want))
	}
	if got, want := FlowIngest.kind(), KindFSWrite; got != want {
		t.Errorf("FlowIngest.kind() = %q, want %q", string(got), string(want))
	}
	if got := FlowNone.kind(); got != "" {
		t.Errorf("FlowNone.kind() = %q, want empty", string(got))
	}
}

// TestEffectNetFlowSerialisation pins the additive shape: a tagged effect
// carries netFlow, an untagged one serialises exactly as it did before the
// field existed (so effect-ir/v2 is byte-compatible with v1 for flowless
// programs).
func TestEffectNetFlowSerialisation(t *testing.T) {
	tagged := Effect{Kind: KindCodeExec, Target: ScopeTop(), Mode: ModeDirect, Certainty: CertaintyCertain, NetFlow: FlowCradle}
	b, err := json.Marshal(tagged)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"netFlow":"cradle"`) {
		t.Errorf("tagged effect did not serialise netFlow: %s", b)
	}
	var back Effect
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.NetFlow != FlowCradle {
		t.Errorf("netFlow round-trip = %q, want %q", string(back.NetFlow), string(FlowCradle))
	}
	if err := back.Validate(); err != nil {
		t.Errorf("validate round-tripped effect: %v", err)
	}

	plain := Effect{Kind: KindFSRead, Target: ScopeOf("/x"), Mode: ModeDirect, Certainty: CertaintyCertain}
	plainJSON, err := json.Marshal(plain)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(plainJSON), "netFlow") {
		t.Errorf("untagged effect serialised netFlow: %s", plainJSON)
	}
}

func TestEffectJoinKeepsNetFlow(t *testing.T) {
	tagged := Effect{Kind: KindFSWrite, Target: ScopeOf("f"), Mode: ModeDirect, Certainty: CertaintyCertain, NetFlow: FlowIngest}
	untagged := Effect{Kind: KindFSWrite, Target: ScopeOf("g"), Mode: ModeDirect, Certainty: CertaintyCertain}
	for _, pair := range [][2]Effect{{tagged, untagged}, {untagged, tagged}} {
		j, ok := pair[0].Join(pair[1])
		if !ok {
			t.Fatalf("join of same-kind/mode effects failed")
		}
		if j.NetFlow != FlowIngest {
			t.Errorf("join dropped netFlow: %q", string(j.NetFlow))
		}
	}
}

func TestEffectValidateNetFlowKind(t *testing.T) {
	cases := []struct {
		name string
		e    Effect
	}{
		{"cradle on FSWrite", Effect{Kind: KindFSWrite, Target: ScopeOf("f"), Mode: ModeDirect, Certainty: CertaintyCertain, NetFlow: FlowCradle}},
		{"ingest on CodeExec", Effect{Kind: KindCodeExec, Target: ScopeTop(), Mode: ModeDirect, Certainty: CertaintyCertain, NetFlow: FlowIngest}},
		{"unknown role", Effect{Kind: KindFSWrite, Target: ScopeOf("f"), Mode: ModeDirect, Certainty: CertaintyCertain, NetFlow: FlowRole("bogus")}},
	}
	for _, tc := range cases {
		if err := tc.e.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want an error", tc.name)
		}
	}
}

func netEffect(target string) Effect {
	return Effect{Kind: KindNetEgress, Target: ScopeOf(target), Mode: ModeDirect, Certainty: CertaintyCertain, Reversible: true}
}

func cradleSink() Effect {
	return Effect{Kind: KindCodeExec, Target: ScopeTop(), Mode: ModeDirect, Certainty: CertaintyCertain, NetFlow: FlowCradle}
}

func ingestSink(target string) Effect {
	return Effect{Kind: KindFSWrite, Target: ScopeOf(target), Mode: ModeDirect, Certainty: CertaintyCertain, NetFlow: FlowIngest}
}

// TestDetectFlows pins the flow-vs-co-occurrence contract: a flow is reported
// only where the analysis established that network content reached the sink
// (the effect carries the matching FlowRole), never merely because a NetEgress
// and a sink appear in the same program.
func TestDetectFlows(t *testing.T) {
	ne := netEffect("https://evil.example/x")
	untaggedCode := Effect{Kind: KindCodeExec, Target: ScopeTop(), Mode: ModeDirect, Certainty: CertaintyCertain}
	untaggedWrite := Effect{Kind: KindFSWrite, Target: ScopeOf("d"), Mode: ModeDirect, Certainty: CertaintyCertain}

	cases := []struct {
		name       string
		effects    []Effect
		wantCradle int
		wantIngest int
	}{
		{"cradle", []Effect{ne, cradleSink()}, 1, 0},
		{"ingest", []Effect{ne, ingestSink("f")}, 0, 1},
		{"both", []Effect{ne, cradleSink(), ingestSink("f")}, 1, 1},
		{"egress alone", []Effect{ne}, 0, 0},
		{"cradle sink alone", []Effect{cradleSink()}, 0, 0},
		{"ingest sink alone", []Effect{ingestSink("f")}, 0, 0},
		{"untagged code exec", []Effect{ne, untaggedCode}, 0, 0},
		{"untagged fs write", []Effect{ne, untaggedWrite}, 0, 0},
		{"unrelated code exec and write", []Effect{ne, untaggedCode, untaggedWrite}, 0, 0},
	}
	for _, tc := range cases {
		if got := len(DetectCradleFlows(tc.effects)); got != tc.wantCradle {
			t.Errorf("%s: DetectCradleFlows = %d, want %d", tc.name, got, tc.wantCradle)
		}
		if got := len(DetectIngestFlows(tc.effects)); got != tc.wantIngest {
			t.Errorf("%s: DetectIngestFlows = %d, want %d", tc.name, got, tc.wantIngest)
		}
	}
}

// TestDetectFlowsDeterministic pins the canonical order of the pairings.
func TestDetectFlowsDeterministic(t *testing.T) {
	effects := []Effect{
		netEffect("https://b.example/x"),
		netEffect("https://a.example/x"),
		cradleSink(),
	}
	flows := DetectCradleFlows(effects)
	if len(flows) != 2 {
		t.Fatalf("got %d cradle flows, want 2", len(flows))
	}
	keys := []string{flows[0].Source.Key(), flows[1].Source.Key()}
	if keys[0] > keys[1] {
		t.Errorf("cradle flows not in canonical source order: %v", keys)
	}
	if !IsCradleSink(flows[0].Sink) {
		t.Errorf("cradle flow sink is not a cradle sink: %+v", flows[0].Sink)
	}
}

// TestScoreCarriesFlows pins that the composite score surfaces the flows (the
// report's score.cradleFlows / score.ingestFlows).
func TestScoreCarriesFlows(t *testing.T) {
	sc := ScoreEffects([]Effect{netEffect("https://evil.example/x"), cradleSink(), ingestSink("f")})
	if len(sc.CradleFlows) != 1 {
		t.Errorf("Score.CradleFlows = %d, want 1", len(sc.CradleFlows))
	}
	if len(sc.IngestFlows) != 1 {
		t.Errorf("Score.IngestFlows = %d, want 1", len(sc.IngestFlows))
	}
	enc, err := sc.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, key := range []string{`"cradleFlows"`, `"ingestFlows"`, `"sink"`, `"source"`} {
		if !strings.Contains(string(enc), key) {
			t.Errorf("score JSON missing %s:\n%s", key, enc)
		}
	}
	// A flowless score omits both fields.
	empty, err := ScoreEffects([]Effect{netEffect("https://evil.example/x")}).Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, key := range []string{"cradleFlows", "ingestFlows"} {
		if strings.Contains(string(empty), key) {
			t.Errorf("flowless score serialised %s:\n%s", key, empty)
		}
	}
}
