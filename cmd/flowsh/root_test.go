package main

import (
	"strings"
	"testing"

	"github.com/v0lka/flowsh/api"
)

// TestRootDistinctPerInputSource is the acceptance criterion that the report
// names its source distinctly for stdin and argument input. The analyser has no
// file input: the CLI surface is the argument and stdin only (Finding 1).
func TestRootDistinctPerInputSource(t *testing.T) {
	// Argument input.
	code, out, errStr := exec(t, []string{"--json", "ls -la"}, "")
	if code != 0 {
		t.Fatalf("argument: exit %d, stderr=%s", code, errStr)
	}
	if got := decodeJSON(t, out).Root; got != api.RootArgument {
		t.Errorf("argument root = %q, want %q", got, api.RootArgument)
	}

	// stdin input (no positional argument).
	code, out, errStr = exec(t, []string{"--json"}, "ls -la\n")
	if code != 0 {
		t.Fatalf("stdin: exit %d, stderr=%s", code, errStr)
	}
	if got := decodeJSON(t, out).Root; got != api.RootStdin {
		t.Errorf("stdin root = %q, want %q", got, api.RootStdin)
	}

	// stdin via the "-" positional.
	code, out, errStr = exec(t, []string{"--json", "-"}, "ls -la\n")
	if code != 0 {
		t.Fatalf("dash: exit %d, stderr=%s", code, errStr)
	}
	if got := decodeJSON(t, out).Root; got != api.RootStdin {
		t.Errorf("dash root = %q, want %q", got, api.RootStdin)
	}
}

// TestExplainPositions checks that a why-step carries a source position and
// that --explain renders it, for the stdin and argument sources.
func TestExplainPositions(t *testing.T) {
	code, out, errStr := exec(t, []string{"--json", "rm -rf /tmp/x"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errStr)
	}
	rep := decodeJSON(t, out)
	located := false
	for _, w := range rep.Why {
		for _, s := range w.Because {
			if s.Loc == nil {
				continue
			}
			located = true
		}
	}
	if !located {
		t.Fatal("no why step carries a source location")
	}

	// The human --explain view renders the position as @line:col.
	code, out, errStr = exec(t, []string{"rm -rf /tmp/x", "--explain"}, "")
	if code != 0 {
		t.Fatalf("explain: exit %d, stderr=%s", code, errStr)
	}
	if !strings.Contains(out, "@1:") {
		t.Errorf("--explain output does not render a position:\n%s", out)
	}
}
