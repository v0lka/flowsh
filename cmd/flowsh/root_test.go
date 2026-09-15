package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/v0lka/flowsh/api"
)

// TestRootDistinctPerInputSource is the acceptance criterion that the report
// names its source distinctly for file, stdin and argument input.
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

	// File input: the root is the path.
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(path, []byte("rm -rf /tmp/x\n"), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	code, out, errStr = exec(t, []string{"--json", "--file", path}, "")
	if code != 0 {
		t.Fatalf("file: exit %d, stderr=%s", code, errStr)
	}
	rep := decodeJSON(t, out)
	if rep.Root != path {
		t.Errorf("file root = %q, want %q", rep.Root, path)
	}
	if rep.Lang != string(api.LangBash) {
		t.Errorf("file lang = %q, want bash", rep.Lang)
	}
	if len(rep.Effects) == 0 {
		t.Errorf("file input produced no effects")
	}
}

// TestFileInputPositions checks that a why-step for a command read from a file
// is located against that file's path, and that --explain renders the position.
func TestFileInputPositions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(path, []byte("rm -rf /tmp/x\n"), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	code, out, errStr := exec(t, []string{"--json", "--file", path}, "")
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
			if s.Loc.File != path {
				t.Errorf("why %s: loc file = %q, want %q", w.Effect, s.Loc.File, path)
			}
		}
	}
	if !located {
		t.Fatal("no why step carries a source location for the file input")
	}

	// The human --explain view renders the position as @line:col.
	_, out, errStr = exec(t, []string{"--file", path, "--explain"}, "")
	if code != 0 {
		t.Fatalf("explain: exit %d, stderr=%s", code, errStr)
	}
	if !strings.Contains(out, "@1:") {
		t.Errorf("--explain output does not render a position:\n%s", out)
	}
}

// TestFileFlagUsageErrors checks the --file flag's misuse paths: conflicting
// sources and a missing value are usage errors (2), while an unreadable file is
// an input error (3).
func TestFileFlagUsageErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(path, []byte("ls\n"), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"file and command", []string{"--file", path, "ls"}, 2},
		{"file and dash", []string{"--file", path, "-"}, 2},
		{"file needs value", []string{"--file"}, 2},
		{"missing file", []string{"--file", filepath.Join(t.TempDir(), "nope.sh")}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errStr := exec(t, tc.args, "")
			if code != tc.want {
				t.Errorf("exit = %d, want %d (stderr=%s)", code, tc.want, errStr)
			}
			if errStr == "" {
				t.Errorf("no diagnostic on stderr")
			}
		})
	}
}
