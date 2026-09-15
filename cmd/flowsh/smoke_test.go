package main

import (
	"bytes"
	"encoding/json"
	"errors"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
)

// smokeReport is the slice of the JSON report the smoke checks assert on. The
// full report is validated by the in-process tests in main_test.go; here we
// decode only the fields the process-boundary smoke run needs, through the
// same encoding/json the CLI emits.
type smokeReport struct {
	Lang        string            `json:"lang"`
	ToolVersion string            `json:"toolVersion"`
	Input       string            `json:"input"`
	Effects     []json.RawMessage `json:"effects"`
}

// buildSmokeBinary builds the flowsh binary for the host OS into dir and
// returns its path. On Windows the executable must carry the ".exe" suffix or
// the OS cannot start it.
func buildSmokeBinary(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "flowsh")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := osexec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build -o %s .: %v\n%s", bin, err, out)
	}
	return bin
}

// runSmoke runs the built binary with the given stdin and args, returning its
// stdout and exit code. A non-zero exit is not an error — the exit-code
// contract is itself under test; only a failure to start the process is fatal.
func runSmoke(t *testing.T, bin, stdin string, args ...string) (string, int) {
	t.Helper()
	cmd := osexec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		return out.String(), 0
	}
	var ee *osexec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("run %s %v: %v (stderr=%s)", bin, args, err, errBuf.String())
	}
	return out.String(), ee.ExitCode()
}

// decodeSmoke decodes a single JSON report from the binary's stdout.
func decodeSmoke(t *testing.T, out string) smokeReport {
	t.Helper()
	if !json.Valid([]byte(out)) {
		t.Fatalf("stdout is not valid JSON:\n%s", out)
	}
	var rep smokeReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout does not decode into a report: %v", err)
	}
	return rep
}

// TestSmoke builds the flowsh binary once and smoke-runs it as a subprocess,
// reproducing every CLI check that used to live in .github/workflows/ci.yml:
// bash/posh JSON, --version, stdin, --lang auto for both dialects, --batch
// NDJSON, and the exit-code contract. Unlike the in-process tests it covers the
// process boundary (argv, stdin, stdout, exit status) without depending on
// python3 or a POSIX shell, so it also runs on Windows. Skipped under -short
// because it shells out to the Go toolchain and runs the real binary.
func TestSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the flowsh binary; skipped in -short mode")
	}
	bin := buildSmokeBinary(t, t.TempDir())

	t.Run("bash JSON", func(t *testing.T) {
		out, code := runSmoke(t, bin, "", "--lang", "bash", "--json", "rm -rf $HOME")
		if code != 0 {
			t.Fatalf("exit %d, want 0", code)
		}
		rep := decodeSmoke(t, out)
		if rep.Lang != string(api.LangBash) {
			t.Errorf("lang = %q, want %q", rep.Lang, api.LangBash)
		}
		if len(rep.Effects) == 0 {
			t.Errorf("no effects for %q", rep.Input)
		}
		if rep.ToolVersion != "flowsh/v1" {
			t.Errorf("toolVersion = %q, want %q", rep.ToolVersion, "flowsh/v1")
		}
	})

	t.Run("version", func(t *testing.T) {
		out, code := runSmoke(t, bin, "", "--version")
		if code != 0 {
			t.Fatalf("exit %d, want 0", code)
		}
		// ci.yml greps the literals; assert the same literals appear.
		if !strings.Contains(out, "flowsh/v1") {
			t.Errorf("--version output missing %q:\n%s", "flowsh/v1", out)
		}
		if !strings.Contains(out, "effect-ir/v1") {
			t.Errorf("--version output missing %q:\n%s", "effect-ir/v1", out)
		}
		if !strings.Contains(out, engine.SchemaVersion) {
			t.Errorf("--version output missing the engine schema %q:\n%s", engine.SchemaVersion, out)
		}
	})

	t.Run("posh JSON", func(t *testing.T) {
		out, code := runSmoke(t, bin, "", "--lang", "posh", "--json", "Remove-Item -Recurse -Force $HOME")
		if code != 0 {
			t.Fatalf("exit %d, want 0", code)
		}
		rep := decodeSmoke(t, out)
		if rep.Lang != string(api.LangPowerShell) {
			t.Errorf("lang = %q, want %q", rep.Lang, api.LangPowerShell)
		}
		if len(rep.Effects) == 0 {
			t.Errorf("no effects for %q", rep.Input)
		}
	})

	t.Run("stdin", func(t *testing.T) {
		out, code := runSmoke(t, bin, "ls -la\n", "--lang", "bash", "--json")
		if code != 0 {
			t.Fatalf("exit %d, want 0", code)
		}
		if rep := decodeSmoke(t, out); rep.Input != "ls -la" {
			t.Errorf("input = %q, want %q", rep.Input, "ls -la")
		}
	})

	t.Run("lang auto", func(t *testing.T) {
		cases := []struct {
			input string
			want  string
		}{
			{"rm -rf $HOME", string(api.LangBash)},
			{"Remove-Item -Recurse -Force $HOME", string(api.LangPowerShell)},
		}
		for _, c := range cases {
			out, code := runSmoke(t, bin, "", "--lang", "auto", "--json", c.input)
			if code != 0 {
				t.Fatalf("--lang auto %q: exit %d, want 0", c.input, code)
			}
			if got := decodeSmoke(t, out).Lang; got != c.want {
				t.Errorf("--lang auto %q: lang = %q, want %q", c.input, got, c.want)
			}
		}
	})

	t.Run("batch NDJSON", func(t *testing.T) {
		stdin := "ls -la\nRemove-Item -Recurse -Force $HOME\n"
		out, code := runSmoke(t, bin, stdin, "--batch", "--lang", "auto")
		if code != 0 {
			t.Fatalf("exit %d, want 0", code)
		}
		var recs []smokeReport
		for _, ln := range strings.Split(out, "\n") {
			if strings.TrimSpace(ln) == "" {
				continue
			}
			recs = append(recs, decodeSmoke(t, ln))
		}
		if len(recs) != 2 {
			t.Fatalf("got %d NDJSON records, want 2:\n%s", len(recs), out)
		}
		wantLangs := []string{string(api.LangBash), string(api.LangPowerShell)}
		for i, rec := range recs {
			if rec.Lang != wantLangs[i] {
				t.Errorf("record %d lang = %q, want %q", i, rec.Lang, wantLangs[i])
			}
			if len(rec.Effects) == 0 {
				t.Errorf("record %d: no effects", i)
			}
		}
	})

	t.Run("exit codes", func(t *testing.T) {
		if _, code := runSmoke(t, bin, "", "--json"); code != 3 {
			t.Errorf("empty input: exit = %d, want 3", code)
		}
		if _, code := runSmoke(t, bin, "", "--wat", "ls"); code != 2 {
			t.Errorf("unknown flag: exit = %d, want 2", code)
		}
	})
}
