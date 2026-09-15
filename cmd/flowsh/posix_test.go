package main

import (
	"testing"

	"github.com/v0lka/flowsh/api"
)

// TestRunPosixDialect is the CLI half of the A6 acceptance: `flowsh --lang
// posix '…'` (and its alias `sh`) analyses the input in the POSIX variant, so
// the bash-only `[[ … ]]` test construct is not recognised. In bash the same
// input is a test clause and yields no effect; in POSIX the unknown command
// degrades to ⊤ — the report says so and stays covered.
func TestRunPosixDialect(t *testing.T) {
	for _, lang := range []string{"posix", "sh"} {
		t.Run(lang, func(t *testing.T) {
			code, out, errStr := exec(t, []string{"--lang", lang, "--json", "[[ 1 == 1 ]]"}, "")
			if code != 0 {
				t.Fatalf("exit %d, stderr=%s", code, errStr)
			}
			rep := decodeJSON(t, out)
			if rep.Lang != string(api.LangPOSIX) {
				t.Errorf("lang = %q, want %q", rep.Lang, api.LangPOSIX)
			}
			if !rep.HasTop() {
				t.Errorf("posix: want the unknown-command ⊤ for [[ ]], got effects=%v", rep.Effects)
			}
			if !rep.Covered() {
				t.Errorf("posix: report must stay covered (effect or ⊤): %+v", rep)
			}
		})
	}

	code, out, errStr := exec(t, []string{"--lang", "bash", "--json", "[[ 1 == 1 ]]"}, "")
	if code != 0 {
		t.Fatalf("bash: exit %d, stderr=%s", code, errStr)
	}
	if rep := decodeJSON(t, out); len(rep.Effects) != 0 || rep.HasTop() {
		t.Errorf("bash: [[ ]] is a test clause and must yield no effect, got effects=%v", rep.Effects)
	}
}
