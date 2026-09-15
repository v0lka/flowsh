package analysis

import "testing"

// TestParseLangPOSIX pins the facade language mapping for the POSIX/sh variant:
// both "posix" and its alias "sh" resolve to LangPOSIX, case-insensitively and
// trimmed, while an unknown name is rejected. This is the mapping the CLI's
// --lang value flows through.
func TestParseLangPOSIX(t *testing.T) {
	for _, in := range []string{"posix", "POSIX", "sh", "  sh  "} {
		got, err := ParseLang(in)
		if err != nil {
			t.Fatalf("ParseLang(%q): %v", in, err)
		}
		if got != LangPOSIX {
			t.Errorf("ParseLang(%q) = %q, want %q", in, got, LangPOSIX)
		}
	}
	if _, err := ParseLang("fish"); err == nil {
		t.Errorf("ParseLang(\"fish\") returned no error, want one")
	}
}

// TestAnalyzePOSIXVariant is the A6 acceptance at the facade: --lang posix
// analyses the source in the POSIX (sh) variant, so a bash-only construct is
// not recognised as its bash special form. Under bash `[[ 1 == 1 ]]` is the
// [[ ]] test clause and contributes no effect; under POSIX `[[` is not a
// reserved word, so the same text is an ordinary (unknown) command that
// degrades to the top effect ⊤. That distinguishability is exactly why the
// dialect split exists, and it must hold through the facade, not just in the
// parser.
func TestAnalyzePOSIXVariant(t *testing.T) {
	a := mustAnalyzer(t)

	const src = `[[ 1 == 1 ]]`

	bash := a.Analyze(LangBash, src)
	if bash.Lang != string(LangBash) {
		t.Errorf("bash: report lang = %q, want %q", bash.Lang, LangBash)
	}
	if len(bash.Effects) != 0 || bash.Top || bash.Conservative || bash.HasTop() {
		t.Errorf("bash: [[ ]] is a test clause and must yield no effect "+
			"(effects=%v top=%v conservative=%v)", bash.Effects, bash.Top, bash.Conservative)
	}

	posix := a.Analyze(LangPOSIX, src)
	if posix.Lang != string(LangPOSIX) {
		t.Errorf("posix: report lang = %q, want %q", posix.Lang, LangPOSIX)
	}
	if !posix.HasTop() {
		t.Errorf("posix: [[ is not a POSIX test construct and must degrade to the "+
			"unknown-command ⊤, got effects=%v", posix.Effects)
	}
	if !posix.Covered() {
		t.Errorf("posix: analysis must stay covered (effect or ⊤), got %+v", posix)
	}
}
