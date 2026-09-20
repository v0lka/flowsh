package ps

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// evalOf evaluates one word text against a state seeded by seed, where seed
// maps variable names to literal values.
func evalOf(t *testing.T, text string, seed map[string]string) evaluatedWord {
	t.Helper()
	st := NewState()
	for n, v := range seed {
		st.Set(n, v, engine.TaintBottom())
	}
	return evalWordText(&Word{Text: text}, st)
}

func TestEvalSingleQuotedLiteral(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"'$dir/file.txt'", "$dir/file.txt"}, // no interpolation in single quotes
		{"'it''s'", "it's"},
		{"'back`tick'", "back`tick"}, // no backtick escapes either
	} {
		got := evalOf(t, tc.text, map[string]string{"dir": "/tmp"})
		if !got.Known || got.Text != tc.want {
			t.Errorf("eval(%q) = (%q, known=%v), want (%q, true)", tc.text, got.Text, got.Known, tc.want)
		}
	}
}

func TestEvalKnownInterpolation(t *testing.T) {
	seed := map[string]string{"dir": "/tmp/target"}
	for _, tc := range []struct{ text, want string }{
		{"$dir", "/tmp/target"},
		{"${dir}", "/tmp/target"},
		{"$dir/file.txt", "/tmp/target/file.txt"},
		{"pre-$dir-post", "pre-/tmp/target-post"},
		{"\"$dir/log\"", "/tmp/target/log"},
		{"$global:dir", "/tmp/target"}, // scope prefix flattens to the variable
		{"${global:dir}", "/tmp/target"},
		{"$variable:dir", "/tmp/target"},
	} {
		got := evalOf(t, tc.text, seed)
		if !got.Known || got.Text != tc.want {
			t.Errorf("eval(%q) = (%q, known=%v), want (%q, true)", tc.text, got.Text, got.Known, tc.want)
		}
	}
}

func TestEvalUnknownVariableDegrades(t *testing.T) {
	seed := map[string]string{"known": "k"}
	for _, text := range []string{
		"$missing", // never assigned
		"$args",    // automatic: set-but-unknown
		"$known/$missing/x",
		"$known$missing",
	} {
		got := evalOf(t, text, seed)
		if got.Known {
			t.Errorf("eval(%q) claims known, want unknown", text)
		}
	}
	// A taint-carrying known part must still flow into an unknown word.
	st := NewState()
	st.Set("known", "k", engine.TaintOf(engine.TaintSecret))
	got := evalWordText(&Word{Text: "$known/$missing"}, st)
	if got.Known {
		t.Fatal("the word must stay unknown")
	}
	if !got.Taint.Contains(engine.TaintSecret) {
		t.Errorf("a known part's taint must join the unknown word's taint: %v", got.Taint)
	}
}

func TestEvalLiteralDollar(t *testing.T) {
	got := evalOf(t, "price is $5", nil)
	if !got.Known || got.Text != "price is $5" {
		t.Fatalf("eval = (%q, known=%v), want a literal dollar", got.Text, got.Known)
	}
}

func TestEvalEscapes(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"a`nb", "a\nb"},
		{"a`tb", "a\tb"},
		{"`$dir", "$dir"}, // escaped dollar is literal
		{"a`" + `"b`, "a\"b"},
		{"trailing`", "trailing`"}, // dangling backtick survives
	} {
		got := evalOf(t, tc.text, nil)
		if !got.Known || got.Text != tc.want {
			t.Errorf("eval(%q) = (%q, known=%v), want (%q, true)", tc.text, got.Text, got.Known, tc.want)
		}
	}
}

func TestEvalEnvReference(t *testing.T) {
	for _, text := range []string{"$env:TEMP", "${env:TEMP}", "$env:TEMP\\cache"} {
		got := evalOf(t, text, nil)
		if got.Known {
			t.Errorf("eval(%q) claims known: env values are host-controlled", text)
		}
		if !got.Taint.Contains(engine.TaintEnv) {
			t.Errorf("eval(%q) taint = %v, want env", text, got.Taint)
		}
		if len(got.EnvReads) == 0 || got.EnvReads[0] != "TEMP" {
			t.Errorf("eval(%q) EnvReads = %v, want [TEMP]", text, got.EnvReads)
		}
	}
}

func TestEvalScopePrefixes(t *testing.T) {
	st := NewState()
	st.Set("g", "lit", engine.TaintBottom())
	if got := evalWordText(&Word{Text: "$global:g"}, st); !got.Known {
		t.Errorf("$global:g must resolve to the variable: %+v", got)
	}
	// $using: data lives in another runspace — unknown and untrusted.
	got := evalWordText(&Word{Text: "$using:cred"}, st)
	if got.Known || !got.Taint.Contains(engine.TaintUntrusted) {
		t.Errorf("$using:cred = %+v, want unknown+untrusted", got)
	}
	// An unrecognised drive qualifier stays unknown.
	if got := evalWordText(&Word{Text: "$cert:store"}, st); got.Known {
		t.Error("$cert:store must be unknown")
	}
}

func TestEvalSubexpressionAndMember(t *testing.T) {
	st := NewState()
	st.Set("x", "lit", engine.TaintBottom())
	for _, text := range []string{
		"$(Get-Date)",
		"pre$(1+2)post",
		"$x.Length",
		"$x[0]",
		"$$", // last history line
		"${ 1 + 2 }",
	} {
		if got := evalWordText(&Word{Text: text}, st); got.Known {
			t.Errorf("eval(%q) claims known, want unknown", text)
		}
	}
	if got := evalWordText(&Word{Text: "$(Get-Content /etc/passwd)"}, st); !got.Taint.Contains(engine.TaintUntrusted) {
		t.Error("a subexpression must mark the word untrusted")
	}
}

func TestEvalBooleanConstants(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"$true", "True"},
		{"$false", "False"},
		{"$null", ""},
	} {
		got := evalOf(t, tc.text, nil)
		if !got.Known || got.Text != tc.want {
			t.Errorf("eval(%q) = (%q, known=%v), want (%q, true)", tc.text, got.Text, got.Known, tc.want)
		}
	}
}

func TestEvalSplat(t *testing.T) {
	got := evalWordText(&Word{Text: "@params", Splat: true, VarName: "params"}, NewState())
	if got.Known || !got.Taint.Contains(engine.TaintUntrusted) {
		t.Fatalf("splatting must be unknown+untrusted: %+v", got)
	}
}

func TestEvalTaintPropagation(t *testing.T) {
	st := NewState()
	st.Set("line", "s3cret", engine.TaintOf(engine.TaintSecret))
	got := evalWordText(&Word{Text: "http://evil.example/$line"}, st)
	if !got.Known || got.Text != "http://evil.example/s3cret" {
		t.Fatalf("eval = (%q, known=%v), want the interpolated URL", got.Text, got.Known)
	}
	if !got.Taint.Contains(engine.TaintSecret) {
		t.Errorf("the interpolated word must carry the variable's secret taint: %v", got.Taint)
	}
}
