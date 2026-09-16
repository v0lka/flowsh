package bash

import "testing"

// TestGlobMatch pins the case-arm pattern matcher against bash's semantics for
// the constructs the code-review regressions covered: a literal leading ']'
// inside a class, backslash escaping, ranges, negation and the POSIX character
// classes.
func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		// literals, '?' and '*'
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"a?c", "abc", true},
		{"a*", "abc", true},
		{"*", "", true},
		{"a*b", "ab", true},
		{"a*b", "axxxb", true},
		{"a*b", "axxxc", false},
		{"/etc/*", "/etc/sub/dir", true},

		// a leading ']' immediately after '[' (or after the negation) is a
		// literal class member
		{"[]abc]", "]", true},
		{"[]abc]", "a", true},
		{"[]abc]", "d", false},
		{"[]]", "]", true},

		// negation, including the literal ']' member
		{"[!]abc]", "]", false},
		{"[!]abc]", "a", false},
		{"[!]abc]", "z", true},
		{"[^abc]", "d", true},
		{"[^abc]", "a", false},

		// ranges
		{"[a-z]", "m", true},
		{"[a-z]", "M", false},
		{"[a-]", "-", true},
		{"[a-]", "a", true},
		{"[!a-z]", "M", true},

		// backslash escaping makes the next character literal
		{`a\*`, "a*", true},
		{`a\*`, "abc", false},
		{`\*`, "*", true},
		{`\?`, "?", true},
		{`a\[b`, "a[b", true},
		{`\\`, `\`, true},
		{`\,`, ",", true},

		// POSIX character classes
		{"[[:alpha:]]", "m", true},
		{"[[:alpha:]]", "5", false},
		{"[[:digit:]]", "5", true},
		{"[[:digit:]]", "m", false},
		{"[[:alnum:]]", "Z", true},
		{"[[:alnum:]]", "!", false},
		{"[[:xdigit:]]", "f", true},
		{"[[:xdigit:]]", "g", false},
		{"[[:space:]]", " ", true},
		{"[[:space:]]", "x", false},
		{"[[:blank:]]", "\t", true},
		{"[[:upper:]]", "A", true},
		{"[[:upper:]]", "a", false},
		{"[[:lower:]]", "a", true},
		{"[[:punct:]]", ";", true},
		{"[[:punct:]]", "a", false},
		{"[[:alpha:]]*", "abc", true},
		{"[![:digit:]]", "a", true},
		{"[![:digit:]]", "7", false},
		{"a[[:digit:]]c", "a7c", true},

		// an unterminated '[' is a literal '['
		{"[abc", "[abc", true},
		{"a[b", "a[b", true},
	}
	for _, tc := range cases {
		got, ok := globMatch(tc.pat, tc.name)
		if !ok {
			t.Errorf("globMatch(%q, %q): unexpectedly undecidable", tc.pat, tc.name)
			continue
		}
		if got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pat, tc.name, got, tc.want)
		}
	}
}

// TestGlobMatchUndecidable pins the soundness backstop: a pattern built from a
// construct the matcher cannot faithfully evaluate must report ok=false, so the
// caller runs the arm and marks ⊤ rather than silently dropping it.
func TestGlobMatchUndecidable(t *testing.T) {
	for _, pat := range []string{
		"[[:foo:]]", // unknown POSIX class name
		"@(a|b)",    // extglob
		"*(x)",      // extglob
		"+(x)",      // extglob
		"?(x)",      // extglob
		"!(x)",      // extglob
		"[[=a=]]",   // equivalence class
		"[[.a.]]",   // collating symbol
	} {
		if _, ok := globMatch(pat, "a"); ok {
			t.Errorf("globMatch(%q): want undecidable (ok=false)", pat)
		}
	}

	// A POSIX class tested against a non-ASCII subject is locale-dependent.
	if _, ok := globMatch("[[:alpha:]]", "é"); ok {
		t.Errorf("globMatch([[:alpha:]], é): want undecidable for a non-ASCII subject")
	}
}

// TestBraceExpansionOverflow pins the bounded-execution guard: an estimate that
// cannot be computed (or that exceeds the field cap) must be reported as a
// possible overflow, so the word degrades to ⊤ instead of being materialised
// unbounded (ADR-0006).
func TestBraceExpansionOverflow(t *testing.T) {
	cases := []struct {
		word string
		want bool
	}{
		{"", false},
		{"plain", false},
		{"{}", false},
		{"{a,b}", false},
		{"{1..3}", false},
		{"{a,b}{c,d}", false},
		{"x{y,z}w", false},
		{"{1..3}{1..3}{1..3}{1..3}{1..3}{1..3}{1..3}", false}, // 3^7 = 2187 ≤ 4096
		{"{1..10}{1..10}{1..10}{1..10}", true},                // 10^4 = 10000 > 4096
		{"{1..2000000}", true},
		{"{1..100000000}", true},
	}
	for _, tc := range cases {
		if got := braceExpansionOverflow(tc.word); got != tc.want {
			t.Errorf("braceExpansionOverflow(%q) = %v, want %v", tc.word, got, tc.want)
		}
	}
}

// TestBraceExpansionOverflowDeepNesting pins that nesting deeper than the
// estimator's cap is treated as a POSSIBLE overflow (the estimate is
// uncomputable), so a short crafted input degrades to ⊤ rather than being
// materialised unbounded.
func TestBraceExpansionOverflowDeepNesting(t *testing.T) {
	word := ""
	for i := 0; i < 25; i++ {
		word += "{a"
	}
	word += "{1..2000000}"
	for i := 0; i < 25; i++ {
		word += "}"
	}
	if !braceExpansionOverflow(word) {
		t.Errorf("deeply nested brace input must be a possible overflow, got false")
	}
}
