package bash

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// AC 1: a valid command lowers to an AST; an invalid one yields ⊤ with a reason
// and never panics.
// ---------------------------------------------------------------------------

func TestParseValidCommand(t *testing.T) {
	p := Parse(Bash, "t.sh", `ls -la /tmp`)
	if p.Top {
		t.Fatalf("valid command reported as top: %s", p.Reason)
	}
	if p.Variant != Bash {
		t.Fatalf("variant: got %q want %q", p.Variant, Bash)
	}
	if len(p.Stmts) != 1 {
		t.Fatalf("stmts: got %d want 1", len(p.Stmts))
	}
	s := p.Stmts[0]
	if s.Kind != KindSimple || s.Cmd == nil {
		t.Fatalf("stmt: got kind %q cmd %v", s.Kind, s.Cmd)
	}
	if s.Cmd.Name != "ls" {
		t.Errorf("name: got %q want %q", s.Cmd.Name, "ls")
	}
	if want := (Pos{Line: 1, Col: 1, Offset: 0}); s.Cmd.Pos != want {
		t.Errorf("cmd pos: got %+v want %+v", s.Cmd.Pos, want)
	}
	if len(s.Cmd.Args) != 2 {
		t.Fatalf("args: got %d want 2", len(s.Cmd.Args))
	}
	if s.Cmd.Args[0].Value != "-la" || s.Cmd.Args[0].Pos.Col != 4 {
		t.Errorf("arg0: got %+v", s.Cmd.Args[0])
	}
	if s.Cmd.Args[1].Value != "/tmp" || s.Cmd.Args[1].Pos.Col != 8 {
		t.Errorf("arg1: got %+v", s.Cmd.Args[1])
	}
}

func TestParseEmptyAndComment(t *testing.T) {
	for _, src := range []string{"", "   \n\t\n", "# just a comment\n", "#!/bin/bash\n"} {
		p := Parse(Bash, "t", src)
		if p.Top {
			t.Errorf("%q: unexpectedly top: %s", src, p.Reason)
			continue
		}
		if len(p.Stmts) != 0 {
			t.Errorf("%q: got %d stmts want 0", src, len(p.Stmts))
		}
	}
}

func TestParseInvalidYieldsTop(t *testing.T) {
	cases := []string{
		`echo "abc`,     // unterminated double quote
		`echo 'abc`,     // unterminated single quote
		`if true; then`, // incomplete if
		`for`,           // for without a name
		`while`,         // while without a body
		`case x in`,     // case without esac
		`(`,             // unmatched (
		`$(`,            // unmatched $(
		`echo $((1+`,    // truncated arithmetic
		`;;`,            // stray case separator
		`&&`,            // dangling and
		`|`,             // dangling pipe
		`function`,      // function without a name
		`{`,             // unmatched {
		`}`,             // stray }
		`[[`,            // empty test clause
		`esac`,          // stray esac
		`done`,          // stray done
		`fi`,            // stray fi
		`x()`,           // function decl without a body
		`((`,            // arithmetic without an expression
		`<<`,            // heredoc without a word
		`cmd ||`,        // dangling or
		`echo >`,        // redirect without a target
	}
	for _, src := range cases {
		p := Parse(Bash, "t", src)
		if !p.Top {
			t.Errorf("%q: expected top, got a parse", src)
			continue
		}
		if p.Reason == "" {
			t.Errorf("%q: top without a reason", src)
		}
		if len(p.Stmts) != 0 {
			t.Errorf("%q: top carries %d stmts", src, len(p.Stmts))
		}
		if p.ErrPos == nil {
			t.Errorf("%q: top without a position", src)
		}
	}
}

// TestParseNeverPanics feeds deliberately hostile input through Parse and
// asserts that it always returns a well-formed verdict instead of crashing.
func TestParseNeverPanics(t *testing.T) {
	inputs := []string{
		"", "\x00", "\x00\xff\xfe", "echo \x00",
		strings.Repeat("(", 5000),
		strings.Repeat("${", 5000),
		strings.Repeat(`"`, 1001),
		strings.Repeat("a|", 10000),
		"$(($(($(($((1)))))))",
		"cat <(ls |",
		"'\xff\xfebutf8'",
		"$'\\x'",
		"a=b=c=d",
		"!!!",
		"[[[[[[",
		"}}}}}}",
	}
	for _, src := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse(%q) panicked: %v", src, r)
				}
			}()
			p := Parse(Bash, "t", src)
			if p == nil {
				t.Fatalf("Parse(%q) returned nil", src)
			}
			if p.Top && p.Reason == "" {
				t.Errorf("Parse(%q): top without a reason", src)
			}
			if !p.Top && p.Validate() != nil {
				t.Errorf("Parse(%q): non-top program failed validation: %v", src, p.Validate())
			}
		}()
	}
}

func TestParseUnknownVariant(t *testing.T) {
	p := Parse(Variant("fish"), "t", "echo hi")
	if !p.Top {
		t.Fatalf("unknown variant should be top")
	}
	if !strings.Contains(p.Reason, "unknown shell variant") {
		t.Errorf("reason: got %q", p.Reason)
	}
	if p.Variant != Variant("fish") {
		t.Errorf("variant preserved: got %q", p.Variant)
	}
}

// ---------------------------------------------------------------------------
// AC 2: LangBash and LangPOSIX are distinguishable.
// ---------------------------------------------------------------------------

func TestParseVariantsDistinguishable(t *testing.T) {
	// Constructs that are bash-only: Bash parses them, POSIX rejects them.
	bashOnly := []string{
		`echo ${x//a/b}`,
		`cat <(ls)`,
		`cat <<<word`,
		`a=(1 2 3)`,
		`function f { :; }`,
		`echo &>/dev/null`,
		`echo ${x^^}`,
		`echo ${!x}`,
	}
	for _, src := range bashOnly {
		b := Parse(Bash, "t", src)
		if b.Top {
			t.Errorf("%q: bash should parse it, got top: %s", src, b.Reason)
		}
		if b.Variant != Bash {
			t.Errorf("%q: variant got %q want bash", src, b.Variant)
		}
		p := Parse(POSIX, "t", src)
		if !p.Top {
			t.Errorf("%q: posix should reject it, but it parsed", src)
		}
		if p.Reason == "" {
			t.Errorf("%q: posix top without a reason", src)
		}
		if p.Variant != POSIX {
			t.Errorf("%q: variant got %q want posix", src, p.Variant)
		}
	}

	// Constructs valid in both dialects parse in both.
	both := []string{
		`echo hi`,
		`f() { :; }`,
		`for i in 1 2; do echo $i; done`,
		`case $x in a) :;; esac`,
		`echo "${x:-def}"`,
		`echo ${#x}`,
		`printf '%s\n' "$1"`,
	}
	for _, src := range both {
		for _, v := range []Variant{Bash, POSIX} {
			if p := Parse(v, "t", src); p.Top {
				t.Errorf("%q (%s): unexpectedly top: %s", src, v, p.Reason)
			}
		}
	}
}

func TestVariantNames(t *testing.T) {
	if Bash.String() != "bash" || !Bash.Valid() {
		t.Errorf("bash: %q valid=%v", Bash.String(), Bash.Valid())
	}
	if POSIX.String() != "posix" || !POSIX.Valid() {
		t.Errorf("posix: %q valid=%v", POSIX.String(), POSIX.Valid())
	}
	if Variant("").Valid() || Variant("nushell").Valid() {
		t.Errorf("unexpectedly valid variant")
	}
}

func TestPosRendering(t *testing.T) {
	if !(Pos{}).IsZero() {
		t.Errorf("zero pos reported non-zero")
	}
	if got := (Pos{}).String(); got != "-" {
		t.Errorf("zero pos string: got %q want -", got)
	}
	if got := (Pos{Line: 3, Col: 7}).String(); got != "3:7" {
		t.Errorf("pos string: got %q want 3:7", got)
	}
}
