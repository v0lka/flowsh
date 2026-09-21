package ps

import (
	"strconv"
	"strings"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// Word evaluation against Σ
// ===========================================================================
//
// A word is evaluated by splitting it into parts — literal runs, variable
// references, environment references, sub-expressions — and combining the
// parts: the word is statically known only when every part is, and its taint
// is the join of its parts' taints. This mirrors the bash frontend's partwise
// expansion knownness (front/bash/expand.go, partKnown).
//
// Soundness rules (degrade-to-⊤, ADR-0003):
//   - a variable that is not set on every path, or whose value is not statically
//     determined, makes the word unknown (its target degrades to ⊤);
//   - an environment reference makes the word unknown (the value is
//     host-controlled; the reference is reported so the lowerer can emit an
//     EnvRead effect — the analysis itself never reads the environment);
//   - a sub-expression $(…) makes the word unknown and untrusted;
//   - member/index access ($x.Length, $a[0]) and splatting (@p) make the word
//     unknown.
//
// PowerShell expands variables in double-quoted strings AND in bare
// (unquoted) arguments, so both go through the same interpolation scanner;
// single-quoted strings are fully literal.

// segKind classifies one part of an interpolated word.
type segKind int

const (
	segLiteral segKind = iota // text is a literal run
	segVar                    // text is the variable name (state key form)
	segEnv                    // text is the environment variable name
	segUnknown                // a part whose value cannot be known
)

// segment is one part of an interpolated word.
type segment struct {
	kind  segKind
	text  string
	taint engine.Taint // provenance contributed by unknown parts
}

// evaluatedWord is the result of evaluating one word against Σ.
type evaluatedWord struct {
	// Text is the concrete value when Known holds (and a best-effort
	// spelling otherwise — callers must ignore it when Known is false).
	Text string
	// Known reports whether the word's value is statically determined.
	Known bool
	// Taint is the joined provenance of the word's parts.
	Taint engine.Taint
	// EnvReads lists the environment variables the word references; the
	// lowerer reports each as an EnvRead effect.
	EnvReads []string
}

// evalWordText evaluates one word's text against the abstract state.
func evalWordText(w *Word, st *State) evaluatedWord {
	if w == nil {
		return evaluatedWord{}
	}
	text := w.Text
	switch {
	case w.Splat:
		// Splatting (@p, @{p}) hides the parameter set; only a statically
		// known hashtable refines this (a later milestone).
		return evaluatedWord{Taint: engine.TaintOf(engine.TaintUntrusted)}
	case strings.HasPrefix(text, "'"), strings.HasPrefix(text, "\""):
		// A word is a quoted literal only when the *whole* word is one balanced
		// quoted string. A word that merely starts with a quote is a
		// concatenation or an operator expression ('x' + $y, 'a.txt','b.txt'):
		// its value is not the text between the first pair of quotes, so it must
		// not be bound as one (ADR-0003/ADR-0014: never fabricate a literal).
		if inner, ok := wholeQuoted(text); ok {
			if text[0] == '\'' {
				// A single-quoted string is fully literal: only '' escapes a
				// quote.
				return evaluatedWord{Text: strings.ReplaceAll(inner, "''", "'"), Known: true}
			}
			return interpolate(inner, st, false)
		}
		return evaluatedWord{Taint: engine.TaintOf(engine.TaintUntrusted)}
	default:
		// A bare argument expands variables and honours backtick escapes,
		// exactly like a double-quoted string — but an unquoted parenthesis
		// starts a sub-expression that executes at run time: its result is
		// never statically known (its inner commands still lower separately).
		if hasUnquotedParen(text) {
			return evaluatedWord{Taint: engine.TaintOf(engine.TaintUntrusted)}
		}
		return interpolate(text, st, true)
	}
}

// wholeQuoted reports whether s is one balanced quoted string literal with
// nothing following the closing quote, and returns the text it encloses. A
// single-quoted string escapes a quote by doubling it; a double-quoted string
// escapes it with a backtick. `'a.txt','b.txt'` is not one literal (the first
// pair of quotes closes before the end of the word), and neither is `'x' + $y`.
func wholeQuoted(s string) (inner string, ok bool) {
	if len(s) < 2 {
		return "", false
	}
	q := s[0]
	if q != '\'' && q != '"' {
		return "", false
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '`':
			if q == '"' {
				i++ // a backtick escape inside a double-quoted string
			}
		case q:
			if q == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				i++ // '' escapes a single quote
				continue
			}
			if i != len(s)-1 {
				return "", false // something follows the closing quote
			}
			return s[1:i], true
		}
	}
	return "", false
}

// hasUnquotedParen reports whether s contains a `(` outside any quoted
// section — the mark of a sub-expression in argument mode.
func hasUnquotedParen(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"':
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '`' {
					i++
				}
				i++
			}
		case '`':
			i++
		case '(':
			return true
		}
	}
	return false
}

// interpolate scans s into parts and folds them into one word value. bare
// reports argument mode: only there does a `.`/`[`/`(` directly after a
// variable name mean member/index access; inside a quoted string such
// punctuation is literal text ("$h.example" interpolates $h and then ".example").
func interpolate(s string, st *State, bare bool) evaluatedWord {
	out := evaluatedWord{Known: true}
	for _, seg := range splitInterpolated(s, bare) {
		switch seg.kind {
		case segLiteral:
			out.Text += seg.text
		case segVar:
			// The boolean/null constants are language literals spelled as
			// variables; PowerShell stringifies them as True/False/empty.
			switch seg.text {
			case "true":
				out.Text += "True"
				continue
			case "false":
				out.Text += "False"
				continue
			case "null":
				continue
			}
			v := st.Get(seg.text)
			switch {
			case v != nil && v.Set && v.Known:
				out.Text += v.Value
				out.Taint = out.Taint.Join(v.Taint)
			default:
				// Unset or set-but-unknown: the word's value is not
				// determined by the script text → unknown (⊤ target).
				t := engine.TaintBottom()
				if v != nil {
					t = v.Taint
				}
				out.Taint = out.Taint.Join(t)
				out.Known = false
			}
		case segEnv:
			// A value the script itself wrote ($env:X = 'lit') resolves through
			// Σ; anything else is host-controlled: unknown + an EnvRead the
			// lowerer reports.
			if v := st.Get("env:" + seg.text); v != nil && v.Set && v.Known {
				out.Text += v.Value
				out.Taint = out.Taint.Join(v.Taint)
			} else {
				out.EnvReads = append(out.EnvReads, seg.text)
				out.Taint = out.Taint.Join(engine.TaintOf(engine.TaintEnv))
				out.Known = false
			}
		case segUnknown:
			out.Taint = out.Taint.Join(seg.taint)
			out.Known = false
		}
	}
	return out
}

// scopeQualifiers are the variable scope prefixes the analysis recognises and
// flattens into the single session scope.
var scopeQualifiers = map[string]bool{
	"global": true, "script": true, "local": true, "private": true,
}

// splitInterpolated scans s into literal, variable, environment and unknown
// segments. A `$` that is not followed by a name or `{` is a literal dollar
// (`price is $5`), as in PowerShell.
func splitInterpolated(s string, bare bool) []segment {
	var segs []segment
	lit := 0 // start of the current literal run
	i := 0
	emitLit := func(end int) {
		if end > lit {
			segs = append(segs, segment{kind: segLiteral, text: s[lit:end]})
		}
	}
	for i < len(s) {
		c := s[i]
		switch c {
		case '`':
			// A backtick escapes the next character.
			emitLit(i)
			if i+1 < len(s) {
				segs = append(segs, segment{kind: segLiteral, text: unescape(s[i+1])})
				i += 2
			} else {
				segs = append(segs, segment{kind: segLiteral, text: "`"})
				i++
			}
			lit = i
		case '$':
			seg, width := scanDollar(s[i:], bare)
			if width == 0 {
				// A literal dollar: not the start of a reference.
				i++
				continue
			}
			emitLit(i)
			segs = append(segs, seg)
			i += width
			lit = i
		default:
			i++
		}
	}
	emitLit(len(s))
	return segs
}

// scanDollar interprets a `$` reference at the start of s and returns the
// segment together with the number of bytes consumed. width 0 means the `$` is
// a literal character.
func scanDollar(s string, bare bool) (segment, int) {
	// s[0] == '$'
	if len(s) >= 2 && s[1] == '{' {
		if end := strings.IndexByte(s[2:], '}'); end >= 0 {
			inner := s[2 : 2+end]
			return checkMember(braceSegment(inner), s[2+end+1:], bare), 2 + end + 1
		}
		return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}, len(s)
	}
	if len(s) >= 2 && s[1] == '$' {
		// $$ (the last line of the history) is unknowable.
		return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}, 2
	}
	if len(s) >= 2 && s[1] == '(' {
		// A sub-expression $(…): executes at run time, never known here.
		if end := matchParen(s[1:]); end > 0 {
			// end is the offset of the closing ')' within s[1:], so the whole
			// reference spans 1 + end + 1 bytes: consuming only 1+end would
			// leave the ')' to be re-scanned as literal text.
			return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}, end + 2
		}
		return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}, len(s)
	}
	name, width := scanVarName(s[1:])
	if width == 0 {
		return segment{}, 0 // literal `$`
	}
	i := 1 + width
	// A scope/drive qualifier: $global:x, $env:x, $using:x, …
	if i < len(s) && s[i] == ':' && i+1 < len(s) {
		_, qwidth := scanVarName(s[i+1:])
		switch {
		case strings.EqualFold(name, "env"):
			if qwidth == 0 {
				return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}, i + 1
			}
			return segment{kind: segEnv, text: s[i+1 : i+1+qwidth]}, i + 1 + qwidth
		case strings.EqualFold(name, "using"):
			// Remoting data: defined in another run space, never known here.
			return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}, i + 1 + qwidth
		case strings.EqualFold(name, "variable"):
			if qwidth == 0 {
				return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}, i + 1
			}
			return checkMember(segment{kind: segVar, text: strings.ToLower(s[i+1 : i+1+qwidth])}, s[i+1+qwidth:], bare), i + 1 + qwidth
		case scopeQualifiers[strings.ToLower(name)]:
			if qwidth == 0 {
				return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}, i + 1
			}
			return checkMember(segment{kind: segVar, text: strings.ToLower(s[i+1 : i+1+qwidth])}, s[i+1+qwidth:], bare), i + 1 + qwidth
		default:
			// An unrecognised drive-qualified reference.
			return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}, i + 1 + qwidth
		}
	}
	return checkMember(segment{kind: segVar, text: strings.ToLower(name)}, s[i:], bare), i
}

// matchParen returns the index of the `)` matching s[0] == '(', counting
// nesting, or 0 when the parenthesis never closes.
func matchParen(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return 0
}

// scanVarName reads [A-Za-z_][A-Za-z0-9_]* at the start of s and returns the
// name and its width.
func scanVarName(s string) (string, int) {
	if s == "" || !isNameStart(s[0]) {
		return "", 0
	}
	i := 1
	for i < len(s) && isNameChar(s[i]) {
		i++
	}
	return s[:i], i
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameChar(c byte) bool { return isNameStart(c) || (c >= '0' && c <= '9') }

// checkMember marks a variable segment unknown when it is followed by member,
// index or call punctuation ($x.Length, $a[0], $f(1)): the access result is
// not statically known. Only bare argument mode treats that punctuation as an
// access; inside a quoted string it is literal text.
func checkMember(seg segment, rest string, bare bool) segment {
	if seg.kind != segVar || !bare {
		return seg
	}
	if rest != "" && (rest[0] == '.' || rest[0] == '[' || rest[0] == '(') {
		return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}
	}
	return seg
}

// braceSegment interprets the inside of ${…}: a bare name, an optional scope
// or env/variable qualifier, else an unknown (expression) reference.
func braceSegment(inner string) segment {
	if name, ok := plainVarName(inner); ok {
		return segment{kind: segVar, text: strings.ToLower(name)}
	}
	if i := strings.IndexByte(inner, ':'); i > 0 {
		qual, name := inner[:i], inner[i+1:]
		switch {
		case strings.EqualFold(qual, "env") && name != "":
			return segment{kind: segEnv, text: name}
		case strings.EqualFold(qual, "using"):
			return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}
		case strings.EqualFold(qual, "variable") && name != "":
			if n, ok := plainVarName(name); ok {
				return segment{kind: segVar, text: strings.ToLower(n)}
			}
		case scopeQualifiers[strings.ToLower(qual)] && name != "":
			if n, ok := plainVarName(name); ok {
				return segment{kind: segVar, text: strings.ToLower(n)}
			}
		}
	}
	return segment{kind: segUnknown, taint: engine.TaintOf(engine.TaintUntrusted)}
}

// plainVarName reports whether s is a plain identifier and returns it.
func plainVarName(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	name, width := scanVarName(s)
	return name, width == len(s)
}

// unescape translates one backticked character to its escape value; an
// unknown escape drops the backtick and keeps the character, as PowerShell
// does.
func unescape(c byte) string {
	switch c {
	case 'n':
		return "\n"
	case 'r':
		return "\r"
	case 't':
		return "\t"
	case '0':
		return "\x00"
	case 'a':
		return "\a"
	case 'b':
		return "\b"
	case 'f':
		return "\f"
	case 'v':
		return "\v"
	default:
		return string(c) // covers `", `$, and any unknown escape
	}
}

// ===========================================================================
// Literal expressions
// ===========================================================================

// numericLiteral parses a PowerShell numeric literal and returns its value.
// The text must be the whole literal, so an expression (`1 + 2`), a range
// (`1..3`) or a path that merely starts with a digit is not one.
func numericLiteral(s string) (float64, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, false
	}
	switch c := t[0]; {
	case c >= '0' && c <= '9', c == '-', c == '+', c == '.':
	default:
		return 0, false
	}
	v, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// maxRangeIterations bounds the exact expansion of a PowerShell range: a range
// wider than this is analysed as an unresolved iterable (one iteration with an
// unknown loop variable) rather than expanded, so a `1..100000` cannot exhaust
// the analysis budget.
const maxRangeIterations = 64

// literalRange parses the PowerShell range operator applied to two literal
// integers (`1..3`, `5..-2`) and returns its inclusive bounds. A dynamic bound
// (`1..$n`) is not a literal range, and a range wider than maxRangeIterations
// is not expanded exactly. The operator counts in either direction (`3..1`
// yields 3, 2, 1), so the span, not the signed difference, is bounded.
func literalRange(text string) (lo, hi int, ok bool) {
	t := strings.TrimSpace(text)
	i := strings.Index(t, "..")
	if i <= 0 {
		return 0, 0, false
	}
	lo, okLo := intLiteral(t[:i])
	hi, okHi := intLiteral(t[i+2:])
	if !okLo || !okHi {
		return 0, 0, false
	}
	span := hi - lo
	if span < 0 {
		span = -span
	}
	if span >= maxRangeIterations {
		return 0, 0, false
	}
	return lo, hi, true
}

// intLiteral parses a whole-number literal.
func intLiteral(s string) (int, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, false
	}
	if _, ok := numericLiteral(t); !ok {
		return 0, false
	}
	v, err := strconv.Atoi(t)
	if err != nil {
		return 0, false
	}
	return v, true
}

// hasRangeOp reports whether text contains the range operator.
func hasRangeOp(text string) bool { return strings.Contains(text, "..") }

// isSingleExpression reports whether text is one PowerShell value: a single
// token with no top-level `+` operator. Anything else — `1 + 2`,
// `'a' + $b`, `$a+$b`, a parenthesised call — is an expression whose value the
// analysis does not compute, so binding its raw text would fabricate a literal
// target (ADR-0003/ADR-0014).
func isSingleExpression(text string) bool {
	return len(tokenFields(text)) <= 1 && !hasTopLevelPlus(text)
}

// hasTopLevelPlus reports whether a `+` appears in text outside quotes and
// brackets (a concatenation or an addition operator).
func hasTopLevelPlus(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '"':
			q := c
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '`' {
					i++
				}
				i++
			}
		case '`':
			i++
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '+':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// tokenFields splits text into top-level tokens (runs separated by whitespace
// outside quotes and brackets).
func tokenFields(s string) []string {
	var out []string
	start := -1
	depth := 0
	flush := func(end int) {
		if start >= 0 {
			out = append(out, s[start:end])
			start = -1
		}
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '"':
			if start < 0 {
				start = i
			}
			q := c
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '`' {
					i++
				}
				i++
			}
		case '(', '[', '{':
			depth++
			if start < 0 {
				start = i
			}
		case ')', ']', '}':
			depth--
			if start < 0 {
				start = i
			}
		case ' ', '\t', '\n', '\r':
			if depth <= 0 {
				flush(i)
			}
		default:
			if start < 0 {
				start = i
			}
		}
	}
	flush(len(s))
	return out
}
