package bash

// globMatch reports whether the shell glob pattern pat matches name, following
// bash's pattern-matching rules for a case arm: '*' matches any run of
// characters *including* '/', '?' matches any single character, and '[…]'
// matches a character class. Unlike path.Match, '/' is not special, so a
// pattern such as '/etc/*' matches '/etc/sub/dir' exactly as bash would.
//
// The class syntax supported is bash's: a leading '!' or '^' negates the class,
// a ']' immediately after the (optional) negation is a literal member, ranges
// ('a-z') are honoured, '\\' escapes the next character, and the POSIX classes
// '[[:alpha:]]', '[[:alnum:]]', '[[:digit:]]', '[[:xdigit:]]', '[[:space:]]',
// '[[:blank:]]', '[[:upper:]]', '[[:lower:]]', '[[:punct:]]', '[[:cntrl:]]',
// '[[:graph:]]' and '[[:print:]]' are recognised.
//
// The second result reports whether the match could be decided faithfully: it
// is false when the pattern uses a construct this matcher does not model (an
// unknown POSIX class, a collating/equivalence symbol, an extglob, or a POSIX
// class tested against a non-ASCII character, which is locale-dependent). The
// caller must then treat the pattern as *possibly* matching — running the arm
// and degrading to ⊤ — rather than as a non-match, so that no arm is ever
// silently dropped.
//
// It is used only by the case-arm matcher; an over-approximation is still sound
// (it would run an arm bash would not) but the matcher is exact for the common
// forms.
func globMatch(pat, name string) (matched, ok bool) {
	toks, ok := tokenizePattern(pat)
	if !ok {
		return false, false
	}
	return matchTokens(toks, []rune(name))
}

// glob token kinds.
const (
	tokLit = iota
	tokStar
	tokQuest
	tokClass
)

// globTok is one token of a tokenized glob pattern.
type globTok struct {
	kind  int
	lit   rune
	class *charClass
}

// tokenizePattern splits a glob pattern into tokens, resolving '\\' escapes to
// their literal character. The boolean is false when the pattern uses a
// construct the matcher cannot faithfully evaluate (see globMatch).
func tokenizePattern(pat string) ([]globTok, bool) {
	runes := []rune(pat)
	var toks []globTok
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '\\':
			// A backslash escapes the next character, making it literal; a
			// trailing backslash stands for a literal backslash.
			if i+1 < len(runes) {
				i++
				toks = append(toks, globTok{kind: tokLit, lit: runes[i]})
			} else {
				toks = append(toks, globTok{kind: tokLit, lit: '\\'})
			}
		case '*', '?', '+', '@', '!':
			// The extglob operators ('?(', '*(' , '+(' , '@(' , '!(') are only
			// special when extglob is enabled, which the analysis does not track;
			// rather than guess, report the pattern as not faithfully decidable.
			if i+1 < len(runes) && runes[i+1] == '(' {
				return nil, false
			}
			switch runes[i] {
			case '*':
				toks = append(toks, globTok{kind: tokStar})
			case '?':
				toks = append(toks, globTok{kind: tokQuest})
			default:
				toks = append(toks, globTok{kind: tokLit, lit: runes[i]})
			}
		case '[':
			cls, end, isClass, ok := parseClass(runes, i)
			if !ok {
				return nil, false
			}
			if !isClass {
				// An unterminated '[' is a literal '[' (as in bash).
				toks = append(toks, globTok{kind: tokLit, lit: '['})
				continue
			}
			toks = append(toks, globTok{kind: tokClass, class: cls})
			i = end
		default:
			toks = append(toks, globTok{kind: tokLit, lit: runes[i]})
		}
	}
	return toks, true
}

// matchTokens reports whether the token sequence matches s, returning false for
// the second result when a class cannot be evaluated faithfully. It is the
// classic linear-time two-pointer matcher with star backtracking, extended so a
// character class behaves like a single-character '?'.
func matchTokens(toks []globTok, s []rune) (bool, bool) {
	ti, si := 0, 0
	star, starS := -1, 0
	for si < len(s) {
		if ti < len(toks) {
			t := toks[ti]
			switch t.kind {
			case tokStar:
				star, starS = ti, si
				ti++
				continue
			case tokQuest:
				ti++
				si++
				continue
			case tokLit:
				if t.lit == s[si] {
					ti++
					si++
					continue
				}
			case tokClass:
				in, ok := t.class.match(s[si])
				if !ok {
					return false, false
				}
				if in {
					ti++
					si++
					continue
				}
			}
		}
		if star >= 0 {
			// Backtrack: let the last '*' swallow one more character.
			starS++
			si = starS
			ti = star + 1
			continue
		}
		return false, true
	}
	for ti < len(toks) && toks[ti].kind == tokStar {
		ti++
	}
	return ti == len(toks), true
}

// charClass is a parsed '[…]' character class.
type charClass struct {
	neg    bool
	runes  map[rune]bool
	ranges [][2]rune
	posix  []string
	// unknown records a construct inside the class the matcher cannot evaluate
	// faithfully (an unknown POSIX class name, or a collating/equivalence
	// symbol); a match then reports "cannot decide" rather than a miss.
	unknown bool
}

// parseClass parses a character class starting at runes[open] == '['. It returns
// the class, the index of the closing ']', whether a class was actually formed
// (false for an unterminated '[' — a literal), and false as the last result when
// the class body contains a construct that cannot be evaluated faithfully.
func parseClass(runes []rune, open int) (cls *charClass, end int, isClass, ok bool) {
	c := &charClass{runes: map[rune]bool{}}
	j := open + 1
	if j < len(runes) && (runes[j] == '!' || runes[j] == '^') {
		c.neg = true
		j++
	}
	// A ']' immediately after the (optional) negation is a literal member, so
	// it is part of the body and the closing bracket must come later.
	if j < len(runes) && runes[j] == ']' {
		c.runes[']'] = true
		j++
	}
	for j < len(runes) && runes[j] != ']' {
		switch {
		case runes[j] == '\\' && j+1 < len(runes):
			c.runes[runes[j+1]] = true
			j += 2
		case runes[j] == '[' && j+1 < len(runes) && (runes[j+1] == ':' || runes[j+1] == '.' || runes[j+1] == '='):
			// '[[:name:]]' (POSIX class), '[.coll.]' or '[=equiv=]'.
			if runes[j+1] != ':' {
				// Collating/equivalence symbols are not modelled.
				c.unknown = true
				j += 2
				continue
			}
			k := j + 2
			for k < len(runes) && (runes[k] != ':' || k+1 >= len(runes) || runes[k+1] != ']') {
				k++
			}
			if k >= len(runes) {
				// Unterminated '[:'; treat '[' and ':' as literals.
				c.runes['['] = true
				j++
				continue
			}
			name := string(runes[j+2 : k])
			if !validPosixClass(name) {
				c.unknown = true
			} else {
				c.posix = append(c.posix, name)
			}
			j = k + 2
		case j+2 < len(runes) && runes[j+1] == '-' && runes[j+2] != ']':
			lo, hi := runes[j], runes[j+2]
			if lo > hi {
				// A reversed range matches nothing in bash.
				lo, hi = hi, lo
			}
			c.ranges = append(c.ranges, [2]rune{lo, hi})
			j += 3
		default:
			c.runes[runes[j]] = true
			j++
		}
	}
	if j >= len(runes) {
		// No closing ']': the '[' is a literal, not a class.
		return nil, 0, false, true
	}
	return c, j, true, true
}

// match reports whether r is a member of the class. The second result is false
// when membership cannot be decided faithfully (a POSIX class tested against a
// non-ASCII character, whose class membership is locale-dependent).
func (c *charClass) match(r rune) (bool, bool) {
	if c.unknown {
		return false, false
	}
	in := c.runes[r]
	if !in {
		for _, rg := range c.ranges {
			if r >= rg[0] && r <= rg[1] {
				in = true
				break
			}
		}
	}
	if !in {
		for _, name := range c.posix {
			if posixClassMatch(name, r) {
				in = true
				break
			}
		}
	}
	if !in && len(c.posix) > 0 && r > 0x7f {
		// A non-ASCII character may belong to a POSIX class under the active
		// locale, which the analysis does not know; do not claim a miss.
		return false, false
	}
	if c.neg {
		return !in, true
	}
	return in, true
}

// posixClassNames is the set of POSIX character-class names the matcher knows.
var posixClassNames = map[string]bool{
	"alpha": true, "alnum": true, "digit": true, "xdigit": true,
	"space": true, "blank": true, "upper": true, "lower": true,
	"punct": true, "cntrl": true, "graph": true, "print": true,
}

// validPosixClass reports whether name is a POSIX class the matcher evaluates.
func validPosixClass(name string) bool { return posixClassNames[name] }

// posixClassMatch reports whether r is a member of the named POSIX class, using
// the C locale (ASCII) definitions.
func posixClassMatch(name string, r rune) bool {
	switch name {
	case "alpha":
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
	case "alnum":
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
	case "digit":
		return r >= '0' && r <= '9'
	case "xdigit":
		return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
	case "space":
		return r == ' ' || r == '\t' || r == '\n' || r == '\v' || r == '\f' || r == '\r'
	case "blank":
		return r == ' ' || r == '\t'
	case "upper":
		return r >= 'A' && r <= 'Z'
	case "lower":
		return r >= 'a' && r <= 'z'
	case "punct":
		return (r >= '!' && r <= '/') || (r >= ':' && r <= '@') ||
			(r >= '[' && r <= '`') || (r >= '{' && r <= '~')
	case "cntrl":
		return r < 0x20 || r == 0x7f
	case "graph":
		return r > 0x20 && r < 0x7f
	case "print":
		return r >= 0x20 && r < 0x7f
	}
	return false
}
