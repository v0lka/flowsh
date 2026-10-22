package js

import (
	"strings"
	"unicode/utf8"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// parseTimeoutMicros bounds parser work before normalization can check its
// node/depth limits. Keep this safety net enabled in every build, including -race.
const parseTimeoutMicros uint64 = 2_000_000

type escapedIdentifier struct{}

// node owns a normalized, position-preserving syntax tree.
// Punctuation preserves operators, holes, and declaration kinds.
type node struct {
	kind, text, field string
	line, col         int
	named             bool
	children          []*node
}

func (n *node) get(field string) *node {
	if n == nil {
		return nil
	}
	for _, c := range n.children {
		if c.field == field {
			return c
		}
	}
	return nil
}

func (n *node) namedChildren() []*node {
	if n == nil {
		return nil
	}
	var out []*node
	for _, c := range n.children {
		if c.named && c.kind != "comment" {
			out = append(out, c)
		}
	}
	return out
}

func (n *node) first() *node {
	for _, c := range n.children {
		if c.named && c.kind != "comment" {
			return c
		}
	}
	return nil
}

func (n *node) operator() string {
	if op := n.get("operator"); op != nil {
		return op.text
	}
	return ""
}

func parse(src string) (*node, string) {
	return parseWithTimeout(src, parseTimeoutMicros)
}

func parseWithTimeout(src string, timeoutMicros uint64) (root *node, reason string) {
	defer func() {
		if p := recover(); p != nil {
			root = nil
			reason = "JavaScript parser or normalization limit reached"
			if _, ok := p.(escapedIdentifier); ok {
				reason = "escaped JavaScript identifiers are unsupported"
			}
		}
	}()
	if len(src) > maxSourceBytes {
		return nil, "JavaScript source size limit exceeded"
	}
	if !utf8.ValidString(src) {
		return nil, "JavaScript source is not valid UTF-8"
	}
	if exceedsDelimiterDepth(src) {
		return nil, "JavaScript source delimiter nesting limit exceeded"
	}
	lang := grammars.JavascriptLanguage()
	if lang == nil {
		return nil, "JavaScript grammar unavailable"
	}
	p := gotreesitter.NewParser(lang)
	p.SetTimeoutMicros(timeoutMicros)
	tree, err := p.Parse([]byte(src))
	if err != nil {
		return nil, "JavaScript parse failed"
	}
	if tree == nil {
		return nil, "JavaScript parser returned no tree"
	}
	defer tree.Release()
	if tree.ParseStoppedEarly() {
		if tree.ParseStopReason() == gotreesitter.ParseStopTimeout {
			return nil, "JavaScript parse timeout"
		}
		return nil, "JavaScript parse stopped early"
	}
	r := tree.RootNode()
	if r == nil || r.HasErrorOrMissing() {
		return nil, "JavaScript syntax error or missing syntax"
	}
	remaining := defaultBudget
	var copyNode func(*gotreesitter.Node, int, string) *node
	copyNode = func(n *gotreesitter.Node, depth int, field string) *node {
		remaining--
		if remaining < 0 || depth > maxDepth {
			panic(budgetExhausted{})
		}
		point := n.StartPoint()
		out := &node{
			kind: n.Type(lang), text: src[n.StartByte():n.EndByte()], field: field,
			named: n.IsNamed(), line: int(point.Row) + 1, col: int(point.Column) + 1,
		}
		if strings.Contains(out.kind, "identifier") && strings.Contains(out.text, `\u`) {
			panic(escapedIdentifier{})
		}
		for i := range n.ChildCount() {
			if c := n.Child(i); c != nil {
				out.children = append(out.children, copyNode(c, depth+1, n.FieldNameForChild(i, lang)))
			}
		}
		return out
	}
	return copyNode(r, 0, ""), ""
}

// exceedsDelimiterDepth is a linear admission check, not a JavaScript lexer.
// It counts raw delimiters even in literals/comments, conservatively rejecting
// deeply delimited data too. The parser timeout covers other expensive shapes;
// normalization still checks actual syntax-tree depth after parsing.
func exceedsDelimiterDepth(src string) bool {
	var closing [maxDepth]byte
	depth := 0
	for i := range len(src) {
		var end byte
		switch src[i] {
		case '(':
			end = ')'
		case '[':
			end = ']'
		case '{':
			end = '}'
		case ')', ']', '}':
			if depth > 0 && closing[depth-1] == src[i] {
				depth--
			}
		}
		if end != 0 {
			if depth == len(closing) {
				return true
			}
			closing[depth] = end
			depth++
		}
	}
	return false
}
