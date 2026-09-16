package kb

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/v0lka/flowsh/engine"
)

// dataFS holds the knowledge-base documents, compiled into the binary. Loading
// therefore needs no files on disk at run time.
//
// The whole data directory is embedded (rather than a `data/*.yaml` glob) so
// that every document documentNames discovers — including a `.yml` file — is
// actually present in the embedded filesystem. A glob would silently ignore a
// `.yml` document that discovery nonetheless reports, and a literal
// `data/*.yml` pattern would fail the build while no .yml file exists.
//
//go:embed data
var dataFS embed.FS

// dataDir is the directory inside dataFS that holds the schema documents.
const dataDir = "data"

// Load parses the embedded knowledge base. It reads only from the embedded
// filesystem, so it works from any working directory and with no external
// files present.
func Load() (*KB, error) {
	return loadFS(dataFS, dataDir)
}

// EmbeddedFiles returns the names of the embedded schema documents, sorted.
func EmbeddedFiles() ([]string, error) {
	names, err := documentNames(dataFS, dataDir)
	if err != nil {
		return nil, err
	}
	return names, nil
}

// loadFS parses every *.yaml document under dir in fsys. It exists (rather than
// Load reaching into the embedded FS directly) so that tests can drive the
// loader from an in-memory filesystem — for instance to inject a document with
// an unknown schema version.
func loadFS(fsys fs.FS, dir string) (*KB, error) {
	names, err := documentNames(fsys, dir)
	if err != nil {
		return nil, err
	}

	kb := &KB{}
	for _, name := range names {
		p := path.Join(dir, name)
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("kb: read %s: %w", p, err)
		}
		doc, err := parseDocument(raw, p)
		if err != nil {
			return nil, err
		}
		if err := kb.merge(doc, p); err != nil {
			return nil, err
		}
	}
	if err := kb.build(); err != nil {
		return nil, err
	}
	if err := kb.Validate(); err != nil {
		return nil, err
	}
	return kb, nil
}

func documentNames(fsys fs.FS, dir string) ([]string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("kb: read data dir %q: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("kb: no *.yaml documents found in %q", dir)
	}
	sort.Strings(names)
	return names, nil
}

// document is one parsed YAML file.
type document struct {
	Version     string
	Commands    []Command
	Destructive []Destructive
}

// merge folds a parsed document into the knowledge base, enforcing that the
// schema version is known and that every file agrees on it.
func (k *KB) merge(doc *document, src string) error {
	if doc.Version == "" {
		return fmt.Errorf("kb: %s: missing schema version (want %q)", src, SchemaVersion)
	}
	if !Known(doc.Version) {
		return fmt.Errorf("kb: %s: unsupported schema version %q (known: %s)", src, doc.Version, strings.Join(KnownVersions, ", "))
	}
	if k.Version == "" {
		k.Version = doc.Version
	} else if k.Version != doc.Version {
		return fmt.Errorf("kb: %s: schema version %q conflicts with %q from a previous document", src, doc.Version, k.Version)
	}
	k.Commands = append(k.Commands, doc.Commands...)
	k.Destructive = append(k.Destructive, doc.Destructive...)
	return nil
}

// build canonicalises order and builds the lookup indexes. Ordering happens
// before indexing because the indexes hold pointers into the slices.
func (k *KB) build() error {
	sort.SliceStable(k.Commands, func(i, j int) bool { return k.Commands[i].Name < k.Commands[j].Name })
	sort.SliceStable(k.Destructive, func(i, j int) bool {
		if k.Destructive[i].Command != k.Destructive[j].Command {
			return k.Destructive[i].Command < k.Destructive[j].Command
		}
		return k.Destructive[i].Spec < k.Destructive[j].Spec
	})

	k.byName = make(map[string]*Command, len(k.Commands))
	for i := range k.Commands {
		c := &k.Commands[i]
		// Precompute the Spec index while the parameter list is final and the
		// address of the slice element is stable; every later Param/HasParam on
		// this command is then an O(1) map hit.
		c.buildIndex()
		for _, n := range append([]string{c.Name}, c.Aliases...) {
			if n == "" {
				continue
			}
			if prev, ok := k.byName[n]; ok {
				return fmt.Errorf("kb: duplicate command name/alias %q (%s and %s)", n, prev.Name, c.Name)
			}
			k.byName[n] = c
		}
	}

	k.byDestr = make(map[string]*Destructive, len(k.Destructive))
	for i := range k.Destructive {
		d := &k.Destructive[i]
		key := d.Command + "|" + d.Spec
		if prev, ok := k.byDestr[key]; ok {
			return fmt.Errorf("kb: duplicate destructive entry %s %s", prev.Command, prev.Spec)
		}
		k.byDestr[key] = d
	}
	return nil
}

var (
	defaultOnce sync.Once
	defaultKB   *KB
	defaultErr  error
)

// Default returns the embedded knowledge base, parsing it at most once. Use it
// on hot paths; use Load when a fresh, independently-parsed copy is wanted.
func Default() (*KB, error) {
	defaultOnce.Do(func() { defaultKB, defaultErr = Load() })
	return defaultKB, defaultErr
}

// ===========================================================================
// Decoding: YAML document -> document
// ===========================================================================

func parseDocument(raw []byte, src string) (*document, error) {
	root, err := parseYAML(string(raw), src)
	if err != nil {
		return nil, err
	}
	if !root.isMap() {
		return nil, fmt.Errorf("kb: %s: top level must be a mapping", src)
	}
	doc := &document{}
	for _, key := range root.keys {
		v := root.fields[key]
		switch key {
		case "version":
			s, ok := v.scalarVal()
			if !ok || s == "" {
				return nil, fmt.Errorf("kb: %s: `version` must be a non-empty scalar", src)
			}
			doc.Version = s
		case "commands":
			cs, err := decodeCommands(v, src)
			if err != nil {
				return nil, err
			}
			doc.Commands = cs
		case "destructive":
			ds, err := decodeDestructive(v, src)
			if err != nil {
				return nil, err
			}
			doc.Destructive = ds
		default:
			return nil, fmt.Errorf("kb: %s: unknown top-level key %q", src, key)
		}
	}
	return doc, nil
}

func decodeCommands(n *yamlNode, src string) ([]Command, error) {
	if isEmpty(n) {
		return nil, nil
	}
	if !n.isSeq() {
		return nil, fmt.Errorf("kb: %s: `commands` must be a sequence", src)
	}
	out := make([]Command, 0, len(n.items))
	for i, it := range n.items {
		c, err := decodeCommand(it, src)
		if err != nil {
			return nil, fmt.Errorf("kb: %s: commands[%d]: %w", src, i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func decodeCommand(n *yamlNode, src string) (Command, error) {
	var c Command
	if !n.isMap() {
		return c, fmt.Errorf("command entry must be a mapping")
	}
	for _, key := range n.keys {
		v := n.fields[key]
		switch key {
		case "name":
			s, ok := v.scalarVal()
			if !ok || s == "" {
				return c, fmt.Errorf("`name` must be a non-empty scalar")
			}
			c.Name = s
		case "dialect":
			s, ok := v.scalarVal()
			if !ok {
				return c, fmt.Errorf("command %q: `dialect` must be a scalar", c.Name)
			}
			c.Dialect = Dialect(s)
		case "aliases":
			as, err := decodeStringList(v)
			if err != nil {
				return c, fmt.Errorf("command %q: aliases: %w", c.Name, err)
			}
			c.Aliases = as
		case "params":
			ps, err := decodeParams(v, src, c.Name)
			if err != nil {
				return c, err
			}
			c.Params = ps
		default:
			return c, fmt.Errorf("command %q: unknown key %q", c.Name, key)
		}
	}
	return c, nil
}

func decodeParams(n *yamlNode, src, cmd string) ([]Param, error) {
	if isEmpty(n) {
		return nil, nil
	}
	if !n.isSeq() {
		return nil, fmt.Errorf("kb: %s: command %q: `params` must be a sequence", src, cmd)
	}
	out := make([]Param, 0, len(n.items))
	for i, it := range n.items {
		p, err := decodeParam(it)
		if err != nil {
			return nil, fmt.Errorf("kb: %s: command %q: params[%d]: %w", src, cmd, i, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func decodeParam(n *yamlNode) (Param, error) {
	var p Param
	if !n.isMap() {
		return p, fmt.Errorf("param entry must be a mapping")
	}
	for _, key := range n.keys {
		v := n.fields[key]
		switch key {
		case "spec":
			s, ok := v.scalarVal()
			if !ok || s == "" {
				return p, fmt.Errorf("`spec` must be a non-empty scalar")
			}
			p.Spec = s
		case "kind":
			s, ok := v.scalarVal()
			if !ok {
				return p, fmt.Errorf("param %q: `kind` must be a scalar", p.Spec)
			}
			p.Kind = ParamKind(s)
		case "effect":
			e, err := decodeEffect(v)
			if err != nil {
				return p, fmt.Errorf("param %q: effect: %w", p.Spec, err)
			}
			p.Effect = e
		default:
			return p, fmt.Errorf("param %q: unknown key %q", p.Spec, key)
		}
	}
	return p, nil
}

func decodeEffect(n *yamlNode) (Effect, error) {
	var e Effect
	if !n.isMap() {
		return e, fmt.Errorf("must be a mapping")
	}
	for _, key := range n.keys {
		s, ok := n.fields[key].scalarVal()
		if !ok {
			return e, fmt.Errorf("`%s` must be a scalar", key)
		}
		switch key {
		case "kind":
			e.Kind = engine.EffectKind(s)
		case "mode":
			e.Mode = engine.EffectMode(s)
		case "valueFrom":
			e.ValueFrom = ValueSource(s)
		case "fileRef":
			switch s {
			case "true":
				e.FileRef = true
			case "false":
				e.FileRef = false
			default:
				return e, fmt.Errorf("`fileRef` must be true or false, got %q", s)
			}
		default:
			return e, fmt.Errorf("unknown key %q", key)
		}
	}
	return e, nil
}

func decodeDestructive(n *yamlNode, src string) ([]Destructive, error) {
	if isEmpty(n) {
		return nil, nil
	}
	if !n.isSeq() {
		return nil, fmt.Errorf("kb: %s: `destructive` must be a sequence", src)
	}
	out := make([]Destructive, 0, len(n.items))
	for i, it := range n.items {
		d, err := decodeDestructiveEntry(it)
		if err != nil {
			return nil, fmt.Errorf("kb: %s: destructive[%d]: %w", src, i, err)
		}
		out = append(out, d)
	}
	return out, nil
}

func decodeDestructiveEntry(n *yamlNode) (Destructive, error) {
	var d Destructive
	if !n.isMap() {
		return d, fmt.Errorf("entry must be a mapping")
	}
	for _, key := range n.keys {
		v := n.fields[key]
		switch key {
		case "command":
			s, ok := v.scalarVal()
			if !ok || s == "" {
				return d, fmt.Errorf("`command` must be a non-empty scalar")
			}
			d.Command = s
		case "spec":
			s, ok := v.scalarVal()
			if !ok || s == "" {
				return d, fmt.Errorf("`spec` must be a non-empty scalar")
			}
			d.Spec = s
		case "class":
			s, ok := v.scalarVal()
			if !ok {
				return d, fmt.Errorf("%s %s: `class` must be a scalar", d.Command, d.Spec)
			}
			d.Class = DestructiveClass(s)
		case "reason":
			s, ok := v.scalarVal()
			if !ok {
				return d, fmt.Errorf("%s %s: `reason` must be a scalar", d.Command, d.Spec)
			}
			d.Reason = s
		default:
			return d, fmt.Errorf("%s %s: unknown key %q", d.Command, d.Spec, key)
		}
	}
	return d, nil
}

func decodeStringList(n *yamlNode) ([]string, error) {
	if isEmpty(n) {
		return nil, nil
	}
	switch n.kind {
	case yamlScalar:
		if n.scalar == "" {
			return nil, nil
		}
		return []string{n.scalar}, nil
	case yamlSeq:
		out := make([]string, 0, len(n.items))
		for i, it := range n.items {
			s, ok := it.scalarVal()
			if !ok {
				return nil, fmt.Errorf("item %d must be a scalar", i)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("must be a scalar or a sequence")
	}
}

func isEmpty(n *yamlNode) bool { return n == nil || n.kind == yamlEmpty }

// ===========================================================================
// Minimal YAML reader
// ===========================================================================
//
// The dataset ships as YAML so that it stays diff-friendly and reviewable, but
// it must load in well under a millisecond and pull in no third-party parser.
// The files therefore use a strict, documented subset of YAML:
//
//   - block mappings (`key: value`, `key:` + indented block),
//   - block sequences (`- value`, `- key: value`),
//   - single-line flow collections on a value (`{k: v, …}`, `[a, b]`),
//   - plain, single- and double-quoted scalars,
//   - `#` comments (whole-line and trailing).
//
// Anything outside that subset — anchors, aliases, tags, multi-line scalars,
// tabs for indentation — is reported as an explicit error rather than silently
// mis-read.

type yamlKind uint8

const (
	yamlEmpty yamlKind = iota
	yamlScalar
	yamlMap
	yamlSeq
)

type yamlNode struct {
	kind   yamlKind
	scalar string
	keys   []string
	fields map[string]*yamlNode
	items  []*yamlNode
}

func (n *yamlNode) isMap() bool { return n != nil && n.kind == yamlMap }
func (n *yamlNode) isSeq() bool { return n != nil && n.kind == yamlSeq }

func (n *yamlNode) scalarVal() (string, bool) {
	if n == nil || n.kind != yamlScalar {
		return "", false
	}
	return n.scalar, true
}

type yamlLine struct {
	no     int
	indent int
	text   string
}

type yamlParser struct {
	name  string
	lines []yamlLine
	pos   int
}

func parseYAML(src, name string) (*yamlNode, error) {
	p, err := newYAMLParser(src, name)
	if err != nil {
		return nil, err
	}
	if len(p.lines) == 0 {
		return &yamlNode{kind: yamlMap}, nil
	}
	root, err := p.parseBlock(p.lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.lines) {
		l := p.lines[p.pos]
		return nil, fmt.Errorf("kb: %s:%d: unexpected content %q (bad indentation?)", name, l.no, l.text)
	}
	return root, nil
}

func newYAMLParser(src, name string) (*yamlParser, error) {
	// Normalise line endings before splitting into lines. A Windows checkout
	// (core.autocrlf) or a CRLF-saved file delivers `\r\n`; the reader is
	// LF-based, so a bare `key:` line would otherwise arrive as `key:\r` and
	// splitKey (which needs the `:` followed by whitespace or end-of-line) would
	// reject the whole document. A lone CR (old-Mac style) is treated as a line
	// break too. .gitattributes pins LF for the embedded data, so this is
	// defence in depth against any other CRLF source.
	src = strings.ReplaceAll(src, "\r\n", "\n")
	src = strings.ReplaceAll(src, "\r", "\n")
	p := &yamlParser{name: name}
	for i, raw := range strings.Split(src, "\n") {
		no := i + 1
		if strings.TrimSpace(raw) == "" {
			continue
		}
		indent := 0
		for indent < len(raw) && raw[indent] == ' ' {
			indent++
		}
		if indent < len(raw) && raw[indent] == '\t' {
			return nil, fmt.Errorf("kb: %s:%d: tab indentation is not supported", name, no)
		}
		text := strings.TrimRight(stripComment(raw[indent:]), " \t")
		if text == "" {
			continue
		}
		p.lines = append(p.lines, yamlLine{no: no, indent: indent, text: text})
	}
	return p, nil
}

// parseBlock parses the block starting at the current line, provided it is
// indented at least minIndent. A block with no content yields an empty node.
func (p *yamlParser) parseBlock(minIndent int) (*yamlNode, error) {
	if p.pos >= len(p.lines) {
		return &yamlNode{kind: yamlEmpty}, nil
	}
	ln := p.lines[p.pos]
	if ln.indent < minIndent {
		return &yamlNode{kind: yamlEmpty}, nil
	}
	if isSeqItem(ln.text) {
		return p.parseSeq(ln.indent)
	}
	if _, _, ok := splitKey(ln.text); ok {
		return p.parseMap(ln.indent)
	}
	// A bare scalar occupying its own indented block.
	p.pos++
	v, err := resolveInline(ln.text)
	if err != nil {
		return nil, fmt.Errorf("kb: %s:%d: %v", p.name, ln.no, err)
	}
	return v, nil
}

func (p *yamlParser) parseMap(indent int) (*yamlNode, error) {
	n := &yamlNode{kind: yamlMap, fields: map[string]*yamlNode{}}
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent != indent || isSeqItem(ln.text) {
			break
		}
		key, rest, ok := splitKey(ln.text)
		if !ok {
			return nil, fmt.Errorf("kb: %s:%d: expected `key: value`, got %q", p.name, ln.no, ln.text)
		}
		if _, dup := n.fields[key]; dup {
			return nil, fmt.Errorf("kb: %s:%d: duplicate key %q", p.name, ln.no, key)
		}
		p.pos++
		v, err := p.value(rest, indent, ln.no)
		if err != nil {
			return nil, err
		}
		n.keys = append(n.keys, key)
		n.fields[key] = v
	}
	return n, nil
}

func (p *yamlParser) parseSeq(indent int) (*yamlNode, error) {
	n := &yamlNode{kind: yamlSeq}
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent != indent || !isSeqItem(ln.text) {
			break
		}
		item := strings.TrimSpace(ln.text[1:])
		_, _, itemIsMap := splitKey(item)
		switch {
		case item == "":
			p.pos++
			v, err := p.parseBlock(indent + 1)
			if err != nil {
				return nil, err
			}
			n.items = append(n.items, v)
		case itemIsMap:
			// A mapping item: re-anchor the line one level deeper and let
			// parseMap consume it together with its sibling keys.
			childIndent := indent + 2
			p.lines[p.pos] = yamlLine{no: ln.no, indent: childIndent, text: item}
			m, err := p.parseMap(childIndent)
			if err != nil {
				return nil, err
			}
			n.items = append(n.items, m)
		default:
			p.pos++
			v, err := resolveInline(item)
			if err != nil {
				return nil, fmt.Errorf("kb: %s:%d: %v", p.name, ln.no, err)
			}
			n.items = append(n.items, v)
		}
	}
	return n, nil
}

// value resolves the value of a `key: rest` mapping entry. When rest is empty
// the value is the following block, indented deeper than the key.
func (p *yamlParser) value(rest string, keyIndent, lineNo int) (*yamlNode, error) {
	if rest != "" {
		v, err := resolveInline(rest)
		if err != nil {
			return nil, fmt.Errorf("kb: %s:%d: %v", p.name, lineNo, err)
		}
		return v, nil
	}
	return p.parseBlock(keyIndent + 1)
}

// resolveInline resolves an inline value written on a single line: a flow
// collection (`{…}` or `[…]`) or a plain/quoted scalar.
func resolveInline(s string) (*yamlNode, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return &yamlNode{kind: yamlEmpty}, nil
	}
	if (strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}")) ||
		(strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]")) {
		return parseFlow(t)
	}
	v, err := unquote(s)
	if err != nil {
		return nil, err
	}
	return &yamlNode{kind: yamlScalar, scalar: v}, nil
}

// parseFlow parses a single-line flow mapping or sequence. Values inside are
// scalars or nested flow collections; the shapes are otherwise those of the
// block reader.
func parseFlow(s string) (*yamlNode, error) {
	switch {
	case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"):
		inner := strings.TrimSpace(s[1 : len(s)-1])
		n := &yamlNode{kind: yamlMap, fields: map[string]*yamlNode{}}
		if inner == "" {
			return n, nil
		}
		parts, err := splitFlow(inner)
		if err != nil {
			return nil, err
		}
		for _, part := range parts {
			key, rest, ok := splitKey(part)
			if !ok {
				return nil, fmt.Errorf("flow mapping entry %q is not `key: value`", part)
			}
			if _, dup := n.fields[key]; dup {
				return nil, fmt.Errorf("duplicate key %q in flow mapping", key)
			}
			val, err := resolveInline(rest)
			if err != nil {
				return nil, err
			}
			n.keys = append(n.keys, key)
			n.fields[key] = val
		}
		return n, nil
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		inner := strings.TrimSpace(s[1 : len(s)-1])
		n := &yamlNode{kind: yamlSeq}
		if inner == "" {
			return n, nil
		}
		parts, err := splitFlow(inner)
		if err != nil {
			return nil, err
		}
		for _, part := range parts {
			val, err := resolveInline(part)
			if err != nil {
				return nil, err
			}
			n.items = append(n.items, val)
		}
		return n, nil
	default:
		return nil, fmt.Errorf("not a flow collection: %q", s)
	}
}

// splitFlow splits the inside of a flow collection on top-level commas,
// respecting quotes and nested braces/brackets.
func splitFlow(s string) ([]string, error) {
	var parts []string
	depth := 0
	inSingle, inDouble := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inDouble && i+1 < len(s):
			i++
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case (c == '{' || c == '[') && !inSingle && !inDouble:
			depth++
		case (c == '}' || c == ']') && !inSingle && !inDouble:
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced flow collection %q", s)
			}
		case c == ',' && !inSingle && !inDouble && depth == 0:
			parts = append(parts, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote in flow collection %q", s)
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced flow collection %q", s)
	}
	return append(parts, strings.TrimSpace(s[start:])), nil
}

func isSeqItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

// splitKey splits `key: value` at the first `:` that is outside quotes and
// followed by whitespace or end-of-line. It reports ok=false when the line is
// not a mapping entry.
func splitKey(s string) (key, rest string, ok bool) {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inDouble && i+1 < len(s):
			i++
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == ':' && !inSingle && !inDouble:
			if i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t' {
				return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}

// stripComment removes a trailing `#` comment, leaving `#` inside quotes alone.
func stripComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inDouble && i+1 < len(s):
			i++
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble:
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

// unquote resolves a scalar: double-quoted (with \\, \", \n, \t escapes),
// single-quoted (with ” for a literal quote), or plain.
func unquote(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	switch s[0] {
	case '"':
		if len(s) < 2 || s[len(s)-1] != '"' {
			return "", fmt.Errorf("unterminated double-quoted scalar %q", s)
		}
		body := s[1 : len(s)-1]
		var b strings.Builder
		b.Grow(len(body))
		for i := 0; i < len(body); i++ {
			if body[i] == '\\' && i+1 < len(body) {
				i++
				switch body[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '\\':
					b.WriteByte('\\')
				case '"':
					b.WriteByte('"')
				default:
					b.WriteByte(body[i])
				}
				continue
			}
			b.WriteByte(body[i])
		}
		return b.String(), nil
	case '\'':
		if len(s) < 2 || s[len(s)-1] != '\'' {
			return "", fmt.Errorf("unterminated single-quoted scalar %q", s)
		}
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	default:
		return s, nil
	}
}
