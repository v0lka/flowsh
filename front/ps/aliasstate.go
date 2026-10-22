package ps

// PowerShell alias state: declaration, immutability and the channels that
// rebind a name.
//
// Name resolution is the one channel a guard-evading command can use to make
// the report describe a command other than the one that runs (SECURITY.md
// no-silent-miss invariant; the same class as the bash hash table and alias
// findings). The frontend therefore models every documented way a script can
// (re)bind a name, and refuses to trust a binding it cannot follow:
//
//   - Set-Alias / New-Alias (and the sal/nal aliases) with a -Name/-Value that
//     is a literal *or* a variable Σ holds; a name or value that is not
//     statically known degrades the affected resolution to ⊤ instead of keeping
//     a stale built-in alias (Finding 77).
//   - ScopedItemOptions: a -Option Constant binding can never be changed or
//     removed, a -Option ReadOnly one only with -Force. A refused redeclaration
//     leaves the original binding in force, so the destructive original — not
//     the benign replacement — is what later calls resolve to (Finding 79).
//   - The Alias: provider (about_Alias_Provider): Set-Item / New-Item create or
//     change an alias, Copy-Item / Rename-Item rebind one, Remove-Item /
//     Clear-Item delete one.
//   - Import-Alias reads a file of definitions the analysis cannot see, so it
//     leaves every name possibly rebound (⊤ for later calls).

import (
	"strings"
)

// aliasBinding is one alias the analysed source declared, together with the
// ScopedItemOptions that decide whether a later declaration may replace it.
type aliasBinding struct {
	// target is the command the alias expands to. unknown marks a target the
	// script did not determine statically: every call through such an alias is
	// ⊤, because the report cannot say what runs.
	target  string
	unknown bool
	// constant and readOnly mirror ScopedItemOptions: a Constant alias "can't
	// be changed or deleted", a ReadOnly one only with -Force.
	constant bool
	readOnly bool
	// mayImmutable marks a binding whose option is not statically known (a
	// variable or an expression): it may be Constant, so a later declaration is
	// refused rather than assumed to replace it.
	mayImmutable bool
}

// replaceable reports whether a new declaration may replace this binding.
func (b aliasBinding) replaceable(force bool) bool {
	switch {
	case b.constant:
		return false
	case b.readOnly:
		return force
	case b.mayImmutable:
		return false
	}
	return true
}

// describe renders a binding's immutability for a note.
func (b aliasBinding) describe() string {
	switch {
	case b.constant:
		return "-Option Constant"
	case b.readOnly:
		return "-Option ReadOnly"
	case b.mayImmutable:
		return "an -Option that may be Constant"
	}
	return ""
}

// applyAliasDecl applies a Set-Alias/New-Alias declaration to the order-aware
// alias state, so it affects the statements that follow it and nothing before.
// It obeys ScopedItemOptions (a Constant / ReadOnly / possibly-Constant binding
// is not replaced) and degrades to unknown when the target cannot be resolved.
func (l *lowerer) applyAliasDecl(c *Command) {
	switch strings.ToLower(strings.TrimSpace(c.Name)) {
	case "set-alias", "new-alias", "sal", "nal":
	default:
		return
	}
	nameWord := c.ParamValue("name")
	valueWord := c.ParamValue("value")
	if nameWord == nil && len(c.Args) >= 1 {
		nameWord = c.Args[0]
	}
	if valueWord == nil && len(c.Args) >= 2 {
		valueWord = c.Args[1]
	}
	name, nameKnown := l.aliasOperand(nameWord)
	if !nameKnown || name == "" {
		// The name is not statically known: any existing alias (including a
		// built-in one) may have been rebound, so no later resolution can be
		// trusted.
		l.aliasStateUnknown = true
		l.note("%s: alias name is not statically known → resolution state unknown", cmdLabel(c, c.Name))
		return
	}
	force := c.HasParam("force") || hasSwitchCanon(c, "force")
	if prev, ok := l.aliases[strings.ToLower(name)]; ok && !prev.replaceable(force) {
		l.note("alias %s: the redeclaration is refused (%s) → %s stays in force",
			name, prev.describe(), prev.target)
		return
	}
	value, valueKnown := l.aliasOperand(valueWord)
	constant, readOnly, definitive := l.aliasOptions(c)
	if !valueKnown || value == "" {
		l.aliases[strings.ToLower(name)] = aliasBinding{
			unknown: true, constant: constant, readOnly: readOnly,
			mayImmutable: !definitive,
		}
		l.note("alias %s → an unresolved target (⊤ for later calls)", name)
		return
	}
	l.aliases[strings.ToLower(name)] = aliasBinding{
		target: value, constant: constant, readOnly: readOnly, mayImmutable: !definitive,
	}
	l.note("alias %s → %s", name, value)
}

// aliasOperand resolves an alias operand (a name, a value or an -Option value)
// through Σ: a quoted or bare literal is itself, a variable resolves to the
// value the script bound to it.
func (l *lowerer) aliasOperand(w *Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var ev evaluatedWord
	if plain, ok := plainAliasText(w.Text); ok {
		return plain, true
	}
	ev = l.evalWord(w)
	if !ev.Known {
		return "", false
	}
	return unquoteWord(strings.TrimSpace(ev.Text)), true
}

// plainAliasText returns a word's own text when it is a literal that needs no
// evaluation (it carries no variable reference, escape or subexpression).
func plainAliasText(text string) (string, bool) {
	s := strings.TrimSpace(text)
	if s == "" || strings.ContainsAny(s, "$`(") {
		return "", false
	}
	if inner, ok := wholeQuoted(s); ok {
		return unquoteWord(strings.TrimSpace(inner)), true
	}
	if strings.HasPrefix(s, "'") || strings.HasPrefix(s, `"`) {
		return "", false
	}
	return unquoteWord(s), true
}

// aliasOptions reads -Option (Set-Alias/New-Alias) or -Options (Set-Item) — the
// ScopedItemOptions flag set — and reports whether the binding is Constant or
// ReadOnly. definitive is false when the option is not statically known or
// carries a value this model does not understand: the binding may then be
// Constant, so a later declaration is refused (fail-closed).
func (l *lowerer) aliasOptions(c *Command) (constant, readOnly, definitive bool) {
	w := paramValuePrefix(c, "option")
	if w == nil {
		w = paramValuePrefix(c, "options")
	}
	if w == nil {
		return false, false, true
	}
	val, known := l.aliasOperand(w)
	if !known {
		return false, false, false
	}
	definitive = true
	if strings.TrimSpace(val) == "" {
		return false, false, true
	}
	for _, part := range splitTopLevelCommas(val) {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "constant":
			constant = true
		case "readonly":
			readOnly = true
		case "", "none", "private", "allscope":
			// Not immutable.
		default:
			// An option this model does not know: it may be Constant.
			definitive = false
		}
	}
	return constant, readOnly, definitive
}

// paramValuePrefix returns the value bound to the first parameter whose
// (lower-cased, dash-less) name is a prefix of canon — PowerShell's parameter
// abbreviation, so -Member binds -MemberName and -Opt binds -Option.
func paramValuePrefix(c *Command, canon string) *Word {
	if c == nil {
		return nil
	}
	for _, b := range c.Bindings {
		if b.Param == nil || b.Value == nil {
			continue
		}
		bare := bareParam(b.Param.Bare())
		if bare != "" && strings.HasPrefix(canon, bare) {
			return b.Value
		}
	}
	return nil
}

// aliasResolutionTop reports whether a call's name cannot be resolved because
// the alias state itself is unknown: a declaration whose name was not
// statically known, or an Import-Alias of a file the analysis cannot see, means
// any name may have been rebound, so the call degrades to ⊤ rather than
// describing the built-in alias it may no longer be.
func (l *lowerer) aliasResolutionTop(c *Command) (string, bool) {
	if c == nil || c.Name == "" {
		return "", false
	}
	if b, ok := l.aliases[strings.ToLower(c.Name)]; ok && b.unknown {
		return "the alias " + c.Name + " has no statically known target", true
	}
	if l.aliasStateUnknown {
		return "an alias was rebound through a channel this analysis cannot follow", true
	}
	return "", false
}

// pipeAliasInfo is the alias set an earlier pipeline stage enumerated: all
// aliases, an unbounded wildcard subset, or the named ones.
type pipeAliasInfo struct {
	all      bool
	wildcard bool
	names    []string
}

// noteAliasEnumeration records, for the pipeline group being lowered, the alias
// items a stage enumerated, so a later Remove-Item/Clear-Item fed by the
// pipeline unbinds them (`Get-Alias cat | Remove-Item`, `Get-ChildItem Alias: |
// Remove-Item`). A name the enumeration cannot bound — no operand, a wildcard, a
// value that is not a literal — widens the record rather than narrowing it.
func (l *lowerer) noteAliasEnumeration(c *Command, canonical string) {
	if l.curPipe == 0 || c == nil {
		return
	}
	info := &pipeAliasInfo{}
	switch strings.ToLower(canonical) {
	case "get-alias":
		words := append(paramWords(c, "name"), c.Args...)
		if len(words) == 0 {
			info.all = true
		}
		for _, w := range words {
			if w == nil {
				continue
			}
			name, ok := plainAliasText(w.Text)
			switch {
			case !ok || name == "":
				info.all = true
			case aliasWildcard(name):
				info.wildcard = true
			default:
				info.names = append(info.names, name)
			}
		}
	case "get-childitem", "get-item":
		words := pathOperandWords(c)
		names := aliasPathNames(c, words)
		root := false
		for _, w := range words {
			if w != nil && aliasProviderRoot(w.Text) {
				root = true
			}
		}
		if len(names) == 0 && !root {
			return
		}
		info.all = root
		for _, n := range names {
			if aliasWildcard(n) {
				info.wildcard = true
				continue
			}
			info.names = append(info.names, n)
		}
	default:
		return
	}
	// Several stages may enumerate aliases before the removing one; the record
	// is joined, never replaced, so a later narrower enumeration cannot narrow
	// what an earlier stage contributed.
	if prev := l.pipeAlias[l.curPipe]; prev != nil {
		prev.all = prev.all || info.all
		prev.wildcard = prev.wildcard || info.wildcard
		prev.names = append(prev.names, info.names...)
		return
	}
	l.pipeAlias[l.curPipe] = info
}

// removePipedAliases unbinds the aliases an earlier pipeline stage enumerated
// when the removing cmdlet names no path of its own.
func (l *lowerer) removePipedAliases(force bool) {
	info := l.pipeAlias[l.curPipe]
	if info == nil {
		return
	}
	if info.all || info.wildcard {
		l.aliasStateUnknown = true
		l.note("a piped alias enumeration was removed: the unbound set is not bounded → resolution state unknown")
	}
	for _, name := range info.names {
		l.removeAlias(name, force)
	}
}

// mutateAliasProvider applies the Alias: provider operations of the state
// cmdlets (about_Alias_Provider) to the alias state:
//
//	Set-Item / New-Item   -Path Alias:NAME -Value CMD   → binds NAME to CMD
//	Copy-Item             -Path Alias:SRC -Destination Alias:DST → rebinds DST
//	Rename-Item           -Path Alias:SRC -NewName DST  → rebinds DST, drops SRC
//	Remove-Item / Clear-Item -Path Alias:NAME           → unbinds NAME
//
// Each is a documented way to rebind a name without going through Set-Alias, so
// leaving it unmodelled would let a script delete a directory tree through an
// alias the report still describes as a read.
func (l *lowerer) mutateAliasProvider(c *Command, canonical string) {
	l.noteAliasEnumeration(c, canonical)
	switch strings.ToLower(canonical) {
	case "set-item", "new-item":
		valueWord := c.ParamValue("value")
		value, valueKnown := l.aliasOperand(valueWord)
		constant, readOnly, definitive := l.aliasOptions(c)
		for _, name := range aliasPathNames(c, pathOperandWords(c)) {
			if prev, ok := l.aliases[strings.ToLower(name)]; ok && !prev.replaceable(false) {
				l.note("alias %s: the provider write is refused (%s)", name, prev.describe())
				continue
			}
			if !valueKnown || value == "" {
				l.aliases[strings.ToLower(name)] = aliasBinding{
					unknown: true, constant: constant, readOnly: readOnly,
					mayImmutable: !definitive,
				}
				l.note("Alias:%s → an unresolved target (⊤ for later calls)", name)
				continue
			}
			l.aliases[strings.ToLower(name)] = aliasBinding{
				target: value, constant: constant, readOnly: readOnly, mayImmutable: !definitive,
			}
			l.note("Alias:%s → %s (provider write)", name, value)
		}
	case "copy-item":
		dst := aliasTargetNames(paramWords(c, "destination"))
		src := aliasPathNames(c, pathOperandWords(c))
		for _, d := range dst {
			if len(src) == 0 {
				l.bindAliasUnknown(d)
				continue
			}
			l.rebindAlias(d, src[0])
		}
	case "rename-item":
		newNames := aliasTargetNames(paramWords(c, "newname"))
		src := aliasPathNames(c, pathOperandWords(c))
		for _, d := range newNames {
			if len(src) == 0 {
				l.bindAliasUnknown(d)
				continue
			}
			l.rebindAlias(d, src[0])
			l.removeAlias(src[0], false)
		}
	case "remove-item", "clear-item":
		force := c.HasParam("force") || hasSwitchCanon(c, "force")
		words := pathOperandWords(c)
		for _, w := range words {
			if w == nil {
				continue
			}
			if aliasProviderRoot(w.Text) {
				// The drive itself, not one item: the deletion may unbind every
				// alias, so no later resolution is trusted.
				l.aliasStateUnknown = true
				l.note("alias provider %s: the whole drive is removed → resolution state unknown", w.Text)
				continue
			}
			if name, ok := aliasPathName(w.Text); ok {
				l.removeAlias(name, force)
			}
		}
		if len(words) == 0 {
			// The items come from the pipeline rather than an operand.
			l.removePipedAliases(force)
		}
	case "remove-alias":
		// The cmdlet form of the same deletion (`Remove-Alias cat`, `ral cat`):
		// it unbinds the name from the table resolution reads.
		force := c.HasParam("force") || hasSwitchCanon(c, "force")
		words := append(paramWords(c, "name"), c.Args...)
		for _, w := range words {
			if w == nil {
				continue
			}
			name, known := l.aliasOperand(w)
			if !known || name == "" {
				l.aliasStateUnknown = true
				l.note("Remove-Alias: the name is not statically known → resolution state unknown")
				continue
			}
			l.removeAlias(name, force)
		}
	case "import-alias":
		// A file of alias definitions the analysis cannot see: every name is
		// possibly rebound, so later calls degrade to ⊤ rather than trusting a
		// built-in alias.
		l.aliasStateUnknown = true
		l.note("Import-Alias: alias definitions come from a file → resolution state unknown")
	}
}

// bindAliasUnknown marks a name as possibly bound to an unknown target.
func (l *lowerer) bindAliasUnknown(name string) {
	l.aliases[strings.ToLower(name)] = aliasBinding{unknown: true}
	l.note("Alias:%s → an unresolved target (⊤ for later calls)", name)
}

// rebindAlias binds dst to whatever src currently resolves to.
func (l *lowerer) rebindAlias(dst, src string) {
	if prev, ok := l.aliases[strings.ToLower(src)]; ok {
		if prev.unknown {
			l.bindAliasUnknown(dst)
			return
		}
		l.aliases[strings.ToLower(dst)] = aliasBinding{target: prev.target,
			constant: prev.constant, readOnly: prev.readOnly, mayImmutable: prev.mayImmutable}
		l.note("Alias:%s → %s (provider copy/rename)", dst, prev.target)
		return
	}
	l.bindAliasUnknown(dst)
}

// removeAlias unbinds a name, refusing when the binding is immutable.
func (l *lowerer) removeAlias(name string, force bool) {
	key := strings.ToLower(name)
	prev, ok := l.aliases[key]
	if !ok {
		// The name may be a *built-in* alias: those live in the table
		// resolution falls back to (Aliases), not in the source-declared one.
		// The provider deletes the alias from that same table, so leaving it in
		// force certifies the benign command the alias names while the script
		// has removed it — `Remove-Item Alias:cat; cat -Recurse -Force …` was
		// reported as Get-Content's read (Findings 77/79).
		if aliasWildcard(name) {
			// A wildcard removes a set this analysis cannot bound: any alias
			// may be gone, so no later name resolution is trusted.
			l.aliasStateUnknown = true
			l.note("alias %q: a wildcard removal may unbind any alias → resolution state unknown", name)
			return
		}
		if _, builtin := LookupAlias(name, nil); builtin {
			l.aliases[key] = aliasBinding{unknown: true}
			l.note("alias %s: the built-in alias was removed → later calls resolve to no known command", name)
		}
		return
	}
	if !prev.replaceable(force) {
		l.note("alias %s: removal is refused (%s) → %s stays in force", name, prev.describe(), prev.target)
		return
	}
	delete(l.aliases, key)
	l.note("alias %s removed", name)
}

// pathOperandWords collects the path-ish words a provider cmdlet acts on: the
// -Path/-LiteralPath/-PSPath values, else the positional operands.
func pathOperandWords(c *Command) []*Word {
	var out []*Word
	for _, b := range c.Bindings {
		if b.Param != nil && b.Value != nil && pathParam(b.Param.Bare()) {
			out = append(out, b.Value)
		}
	}
	if len(out) > 0 {
		return out
	}
	return c.Args
}

// paramWords returns the words bound to a named parameter (accepting
// abbreviations).
func paramWords(c *Command, canon string) []*Word {
	var out []*Word
	for _, b := range c.Bindings {
		if b.Param == nil || b.Value == nil {
			continue
		}
		bare := bareParam(b.Param.Bare())
		if bare != "" && strings.HasPrefix(canon, bare) {
			out = append(out, b.Value)
		}
	}
	return out
}

// aliasPathNames maps each word that names an Alias: provider path onto the
// alias name it designates.
func aliasPathNames(c *Command, words []*Word) []string {
	var out []string
	for _, w := range words {
		if w == nil {
			continue
		}
		if name, ok := aliasPathName(w.Text); ok {
			out = append(out, name)
		}
	}
	return out
}

// aliasTargetNames maps the words of a rebinding operand (-Destination,
// -NewName) onto alias names: both the provider spelling (Alias:x) and a bare
// name are accepted, as about_Alias_Provider documents both.
func aliasTargetNames(words []*Word) []string {
	var out []string
	for _, w := range words {
		if w == nil {
			continue
		}
		if name, ok := aliasPathName(w.Text); ok {
			out = append(out, name)
			continue
		}
		if name, ok := plainAliasText(w.Text); ok && name != "" {
			out = append(out, name)
		}
	}
	return out
}

// aliasPathName reports whether a path designates an alias and returns its name
// ("Alias:cat", "alias:\cat" → "cat").
func aliasPathName(s string) (string, bool) {
	t := strings.TrimSpace(unquoteWord(unbrace(s)))
	const prefix = "alias:"
	if len(t) <= len(prefix) || !strings.EqualFold(t[:len(prefix)], prefix) {
		return "", false
	}
	name := strings.TrimLeft(t[len(prefix):], `\/`)
	if name == "" || strings.ContainsAny(name, `\/`) {
		return "", false
	}
	return name, true
}

// aliasWildcard reports whether a provider path names a set of aliases rather
// than one item (`Alias:*`, `Alias:c*`, `Alias:[cr]*`). Such a removal unbinds a
// set the analysis cannot enumerate.
func aliasWildcard(name string) bool {
	return strings.ContainsAny(name, "*?[")
}

// aliasProviderRoot reports whether a word names the Alias: drive itself rather
// than one item in it (`Alias:`, `Alias:\`): removing it may unbind every alias.
func aliasProviderRoot(s string) bool {
	t := strings.TrimRight(strings.TrimSpace(unquoteWord(unbrace(s))), `\/`)
	return strings.EqualFold(t, "alias:")
}
