package kb

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/v0lka/flowsh/engine"
)

// JSModule is an offline builtin namespace. An internal namespace is reachable
// only through another module's property, never through require or import.
type JSModule struct {
	Name       string
	Aliases    []string
	Properties map[string]string
	Constants  map[string]int64
	Internal   bool
}

// JSCall describes a builtin export's arguments and effects.
type JSCall struct {
	Module, Export, Style, Operation, Return string
	MinArgs, MaxArgs, Options                int
	ModeArg, DataArg                         int
	OptionShape                              string
	OptionKeys                               []string
	FlagOption, FlagDefault                  string
	Effects                                  []JSEffect
	Destructive                              []JSDestructive
}

// JSEffect selects a positional path or a generated path prefix.
type JSEffect struct {
	Kind   engine.EffectKind
	Arg    int
	Target string
}

// JSDestructive classifies true or unknown boolean options.
type JSDestructive struct {
	Option string
	Class  DestructiveClass
	Reason string
}

// JSModule looks up a builtin module or alias.
func (k *KB) JSModule(name string) (*JSModule, bool) { m, ok := k.jsModules[name]; return m, ok }

// JSCall looks up a canonical module/export pair.
func (k *KB) JSCall(module, export string) (*JSCall, bool) {
	c, ok := k.jsCalls[module+"\x00"+export]
	return c, ok
}

func (k *KB) buildJS() error {
	slices.SortFunc(k.JSModules, func(a, b JSModule) int { return cmp.Compare(a.Name, b.Name) })
	slices.SortFunc(k.JSCalls, func(a, b JSCall) int {
		return cmp.Or(cmp.Compare(a.Module, b.Module), cmp.Compare(a.Export, b.Export))
	})
	k.jsModules = map[string]*JSModule{}
	k.jsCalls = map[string]*JSCall{}
	for i := range k.JSModules {
		m := &k.JSModules[i]
		for _, name := range append([]string{m.Name}, m.Aliases...) {
			if name == "" || k.jsModules[name] != nil {
				return fmt.Errorf("kb: empty or duplicate JS module/alias %q", name)
			}
			k.jsModules[name] = m
		}
	}
	for i := range k.JSCalls {
		c := &k.JSCalls[i]
		key := c.Module + "\x00" + c.Export
		if k.jsCalls[key] != nil {
			return fmt.Errorf("kb: duplicate JS call %s.%s", c.Module, c.Export)
		}
		k.jsCalls[key] = c
	}
	return nil
}

func (k *KB) validateJS() error {
	targets := map[string]bool{}
	for _, m := range k.JSModules {
		for _, target := range m.Properties {
			targets[target] = true
		}
	}
	for _, m := range k.JSModules {
		if !validJSName(m.Name) {
			return fmt.Errorf("kb: invalid JS module %q", m.Name)
		}
		if m.Internal && len(m.Aliases) > 0 {
			return fmt.Errorf("kb: internal JS module %q cannot declare aliases", m.Name)
		}
		if m.Internal && !targets[m.Name] {
			return fmt.Errorf("kb: internal JS module %q is not a module property target", m.Name)
		}
		for _, alias := range m.Aliases {
			if !validJSName(alias) {
				return fmt.Errorf("kb: invalid JS module alias %q", alias)
			}
		}
		for _, property := range slices.Sorted(maps.Keys(m.Properties)) {
			target := m.Properties[property]
			ref, ok := k.JSModule(target)
			if !validJSName(property) || !ok || ref.Name != target {
				return fmt.Errorf("kb: invalid JS module property %s.%s", m.Name, property)
			}
			if _, conflict := k.JSCall(m.Name, property); conflict {
				return fmt.Errorf("kb: conflicting JS property/export %s.%s", m.Name, property)
			}
		}
		for _, constant := range slices.Sorted(maps.Keys(m.Constants)) {
			if !validJSName(constant) {
				return fmt.Errorf("kb: invalid JS module constant %s.%s", m.Name, constant)
			}
			if value := m.Constants[constant]; value > maxJSConstant || value < -maxJSConstant {
				return fmt.Errorf("kb: JS module constant %s.%s exceeds the exact integer range", m.Name, constant)
			}
			if _, conflict := m.Properties[constant]; conflict {
				return fmt.Errorf("kb: conflicting JS constant/property %s.%s", m.Name, constant)
			}
			if _, conflict := k.JSCall(m.Name, constant); conflict {
				return fmt.Errorf("kb: conflicting JS constant/export %s.%s", m.Name, constant)
			}
		}
	}
	for _, c := range k.JSCalls {
		m, ok := k.JSModule(c.Module)
		if !ok || m.Name != c.Module || !validJSName(c.Export) {
			return fmt.Errorf("kb: invalid JS call identity %s.%s", c.Module, c.Export)
		}
		if err := c.validate(); err != nil {
			return fmt.Errorf("kb: JS %s.%s: %w", c.Module, c.Export, err)
		}
	}
	return nil
}

// maxJSConstant bounds module constants to integers float64 represents exactly.
const maxJSConstant = 1 << 53

func validJSName(s string) bool {
	return s != "" && len(s) <= 128 && !strings.ContainsAny(s, " \t\r\n\x00")
}

func (c JSCall) validate() error {
	if !slices.Contains([]string{"sync", "promise", "callback", "stream", "pure"}, c.Style) {
		return fmt.Errorf("invalid style %q", c.Style)
	}
	if c.ModeArg < -1 || c.ModeArg >= c.MinArgs || c.DataArg < -1 || c.DataArg >= c.MinArgs {
		return fmt.Errorf("invalid mode selector")
	}
	if c.MinArgs < 0 || c.MaxArgs < c.MinArgs || c.MaxArgs > 1024 || c.Options < -1 || c.Options >= c.MaxArgs {
		return fmt.Errorf("invalid argument/option selector")
	}
	if !slices.Contains([]string{"filesystem", "join", "resolve", "dirname", "basename", "homedir"}, c.Operation) {
		return fmt.Errorf("invalid operation %q", c.Operation)
	}
	if !slices.Contains([]string{"unknown", "undefined", "content", "boolean"}, c.Return) {
		return fmt.Errorf("invalid return model %q", c.Return)
	}
	if !slices.Contains([]string{"record", "encoding", "mode", "number"}, c.OptionShape) {
		return fmt.Errorf("invalid options shape %q", c.OptionShape)
	}
	seen := map[string]bool{}
	if c.Options < 0 && len(c.OptionKeys) > 0 {
		return fmt.Errorf("option keys require an options selector")
	}
	for _, key := range c.OptionKeys {
		if !slices.Contains([]string{"encoding", "flag", "flags", "mode", "recursive", "force", "maxRetries", "retryDelay", "bigint", "throwIfNoEntry", "flush", "autoClose", "emitClose", "start", "end", "highWaterMark", "fd", "fs", "signal"}, key) || seen[key] {
			return fmt.Errorf("invalid or duplicate option %q", key)
		}
		seen[key] = true
	}
	if c.FlagOption != "" && (c.Options < 0 || !seen[c.FlagOption] || c.FlagDefault == "") {
		return fmt.Errorf("invalid flag selector")
	}
	if c.FlagOption == "" && c.FlagDefault != "" {
		return fmt.Errorf("flag default requires a flag selector")
	}
	if c.Operation != "filesystem" && (c.Style != "pure" || len(c.Effects) != 0) {
		return fmt.Errorf("path operation must be pure")
	}
	if c.Operation == "filesystem" && (c.Style == "pure" || len(c.Effects) == 0) {
		return fmt.Errorf("filesystem operation requires effects")
	}
	effects := map[JSEffect]bool{}
	for _, eff := range c.Effects {
		if !slices.Contains([]engine.EffectKind{engine.KindFSRead, engine.KindFSWrite, engine.KindFSMeta}, eff.Kind) || eff.Arg < 0 || eff.Arg >= c.MinArgs || !slices.Contains([]string{"path", "prefix"}, eff.Target) {
			return fmt.Errorf("invalid effect selector")
		}
		if effects[eff] {
			return fmt.Errorf("duplicate effect selector")
		}
		effects[eff] = true
	}
	seen = map[string]bool{}
	for _, d := range c.Destructive {
		if c.Options < 0 || !slices.Contains(c.OptionKeys, d.Option) || !slices.Contains([]string{"recursive", "force"}, d.Option) || !d.Class.Valid() || d.Reason == "" || seen[d.Option] {
			return fmt.Errorf("invalid destructive predicate")
		}
		seen[d.Option] = true
	}
	return nil
}
