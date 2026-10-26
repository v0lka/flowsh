package bind

import (
	"math"
	"slices"
	"strings"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/js"
	"github.com/v0lka/flowsh/kb"
)

// JSContext holds offline paths; empty fields are unknown.
type JSContext struct{ Home, Cwd string }

// JSResult holds modeled values, effects, and report metadata.
type JSResult struct {
	Resolution js.Resolution
	Binding    Result
}

// BindJS models a builtin JavaScript lookup or call.
func (b *Binder) BindJS(call js.Call, context JSContext) JSResult {
	out := JSResult{}
	if b == nil || b.k == nil {
		return out
	}
	if call.Kind == "module" {
		if module, ok := b.k.JSModule(call.Module); ok && !module.Internal {
			out.Resolution = js.Resolution{Handled: true, Value: js.BuiltinValue(module.Name, "")}
		}
		return out
	}
	if call.Kind == "property" {
		if module, ok := b.k.JSModule(call.Module); ok {
			if target := module.Properties[call.Export]; target != "" {
				out.Resolution = js.Resolution{Handled: true, Value: js.BuiltinValue(target, "")}
				return out
			}
			if constant, ok := module.Constants[call.Export]; ok {
				out.Resolution = js.Resolution{Handled: true, Value: js.NumberValue(float64(constant))}
				return out
			}
		}
		if _, ok := b.k.JSCall(call.Module, call.Export); ok {
			out.Resolution = js.Resolution{Handled: true, Value: js.BuiltinValue(call.Module, call.Export)}
		}
		return out
	}
	model, ok := b.k.JSCall(call.Module, call.Export)
	if !ok {
		return out
	}
	if call.Charge != nil {
		switch model.Operation {
		case "homedir":
			call.Charge(len(context.Home))
		case "resolve":
			if jsResolveAnchor(call.Args) < 0 {
				call.Charge(len(context.Cwd))
			}
		}
		for _, effect := range model.Effects {
			if text, known := jsArg(call.Args, effect.Arg).String(); known && (strings.HasPrefix(text, "~") || strings.HasPrefix(text, "$HOME") || strings.HasPrefix(text, "${HOME}")) {
				call.Charge(len(context.Home))
			}
		}
	}
	out.Resolution.Handled = true
	out.Resolution.MayThrow = model.Style != "promise" && model.Style != "pure"
	name := model.Module + "." + model.Export
	out.Binding.Resolution = Resolution{Invoked: call.Callee, Kind: ResolveBuiltin, Name: name}
	args := call.Args
	if model.Style == "callback" {
		if len(args) > 0 {
			args = args[:len(args)-1]
		}
	}
	if len(args) < model.MinArgs || len(args) > model.MaxArgs {
		out.Resolution.Reason = "unsupported JavaScript API argument shape"
	}
	if model.Operation != "filesystem" {
		out.Resolution.Value = jsPathValue(model.Operation, args, context)
		if out.Resolution.Value.Kind() == "" {
			out.Resolution.Reason = "JavaScript path helper requires known strings and abstract context"
		}
		return out
	}
	options := js.UndefinedValue()
	if model.Return == "content" {
		out.Resolution.Value = js.ContentValue()
	}
	if model.Return == "boolean" {
		out.Resolution.Value = js.UnknownBoolean()
	}
	if model.DataArg >= 0 {
		data := jsArg(args, model.DataArg)
		if data.Kind() != "string" && data.Kind() != "content" {
			out.Resolution.Reason = "unknown or unsupported JavaScript filesystem data may invoke user code"
		}
	}
	if model.Options >= 0 && model.Options < len(args) {
		options = args[model.Options]
	}
	if !jsOptionsValid(options, model) {
		out.Resolution.Reason = "unknown or unsupported JavaScript filesystem options"
	}
	sourceTaint := engine.TaintBottom()
	add := func(kind engine.EffectKind, index int, prefix bool) {
		value := jsArg(args, index)
		target := jsPathScope(value, context)
		if target.IsTop() {
			out.Resolution.Reason = "unknown or unsupported JavaScript filesystem path"
		}
		if prefix {
			target = engine.ScopeTop()
		}
		taint := value.Taint
		if kind == engine.KindFSRead {
			taint = jsReadTaint(taint, target)
			out.Resolution.Value.Taint = out.Resolution.Value.Taint.Join(taint)
		}
		if kind == engine.KindFSRead || kind == engine.KindFSMeta {
			sourceTaint = sourceTaint.Join(jsReadTaint(taint, target))
		}
		if kind == engine.KindFSWrite && model.DataArg >= 0 {
			taint = taint.Join(jsArg(args, model.DataArg).Taint)
		}
		effect := kb.Effect{Kind: kind, Mode: engine.ModeDirect}.EngineEffect(target, taint, engine.CertaintyCertain)
		out.Binding.Effects = append(out.Binding.Effects, effect)
		loc := call.Loc
		if index < len(call.ArgLocs) {
			loc = call.ArgLocs[index]
		}
		atoms := []engine.Atom{{Kind: engine.AtomCommand, Text: name, Loc: &call.Loc}, {Kind: engine.AtomLiteral, Text: jsEvidence(value), Loc: &loc}}
		out.Binding.Derivations = append(out.Binding.Derivations, engine.Derivation{Effect: effect, Atoms: atoms, Rules: []string{"js.kb.filesystem"}})
	}
	for _, effect := range model.Effects {
		add(effect.Kind, effect.Arg, effect.Target == "prefix")
	}
	if model.FlagOption != "" {
		flag := jsOption(options, model.FlagOption)
		if flag.Kind() == "undefined" {
			flag = js.StringValue(model.FlagDefault)
		}
		read, write, known := jsOpenFlags(flag)
		if !known {
			out.Resolution.Reason = "unsupported JavaScript filesystem open flags"
		}
		if read {
			add(engine.KindFSRead, 0, false)
		}
		if write {
			add(engine.KindFSWrite, 0, false)
		}
	}
	// Source selectors describe copied content or the old path of a rename.
	// Join after collecting effects so YAML selector order cannot drop taint.
	for i := range out.Binding.Effects {
		effect := &out.Binding.Effects[i]
		if effect.Kind == engine.KindFSWrite {
			effect.Taint = effect.Taint.Join(sourceTaint)
			out.Binding.Derivations[i].Effect = *effect
		}
	}
	for _, predicate := range model.Destructive {
		value := jsOption(options, predicate.Option)
		active, known := value.Boolean()
		if value.Kind() == "undefined" {
			known = true
		}
		if !known {
			out.Resolution.Reason = "unknown JavaScript deletion options retain possible destructive behavior"
		}
		if active || !known {
			out.Binding.Destructive = append(out.Binding.Destructive, kb.Destructive{Command: name, Spec: predicate.Option, Class: predicate.Class, Reason: predicate.Reason})
			out.Binding.Destructiveness = out.Binding.Destructiveness.Join(predicate.Class.Severity())
			loc := call.Loc
			if model.Options < len(call.ArgLocs) && model.Options >= 0 {
				loc = call.ArgLocs[model.Options]
			}
			// The option qualifies the call's modeled effects; a flag-derived
			// effect of another kind is not deletion evidence.
			for i := range out.Binding.Derivations {
				kind := out.Binding.Derivations[i].Effect.Kind
				if !slices.ContainsFunc(model.Effects, func(e kb.JSEffect) bool { return e.Kind == kind }) {
					continue
				}
				out.Binding.Derivations[i].Atoms = append(out.Binding.Derivations[i].Atoms, engine.Atom{Kind: engine.AtomLiteral, Text: predicate.Option, Loc: &loc})
			}
		}
	}
	// Significant chmod modes remain conservative until #33.
	if model.ModeArg >= 0 {
		mode, known := jsArg(args, model.ModeArg).Number()
		if text, ok := jsArg(args, model.ModeArg).String(); ok {
			mode, known = jsOctalMode(text)
		}
		if !known || mode < 0 || mode > 0777 || math.Trunc(mode) != mode {
			out.Resolution.Reason = "JavaScript permission mode requires destructive classification"
		}
	}
	if model.Return == "undefined" {
		out.Resolution.Value = js.UndefinedValue()
	}
	if model.Style == "promise" {
		out.Resolution.Value = js.PromiseValue(out.Resolution.Value)
	}
	if model.Style == "callback" {
		out.Resolution.Value = js.UndefinedValue()
		out.Resolution.Reason = "JavaScript filesystem callback execution is unmodelled"
	}
	if slices.ContainsFunc(model.Effects, func(e kb.JSEffect) bool { return e.Target == "prefix" }) {
		out.Binding.Notes = append(out.Binding.Notes, "mkdtemp creates a path with an unknown suffix; target widened to any path")
	}
	out.Binding.Destructiveness = out.Binding.Destructiveness.Join(engine.ComputeDestructiveness(out.Binding.Effects))
	out.Resolution.Effects = out.Binding.Effects
	out.Resolution.Derivations = out.Binding.Derivations
	if out.Resolution.Reason != "" {
		out.Binding.Conservative = true
		out.Binding.Notes = append(out.Binding.Notes, out.Resolution.Reason)
	}
	return out
}

func jsReadTaint(taint engine.Taint, target engine.Scope) engine.Taint {
	taint = taint.Join(engine.TaintOf(engine.TaintFileSystem))
	if target.IsTop() {
		return taint.Join(engine.TaintOf(engine.TaintSecret))
	}
	for _, path := range target.Targets() {
		if engine.SecretPath(path) {
			return taint.Join(engine.TaintOf(engine.TaintSecret))
		}
	}
	return taint
}

func jsArg(args []js.Value, index int) js.Value {
	if index < 0 || index >= len(args) {
		return js.Value{}
	}
	return args[index]
}

func jsOption(options js.Value, key string) js.Value {
	if options.Kind() == "undefined" || options.Kind() == "null" || options.Kind() == "string" || options.Kind() == "number" {
		return js.UndefinedValue()
	}
	value, ok := options.Property(key)
	if !ok {
		return js.Value{}
	}
	return value
}

func jsEvidence(value js.Value) string {
	if text, ok := value.String(); ok && len(text) <= 4096 {
		return text
	}
	return "js:" + value.Kind()
}
