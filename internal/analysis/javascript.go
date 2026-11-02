package analysis

import (
	"slices"
	"strings"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/js"
)

// maxJSMetadata caps each JS report metadata collection.
const maxJSMetadata = 1024

// analyzeJS evaluates src with the injected JS binder.
func (a *Analyzer) analyzeJS(src string, opts Options) *Report {
	jsCtx, validCtx := jsContext(opts.JavaScript)
	var (
		agg         aggregatedResolution
		calls       []CommandCall
		seenCalls   = map[string]bool{}
		destructive []DestructiveFinding
		notes       []string
		sites       = map[engine.SourceLoc]bool{}
		kbDestruct  engine.Destructiveness
	)
	resolver := func(call js.Call) js.Resolution {
		var bound bind.JSResult
		if a != nil && a.binder != nil {
			bound = a.binder.BindJS(call, jsCtx)
		}
		if call.Kind == "module" || call.Kind == "property" {
			return bound.Resolution
		}
		if max(len(sites), len(calls), len(notes), len(destructive)) >= maxJSMetadata {
			return js.Resolution{Handled: true, Reason: "JavaScript report metadata limit reached", MayThrow: true}
		}
		sites[call.Loc] = true
		res := bound.Binding.Resolution
		if !bound.Resolution.Handled {
			res = bind.Resolution{Invoked: call.Callee, Kind: bind.ResolveUnknown}
		}
		agg.observe(res)
		args := make([]string, len(call.Args))
		for i, arg := range call.Args {
			args[i] = arg.Projection()
		}
		calls = appendCall(calls, seenCalls, CommandCall{Invoked: call.Callee, Resolved: res.Name, Args: args})
		kbDestruct = kbDestruct.Join(bound.Binding.Destructiveness)
		found := destructiveFindings(bound.Binding.Destructive)
		destructive = append(destructive, found[:min(len(found), maxJSMetadata-len(destructive))]...)
		bn := bound.Binding.Notes
		notes = append(notes, bn[:min(len(bn), maxJSMetadata-len(notes))]...)
		return bound.Resolution
	}
	res := js.AnalyzeWith(sourceName(opts.Root, "script"), src, resolver)
	rep := newReport(LangJavaScript, src, opts.Root)
	rep.Effects = normalizeEffects(res.Effects)
	rep.Score = engine.ScoreEffects(rep.Effects)
	rep.Score.Destructiveness = rep.Score.Destructiveness.Join(kbDestruct)
	rep.Score.Grade = rep.Score.Grade.Join(kbDestruct)
	rep.Destructiveness = rep.Score.Destructiveness
	rep.Why = buildWhy(rep.Effects, res.Derivations, engine.Atom{Kind: engine.AtomLiteral, Text: "js-opaque"})
	rep.Top, rep.Conservative, rep.Reason = res.Top, res.Conservative, res.Reason
	rep.Commands = len(sites)
	rep.Resolution = agg.resolution()
	rep.CommandCalls = calls
	rep.Destructive = normalizeDestructive(destructive)
	rep.Notes = mergeNotes(notes, nil)
	if !validCtx {
		rep.Notes = append(rep.Notes, "invalid JavaScript abstract context; home and cwd treated as unknown")
	}
	if len(rep.Effects) > 0 {
		// Bound JS targets skip the shell canonical filters.
		rep.Canonical = &Canonical{Effects: slices.Clone(rep.Effects), Key: canonicalKey(rep.Effects)}
	}
	return rep
}

// jsContext resolves the binder path context. An invalid
// caller context is reported as false and becomes unknown.
func jsContext(c *JavaScriptContext) (bind.JSContext, bool) {
	if c == nil {
		return bind.JSContext{Home: "/root", SymbolicHome: true}, true
	}
	if !validJSPath(c.Home) || !validJSPath(c.Cwd) {
		return bind.JSContext{}, false
	}
	return bind.JSContext{Home: c.Home, Cwd: c.Cwd}, true
}

// validJSPath accepts "" or an absolute path within the
// source-string limits.
func validJSPath(path string) bool {
	return path == "" || len(path) <= 65536 && !strings.ContainsRune(path, 0) && strings.HasPrefix(path, "/")
}
