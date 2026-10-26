package analysis

import (
	"strings"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/js"
)

const maxJSMetadata = 1024

func (a *Analyzer) analyzeJS(src string, opts Options) *Report {
	context := bind.JSContext{Home: "/root"}
	if opts.JavaScript != nil {
		context = bind.JSContext{Home: opts.JavaScript.Home, Cwd: opts.JavaScript.Cwd}
	}
	// Caller paths share the source-string limits.
	validContext := func(path string) bool {
		return len(path) <= 65536 && !strings.ContainsRune(path, 0) && (path == "" || strings.HasPrefix(path, "/"))
	}
	invalidContext := !validContext(context.Home) || !validContext(context.Cwd)
	if invalidContext {
		context = bind.JSContext{}
	}
	var agg aggregatedResolution
	calls := []CommandCall{}
	destructive := []DestructiveFinding{}
	notes := []string{}
	seenCalls := map[string]bool{}
	sites := map[engine.SourceLoc]bool{}
	severity := engine.DestructNone
	resolver := func(call js.Call) js.Resolution {
		var bound bind.JSResult
		if a != nil && a.binder != nil {
			bound = a.binder.BindJS(call, context)
		}
		if call.Kind == "module" || call.Kind == "property" {
			return bound.Resolution
		}
		if len(sites) >= maxJSMetadata || len(calls) >= maxJSMetadata || len(notes) >= maxJSMetadata || len(destructive) >= maxJSMetadata {
			return js.Resolution{Handled: true, Reason: "JavaScript report metadata limit reached", MayThrow: true}
		}
		sites[call.Loc] = true
		resolution := bound.Binding.Resolution
		if !bound.Resolution.Handled {
			resolution = bind.Resolution{Invoked: call.Callee, Kind: bind.ResolveUnknown}
		}
		agg.observe(resolution)
		args := make([]string, len(call.Args))
		for i, arg := range call.Args {
			args[i] = arg.Projection()
		}
		cc := CommandCall{Invoked: call.Callee, Resolved: resolution.Name, Args: args}
		key := cc.identity()
		if !seenCalls[key] {
			seenCalls[key] = true
			calls = append(calls, cc)
		}
		severity = severity.Join(bound.Binding.Destructiveness)
		for _, finding := range bound.Binding.Destructive {
			if len(destructive) >= maxJSMetadata {
				break
			}
			destructive = append(destructive, DestructiveFinding{Command: finding.Command, Spec: finding.Spec, Class: string(finding.Class), Reason: finding.Reason})
		}
		for _, note := range bound.Binding.Notes {
			if len(notes) >= maxJSMetadata {
				break
			}
			notes = append(notes, note)
		}
		return bound.Resolution
	}
	res := js.AnalyzeWith(sourceName(opts.Root, "script"), src, resolver)
	rep := newReport(LangJavaScript, src, opts.Root)
	rep.Effects = normalizeEffects(res.Effects)
	rep.Score = engine.ScoreEffects(rep.Effects)
	rep.Score.Destructiveness = rep.Score.Destructiveness.Join(severity)
	rep.Score.Grade = rep.Score.Grade.Join(severity)
	rep.Destructiveness = rep.Score.Destructiveness
	rep.Why = buildWhy(rep.Effects, res.Derivations, engine.Atom{Kind: engine.AtomLiteral, Text: "js-opaque"})
	rep.Top, rep.Conservative, rep.Reason = res.Top, res.Conservative, res.Reason
	rep.Commands = len(sites)
	rep.Resolution = agg.resolution()
	rep.CommandCalls = calls
	rep.Destructive = normalizeDestructive(destructive)
	rep.Notes = mergeNotes(notes, nil)
	if invalidContext {
		rep.Notes = append(rep.Notes, "invalid JavaScript abstract context; home and cwd treated as unknown")
	}
	if len(rep.Effects) > 0 {
		rep.Canonical = &Canonical{Effects: rep.Effects, Key: canonicalKey(rep.Effects)}
	}
	return rep
}
