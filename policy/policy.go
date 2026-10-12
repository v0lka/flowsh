// Package policy evaluates flowsh reports without executing their input or
// changing their analysis. Configuration comes from the embedding application,
// never from the command being analysed. An Allow decision means only that the
// configured rules did not object; it is not a proof of safety or confinement.
package policy

import (
	"fmt"
	"maps"
	"slices"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
)

// Action is a policy outcome, ordered conceptually as Allow < Review < Deny.
// Its zero value is invalid and never grants permission.
type Action string

const (
	Allow  Action = "allow"
	Review Action = "review"
	Deny   Action = "deny"
)

// Config selects actions for report signals. Empty scalar actions default to
// Deny for Unknown and Exfiltration, Review for Conservative and Cradle, and
// Allow for Ingest. Unknown and Conservative accept only Review or Deny.
// Unlisted effect kinds and grades impose no additional restriction. An Allow
// entry disables that rule; it cannot override another rule's Review or Deny.
type Config struct {
	Unknown      Action
	Conservative Action
	Exfiltration Action
	Cradle       Action
	Ingest       Action
	Effects      map[engine.EffectKind]Action
	Grades       map[engine.Destructiveness]Action
}

// Policy is an immutable, reusable set of rules. Construct it with New; a nil
// or zero Policy denies evaluation. It is safe for concurrent use provided the
// caller does not modify the report during evaluation.
type Policy struct {
	config Config
	ready  bool
}

// Match identifies a rule that imposed a restriction. Code contains only a
// fixed signal name or a validated effect kind/grade, never command text.
type Match struct {
	Code   string `json:"code"`
	Action Action `json:"action"`
}

// Decision is the strongest matched action and all restrictive matches, sorted
// by code. Review requires inspection by the consumer; it is not permission to
// execute. The original report remains the source of evidence and uncertainty.
type Decision struct {
	Action  Action  `json:"action"`
	Matches []Match `json:"matches,omitempty"`
}

// Allowed reports whether the policy explicitly returned Allow. In particular,
// a zero Decision, Review, and Deny all return false.
func (d Decision) Allowed() bool { return d.Action == Allow }

// New validates and copies the configuration. It performs no I/O and installs
// no global rules. Callers must handle construction errors before execution.
func New(c Config) (*Policy, error) {
	for _, field := range []struct {
		name       string
		value      *Action
		fallback   Action
		incomplete bool
	}{
		{"unknown", &c.Unknown, Deny, true},
		{"conservative", &c.Conservative, Review, true},
		{"exfiltration", &c.Exfiltration, Deny, false},
		{"cradle", &c.Cradle, Review, false},
		{"ingest", &c.Ingest, Allow, false},
	} {
		if *field.value == "" {
			*field.value = field.fallback
		}
		if !validAction(*field.value) || (field.incomplete && *field.value == Allow) {
			return nil, fmt.Errorf("policy: invalid %s action", field.name)
		}
	}
	for kind, action := range c.Effects {
		if !kind.Valid() || !validAction(action) {
			return nil, fmt.Errorf("policy: invalid effect rule")
		}
	}
	for grade, action := range c.Grades {
		if !grade.Valid() || !validAction(action) {
			return nil, fmt.Errorf("policy: invalid grade rule")
		}
	}
	c.Effects = maps.Clone(c.Effects)
	c.Grades = maps.Clone(c.Grades)
	return &Policy{config: c, ready: true}, nil
}

// Evaluate applies all rules without mutating r. Missing, incompatible, invalid,
// or uncovered reports always produce Deny, independently of configuration.
// Use a report obtained directly from api after checking its analysis error;
// validation is not authentication of a report supplied by an untrusted party.
// Unknown includes both Report.Top and Report.HasTop(), so dropping the Top flag
// cannot hide an unbounded CodeExec effect. No command-name or source-text
// matching is performed.
func (p *Policy) Evaluate(r *api.Report) Decision {
	if p == nil || !p.ready {
		return denied("invalid_policy")
	}
	if r == nil || r.Tool != api.ToolName || r.ToolVersion != api.ToolVersion ||
		r.SchemaVersion != api.SchemaVersion || r.Validate() != nil ||
		!r.Score.Grade.Valid() || !r.Covered() {
		return denied("invalid_report")
	}
	switch api.Lang(r.Lang) {
	case api.LangBash, api.LangPOSIX, api.LangPowerShell:
	default:
		return denied("invalid_report")
	}
	matched := make(map[string]Action)
	add := func(code string, action Action, applies bool) {
		if applies && (action == Review || action == Deny) {
			matched[code] = action
		}
	}
	add("unknown", p.config.Unknown, r.Top || r.HasTop())
	add("conservative", p.config.Conservative, r.Conservative)
	add("exfiltration", p.config.Exfiltration, len(r.Score.ExfilPairs) > 0)
	add("cradle", p.config.Cradle, len(r.Score.CradleFlows) > 0)
	add("ingest", p.config.Ingest, len(r.Score.IngestFlows) > 0)
	add("grade:"+r.Score.Grade.String(), p.config.Grades[r.Score.Grade], true)
	for _, effect := range r.Effects {
		add("effect:"+string(effect.Kind), p.config.Effects[effect.Kind], true)
	}
	result := Decision{Action: Allow}
	for _, code := range slices.Sorted(maps.Keys(matched)) {
		action := matched[code]
		result.Matches = append(result.Matches, Match{Code: code, Action: action})
		if result.Action == Allow || action == Deny {
			result.Action = action
		}
	}
	return result
}

func denied(code string) Decision {
	return Decision{Action: Deny, Matches: []Match{{Code: code, Action: Deny}}}
}

func validAction(action Action) bool {
	return action == Allow || action == Review || action == Deny
}
