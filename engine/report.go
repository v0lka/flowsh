package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SchemaVersion tags the frozen JSON schema of Report and Effect. Consumers and
// golden fixtures pin to this value.
//
// v1 was the starting effect schema. v2 adds the additive, optional
// `netFlow` field: an effect that is the sink of a network data flow (a code
// execution reached by network content, or a filesystem write of downloaded
// content) carries the flow role, so a report can assert the flow rather than
// leave a consumer to infer it from the co-occurrence of a NetEgress and a
// sink. An effect with no network flow serialises exactly as in v1.
const SchemaVersion = "effect-ir/v2"

// SourceLoc is a frontend-agnostic source location. It deliberately carries no
// frontend-specific node handle, only a file/line/column triple that any
// frontend can produce and any consumer can render.
type SourceLoc struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	Col  int    `json:"col,omitempty"`
}

// WhyStep is a single inference step of a why-trace: the rule that fired and the
// premises it consumed. Premises are free-form tokens the frontend defines
// (call ids, argument slices, other Effect.Key() values); the core only keeps
// them ordered and stable.
type WhyStep struct {
	Rule     string     `json:"rule"`
	Premises []string   `json:"premises,omitempty"`
	Note     string     `json:"note,omitempty"`
	Loc      *SourceLoc `json:"loc,omitempty"`
}

// WhyTrace explains how a single effect was derived. Effect is the Effect.Key()
// of the explained effect; Because is the ordered chain of steps that produced
// it (closest step first).
type WhyTrace struct {
	Effect  string    `json:"effect"`
	Because []WhyStep `json:"because"`
}

// Report is the frozen analysis output. It is plain data, serialisable to JSON,
// and carries no reference to any frontend type.
type Report struct {
	SchemaVersion   string          `json:"schemaVersion"`
	Root            string          `json:"root,omitempty"`
	Effects         []Effect        `json:"effects"`
	Destructiveness Destructiveness `json:"destructiveness"`
	Why             []WhyTrace      `json:"why,omitempty"`
	Notes           []string        `json:"notes,omitempty"`
}

// NewReport returns an empty report stamped with the current schema version.
func NewReport() *Report {
	return &Report{SchemaVersion: SchemaVersion, Effects: []Effect{}}
}

// KindDestructiveness maps an effect kind to its worst-case destructiveness
// level. The mapping is global (target- and taint-independent) so that it is
// stable and cheap to reason about.
func KindDestructiveness(k EffectKind) Destructiveness {
	switch k {
	case KindCodeExec, KindCredAccess:
		return DestructCritical
	case KindPrivEsc, KindPersist, KindFSWrite, KindProcSignal:
		return DestructHigh
	case KindFSMeta, KindEnvWrite, KindNetEgress, KindProcSpawn, KindIPC:
		return DestructMedium
	case KindFSRead, KindEnvRead, KindNetIngress, KindStdio:
		return DestructLow
	default:
		return DestructNone
	}
}

// ComputeDestructiveness folds the destructiveness of every effect with join
// (max), yielding the overall severity of a set of effects.
func ComputeDestructiveness(effects []Effect) Destructiveness {
	d := DestructBottom()
	for _, e := range effects {
		d = d.Join(KindDestructiveness(e.Kind))
	}
	return d
}

// Sort orders the report's slices into their canonical, deterministic order.
func (r *Report) Sort() {
	sort.SliceStable(r.Effects, func(i, j int) bool {
		return r.Effects[i].Key() < r.Effects[j].Key()
	})
	sort.SliceStable(r.Why, func(i, j int) bool {
		if r.Why[i].Effect != r.Why[j].Effect {
			return r.Why[i].Effect < r.Why[j].Effect
		}
		return whyFingerprint(r.Why[i]) < whyFingerprint(r.Why[j])
	})
	sort.Strings(r.Notes)
}

// normalizeKey is the identity Normalize merges on: two effects join exactly
// when their kind, their mode and their network-flow role agree. The flow role
// belongs in the key because it is per-effect evidence, not a property of a
// kind: merging a write tagged as carrying downloaded content (FlowIngest) with
// an unrelated untagged write of the same kind and mode would promote the
// merged effect to the tagged role and thereby claim the unrelated write's
// targets as download sinks.
func normalizeKey(e Effect) string {
	return string(e.Kind) + "|" + string(e.Mode) + "|" + string(e.NetFlow)
}

// Normalize canonicalises the report: effects that share a kind, a mode and a
// network-flow role are merged with join (unioning targets and taint, joining
// certainty), the destructiveness summary is recomputed, and every slice is
// sorted. Two reports built from the same effects normalise to byte-identical
// JSON.
func (r *Report) Normalize() {
	if r.SchemaVersion == "" {
		r.SchemaVersion = SchemaVersion
	}
	orig := r.Effects
	// group[i] is the index in merged of the effect the i-th input effect was
	// merged into; it is what re-points the why-traces afterwards.
	group := make([]int, len(orig))
	merged := make([]Effect, 0, len(orig))
	index := make(map[string]int, len(orig))
	for i, e := range orig {
		k := normalizeKey(e)
		if gi, ok := index[k]; ok {
			if joined, ok := merged[gi].Join(e); ok {
				merged[gi] = joined
				group[i] = gi
				continue
			}
			// Unreachable while normalizeKey covers every field Join compares;
			// if it ever were reached, the effect is kept as its own group
			// rather than silently dropped.
		}
		index[k] = len(merged)
		group[i] = len(merged)
		merged = append(merged, e)
	}
	r.Effects = merged
	// Merging under join changes the merged effect's Key, so re-point every
	// why-trace at the effect it now explains; otherwise WhyGaps would report
	// a spurious gap for a fully explained (merged) effect.
	r.Why = remapWhy(r.Why, newWhyRemap(orig, merged, group))
	r.Destructiveness = ComputeDestructiveness(r.Effects)
	r.Sort()
}

// whyRemap resolves the key a why-trace carries onto the key of the effect
// Normalize merged it into.
//
// The exact table maps every pre-merge effect key to its merged counterpart and
// is what makes the remap precise now that the merge key carries the flow role:
// two effects of the same kind and mode but different roles merge into two
// distinct effects, so a kind/mode-only lookup could no longer tell them apart.
//
// The kind/mode table is the fallback for a trace whose key names no known
// pre-merge effect (a hand-built report). It is populated only when a kind/mode
// pair identifies exactly one merged effect, so it can never pick the wrong one
// of two flow-split effects. A key left ambiguous by both tables is not
// re-pointed — the trace keeps the key it had.
type whyRemap struct {
	exact      map[string]string
	byKindMode map[string]string
}

// newWhyRemap builds the remap table for a Normalize pass: orig are the effects
// before the merge, merged the effects after it, and group[i] the merged index
// the i-th original effect went into.
func newWhyRemap(orig, merged []Effect, group []int) whyRemap {
	rm := whyRemap{
		exact:      make(map[string]string, len(orig)),
		byKindMode: make(map[string]string, len(merged)),
	}
	// A pre-merge key is ambiguous when two effects that carry it merged into
	// different effects (they differ only in a field the key does not spell
	// out, i.e. their network-flow role). Such a key is dropped from the exact
	// table: the trace cannot be attributed to one of the two.
	ambiguous := make(map[string]bool)
	for i, e := range orig {
		k := e.Key()
		want := merged[group[i]].Key()
		if prev, ok := rm.exact[k]; ok {
			if prev != want {
				ambiguous[k] = true
			}
			continue
		}
		rm.exact[k] = want
	}
	for k := range ambiguous {
		delete(rm.exact, k)
	}
	dup := make(map[string]bool, len(merged))
	for _, e := range merged {
		km := effectKindMode(e.Key())
		if _, ok := rm.byKindMode[km]; ok {
			dup[km] = true
			continue
		}
		rm.byKindMode[km] = e.Key()
	}
	for k := range dup {
		delete(rm.byKindMode, k)
	}
	return rm
}

// resolve returns the merged-effect key a trace key now names.
func (rm whyRemap) resolve(key string) string {
	if k, ok := rm.exact[key]; ok {
		return k
	}
	if k, ok := rm.byKindMode[effectKindMode(key)]; ok {
		return k
	}
	return key
}

// remapWhy re-points why-traces at the effects Normalize merged them into, so
// that a trace recorded for a narrower target still explains the merged effect;
// traces that land on the same effect are combined. A trace no table resolves is
// left untouched. The result is order-stable for a report that is already
// normalised, so Normalize is idempotent.
func remapWhy(why []WhyTrace, rm whyRemap) []WhyTrace {
	if len(why) == 0 {
		return why
	}
	merged := make(map[string]*WhyTrace, len(why))
	order := make([]string, 0, len(why))
	for _, w := range why {
		key := rm.resolve(w.Effect)
		m, ok := merged[key]
		if !ok {
			m = &WhyTrace{Effect: key}
			merged[key] = m
			order = append(order, key)
		}
		m.Because = append(m.Because, w.Because...)
	}
	out := make([]WhyTrace, 0, len(order))
	for _, key := range order {
		m := merged[key]
		m.Because = dedupSteps(m.Because)
		out = append(out, *m)
	}
	return out
}

// effectKindMode extracts the "kind|mode" prefix of an Effect.Key, the pair
// Normalize merges on. A key without a mode segment (unexpected) is returned
// unchanged so the trace is preserved rather than dropped.
func effectKindMode(key string) string {
	i := strings.IndexByte(key, '|')
	if i < 0 {
		return key
	}
	j := strings.IndexByte(key[i+1:], '|')
	if j < 0 {
		return key
	}
	return key[:i+1+j]
}

// Validate reports whether the report is well-formed: a schema version is set,
// every effect is valid, and every why-trace references a non-empty effect key.
func (r *Report) Validate() error {
	if r.SchemaVersion == "" {
		return fmt.Errorf("engine: report schemaVersion is empty")
	}
	for i := range r.Effects {
		if err := r.Effects[i].Validate(); err != nil {
			return fmt.Errorf("engine: effects[%d]: %w", i, err)
		}
	}
	for i := range r.Why {
		if r.Why[i].Effect == "" {
			return fmt.Errorf("engine: why[%d]: empty effect key", i)
		}
	}
	return nil
}

// Encode validates the report and returns its canonical indented JSON.
func (r *Report) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(r, "", "  ")
}

func whyFingerprint(w WhyTrace) string {
	var b strings.Builder
	for _, s := range w.Because {
		b.WriteString(s.Rule)
		b.WriteByte('(')
		b.WriteString(strings.Join(s.Premises, ","))
		b.WriteString(");")
	}
	return b.String()
}
