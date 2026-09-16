package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SchemaVersion tags the frozen JSON schema of Report and Effect. Consumers and
// golden fixtures pin to this value.
const SchemaVersion = "effect-ir/v1"

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

// Normalize canonicalises the report: effects that share a kind and a mode are
// merged with join (unioning targets and taint, joining certainty), the
// destructiveness summary is recomputed, and every slice is sorted. Two reports
// built from the same effects normalise to byte-identical JSON.
func (r *Report) Normalize() {
	if r.SchemaVersion == "" {
		r.SchemaVersion = SchemaVersion
	}
	merged := make([]Effect, 0, len(r.Effects))
	index := make(map[string]int, len(r.Effects))
	for _, e := range r.Effects {
		k := string(e.Kind) + "|" + string(e.Mode)
		if i, ok := index[k]; ok {
			if joined, ok := merged[i].Join(e); ok {
				merged[i] = joined
			}
			continue
		}
		index[k] = len(merged)
		merged = append(merged, e)
	}
	r.Effects = merged
	// Merging under join changes the merged effect's Key, so re-point every
	// why-trace at the effect it now explains; otherwise WhyGaps would report
	// a spurious gap for a fully explained (merged) effect.
	keyByMode := make(map[string]string, len(merged))
	for _, e := range merged {
		keyByMode[string(e.Kind)+"|"+string(e.Mode)] = e.Key()
	}
	r.Why = remapWhy(r.Why, keyByMode)
	r.Destructiveness = ComputeDestructiveness(r.Effects)
	r.Sort()
}

// remapWhy re-points why-traces at the effects Normalize merged them into.
// Traces are matched by the (kind, mode) pair Normalize merges on, so a trace
// recorded for a narrower target still explains the merged effect; traces that
// land on the same effect are combined. A trace whose kind/mode matches no
// effect is left untouched. The result is order-stable for a report that is
// already normalised, so Normalize is idempotent.
func remapWhy(why []WhyTrace, keyByMode map[string]string) []WhyTrace {
	if len(why) == 0 {
		return why
	}
	merged := make(map[string]*WhyTrace, len(why))
	order := make([]string, 0, len(why))
	for _, w := range why {
		key := w.Effect
		if nk, ok := keyByMode[effectKindMode(key)]; ok {
			key = nk
		}
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
