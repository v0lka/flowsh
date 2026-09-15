package engine

import (
	"fmt"
	"sort"
	"strings"
)

// ===========================================================================
// Provenance: source classes and attacker influence
// ===========================================================================

// SourceClass names the origin class of a value observed by the taint flow. The
// four classes are exactly those the analysis distinguishes: untrusted external
// content, the process environment, file content, and statically-known
// literals. Literal is the only trusted class; the others are progressively
// attacker-influenced.
type SourceClass string

const (
	// SourceUntrustedContent is content the attacker can steer directly:
	// network responses, prompt text, stdin of a pipeline fed by an untrusted
	// producer.
	SourceUntrustedContent SourceClass = "UntrustedContent"
	// SourceEnv is the process environment.
	SourceEnv SourceClass = "Env"
	// SourceFile is file content.
	SourceFile SourceClass = "File"
	// SourceLiteral is a statically-known literal: trusted by construction.
	SourceLiteral SourceClass = "Literal"
)

// SourceClasses lists every source class, in canonical order (most
// attacker-influenced first).
var SourceClasses = []SourceClass{SourceUntrustedContent, SourceEnv, SourceFile, SourceLiteral}

// Valid reports whether c is a defined source class.
func (c SourceClass) Valid() bool {
	switch c {
	case SourceUntrustedContent, SourceEnv, SourceFile, SourceLiteral:
		return true
	}
	return false
}

// Influence is the lattice of attacker control over a value: how far an
// adversary can steer it.
//
//	None ⊑ Indirect ⊑ Direct
//
// Join (⊔) is the least upper bound (max).
type Influence int

const (
	// InfluenceNone means the value is not attacker-controlled.
	InfluenceNone Influence = iota
	// InfluenceIndirect means the value is attacker-controlled only insofar as
	// its container is (the environment or a file the attacker could have
	// written).
	InfluenceIndirect
	// InfluenceDirect means the value is directly attacker-controlled.
	InfluenceDirect
)

var influenceNames = [...]string{"None", "Indirect", "Direct"}

// Valid reports whether i is a defined influence level.
func (i Influence) Valid() bool { return i >= InfluenceNone && i <= InfluenceDirect }

// String returns the canonical name of the influence level.
func (i Influence) String() string {
	if !i.Valid() {
		return fmt.Sprintf("Influence(%d)", int(i))
	}
	return influenceNames[i]
}

// Join returns the least upper bound (⊔) of i and o.
func (i Influence) Join(o Influence) Influence {
	if o > i {
		return o
	}
	return i
}

// LessOrEqual reports whether i ⊑ o.
func (i Influence) LessOrEqual(o Influence) bool { return i <= o }

// Severity maps attacker influence onto the shared severity scale (the
// destructiveness lattice) so it can be folded into a composite score.
func (i Influence) Severity() Destructiveness {
	switch i {
	case InfluenceDirect:
		return DestructHigh
	case InfluenceIndirect:
		return DestructMedium
	default:
		return DestructNone
	}
}

// Influence returns the attacker control over a value of class c.
func (c SourceClass) Influence() Influence {
	switch c {
	case SourceUntrustedContent:
		return InfluenceDirect
	case SourceEnv, SourceFile:
		return InfluenceIndirect
	default:
		return InfluenceNone
	}
}

// Labels returns the taint a value of class c carries: the core labels the
// analysis attaches to a value whose provenance is class c.
func (c SourceClass) Labels() Taint {
	switch c {
	case SourceUntrustedContent:
		return TaintOf(TaintUntrusted)
	case SourceEnv:
		return TaintOf(TaintEnv)
	case SourceFile:
		return TaintOf(TaintFileSystem)
	default:
		return TaintBottom()
	}
}

// Provenance is the source-class summary of the data an effect consumes: the
// set of provenance classes a value flows from. It is what the taint flow
// produces before the classes are folded into taint labels and attacker
// influence.
type Provenance struct {
	Sources []SourceClass `json:"sources,omitempty"`
}

// NewProvenance returns a provenance over the given classes, normalised
// (sorted, de-duplicated, empty entries dropped).
func NewProvenance(classes ...SourceClass) Provenance {
	return Provenance{Sources: normaliseClasses(classes)}
}

func normaliseClasses(cs []SourceClass) []SourceClass {
	if len(cs) == 0 {
		return nil
	}
	tmp := make([]SourceClass, 0, len(cs))
	for _, c := range cs {
		if c != "" {
			tmp = append(tmp, c)
		}
	}
	if len(tmp) == 0 {
		return nil
	}
	sort.Slice(tmp, func(i, j int) bool { return tmp[i] < tmp[j] })
	w := 1
	for i := 1; i < len(tmp); i++ {
		if tmp[i] != tmp[w-1] {
			tmp[w] = tmp[i]
			w++
		}
	}
	return tmp[:w]
}

// Has reports whether the provenance includes class c.
func (p Provenance) Has(c SourceClass) bool {
	for _, s := range p.Sources {
		if s == c {
			return true
		}
	}
	return false
}

// Taint returns the join of the taint labels of every source class.
func (p Provenance) Taint() Taint {
	t := TaintBottom()
	for _, c := range p.Sources {
		t = t.Join(c.Labels())
	}
	return t
}

// Influence returns the greatest attacker influence over the source classes.
func (p Provenance) Influence() Influence {
	i := InfluenceNone
	for _, c := range p.Sources {
		i = i.Join(c.Influence())
	}
	return i
}

// Trusted reports whether the provenance is entirely literal (no attacker
// influence at all).
func (p Provenance) Trusted() bool { return p.Influence() == InfluenceNone }

// ===========================================================================
// Taint flow: reading influence off an effect
// ===========================================================================

// Flow is one taint-flow edge: a value read from a source class reaches an
// effect. It is the unit the taint analysis produces before effects are folded
// into a score.
type Flow struct {
	Source SourceClass `json:"source"`
	Effect Effect      `json:"effect"`
}

// InfluenceOf returns the attacker influence over the data an effect consumes,
// read off its taint labels (⊤ taint is direct control).
func InfluenceOf(e Effect) Influence {
	switch {
	case e.Taint.IsTop():
		return InfluenceDirect
	case e.Taint.Contains(TaintUntrusted) || e.Taint.Contains(TaintUserInput):
		return InfluenceDirect
	case e.Taint.Contains(TaintEnv) || e.Taint.Contains(TaintNetwork) || e.Taint.Contains(TaintProcess):
		return InfluenceIndirect
	case e.Taint.Contains(TaintFileSystem):
		return InfluenceIndirect
	default:
		return InfluenceNone
	}
}

// MaxInfluence folds the influence of every effect with join (max).
func MaxInfluence(effects []Effect) Influence {
	i := InfluenceNone
	for _, e := range effects {
		i = i.Join(InfluenceOf(e))
	}
	return i
}

// ===========================================================================
// Secrets and exfiltration
// ===========================================================================

// secretPathMarkers are substrings that mark a well-known credential or secret
// location. Matching is case-insensitive and substring-based, so both ~/.aws and
// /root/.aws match, and it stays robust across path spellings.
var secretPathMarkers = []string{
	".ssh", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys",
	".aws", ".gnupg", ".netrc", ".pgpass", ".my.cnf", ".git-credentials",
	".kube/config", ".docker/config.json", ".npmrc", ".pypirc", ".htpasswd",
	".bash_history", ".zsh_history", ".env", "/etc/shadow", "/etc/gshadow",
	"/etc/sudoers", ".pem", "keystore", "credentials", "secrets",
}

// SecretPath reports whether p names (or lies under) a well-known credential or
// secret location.
func SecretPath(p string) bool {
	if p == "" {
		return false
	}
	lp := strings.ToLower(p)
	for _, m := range secretPathMarkers {
		if strings.Contains(lp, m) {
			return true
		}
	}
	return false
}

// anySecretTarget reports whether s includes at least one secret path.
func anySecretTarget(s Scope) bool {
	for _, t := range s.Targets() {
		if SecretPath(t) {
			return true
		}
	}
	return false
}

// IsSecretRead reports whether e obtains credential/secret material: either a
// CredAccess effect, or a read of a secret-bearing path or secret-tainted data.
func IsSecretRead(e Effect) bool {
	switch e.Kind {
	case KindCredAccess:
		return true
	case KindFSRead, KindFSMeta:
		return e.Taint.Contains(TaintSecret) || anySecretTarget(e.Target)
	default:
		return false
	}
}

// IsEgressSink reports whether e carries data off-host: a NetEgress whose payload
// is tainted (its provenance is known, so content actually leaves the host).
func IsEgressSink(e Effect) bool {
	if e.Kind != KindNetEgress {
		return false
	}
	return !e.Taint.IsBottom()
}

// Exfil is one credential-exfiltration finding: a secret read paired with an
// outbound sink carrying tainted data — CredAccess/FSRead(secret) ⊗
// NetEgress(tainted).
type Exfil struct {
	// Source is the secret read: a CredAccess effect, or an FSRead/FSMeta of a
	// secret-bearing path.
	Source Effect `json:"source"`
	// Sink is the tainted egress that carries the read data out.
	Sink Effect `json:"sink"`
}

// DetectExfil returns every (secret source, tainted egress) pairing found in
// effects, in canonical (deterministic) order.
func DetectExfil(effects []Effect) []Exfil {
	var sources, sinks []Effect
	for _, e := range effects {
		if IsSecretRead(e) {
			sources = append(sources, e)
		}
		if IsEgressSink(e) {
			sinks = append(sinks, e)
		}
	}
	var out []Exfil
	for _, s := range sources {
		for _, k := range sinks {
			out = append(out, Exfil{Source: s, Sink: k})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source.Key() != out[j].Source.Key() {
			return out[i].Source.Key() < out[j].Source.Key()
		}
		return out[i].Sink.Key() < out[j].Sink.Key()
	})
	return out
}
