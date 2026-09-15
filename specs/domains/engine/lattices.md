# Lattices

## Role

The value lattices define the order and combination operators over every scalar and set value the IR carries: `Certainty`, `Scope`, `Taint`, `Destructiveness`, `Breadth`, `Irreversibility` and `Influence`. Every lattice has a least element `⊥` and a greatest element `⊤`, and — where meaningful — a join `⊔` (least upper bound) and meet `⊓` (greatest lower bound).

## Key Files

- `engine/lattice.go` — `Certainty`, `Destructiveness`, the shared `flatSet` shape, `Scope`, `Taint`, and the string-set helpers.
- `engine/score.go` — `Breadth` and `Irreversibility` (ordinal chains) and their `Severity` mappings.
- `engine/taint.go` — `Influence` (ordinal chain) and its `Severity` mapping.
- `engine/report_test.go` — `TestLatticeLaws` verifies idempotence, commutativity, associativity, absorption and the `⊥`/`⊤` identities for certainty, destructiveness, scope and taint.

## Behavior

### Common shape

Two structural shapes cover all seven lattices:

- **Ordinal chain** — a bounded integer with `Join = max`, `Meet = min`, `⊥ = 0` and `⊤ = n`. `Certainty`, `Destructiveness`, `Breadth`, `Irreversibility` and `Influence` are chains of this shape.
- **Flat set (powerset)** — `flatSet` is the powerset lattice over an open universe of strings plus a single maximal element `{arbitrary}`. `Scope` and `Taint` are this shape.

Each lattice also exposes `Valid`, `String`, and (except for the set lattices) `LessOrEqual`; the scoring lattices add a `Severity() Destructiveness` projection so every dimension is comparable on the shared severity scale.

### Certainty (chain, 5 levels)

`Certainty` models how strongly the analysis believes an effect occurs:

```
⊥ = Unknown ⊑ Unlikely ⊑ Possible ⊑ Likely ⊑ Certain = ⊤
```

| Constant | Ordinal | `⊥`/`⊤` | Meaning |
| --- | --- | --- | --- |
| `CertaintyUnknown` | 0 | `⊥` | no supporting evidence |
| `CertaintyUnlikely` | 1 | | weak evidence |
| `CertaintyPossible` | 2 | | plausible |
| `CertaintyLikely` | 3 | | strong evidence |
| `CertaintyCertain` | 4 | `⊤` | definitely occurs |

`Join = max`, `Meet = min`, `LessOrEqual` is `≤`. `CertaintyBottom()`/`CertaintyTop()` return `⊥`/`⊤`. JSON encodes as the canonical name (`"Certain"`) and decodes from either the name or the numeric ordinal.

### Destructiveness (chain, 5 levels)

`Destructiveness` is an ordinal severity of how hard an effect is to undo:

```
⊥ = None ⊑ Low ⊑ Medium ⊑ High ⊑ Critical = ⊤
```

| Constant | Ordinal | `⊥`/`⊤` | Meaning |
| --- | --- | --- | --- |
| `DestructNone` | 0 | `⊥` | no lasting impact |
| `DestructLow` | 1 | | reversible or read-only |
| `DestructMedium` | 2 | | recoverable with effort |
| `DestructHigh` | 3 | | hard to reverse |
| `DestructCritical` | 4 | `⊤` | irreversible / trust-breaking |

`Join = max`, `Meet = min`. `DestructBottom()`/`DestructTop()` return `⊥`/`⊤`. JSON encodes/decodes like `Certainty`.

### Flat set (`flatSet`)

`flatSet` is a flat (powerset) lattice over an open universe of strings with a single added maximal element `arbitrary` (`⊤`):

```
⊥        = ∅
⊤        = {arbitrary}
⊔ (join) = set union, ⊤ absorbing
⊓ (meet) = set intersection, ⊤ as identity
```

Elements are kept sorted and unique, so every representation — and hence every JSON encoding — is canonical (`sortedUnique` drops empty strings and de-duplicates).

```go
type flatSet struct {
	arbitrary bool
	elems     []string
}
```

### Scope (flat set)

`Scope` is the target-set lattice: the set of resources an effect may apply to — the `flatSet` lattice specialised to targets.

```
⊥        = ∅            (no target)
⊤        = {arbitrary}  (any target)
⊔        = set union
⊓        = set intersection
```

Constructors: `ScopeBottom()` (`⊥`), `ScopeTop()` (`⊤`), `ScopeOf(targets ...string)`. Operations: `Join`, `Meet`, `IsBottom`, `IsTop`, `Equal`, `LessOrEqual`, `Contains(target)`, `Targets()` (sorted; nil for `⊥` and `⊤`), `String` (`∅`, `⊤`, or `{a,b}`), and canonical JSON `{"targets":[…],"arbitrary":bool}`.

### Taint (flat set)

`Taint` is the taint-label lattice: the set of provenance labels carried by an effect's data. It shares the `flatSet` shape with `Scope`.

```
⊥        = ∅            (untainted)
⊤        = {arbitrary}  (any taint)
⊔        = set union
⊓        = set intersection
```

The core recognises these canonical labels (the universe is otherwise open-ended); frontends are expected to use them:

| Constant | Value |
| --- | --- |
| `TaintUntrusted` | `untrusted` |
| `TaintUserInput` | `userInput` |
| `TaintEnv` | `env` |
| `TaintNetwork` | `network` |
| `TaintSecret` | `secret` |
| `TaintFileSystem` | `fileSystem` |
| `TaintProcess` | `process` |

Constructors/operations mirror `Scope`: `TaintBottom()`, `TaintTop()`, `TaintOf(labels ...string)`, `Join`, `Meet`, `IsBottom`, `IsTop`, `Equal`, `LessOrEqual`, `Contains(label)`, `Labels()`, and canonical JSON `{"labels":[…],"arbitrary":bool}`.

### Breadth (chain, 5 levels)

`Breadth` classifies how wide an effect's target scope is, in the fixed order `exact < glob < $HOME < /`:

| Constant | Ordinal | `⊥`/`⊤` | Meaning | `Severity()` |
| --- | --- | --- | --- | --- |
| `BreadthNone` | 0 | `⊥` | no target at all | `DestructNone` |
| `BreadthExact` | 1 | | a single concrete target | `DestructLow` |
| `BreadthGlob` | 2 | | a wildcard pattern (contains `*`, `?` or `[`) | `DestructMedium` |
| `BreadthHome` | 3 | | the user's home directory or a home subtree (`$HOME`, `~`) | `DestructHigh` |
| `BreadthRoot` | 4 | `⊤` | `/` or the whole host | `DestructCritical` |

`Join = max`, `LessOrEqual` is `≤`. `Severity()` maps each level onto the shared destructiveness scale (`BreadthNone ⇒ DestructNone`).

### Irreversibility (chain, 4 levels)

`Irreversibility` grades how hard an operation is to undo, from trivially recoverable reads to irrecoverable data destruction:

| Constant | Ordinal | Meaning | `Severity()` |
| --- | --- | --- | --- |
| `IrrevReversible` | 0 | can be undone trivially (reads, copies) | `DestructNone` |
| `IrrevRecoverable` | 1 | recoverable with effort | `DestructMedium` |
| `IrrevPermanent` | 2 | data loss that resists recovery | `DestructHigh` |
| `IrrevDestructive` | 3 | data destruction, effectively irreversible | `DestructCritical` |

`Join = max`, `LessOrEqual` is `≤`. `Severity()` maps each level onto the shared scale (`IrrevReversible ⇒ DestructNone`).

### Influence (chain, 3 levels)

`Influence` is the lattice of attacker control over a value: how far an adversary can steer it.

```
None ⊑ Indirect ⊑ Direct
```

| Constant | Ordinal | Meaning | `Severity()` |
| --- | --- | --- | --- |
| `InfluenceNone` | 0 | value is not attacker-controlled | `DestructNone` |
| `InfluenceIndirect` | 1 | attacker-controlled only insofar as its container is | `DestructMedium` |
| `InfluenceDirect` | 2 | directly attacker-controlled | `DestructHigh` |

`Join = max`, `LessOrEqual` is `≤`. `Severity()` maps each level onto the shared scale (`InfluenceNone ⇒ DestructNone`).

### Lattice laws

`TestLatticeLaws` checks, over sample elements, that each of `Certainty`, `Destructiveness`, `Scope` and `Taint` satisfies:

- **Idempotence** — `a ⊔ a = a` and `a ⊓ a = a`.
- **Commutativity** — `a ⊔ b = b ⊔ a` and `a ⊓ b = b ⊓ a`.
- **Associativity** — `(a ⊔ b) ⊔ c = a ⊔ (b ⊔ c)` and `(a ⊓ b) ⊓ c = a ⊓ (b ⊓ c)`.
- **Absorption** — `a ⊔ (a ⊓ b) = a` and `a ⊓ (a ⊔ b) = a`.
- **`⊥`/`⊤` identities** — `a ⊔ ⊥ = a`, `a ⊓ ⊤ = a`, `a ⊔ ⊤ = ⊤` (absorption) and `a ⊓ ⊥ = ⊥`.

Because `Certainty`, `Destructiveness`, `Breadth`, `Irreversibility` and `Influence` are chains, these identities hold with `⊔ = max` and `⊓ = min`. `Scope`/`Taint` are set lattices, so `⊔`/`⊓` are union/intersection with `arbitrary` as `⊤`.

## Error Handling

- `Certainty.UnmarshalJSON` and `Destructiveness.UnmarshalJSON` reject an unknown canonical name (`engine: unknown …`) and an out-of-range ordinal (`… ordinal out of range`), and wrap a non-integer/`null` payload as `engine: cannot decode … from …`.
- `Certainty.MarshalJSON` and `Destructiveness.MarshalJSON` refuse to encode an invalid value (`engine: cannot marshal invalid …`).
- `parseFlatSet` errors with `engine: cannot decode set from …` for a token that is neither a string, an array, nor an object; `null`/empty decode to `⊥`. It accepts the canonical object form plus a bare string or array (keeping hand-written fixtures terse).
- `Valid` is total: it returns `false` for any out-of-range value and never panics.

## Invariants

- Every lattice has a least element `⊥` and greatest element `⊤` accessible via its constructor (`…Bottom()`/`…Top()` or `ScopeBottom`/`ScopeTop`).
- `Join` is the least upper bound and `Meet` the greatest lower bound; both are idempotent, commutative and associative, and satisfy absorption.
- The ordinal chains use `Join = max` and `Meet = min`; `⊥` is the zero ordinal and `⊤` the maximum ordinal.
- `Scope` and `Taint` are canonical: their elements are sorted and unique, and each has exactly one JSON encoding (an object with the appropriate key plus `arbitrary`).
- For a flat set, `⊤ = {arbitrary}` is absorbing under `⊔` and an identity under `⊓`; `⊥ = ∅` is an identity under `⊔` and absorbing under `⊓`.
- `LessOrEqual(a, b)` is true exactly when `a ⊔ b = b`; `Equal` coincides with mutual `LessOrEqual`.
- `Breadth.Severity`, `Irreversibility.Severity`, `Influence.Severity` and `KindDestructiveness` all map onto the single `Destructiveness` scale, so dimensions can be joined and compared.

## Related Specs

- [Engine (Frozen Core)](README.md) — the domain overview and cross-cutting invariants.
- [Effect IR](effect-ir.md) — `Effect` carries `Target Scope`, `Certainty` and `Taint`; `Join` composes them.
- [Scoring](scoring.md) — how `Breadth`, `Irreversibility`, `Influence` and `Destructiveness` are folded into a `Score`.
- [ADR-0001: Freeze the effect IR](../../decisions/0001-frozen-effect-ir.md) — the frozen IR and lattice set.
- [META.md](../../META.md) — spec formats and update rules.
