# Conservatism: the ⊤ Semantics

## Context

The analyser must never under-report. If it cannot bound what a command does, the
sound answer is "anything" — the top element ⊤ of the lattice — never "nothing".
This is the load-bearing rule behind the whole tool: a "no effect" result is
reserved for input the analysis genuinely understood, and every unanalysable
construct degrades upward to ⊤. This document fixes what ⊤ is, where each layer
emits it, and the bounds that keep that degradation cheap and terminating.

## What ⊤ is

⊤ is represented uniformly as a single `engine.Effect`:

```
 Effect{
   Kind:       KindCodeExec        // "CodeExec" — execute data as code
   Target:     ScopeTop()          // {arbitrary} — any target
   Mode:       ModeDirect | ModeTransitive
   Certainty:  CertaintyCertain    // ⊤ is asserted, not doubted
   Taint:      TaintBottom()
   Reversible: false
 }
```

The same helper is defined once per emitting layer:

```go
// bind/bind.go, front/bash/exec.go — identical bodies
func topEffect(mode engine.EffectMode) engine.Effect {
    return engine.Effect{Kind: KindCodeExec, Target: ScopeTop(),
        Mode: mode, Certainty: CertaintyCertain, Taint: TaintBottom(),
        Reversible: false}
}
// front/ps/parse.go
func topEffect(mode engine.EffectMode) engine.Effect {
    return effectOf(engine.KindCodeExec, engine.ScopeTop(), mode, false)
}
```

`isTopEffect` recognises it as `Kind == KindCodeExec && Target.IsTop()`
(`front/bash/exec.go`). Because `KindCodeExec` maps to the worst-case
destructiveness `DestructCritical` (`engine/report.go`, `KindDestructiveness`)
and `ScopeTop` classifies as `BreadthRoot` (`engine/score.go`, `BreadthOf`), ⊤
propagates as maximum severity and minimum confidence through scoring.

`ModeDirect` marks ⊤ for the analysed unit's own opaque step; `ModeTransitive`
marks ⊤ for an opaque callee (a shell function body). Since `Report.Normalize`
merges effects sharing `(Kind, Mode)`, repeated ⊤ emissions inside one mode
collapse to a single effect.

## When ⊤ is emitted — by layer

### `bind` — unresolved or opaque invocations

| Condition | Mode | Note emitted | Source |
| --------- | ---- | ------------ | ------ |
| nil call | Direct | `nil call` | `bind/bind.go` (`conservativeResult`) |
| no knowledge base bound | Direct | `no knowledge base bound` | `bind/bind.go` |
| name not statically known | Direct | `unresolved command …: assuming ⊤ (CodeExec)` | `bind/bind.go` |
| shell function body | Transitive | `shell function body is opaque to command binding` | `bind/bind.go` |
| alias that did not resolve to a command | Direct | `unresolved command …` | `bind/bind.go` (`res.res.Kind` default branch) |

`Result.Conservative` is set true whenever the outcome contains a ⊤
(`CodeExec`) effect; `Result.conservativeResult` builds the fully-⊤ result.

### `front/bash` — abstract-execution degradation

The interpreter's budget bounds are:

| Bound | Value | Effect on exhaustion | Source |
| ----- | ----- | -------------------- | ------ |
| `defaultBudget` | `50000` steps | `markTop` ⇒ whole analysis ⊤ | `front/bash/exec.go` |
| `maxFuncDepth` | `64` | `markTopEffect` | `front/bash/exec.go` |
| `maxAliasDepth` | `32` | alias body treated as opaque | `front/bash/exec.go` |
| `maxRecorded` | `1024` | caps recorded invocations / notes | `front/bash/exec.go` |

- **Step budget (50000).** `interp.step()` decrements `it.budget` and panics a
  `budgetError` when it reaches zero (`front/bash/exec.go`). The panic is
  recovered in `Exec`'s deferred handler, which calls `finish` →
  `markTop("analysis budget exhausted: …")`; the accumulated effects are kept
  and a ⊤ effect is appended. This is what makes `while true` cheap: an
  undecidable loop consumes the budget and yields ⊤ instead of diverging. A
  parse failure or unknown variant is folded to a whole-program ⊤ by
  `topResult` (`ExecResult.Top = true`).
- **Code-execution sinks (`sinkSet`).** If the dispatched name is in `sinkSet`,
  `dispatch` calls `markTopEffect("code-execution sink …")`
  (`front/bash/exec.go`). `sinkSet` (`front/bash/builtins.go`) is the
  closed set: `sh`, `bash`, `dash`, `ash`, `zsh`, `ksh`, `ksh93`, `csh`, `tcsh`,
  `fish`, `python`, `python2`, `python3`, `node`, `nodejs`, `deno`, `bun`,
  `perl`, `ruby`, `php`, `lua`, `tclsh`, `awk`, `gawk`, `mawk`, `nawk`,
  `osascript`, `docker`, `podman`. Feeding data to any of them executes that
  data as code, so the value-flow aggregate becomes ⊤.
- **Code-executing builtins `{eval, source, .}`.** `isCodeExecBuiltin` matches
  `codeExecBuiltins` (`front/bash/builtins.go`); `dispatch` calls
  `markTopEffect("code-executing builtin …")` (`front/bash/exec.go`). These
  execute shell source supplied at run time, so their effects cannot be bounded.
- **Dynamically-named command.** When `nameOK` is false, `dispatch` calls
  `markTopEffect("dynamically-named command")` (`front/bash/exec.go`).
- **Function recursion limit.** `callFunc` calls `markTopEffect("function
  recursion limit reached …")` once `it.depth >= maxFuncDepth`
  (`front/bash/exec.go`).

`markTop` (whole program ⊤) sets `ExecResult.Top`; `markTopEffect` (one
sub-computation) leaves `Top` false but sets `Conservative` when a ⊤ effect is
present. `HasTop` inspects the aggregate for a ⊤ effect. Note that pure
shell-state builtins (`shellOnlyBuiltins`, e.g. `:`, `true`, `alias`, `break`)
are handled in the frontend precisely so they do **not** produce a spurious ⊤ by
being queried against a knowledge base that does not describe them.

### `front/ps` — lowering-based degradation

`lowerer.top(reason)` emits a Direct ⊤ and sets `Conservative`
(`front/ps/lower.go`). `lowerer.topReason` (`front/ps/lower.go`) is the
single decision point for the constructs the task pins:

| Condition | Mode | Reason string | Source |
| --------- | ---- | ------------- | ------ |
| `Invoke-Expression` (incl. alias `iex`) | Direct | `Invoke-Expression evaluates data as code` | `front/ps/lower.go` |
| `Add-Type` | Direct | `Add-Type compiles and loads arbitrary code` | `front/ps/lower.go` |
| `New-Object` | Direct | `New-Object instantiates an arbitrary .NET type` | `front/ps/lower.go` |
| dot-sourcing (`c.DotSource`) | Direct | `dot-sourcing runs an external script in the caller's scope` | `front/ps/lower.go` |
| call operator `&` with a computed name | Direct | `call operator & with a computed name` | `front/ps/lower.go` |
| splatting (`a.Splat`) | Direct | `splatting … hides the parameter set` | `front/ps/lower.go` |
| computed command name | Direct | `computed command name` | `front/ps/lower.go` |
| shell function body | Transitive | `⊤ shell function … body is opaque` | `front/ps/lower.go` |
| unknown command | Direct | `⊤ unknown command …` | `front/ps/lower.go` |
| unparseable program / timeout | Direct | the parse `Reason` | `front/ps/lower.go`, `front/ps/parse.go` |

Parse itself is bounded: in an ordinary build `DefaultTimeoutMicros = 250_000`
(250 ms) bounds one parse (`front/ps/parse.go`); under the race detector the
wall-clock budget is disabled (`front/ps/budget_race.go`), because a wall-clock
bound would otherwise make the result depend on host load — see
[ADR-0012](../decisions/0012-race-advisory-parse-budget.md). Either way a stop,
timeout or internal failure becomes `Program.Top = true` with a `Reason`, and
`Lower` then emits ⊤ and nothing else; the parser's deterministic
iteration/node/depth limits still bound the parse. The 250 ms budget is also far
above one tick of any host clock, so it is observable everywhere; only a
sub-tick budget is not, because gotreesitter's deadline poll compares
`time.Now()` and Windows advances it on the system timer tick (≥ 1 ms) — see
[ADR-0013](../decisions/0013-windows-clock-tick-parse-budget.md). `ps.Lower` also
treats a nil program as ⊤ (`front/ps/lower.go`).

## No-silent-miss invariant

`analysis.Report.Covered` (`internal/analysis/analyze.go`) encodes the rule
the GuardFall corpus checks:

```
Covered() == len(Effects) > 0 || Top || Conservative
```

A report that has neither an effect nor a ⊤ flag is a *miss*. The corpus classes
(`internal/analysis/corpus.go`) name the evasion families this is designed
against: A quoting/escaping fragments, B separator injection (`$IFS`), C
indirection (command substitution, dynamically-named programs), D encoded
payloads fed to an interpreter (`base64|sh`, `eval`, `sh -c`), E unbounded/opaque
work that must degrade to ⊤ (budget exhaustion, unknown).

## Invariants

- Every unanalysable construct degrades to ⊤; it never degrades to "no effect".
- ⊤ is exactly `CodeExec` over `ScopeTop`; no other kind/mode pair is used to
  express it.
- A ⊤ effect is `CertaintyCertain`, `TaintBottom`, `Reversible:false`.
- An unparsable source yields a whole-program ⊤ with a non-empty `Reason`
  (`Program.Top` for both frontends; `ExecResult.Top` for bash).
- The bash abstract execution always terminates within the step budget; running
  out of budget yields ⊤ and preserves the effects discovered so far.
- `Result.Conservative` / `Report.Conservative` is true whenever a ⊤ effect is
  present in the aggregate, even if the program as a whole was analysed.
- Pure shell-state builtins never produce ⊤.
- `Report.Covered()` is true for every effect-bearing or ⊤ report.

## Anti-Patterns

- **Returning "no effect" for input the layer did not understand.** Violates the
  no-silent-miss rule; the correct outcome is ⊤.
- **Unbounded interpretation.** Interpreting a non-terminating loop (or
  unbounded recursion) without the step/functions budget would hang the analysis
  instead of yielding ⊤.
- **Emitting a ⊤ with `Target` other than `ScopeTop`, or a kind other than
  `CodeExec`.** Breaks `isTopEffect` / `HasTop` detection and the severity
  propagation that relies on `CodeExec` ⇒ `DestructCritical`.
- **Marking `Conservative` (or `Top`) without emitting the ⊤ effect.** Leaves a
  report that claims degradation while carrying no ⊤ the consumer can see.
- **Querying the knowledge base for a pure shell-state builtin.** Would produce a
  spurious ⊤ for commands that in fact have no external effect.
- **Letting a frontend-specific ⊤ path define its own ⊤ shape.** Every layer
  reuses the shared `topEffect` shape so detection and scoring stay uniform.

## Related Specs

- [data-flow.md](data-flow.md) — where in each pipeline these degradations fire.
- [layers.md](layers.md) — the layer boundaries each emitter belongs to.
