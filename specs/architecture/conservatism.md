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
(`front/bash/exec.go`). A ⊤ may additionally carry the orthogonal `NetFlow`
role — a `FlowCradle`-tagged ⊤ (network content executed as code) is distinct
from an untagged ⊤; the role changes neither kind nor target.
Because `KindCodeExec` maps to the worst-case
destructiveness `DestructCritical` (`engine/report.go`, `KindDestructiveness`)
and `ScopeTop` classifies as `BreadthRoot` (`engine/score.go`, `BreadthOf`), ⊤
propagates as maximum severity and minimum confidence through scoring.

`ModeDirect` marks ⊤ for the analysed unit's own opaque step; `ModeTransitive`
marks ⊤ for an opaque callee (a shell function body). Since `Report.Normalize`
merges effects sharing `(Kind, Mode, NetFlow)`, repeated ⊤ emissions inside one
mode collapse to a single effect — but a `FlowCradle`-tagged ⊤ no longer merges
with an untagged ⊤ in the same mode: the flow role is per-effect evidence and
part of the merge key.

## When ⊤ is emitted — by layer

### `bind` — unresolved or opaque invocations

| Condition | Mode | Note emitted | Source |
| --------- | ---- | ------------ | ------ |
| nil call | Direct | `nil call` | `bind/bind.go` (`conservativeResult`) |
| no knowledge base bound | Direct | `no knowledge base bound` | `bind/bind.go` |
| name not statically known | Direct | `unresolved command …: assuming ⊤ (CodeExec)` | `bind/bind.go` |
| shell function body | Transitive | `shell function body is opaque to command binding` | `bind/bind.go` |
| alias that did not resolve to a command | Direct | `unresolved command …` | `bind/bind.go` (`res.res.Kind` default branch) |
| payload-carrying privilege wrapper the frontend did not peel (a path-qualified `/usr/bin/sudo …`) | Direct | `…: wrapped command not analyzable; assuming ⊤ (CodeExec)` | `bind/bind.go` (`declaresWrapperPayload`) |

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
| `maxFindDepth` | `8` | bounds nesting of `find … -exec` payloads | `front/bash/exec.go` |

- **Step budget (50000).** `interp.step()` decrements `it.budget` and panics a
  `budgetError` when it reaches zero (`front/bash/exec.go`). The panic is
  recovered in `Exec`'s deferred handler, which calls `finish` →
  `markTop("analysis budget exhausted: …")`; the accumulated effects are kept
  and a ⊤ effect is appended. This is what makes `while true` cheap: an
  undecidable loop consumes the budget and yields ⊤ instead of diverging. A
  parse failure or unknown variant is folded to a whole-program ⊤ by
  `topResult` (`ExecResult.Top = true`).
- **Code-execution sinks (`sinkSet`).** If the dispatched name is in `sinkSet`,
  `dispatch` calls `markTopEffectFlow("code-execution sink …", sinkFlowRole(cmd))`
  (`front/bash/exec.go`). `sinkSet` (`front/bash/builtins.go`) is the
  closed set: `sh`, `bash`, `dash`, `ash`, `zsh`, `ksh`, `ksh93`, `csh`, `tcsh`,
  `fish`, `python`, `python2`, `python3`, `node`, `nodejs`, `deno`, `bun`,
  `perl`, `ruby`, `php`, `lua`, `tclsh`, `awk`, `gawk`, `mawk`, `nawk`,
  `osascript`, `docker`, `podman`. Feeding data to any of them executes that
  data as code, so the value-flow aggregate becomes ⊤.
- **Code-executing builtins `{eval, source, ., trap}`.** `isCodeExecBuiltin` matches
  `codeExecBuiltins` (`front/bash/builtins.go`); `dispatch` calls
  `markTopEffectFlow("code-executing builtin …", sinkFlowRole(cmd))` (`front/bash/exec.go`). These
  execute shell source supplied at run time, so their effects cannot be bounded.
  `trap` ⊤-fires only when it registers a non-empty ACTION (`trapHasAction`):
  the listing/query forms (`trap`, `trap -p`, `trap -l`) and the reset form
  (`trap - INT`) carry no action and execute no code.
- **Dynamically-named command.** When `nameOK` is false, `dispatch` calls
  `markTopEffectFlow("dynamically-named command", sinkFlowRole(cmd))` (`front/bash/exec.go`).
- **Function recursion limit.** `callFunc` calls `markTopEffect("function
  recursion limit reached …")` once `it.depth >= maxFuncDepth`
  (`front/bash/exec.go`).
- **Alias-table opacity.** A dynamic alias operand leaves the alias table not
  statically known; `dispatch` emits `markTopEffectFlow("alias table not
  statically known")` instead of expanding a body it cannot bound
  (`front/bash/exec.go`).
- **find exec payloads.** `find -exec`/`-execdir`/`-ok`/`-okdir` payloads are
  analysed as the invocations they perform, with nesting bounded by
  `maxFindDepth`; a payload the analysis cannot bound (a dynamically-named
  command, an expansion-bearing word, an unresolvable search root) emits
  `markTopEffect("find exec payload not analyzable")` (`front/bash/exec.go`).
- **Command language on standard input.** Feeding a command language on stdin
  to a client that interprets it (`stdinCodeClient`: sqlite3's `.shell`, gdb's
  `shell`, an interactive SQL client's `\!`, ssh's remote login shell) emits
  `markTopEffectFlow("command language on standard input to …")`
  (`front/bash/exec.go`).
- **Command-hash opacity.** The shell's command-hash table: a dynamic
  `hash -p` leaves name resolution unbound (`markTopEffectFlow("name
  resolution unbound after a dynamic hash -p")`), and a hashed name whose
  path cannot be resolved emits `markTopEffectFlow("hashed name … with an
  unresolvable path")` instead of binding the name's knowledge-base row
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
| `Invoke-History` | Direct | `Invoke-History re-executes a previous command (arbitrary code)` | `front/ps/lower.go` |
| `Trace-Command` | Direct | `Trace-Command evaluates an arbitrary expression string` | `front/ps/lower.go` |
| static .NET invocation (`[ScriptBlock]::Create`) | Direct | static-invocation reason (emitted as `KindTop` by the parser) | `front/ps/parse.go` |
| dot-sourcing (`c.DotSource`) | Direct | `dot-sourcing runs an external script in the caller's scope` | `front/ps/lower.go` |
| call operator `&` with a computed name | Direct | `call operator & with a computed name` | `front/ps/lower.go` |
| splatting (`a.Splat`) — only when the splat variable is unknown or has an entry-unknown value; a statically-known hashtable/array splat expands into parameter bindings (`a.Splat = false`, so switch entries like `-Recurse` survive) and does not degrade | Direct | `splatting … hides the parameter set` | `front/ps/lower.go` |
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
[ADR-0013](../decisions/0013-windows-clock-tick-parse-budget.md). Lowering is bounded too, and deterministically: the lowerer charges its own
step budget (`defaultBudget = 50000`, `front/ps/lower.go`) and recovers the
exhaustion panic (`budgetError`) into `l.top("analysis budget exhausted")`,
keeping the effects discovered so far. Unlike the parse budget it is a step
counter, not a wall clock, so it needs no race-detector special case.
`ps.Lower` also treats a nil program as ⊤ (`front/ps/lower.go`).

### `front/js` — bounded JavaScript evaluation

`js.Analyze` parses and evaluates the documented subset under source/node/depth,
step, recording, and value-size limits. Parser failures and budget exhaustion
set Top and Conservative with the canonical Direct top effect; prior effects
survive evaluation exhaustion. Unsupported execution sets Conservative and
provides a fixed reason and source-located derivation. Unmodelled calls remain
top; no function invocation or Node API effects are inferred. Pure understood
programs can have no effects and remain uncovered under the existing policy.
See [JavaScript Frontend](../domains/javascript-frontend.md) and
[ADR-0018](../decisions/0018-javascript-semantic-kernel.md).

### `internal/analysis` — composition-layer degradation

With no binder bound, any program that contains at least one command statement
degrades to Conservative with the reason `no effect resolver bound: command
effects cannot be resolved` (`internal/analysis/analyze.go`) — a zero-value
`Analyzer` must not emit a fail-open empty report (the no-silent-miss guard).
A source with no command statement at all — empty input, a bare assignment, a
lone redirection — is left untouched. In the frontend, a nil resolver on an
ordinary command emits the note `no effect resolver bound for X` and the shell
reports only its own intrinsic effects (`front/bash/exec.go`).

## No-silent-miss invariant

`analysis.Report.Covered` (`internal/analysis/analyze.go`) encodes the rule
the GuardFall corpus checks:

```
Covered() == len(Effects) > 0 || Top || Conservative
```

A report that has neither an effect nor a ⊤ flag is a *miss*. The corpus classes
(`internal/corpus/corpus.go`) name the evasion families this is designed
against: A quoting/escaping fragments, B separator injection (`$IFS`), C
indirection (command substitution, dynamically-named programs), D encoded
payloads fed to an interpreter (`base64|sh`, `eval`, `sh -c`), E unbounded/opaque
work that must degrade to ⊤ (budget exhaustion, unknown).

## Invariants

- Every unanalysable construct degrades to ⊤; it never degrades to "no effect".
- ⊤ is exactly `CodeExec` over `ScopeTop` — optionally carrying the orthogonal
  `NetFlow` role, so a `FlowCradle`-tagged ⊤ is distinct from an untagged ⊤; no
  other kind/target pair is used to express it.
- A ⊤ effect is `CertaintyCertain`, `TaintBottom`, `Reversible:false`.
- An unparsable source yields a whole-program ⊤ with a non-empty `Reason`
  (`Program.Top` for bash/PowerShell; `ExecResult.Top` for bash;
  `Result.Top` for JavaScript whole-unit failures).
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
