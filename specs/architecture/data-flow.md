# Data Flow

## Context

Both supported dialects end in the same place — a `analysis.Report` whose
`effects` are the frozen `engine.Effect` IR and whose `score` is the composite
`engine.Score` — but they reach it along two different paths. Bash is analysed by
*abstract execution*: the frontend walks the syntax tree with an abstract state
and interprets control flow, pipelines and redirections, asking the binding layer
for the effects of ordinary commands. PowerShell is analysed by *lowering*: the
frontend folds a normalized AST directly into effects, with no abstract state and
no binder. This document traces both paths end to end, then the shared
resolution, scoring, facade and CLI stages.

## Bash path: parse → normalize / abstract-exec → bind

```
 source text
     │
     ▼
 bash.Parse                       front/bash/parse.go
   (mvdan.cc/sh/v3/syntax parser; failure ⇒ Program.Top=true, Reason set)
     │  *syntax.File  +  normalized Program
     ▼
 bash.Exec / bash.ExecBash        front/bash/exec.go 
   newNormalizer(src).fill(f, prog)          (builds the normalized AST)
   newInterp(...)                            (Σ = NewState() from expand.go)
   it.execStmts(f.Stmts)                     (abstract execution)
     │
     │  per CallExpr:  execCall (exec.go)
     │    1. env assignments  VAR=x cmd     → envWriteEffect, folded into Σ
     │    2. peel wrappers (sudo, env, …)   → donated env assignments
     │    3. expand command words (Σ)       → name + argv + taint
     │    4. build *bash.Command            → handed to dispatch
     │    5. no command word ⇒ bare assignment/redirection, return
     │    6. dispatch(name, nameOK, argv, cmd)
     │
     ▼
 interp.dispatch                  front/bash/exec.go
   alias expansion (bounded) → shell function call → code-exec sink (⊤)
   → builtin state mutation → code-exec builtin (⊤) → shell-only builtin
   → otherwise: effs := it.res(cmd, it.prog)   ◄── the Resolver seam
     │
     ▼
 bind.Binder.BindBash             bind/bind.go
   FromBash(cmd, prog) → *bind.Call → Bind
     │
     ▼
 bind.Binder.Bind                 bind/bind.go
   resolve(c)  →  bindCommand(res.command, res.args, c.StdinTaint)
     │                        │
     │                        ▼
     │            lowerParam: KB param → engine.Effect
     │            (target scope, taint, certainty, reversibility)
     ▼
 []engine.Effect   ── returned up through interp.effs
     │
     ▼
 interp.result / ExecResult       front/bash/exec.go
   engine.NewReport(); rep.Effects = it.effs; rep.Normalize()
   ⇒ canonical, merged, sorted effects + Destructiveness
```

Notes on the bash stage:

- The abstract state Σ = `⟨Vars↑taint, PWD, umask, funcs, aliases⟩` is defined in
  `front/bash/expand.go` (package section "Σ — the abstract state"). Every value
  carries a taint label and a `Known` flag; an unknown value makes words that
  read it dynamic.
- Pipelines thread a value and its provenance stage to stage
  (`execPipeline`, `front/bash/exec.go`); the per-command `outTaintOf`
  (`front/bash/exec.go`) is what makes an egress pairing a real data flow.
- `Bind` always calls `normalizeResult` (`bind/bind.go`), so the binder's output
  is already canonical.

## PowerShell path: parse → lower

```
 source text
     │
     ▼
 ps.Parse / ps.ParseTimeout      front/ps/parse.go
   (gotreesitter grammar; 250 ms wall-clock budget — DefaultTimeoutMicros,
    disabled under the race detector, see front/ps/budget_race.go)
   parse stop / timeout / panic ⇒ Program.Top=true, Reason set
     │  *ps.Program  (normalized AST: Stmts, decls of Aliases/Funcs)
     ▼
 ps.Lower / ps.LowerWith         front/ps/lower.go 
   for each Stmt:
     KindCommand    → lowerer.command(s)
     KindAssignment → lowerer.assignment(a)
     KindTop        → lowerer.top(reason)                 (⊤)
     │
     │  lowerer.command:
     │    resolve(name) → canonical cmdlet (script aliases ⧺ built-in aliases)
     │    topReason(c, canonical)?  ⇒ ⊤ CodeExec           (see conservatism.md)
     │    shell function?           ⇒ ⊤ CodeExec (transitive)
     │    unknown cmdlet?           ⇒ ⊤ CodeExec
     │    known cmdlet ⇒ emit one effect per Spec, mapping
     │      Target{X}, provider Env/Variable/Registry, credentials
     │    Remove-Item -Recurse/-Force ⇒ bump Destructiveness to Critical
     │    redirs ⇒ FSWrite
     ▼
 Result (Effects, Destructiveness, Conservative, Notes)
   lowerer.finish: rep.Normalize(); Destructiveness.Join(bump)
     │
     ▼
 []engine.Effect
```

The PowerShell frontend consults **its own** tables — `ps.Aliases`
(`front/ps/aliases.go`) and `ps.Cmdlets` — never the bash knowledge base. Its
effects already carry `Mode`/`Certainty` chosen through `effectOf` /
`certaintyOf` (`front/ps/parse.go`).

## Shared resolution and binding (`bind`)

`bind.Binder.resolve` (`bind/resolve.go`) answers "which command does this
call name?" by walking a fixed chain, stopping at the first match:

```
 builtin → function → alias → command (PATH) → ⊤ (ResolveUnknown)
```

- **builtin**: `kb.Command(name).Dialect == DialectBuiltin`.
- **function**: name present in the call's `Funcs` (body opaque to binding ⇒ ⊤).
- **alias**: expanded textually via `expandAliases` (bounded by
  `maxAliasDepth = 32`); the effective command may itself be shadowed by a
  function.
- **command**: a signature in the knowledge base for the name.
- **⊤**: nothing matched, or the name is not statically known.

Once a knowledge-base command is found, `bindCommand` (`bind/bind.go`) splits
argv into matched flags/options, assignment operands (`of=…`) and positional
operands, and `lowerParam` lowers each matched parameter to an `engine.Effect`,
combining the parameter's declared effect (`kb.schema.Effect.EngineEffect`) with
a concrete target scope, taint and certainty. `taintEgress` then carries the
per-command read provenance into the egress effects.

## Shared scoring (`engine`)

`engine.ScoreEffects(effects, tokens...)` (`engine/score.go`) composes the
`Score`:

```
 Destructiveness = ComputeDestructiveness(effects)   fold of KindDestructiveness
 Irreversibility = fold(IrreversibilityOf(e, tokens…))   (rm/dd/mkfs… ⇒ worse)
 Breadth        = BreadthSeverity(⊔ targets)          (secret path ⇒ escalate)
 Influence      = MaxInfluence(effects)               fold of taint labels
 Exfil          = exfilSeverity(DetectExfil(effects)) (secret read ⊗ tainted egress)
 Confidence     = min ConfidenceOf(e)  (halved* for ⊤/⊥ targets)
 Reversible     = AND of every effect's Reversible
 Grade          = join(all risk dimensions)
```

`tokens` are the resolved command names (from `bashTokens` / `psTokens`), which
let irreversibility recognise destructive commands a single effect does not
name. The why-trace is built by `engine.BuildWhy` (`engine/why.go`), and
exfiltration pairings by `engine.DetectExfil` (`engine/taint.go`).

## Composition facade (`internal/analysis`)

`analysis.Analyzer.AnalyzeWith` (`internal/analysis/analyze.go`) dispatches on
the language:

```
 analyzeBash (analyze.go)                    analyzePS (analyze.go)
   res := bash.Exec(v, source, src, resolver)      prog := ps.Parse("flowsh", src)
       resolver = b.BindBash(cmd,prog)               res  := ps.LowerWith(prog, opts)
       → Resolution{Effects, Derivations}
   rep.Effects = normalizeEffects(res.Effects)     rep.Effects = normalizeEffects(res.Effects)
   rep.Root = root                                 rep.Root = root
   rep.Destructiveness = ComputeDestructiveness    rep.Destructiveness = ComputeDestructiveness
   rep.Conservative/Top/Reason = res…              rep.Conservative = res.Conservative
   rep.Commands = len(res.Cmds)                    rep.Top/Reason = prog.Top/Reason
   rep.Why = BuildWhy(…)                           rep.Why = BuildWhy(…)
   rep.Resolution/Destructive = binder aggregate   (PowerShell: Resolution stays zero)
   rep.Score = ScoreEffects(effects, bashTokens…)  rep.Score = ScoreEffects(effects, psTokens…)
                     │                                          │
                     └──────────────► analysis.Report ◄─────────┘
```

`normalizeEffects` (`internal/analysis/analyze.go`) re-runs
`engine.Report.Normalize` (`engine/report.go`), which merges effects sharing
`(Kind, Mode)` and sorts them — so two reports built from the same effects
normalise to byte-identical JSON. `analyzePS` is a free function (no binder
needed); `analyzeBash` uses the process-wide `bind.Binder` memoised by
`defaultAnalyzer`.

## CLI (`cmd/flowsh`)

`main.run` (`cmd/flowsh/main.go`) parses flags (`--lang bash|posix|posh|auto`,
`--file PATH`, `--batch`, `--json`, `--explain`/`--why`, `--windows[=bool]`,
`--version`, `-h`), reads the command from `--file`, the positional argument, or
stdin, resolves the language (`api.ParseLang`, or `detectLang` for `auto`,
after the input is known), then calls
`api.AnalyzeWith(lang, src, api.Options{Root: …})` and either:

- `--json`: `Report.Encode()` → canonical indented JSON on stdout; or
- default: `writeText` prints a human summary (lang, input, root, commands,
  effects, destructiveness, irreversibility, breadth, influence, grade,
  confidence, exfil risk, conservative, top, resolution, destructive entries,
  effect keys, exfil pairs, notes); with `--explain`/`--why`, `writeWhy` then
  prints the why-trace.

With `--batch` the selected source is split into non-blank lines (`splitBatch`)
and each line is analysed (re-running `detectLang` per line for `auto`) and
written as one compact single-line report (`encodeCompact` → `json.Marshal`), so
the output is NDJSON.

The CLI reaches the facade exclusively through the public `api` package (and
imports `engine` for the frozen IR types it prints); it does not import
`internal/analysis` directly.

Two flags short-circuit before any analysis: `--help` prints the usage text and
`--version` prints the tool-contract tag (`flowsh/v1`) and `engine.SchemaVersion`
(`effect-ir/v1`), one per line, to stdout; both exit `0` without reading stdin.

Exit status: `0` analysis produced a report (or `--help`/`--version`), `1`
internal failure, `2` usage error, `3` input error (the source could not be
read, or was empty).

## Invariants

- A source produces exactly one `analysis.Report`; both dialects terminate at
  `internal/analysis`'s `Report`.
- The bash path reaches command effects only through the injected `Resolver`
  seam; the PowerShell path reaches them only through its own alias/cmdlet
  tables.
- The resolution chain is ordered `builtin → function → alias → command →
  ⊤` and stops at the first match.
- Every stage output is normalised by `engine.Report.Normalize` before it is
  serialised, so equal effect sets yield byte-identical JSON.
- `Report.Score` is always the result of `engine.ScoreEffects` over the report's
  (normalised) effects plus the dialect's resolved command tokens.
- The analysis is total and deterministic: no stage returns a Go error for
  ill-formed input; failure is represented as ⊤ (see
  [conservatism.md](conservatism.md)).

## Anti-Patterns

- **Bypassing `Normalize` before comparison or serialisation.** Effects that
  share `(Kind, Mode)` would not be merged and outputs would differ run to run.
- **Scoring effects without the command tokens.** The irreversibility dimension
  would miss destructive commands (`rm`, `dd`, `mkfs*`) that a single effect
  does not name.
- **Threading a pipeline value as per-script rather than per-command taint.**
  Would turn mere co-occurrence of a read and an egress into a false
  exfiltration pairing.
- **Resolving commands in the PowerShell path through the bash knowledge base.**
  Tokens such as `rm`, `curl` and `iex` mean different things in the two
  dialects.
- **Adding a second facade that wires the frontends itself.** Frontend + binder
  + engine composition belongs only in `internal/analysis`.

## Related Specs

- [layers.md](layers.md) — the layer boundaries and import rules these flows
  obey.
- [conservatism.md](conservatism.md) — the ⊤ outcomes each stage can produce.
