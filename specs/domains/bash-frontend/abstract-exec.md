# Abstract Execution

## Role

This component is the frontend's transfer-function engine: it walks the parsed syntax tree with an abstract state Σ, expanding words, interpreting redirections, pipelines, control flow and subshells, and folding the effects it discovers into a single aggregate `ExecResult`.

## Key Files

- `front/bash/exec.go` — the interpreter: `Resolver`, `ExecResult`, bounds, `interp`, `Exec`/`ExecBash`, statement/command execution, pipelines, control flow, redirections, substitution capture, dispatch, and the ⊤/budget machinery.
- `front/bash/expand.go` — Σ (`State`, `Var`, `NewState`, `Clone`, `joinStates`), the expansion configuration (`newCfg`), word expansion (`expandFields`/`expandLiteral`), static knownness (`wordKnown`/`partKnown`/`paramKnown`/`arithKnown`) and taint (`wordTaint`/`partTaint`).
- `front/bash/builtins.go` — the sink set, code-executing/shell-only builtins, stdout folding (`stdoutOf`, `echoOut`, `printfOut`, `base64Out`) and builtin state transfer (`builtinState`).

## Behavior

### The Resolver seam

```go
type Resolution struct {
	Effects     []engine.Effect
	Derivations []engine.Derivation
}

type Resolver func(cmd *Command, prog *Program) Resolution
```

Ordinary command effects are obtained through this injected seam (the binding layer, `bind`, knows how to bind a normalized invocation but imports `front/bash`, so `front/bash` cannot import it back). Everything the shell itself contributes — redirections, code-execution sinks, environment writes — is emitted here directly. A `nil` resolver disables command binding; only the shell's intrinsic effects are then reported. Each call returns a `Resolution`: the `Effects` plus the `Derivations` (concrete source atoms — flags, operands, redirects, sinks) that justify them; the shell's own contributions carry derivations too, so the composition layer can build a complete `report.why`.

### Bounds and control-flow signals

```
defaultBudget = 50000   // redirections, statements, iterations, calls all draw on it
maxFuncDepth  = 64      // function recursion
maxAliasDepth = 32      // alias-chain expansion
maxRecorded   = 1024    // caps Cmds and Notes

ctlNone < (ctlBreak, ctlContinue, ctlReturn, ctlExit)
```

`step()` charges one unit and panics with `budgetError` when the budget is exhausted; the panic is recovered and converted to ⊤. The `ctl*` signals propagate through `execStmts` until a loop or function consumes them.

### Statement and command execution

```
execStmts(ss):  for each s { if ctl != none → stop; execStmt(s) }
execStmt(s):    step(); save/restore stdinTaint; apply s.Redirs;
                if s.Cmd == nil → return;
                if Background/Coprocess → run in a cloned Σ; else execCommand(s.Cmd)
execCommand(c): dispatch on syntax.Command type:
   CallExpr→execCall  BinaryCmd→execBinary  Block→execStmts  Subshell→(cloned Σ)
   IfClause→execIf    WhileClause→execWhile ForClause→execFor CaseClause→execCase
   FuncDecl→execFuncDecl  DeclClause→execDecl  TimeClause→execStmt  CoprocClause→(cloned Σ)
   ArithmCmd/TestClause/LetClause → status unknown
   default → note "unsupported construct at <pos>"
```

### Pipelines (`execPipeline`)

Each stage runs in its own subshell copy of Σ. The interpreter threads the folded standard output of each stage into the next as its stdin (`it.stdout`/`stdoutKnown`/`stdoutTaint` → `it.stdin`/`stdinKnown`/`stdinTaint`), which is the pipeline's value flow. A stage that is a code-execution sink turns the flowing value into executed code (the sink reports ⊤ when dispatched). After the pipeline, the original stdin thread is restored and the status is set unknown.

### AND/OR lists (`execAndOr`)

The right-hand side runs only when the left-hand side's exit status makes it reachable; an unknown status conservatively runs it (`&&` requires status 0, `||` requires non-zero).

### Control flow

- `execIf`: if the condition's status is known, run the taken branch; otherwise run **both** branches (effects accumulate) and join the two resulting states (`joinStates`) — the least upper bound, where a variable keeps its value only when both branches agree.
- `execWhile`: iterate while the (statically decidable) condition holds; a non-decidable condition runs the body once and yields a ⊤ note. `until` inverts the test.
- `execFor`: over a statically-known word list it iterates exactly; over a dynamic list or over positional parameters it runs the body once and yields ⊤. A C-style loop is treated like an unknown bound (iterate until the budget stops it).
- `execCase`: a known subject selects the first matching pattern (glob `path.Match`); a non-decidable subject runs every arm and yields ⊤.
- `execFuncDecl` records the body; `callFunc` binds positional parameters (`0`, `#`, `@`, `*`, `1..n`) in a **fresh clone** of Σ and executes the body, with a recursion limit.
- `execDecl` applies the state component of `declare`/`local`/`export`/`readonly` and asks the resolver for the declaration's own effects.

### Redirections (`redir` / `redirectTarget`)

- Output (`>`, `>>`, `>|`, `&>`, `&>>`) ⇒ `FSWrite` of the target (⊤ when the target is unknown); input (`<`) ⇒ `FSRead`, and the file's provenance is joined into the statement's stdin taint so an egress fed only by the redirection is still seen to carry the data out.
- In/out (`<>`) emits both read and write.
- Dup (`>&`, `<&`) and heredocs (`<<`, `<<-`, `<<<`) ⇒ `Stdio` (with a `Stdio` effect for the here-string).
- `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` pseudo-files are recognised: reading ⇒ `NetIngress`, writing ⇒ `NetEgress` (scoped to `host:port` when known, else ⊤), plus an `IPC` ambient effect.

### Dispatch: sinks, builtins, and the resolver (`dispatch`)

```
dispatch(name, nameOK, argv, cmd)
  1. !nameOK                     → ⊤ effect "dynamically-named command"
  2. alias expansion (≤ maxAliasDepth, textual: body words prepended)
  3. shell function declared?    → callFunc (executes the body), no resolver call
  4. isSink(name)?               → ⊤ effect "code-execution sink "name""
  5. builtinState(name, argv)    → mutate Σ (cd, umask, unset, alias, unalias, read)
  6. isCodeExecBuiltin(name)?    → ⊤ effect  (eval, source, .)
  7. isShellOnlyBuiltin(name)?   → set ctl for break/continue/return/exit; no external effect
  8. else                        → it.res(cmd, prog)   [Resolver seam]
```

`sinkSet` (closed) covers interpreters/shells (`sh`, `bash`, `zsh`, `python`, `node`, `perl`, `awk`, …) and container/orchestration tools (`docker`, `podman`); feeding data to any of them means that data is executed as code (⊤). `codeExecBuiltins = {eval, source, .}`. `shellOnlyBuiltins` covers pure shell-state builtins (`:`, `true`, `false`, `break`, `alias`, `shift`, `command`, `[`, …) that would otherwise produce a spurious ⊤ from the KB.

### Stdout folding and substitution (`stdoutOf`, `captureSubst`)

A command substitution is statically known only when the command producing its stdout is. `stdoutOf` folds commands whose output is a pure function of their expanded arguments (and, for the deliberately simple `base64` case, of stdin): `echo`, a subset of `printf` (`%s`/`%d`/`%i`/`%%` and backslash escapes), the no-output commands (`true`, `sleep`, `export`, `read`, …), and `base64` encode/decode when its stdin is known. Everything else reports unknown, which keeps the analysis sound. Command substitutions run their body in a cloned Σ and record the folded stdout (and its knownness/taint) in `it.subst`; process substitutions are recorded as unknown/untrusted.

### Taint

- Σ variables carry a `Taint` label; `partTaint` joins the taint of a word's parts (a parameter expansion takes the variable's taint; a command/process substitution carries at least `untrusted`, joined with the captured provenance).
- `outTaintOf(effs, stdinTaint)` is a **per-command** over-approximation of a command's stdout provenance: it joins the stdin taint with the taint of the command's filesystem reads, credential access (adding `secret`), and network ingress (`untrusted`) — but never another command's — so an egress pairing is a real per-command data flow rather than mere co-occurrence.

## Error Handling

- A parse failure, an unknown variant, or an internal panic ⇒ a fully-⊤ `ExecResult` (`topResult`) with a reason; `Exec` recovers panics in a `defer`.
- An exhausted budget ⇒ `budgetError`, caught by `finish`, which calls `markTop("analysis budget exhausted: …")` and preserves the effects discovered before unwinding.
- `markTop` sets the whole-analysis ⊤ flag and appends one ⊤ effect; `markTopEffect` records a ⊤ effect for one sub-computation (a sink) without claiming the whole program is unanalysable.
- Expansion is guarded: `expandFields`/`expandLiteral` recover panics and degrade to "unknown" rather than propagating.
- `addNote`/`addCmd` bound their lists by `maxRecorded` so a non-terminating loop cannot grow them without limit before the budget stops it.

## Invariants

- `Exec` never panics; every failure path produces a `*ExecResult` with `Top`/`Conservative` set appropriately.
- The interpreter never touches the filesystem: expansion has globbing disabled and reads nothing from disk; effects describe *intended* operations only.
- Σ is cloned (never shared) across subshells, each pipeline stage, function calls, background/coprocess jobs, command/process substitutions, and each arm of an undecidable branch.
- The step budget strictly bounds the work: every statement, redirection and loop iteration charges `step()`.
- `isTopEffect(e)` identifies the ⊤ effect as `Kind == CodeExec` with a top (`{arbitrary}`) target; `ExecResult.HasTop()` scans for it and `Conservative` is true whenever one is present.
- The final effect set is canonicalized through `engine.NewReport().Normalize()`.
- An input redirection's taint contribution is scoped to its statement (saved/restored), so it cannot leak into a following statement.

## Related Specs

- [Bash Frontend](README.md) — domain overview.
- [Parse & Normalize](parse-normalize.md) — produces the syntax tree and `Program` this component interprets.
- [Binding](../binding.md) — supplies the `Resolver` implementation (`bind.Binder.BindBash`).
- [Knowledge Base](../knowledge-base.md) — the effect signatures behind the resolver.
