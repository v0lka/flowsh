# Contract: Front/Bash <-> Caller (Resolver Seam)

## Boundary Rule

`front/bash` depends on `engine` only, and must never import `bind`, `kb`, or `front/ps`. The dependency is inverted through a function value — the `Resolver` seam — so the caller injects the binder rather than the frontend reaching for it. `bind` already imports `front/bash` (via `FromBash` and the exported env-assignment helpers `ExecEnvVar`/`ExecEnvEffect`), so a `front/bash`→`bind` import would be a cycle; the seam is what keeps the shell frontend free of the knowledge base entirely. A `nil` Resolver is a valid configuration: it disables command binding and leaves only the shell's own intrinsic effects.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |
| `type Resolution struct{ Effects []engine.Effect; Derivations []engine.Derivation }` + `type Resolver func(cmd *Command, prog *Program) Resolution` | `front/bash` (`exec.go`) | the caller — `internal/analysis` (production), `front/bash/exec_test.go` (tests) | The seam: maps one normalized, fully-expanded command invocation to its effects and the derivations (concrete source atoms) that justify them. |
| `func ExecWithVars(v Variant, name, src string, r Resolver, vars map[string]string) *ExecResult` | `front/bash` (`exec.go`) | `internal/analysis.analyzeBash` | The production entry: parse and abstractly execute `src`, with the abstract state pre-seeded from host-known `vars` bindings (a nil/empty table reproduces the plain interpreter); never panics; every failure degrades to ⊤. |
| `func Exec(v Variant, name, src string, r Resolver) *ExecResult` | `front/bash` (`exec.go`) | tests | `ExecWithVars` without host-seeded variables; never panics; every failure degrades to ⊤. |
| `func ExecBash(src string, r Resolver) *ExecResult` | `front/bash` (`exec.go`) | tests (`front/bash/exec_test.go`) | `Exec` specialised to the bash dialect (`Exec(Bash, "script", src, r)`); a test-facing wrapper — the production caller `internal/analysis.analyzeBash` calls `ExecWithVars` directly. |
| `func Parse(v Variant, name, src string) *Program` | `front/bash` (`parse.go`) | `bind.resolve` (alias expansion), tests | Produce the normalized `Program` that a Resolver receives. |
| `type Program struct{ Variant Variant; File, Source string; Top bool; Reason string; ErrPos *Pos; Stmts []*Stmt; Aliases map[string]*Alias; Funcs map[string]*Func }` | `front/bash` (`normalize.go`) | the Resolver impl, `bind.FromBash` | The normalized AST handed to the Resolver (carries the declared aliases/functions). |
| `type Command struct{ Pos Pos; Name string; NameWord *Word; Args []*Word; Assigns []*Assign; Wrappers []*Wrapper; ResolveKind, ResolvesTo string; StdinTaint engine.Taint; Redirs []ExecRedirect \`json:"-"\` }` | `front/bash` (`normalize.go`) | the Resolver impl, `bind.FromBash` | The normalized simple command handed to the Resolver. `Redirs` carries the statement's resolved redirections (operator + expanded target), attached during execution to feed the report's `commandCalls[].redirs` view; it is deliberately not part of the serialized normalized AST. |
| `type ExecResult struct{ Variant Variant; File, Source string; Top bool; Reason string; Conservative bool; Effects []engine.Effect; Destructiveness engine.Destructiveness; Derivations []engine.Derivation; State *State; Cmds []*Command; Notes []string }` | `front/bash` (`exec.go`) | `internal/analysis` | Aggregate result of abstract execution (effects from both the Resolver and the shell itself, plus their derivations). |
| `func FromBash(cmd *bash.Command, prog *bash.Program) *Call` | `bind` (`bind.go`) | `Binder.BindBash`, tests | Adapter: lowers the frontend's `Command`/`Program` into the binder's frontend-agnostic `Call`. |
| `func ExecEnvVar(name string) bool` / `func ExecEnvEffect(name, val string, known bool, taint engine.Taint) (engine.Effect, bool)` | `front/bash` (`exec.go`) | the interpreter, `bind.envAssignEffects` | Whether an environment assignment reaches the code-execution channel (a program-valued variable, an option channel, git's `GIT_CONFIG_*` family), and the effect it implies — the single source of truth shared by the shell's own assignment channels and the binder's copy of them; a second `bind`→`front/bash` surface besides `FromBash`. |
| `func (b *Binder) BindBash(cmd *bash.Command, prog *bash.Program) *Result` | `bind` (`bind.go`) | the injected Resolver closure | Convenience wrapper: `Bind(FromBash(cmd, prog))`. |
| `func (b *Binder) Bind(c *Call) *Result` | `bind` (`bind.go`) | `Binder.BindBash` | The actual binding entry point for a normalized `Call`. |

## Initialization

The two halves are joined in exactly one place, `internal/analysis/analyze.go`, which holds a `*bind.Binder` and passes a closure matching the `Resolver` signature to `bash.ExecWithVars`:

```go
b := a.binder
res = bash.ExecWithVars(v, sourceName(root, "script"), src, func(cmd *bash.Command, prog *bash.Program) bash.Resolution {
    br := b.BindBash(cmd, prog)
    // … observe br.Resolution (the aggregated report resolution), append the
    // per-command call view, join br.Destructiveness (raise-only, D6), and
    // collect br.Notes …
    return bash.Resolution{Effects: br.Effects, Derivations: br.Derivations}
}, vars)
```

The seam's return type is unchanged — only `Effects` and `Derivations` cross it; the closure's additional observations (`br.Resolution`, the per-command calls, `br.Destructiveness`, `br.Notes`) stay on the composition side. When the analyser holds no binder, it calls `bash.ExecWithVars(v, sourceName(root, "script"), src, nil, vars)`, and only the shell's intrinsic effects are reported. `bind.FromBash(cmd, prog) *Call` is the pure `Command`/`Program`→`Call` handoff used by `BindBash`; the whole-program walkers `BindProgram`/`BindScript` (test-only, in `bind/program_bind_test.go`) use it too, binding a whole program without abstract execution. The frontend side is wired by the interpreter: `newInterpVars(src, prog, r, f, vars)` stores `r` in `interp.res` and seeds the abstract state from `vars`, and the interpreter invokes `it.res(cmd, it.resolutionProgram())` for each ordinary command it reaches — a copy of the program whose `Aliases` are restricted to those declared so far (`resolutionProgramExcluding` additionally suppresses the alias for a quoted or backslash-escaped command word, Finding 78).

## Data Flow Across Boundary

```
  internal/analysis.analyzeBash
        │  holds *bind.Binder
        ▼
  bash.ExecWithVars(v, name, src, r, vars)   r == nil ⇒ no command binding
        │                                    │
        ▼                                    ▼
  interp{ .res = r } (newInterpVars, vars-seeded) ── per ordinary command ──▶  r(cmd *bash.Command, it.resolutionProgram())
        │                                                  │  (closure)
        │                                                  ▼
        │                                          b.BindBash(cmd, prog)
        │                                                  │  FromBash → *Call → Bind
        │                                                  ▼
        │                                          *bind.Result
        │                                                  │  .Effects, .Derivations
        ▼                                                  ▼
  interp.effs/ders  ◀───  bash.Resolution{Effects, Derivations}  ───┘
        │  folded with shell-intrinsic effects (redirections, env writes, code-exec sinks)
        ▼
  ExecResult{ Effects, Derivations, Destructiveness, Cmds, Conservative, Top, Notes }
```

The Resolver is called for *ordinary* commands; everything the shell contributes on its own (redirections, environment writes, code-execution sinks) is emitted directly by the interpreter. It is also consulted for the call shapes that never reach the ordinary flow but still carry privilege-wrapper knowledge: a wrapper that consumed the whole command line (`sudo -i` — no command word after the peel), a wrapper over a dynamically-named inner command (`sudo $X` — the name cannot be bound), a wrapper over a code-execution sink (`sudo sh -c '…'`), and a wrapper over a code-executing builtin (`sudo eval '…'`); the interpreter folds the returned effects (the wrapper's `PrivEsc`; the binder's own ⊤ `CodeExec` for a dynamically-named inner command is subsumed by the interpreter's) via `elevateWrappers` — and folds a consult at all only when it carries elevation evidence, so a wrapper over an effect-free line stays benign. When the interpreter has already derived its own ⊤ `CodeExec` for the statement, the binder's ⊤ (with its derivation) is dropped — `Report.Normalize` keys the merge on the flow role, so both rows would report the same unknown execution twice. The seam carries effects and derivations but no notes, so the composition layer may still hold a binder note explaining a ⊤ the interpreter subsumed (e.g. `unresolved command "sh": assuming ⊤ (CodeExec)` beside the sink's own note) — duplicative provenance for one row, never a false claim; for the same reason, a destructive-table row joined per consult can survive a subsumed ⊤ (documented residual, SECURITY.md Known Risks). Each call returns a fresh `bash.Resolution` whose `Effects` and `Derivations` the interpreter accumulates; the frontend never sees `bind` types, only `engine.Effect`/`engine.Derivation`.

## Error Propagation

`bash.Exec`/`bash.ExecWithVars` never propagate an error across the seam: they recover from any panic and return a ⊤ result (`topResult`), a parse failure becomes `Program.Top=true` with a `Reason`, and an exhausted step budget unwinds to ⊤ as well. The `Resolver` contract carries no `error` — a resolver that cannot bound a command returns the ⊤ effect (`CodeExec` over `ScopeTop()`) inside the returned slice. On the binder side `Bind` is total: it returns a non-nil `*Result` for any well-formed `Call` (a `nil` call yields a conservative result). Because binding cannot fail, the only way the seam affects the analysis outcome is by returning a more or less precise effect set, never by raising.

## Breaking Change Checklist

- **Change the `Resolver` signature** — you MUST update `type Resolver`, the `interp.res` field, `newInterpVars`, `Exec`, `ExecWithVars`/`execVars`, and `ExecBash` in `front/bash/exec.go`, then every injection site: the closure in `internal/analysis/analyze.go` (`analyzeBash`) and `newResolver` in `front/bash/exec_test.go`.
- **Change `bash.Command` or `bash.Program`** — you MUST update `bind.FromBash` (`bind/bind.go`) and its consumers (`BindBash` in production; `BindProgram`/`bindStmt`, test-only in `bind/program_bind_test.go`), and regenerate the frontend golden fixtures `front/bash/testdata/program.golden.json` and `front/bash/testdata/wrappers.golden.json`.
- **Change `bind.Result`** — you MUST update the closure in `internal/analysis/analyze.go` (it reads `.Effects` and `.Derivations`) and the consumers of `ExecResult`.
- **Make `front/bash` import `bind`/`kb`/`front/ps`** — forbidden: it creates an import cycle and violates the one-way rule; extend the `Resolver` seam instead.
- **Change `bash.ExecResult`** — you MUST update `internal/analysis.analyzeBash`, which reads `Effects`, `Derivations`, `Conservative`, `Top`, `Reason`, `Cmds`, and `Notes`.

**Related specs:** [frontend-engine.md](frontend-engine.md) — the `engine.Effect` values that cross this seam; [bind-kb.md](bind-kb.md) — what the injected binder does once the Resolver calls it.
