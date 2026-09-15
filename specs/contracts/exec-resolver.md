# Contract: Front/Bash <-> Caller (Resolver Seam)

## Boundary Rule

`front/bash` depends on `engine` only, and must never import `bind`, `kb`, or `front/ps`. The dependency is inverted through a function value — the `Resolver` seam — so the caller injects the binder rather than the frontend reaching for it. `bind` already imports `front/bash` (via `FromBash`), so a `front/bash`→`bind` import would be a cycle; the seam is what keeps the shell frontend free of the knowledge base entirely. A `nil` Resolver is a valid configuration: it disables command binding and leaves only the shell's own intrinsic effects.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |
| `type Resolution struct{ Effects []engine.Effect; Derivations []engine.Derivation }` + `type Resolver func(cmd *Command, prog *Program) Resolution` | `front/bash` (`exec.go`) | the caller — `internal/analysis` (production), `front/bash/exec_test.go` (tests) | The seam: maps one normalized, fully-expanded command invocation to its effects and the derivations (concrete source atoms) that justify them. |
| `func Exec(v Variant, name, src string, r Resolver) *ExecResult` | `front/bash` (`exec.go`) | `internal/analysis`, tests | Parse and abstractly execute `src`; never panics; every failure degrades to ⊤. |
| `func ExecBash(src string, r Resolver) *ExecResult` | `front/bash` (`exec.go`) | tests (`front/bash/exec_test.go`) | `Exec` specialised to the bash dialect (`Exec(Bash, "script", src, r)`); the production caller `internal/analysis.analyzeBash` calls `Exec` directly. |
| `func ExecPOSIX(src string, r Resolver) *ExecResult` | `front/bash` (`exec.go`) | external callers (no in-module caller) | `Exec` specialised to the POSIX shell (`Exec(POSIX, "script", src, r)`). |
| `func Parse(v Variant, name, src string) *Program` | `front/bash` (`parse.go`) | `bind.BindScript`/`BindProgram`, tests | Produce the normalized `Program` that a Resolver receives. |
| `type Program struct{ Variant Variant; File, Source string; Top bool; Reason string; ErrPos *Pos; Stmts []*Stmt; Aliases map[string]*Alias; Funcs map[string]*Func }` | `front/bash` (`normalize.go`) | the Resolver impl, `bind.FromBash` | The normalized AST handed to the Resolver (carries the declared aliases/functions). |
| `type Command struct{ Pos Pos; Name string; NameWord *Word; Args []*Word; Assigns []*Assign; Wrappers []*Wrapper; ResolveKind, ResolvesTo string; StdinTaint engine.Taint }` | `front/bash` (`normalize.go`) | the Resolver impl, `bind.FromBash` | The normalized simple command handed to the Resolver. |
| `type ExecResult struct{ Variant Variant; File, Source string; Top bool; Reason string; Conservative bool; Effects []engine.Effect; Destructiveness engine.Destructiveness; Derivations []engine.Derivation; State *State; Cmds []*Command; Notes []string }` | `front/bash` (`exec.go`) | `internal/analysis` | Aggregate result of abstract execution (effects from both the Resolver and the shell itself, plus their derivations). |
| `func FromBash(cmd *bash.Command, prog *bash.Program) *Call` | `bind` (`bind.go`) | `Binder.BindBash`, tests | Adapter: lowers the frontend's `Command`/`Program` into the binder's frontend-agnostic `Call`. |
| `func (b *Binder) BindBash(cmd *bash.Command, prog *bash.Program) *Result` | `bind` (`bind.go`) | the injected Resolver closure | Convenience wrapper: `Bind(FromBash(cmd, prog))`. |
| `func (b *Binder) Bind(c *Call) *Result` | `bind` (`bind.go`) | `Binder.BindBash`, `Binder.BindProgram` | The actual binding entry point for a normalized `Call`. |

## Initialization

The two halves are joined in exactly one place, `internal/analysis/analyze.go`, which holds a `*bind.Binder` and passes a closure matching the `Resolver` signature to `bash.Exec`:

```go
b := a.binder
res = bash.Exec(v, sourceName(root, "script"), src, func(cmd *bash.Command, prog *bash.Program) bash.Resolution {
    br := b.BindBash(cmd, prog)
    return bash.Resolution{Effects: br.Effects, Derivations: br.Derivations}
})
```

When the analyser holds no binder, it calls `bash.Exec(v, sourceName(root, "script"), src, nil)`, and only the shell's intrinsic effects are reported. `bind.FromBash(cmd, prog) *Call` is the pure `Command`/`Program`→`Call` handoff used both by `BindBash` and by `Binder.BindProgram`/`BindScript`, which bind a whole program without abstract execution. The frontend side is wired by the interpreter: `newInterp(src, prog, r, file)` stores `r` in `interp.res`, and the interpreter invokes `it.res(cmd, prog)` for each ordinary command it reaches.

## Data Flow Across Boundary

```
  internal/analysis.analyzeBash
        │  holds *bind.Binder
        ▼
  bash.Exec(v, name, src, r Resolver)     r == nil ⇒ no command binding
        │                                    │
        ▼                                    ▼
  interp{ .res = r } ── per ordinary command ──▶  r(cmd *bash.Command, prog *bash.Program)
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

The Resolver is called only for *ordinary* commands; everything the shell contributes on its own (redirections, environment writes, code-execution sinks) is emitted directly by the interpreter. Each call returns a fresh `bash.Resolution` whose `Effects` and `Derivations` the interpreter accumulates; the frontend never sees `bind` types, only `engine.Effect`/`engine.Derivation`.

## Error Propagation

`bash.Exec` never propagates an error across the seam: it recovers from any panic and returns a ⊤ result (`topResult`), a parse failure becomes `Program.Top=true` with a `Reason`, and an exhausted step budget unwinds to ⊤ as well. The `Resolver` contract carries no `error` — a resolver that cannot bound a command returns the ⊤ effect (`CodeExec` over `ScopeTop()`) inside the returned slice. On the binder side `Bind` is total: it returns a non-nil `*Result` for any well-formed `Call` (a `nil` call yields a conservative result). Because binding cannot fail, the only way the seam affects the analysis outcome is by returning a more or less precise effect set, never by raising.

## Breaking Change Checklist

- **Change the `Resolver` signature** — you MUST update `type Resolver`, the `interp.res` field, `newInterp`, `Exec`, and `ExecBash` in `front/bash/exec.go`, then every injection site: the closure in `internal/analysis/analyze.go` (`analyzeBash`) and `newResolver` in `front/bash/exec_test.go`.
- **Change `bash.Command` or `bash.Program`** — you MUST update `bind.FromBash` (`bind/bind.go`) and its consumers (`BindBash`, `BindProgram`, `bindStmt`), and regenerate the frontend golden fixtures `front/bash/testdata/program.golden.json` and `front/bash/testdata/wrappers.golden.json`.
- **Change `bind.Result`** — you MUST update the closure in `internal/analysis/analyze.go` (it reads `.Effects` and `.Derivations`) and the consumers of `ExecResult`.
- **Make `front/bash` import `bind`/`kb`/`front/ps`** — forbidden: it creates an import cycle and violates the one-way rule; extend the `Resolver` seam instead.
- **Change `bash.ExecResult`** — you MUST update `internal/analysis.analyzeBash`, which reads `Effects`, `Derivations`, `Conservative`, `Top`, `Reason`, `Cmds`, and `Notes`.

**Related specs:** [frontend-engine.md](frontend-engine.md) — the `engine.Effect` values that cross this seam; [bind-kb.md](bind-kb.md) — what the injected binder does once the Resolver calls it.
