# Contract: Bind <-> Knowledge Base

## Boundary Rule

`bind` depends on `kb`; `kb` never depends on `bind`. The direction is forced by the module graph: `kb` already imports `engine`, so `engine` cannot import `kb`, and a `kb`→`bind` import would be a cycle. `bind` therefore holds a `*kb.KB` and drives it, while `kb` exposes only plain data (`Command`, `Param`, `Effect`, `Destructive`) and pure lookups. Where `bind` cannot match a call against the KB — an unknown command name, or a name that is not statically known — it must not invent an effect: it degrades to the top element ⊤ (`CodeExec` over `ScopeTop()`), never to "no effect".

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |
| `const SchemaVersion = "effect-kb/v2"` + `var KnownVersions []string` + `func Known(v string) bool` | `kb` (`schema.go`) | `kb` loader, tests | Frozen document-schema version; the loader rejects a data file whose `version` is not known. |
| `type KB struct{ Version string; Commands []Command; Destructive []Destructive; ... }` | `kb` (`schema.go`) | `bind.Binder` | Loaded knowledge base: commands (sorted by name) plus the destructive-flags table. |
| `func (k *KB) Command(name string) (*Command, bool)` / `func (k *KB) CommandNames() []string` | `kb` (`schema.go`) | `bind.Binder.resolve` | Resolve an invoked name or alias to its command entry. |
| `func (k *KB) DestructiveFor(command, spec string) (*Destructive, bool)` | `kb` (`schema.go`) | `bind.destructiveEntries` | Look up a matched `(command, spec)` pair in the destructive-flags table. |
| `func (k *KB) Validate() error` | `kb` (`schema.go`) | `kb` loader, tests | Referential integrity: known version, well-formed commands, every destructive entry naming a declared param. |
| `type Command struct{ Name string; Dialect Dialect; Aliases []string; Params []Param }` | `kb` (`schema.go`) | `bind.bindCommand` | One command's parameter set. |
| `func (c Command) Param(spec string) (Param, bool)` / `func (c Command) HasParam(spec string) bool` | `kb` (`schema.go`) | `bind.parseArgs`, `bind.bindCommand`, `KB.Validate` | Match a written flag/option/operand against the declared specs. |
| `type Param struct{ Spec string; Kind ParamKind; Effect Effect }` | `kb` (`schema.go`) | `bind.bindCommand`, `bind.lowerParam` | One parameter and the primary effect it contributes. |
| `func (p Param) Validate() error` / `func (c Command) Validate() error` | `kb` (`schema.go`) | `kb` loader, tests | Spec/kind coherence and command well-formedness. |
| `type ParamKind string` (`ParamFlag`, `ParamOption`, `ParamPositional`, `ParamAssign`) | `kb` (`schema.go`) | `bind.parseArgs`, `bind.bindCommand` | Surface syntax classification that drives argv parsing. |
| `type ValueSource string` (`ValueArgs`, `ValueFlagValue`, `ValueStdin`, `ValueEnv`, `ValueCwd`, `ValueSelf`, `ValueLiteral`) | `kb` (`schema.go`) | `bind.taintFor` | Which token of the invocation becomes the effect's target/taint. |
| `type Dialect string` (`DialectPOSIX`, `DialectGNU`, `DialectBuiltin`, …) | `kb` (`schema.go`) | `bind.resolve` | Command tradition; `DialectBuiltin` is the first link of the resolution chain. |
| `type Effect struct{ Kind engine.EffectKind; Mode engine.EffectMode; ValueFrom ValueSource; FileRef bool }` | `kb` (`schema.go`) | `bind.lowerParam` | The effect a parameter contributes, reusing the core's closed kind/mode sets. |
| `func (e Effect) EngineEffect(target engine.Scope, taint engine.Taint, c engine.Certainty) engine.Effect` | `kb` (`schema.go`) | `bind.lowerParam` | Lower a KB effect into the core IR (kind, mode, default reversibility). |
| `type Destructive struct{ Command string; Spec string; Class DestructiveClass; Reason string }` | `kb` (`schema.go`) | `bind.Result.Destructive` | One entry of the destructive-flags table. |
| `type DestructiveClass string` (`ClassNone`="A" … `ClassCritical`="E") + `func (c DestructiveClass) Severity() engine.Destructiveness` | `kb` (`schema.go`) | `bind.normalizeResult` | Lettered class folded into the core `Destructiveness` lattice (A↔None … E↔Critical). |
| `func Load() (*KB, error)` / `func Default() (*KB, error)` / `func MustLoad() *KB` | `kb` (`loader.go`) | `bind.New`, `bind.NewDefault`, `bind.MustDefault` | Parse the embedded (`//go:embed data/*.yaml`) KB, memoised for hot paths. |
| `func New(k *KB) *Binder` / `func NewDefault() (*Binder, error)` / `func (b *Binder) KB() *kb.KB` | `bind` (`bind.go`) | `internal/analysis` | Construct the binder over an explicit or embedded KB. |
| `func (b *Binder) Bind(c *Call) *Result` / `func (b *Binder) BindBash(cmd *bash.Command, prog *bash.Program) *Result` | `bind` (`bind.go`) | `internal/analysis` | Bind one call and return effects + resolution + matched destructive entries. |
| `type Result struct{ … Destructive []kb.Destructive … }` | `bind` (`bind.go`) | `internal/analysis` | Binding outcome, surfaced including the matched destructive-table entries. |

## Initialization

The KB is compiled into the binary: `kb/loader.go` embeds `data/*.yaml` via `//go:embed data/*.yaml` and `Load` parses it without touching the filesystem. `Default` memoises the parse with a `sync.Once`, and `MustLoad` panics on failure for start-up wiring. `bind.New(k)` wraps an explicit `*kb.KB`; `bind.NewDefault`/`bind.MustDefault` call `kb.Default` for the embedded KB. The composition layer (`internal/analysis.NewAnalyzer`) is the only place that calls `bind.NewDefault`, and it holds the resulting binder as reusable, concurrency-safe state so the one-time KB load is paid once per process.

## Data Flow Across Boundary

```
  Call (normalized name + argv)
        │
        ▼
  Binder.resolve ── k.Command(name) ──▶ *kb.Command ── Dialect==DialectBuiltin? ─┐
        │                                                                        │
        ▼                                                                        │
  bindCommand(cmd, argv, stdinTaint) ◀──────────────────────────────────────────┘
        │  parseArgs: cmd.Param(spec) per flag/option  ── ParamKind decides value capture
        │  Command.Param / Params iteration for positional & assign operands
        ▼
  lowerParam: p.Effect.EngineEffect(target, taint, certainty) ──▶ []engine.Effect
        │      (ValueSource picks target/taint; FileRef adds an @file FSRead)
        ▼
  specs []string ──▶ destructiveEntries(k, cmd.Name, specs)
        │                 └─ k.DestructiveFor(cmd, spec) ──▶ []kb.Destructive (sorted)
        ▼
  Result{ Effects, Resolution, Destructive, Destructiveness }
        │   Destructiveness = join(effects…) ⋈ join(d.Class.Severity() for d in Destructive)
        ▼
  engine.Report (frozen IR)
```

Only plain values cross the boundary: `bind` never calls into `kb` mutably, and `kb` never calls back into `bind`. The KB contributes two independent things: per-parameter effects (lowered to `engine.Effect`) and destructive-table entries (whose `Class` is folded, via `Severity()`, into the report's `Destructiveness`).

## Error Propagation

KB problems are start-up errors, not per-call errors. `Load`/`Default` return a Go `error` when a document declares a missing or unknown `version` (`Known` rejects anything but `effect-kb/v2`), when YAML is malformed, or when `KB.Validate` finds a destructive entry that names an undeclared parameter or unknown command — `MustLoad` converts that into a panic at wiring time. Once a KB is loaded, binding is total and error-free per call: an unrecognized flag is recorded in `Result.Notes` ("unrecognized flag(s): …"), not returned as an error; a name that matches no builtin/function/alias/command sets `ResolveUnknown` and yields the ⊤ effect with `Conservative=true`. `Bind` never returns nil and never panics on a well-formed `Call`.

## Breaking Change Checklist

- **Change the KB document schema** (add/rename a field in a `data/*.yaml` document) — you MUST bump `kb.SchemaVersion` (currently `effect-kb/v2`), add the new value to `KnownVersions`, update `parseDocument`/`loadFS` in `kb/loader.go`, and update the loader tests that assert unknown versions are rejected.
- **Add a `ParamKind`** — you MUST update the `ParamKind` constants and `ParamKinds`, the `Param.Validate` spec/kind check, `bind.parseArgs` (how the surface token is captured), and `bind.bindCommand` (positional/assign handling).
- **Add a `ValueSource`** — you MUST update the `ValueSource` constants and `ValueSources` and the `taintFor` switch in `bind/bind.go` (and `kb.Effect.Validate` if it constrains the value).
- **Add a `DestructiveClass`** — you MUST update the `DestructiveClass` constants/`DestructiveClasses` **and** the `Severity()` mapping so the class still folds onto the core `Destructiveness` lattice.
- **Change a `Command`/`Param`/`Effect` struct field or its YAML tag** — you MUST update the `kb/data/*.yaml` documents, the loader decode path (`kb/loader.go`), and every `bind` consumer (`resolve`, `bindCommand`, `lowerParam`, `taintFor`) plus `kb/schema.go` validation.
- **Add an `EffectKind`/`EffectMode`** — you MUST also extend `kb.DefaultReversible` and `kb.Effect.Validate` (see [frontend-engine.md](frontend-engine.md)).

**Related specs:** [frontend-engine.md](frontend-engine.md) — the core IR that `kb.Effect.EngineEffect` lowers into; [exec-resolver.md](exec-resolver.md) — how the composed binder is injected into the shell frontend; [report-json.md](report-json.md) — the frozen JSON that carries the bound effects and destructiveness.
