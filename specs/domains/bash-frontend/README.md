# Bash Frontend

## Purpose

`front/bash` is the shell frontend of the effect IR. It parses shell source text into a faithful, position-preserving syntax tree, lowers that tree into its own normalized AST (unwrapping the ubiquitous command wrappers such as `sudo`, `env` and `timeout` and recording the declared aliases and functions), and abstractly executes the program over an abstract state Σ to discover the effects it implies. Where it cannot see, it degrades to the top element ⊤ rather than guessing or crashing.

## Key Files

- `front/bash/parse.go` — the entry point: `Variant` (`Bash`/`POSIX`), `Parse` (mvdan `syntax` parser + `syntax.Simplify`), `Pos`, and the ⊤ fallback (`topProgram`).
- `front/bash/normalize.go` — the normalized AST (`Kind`, `Program`, `Stmt`, `Command`, `Wrapper`, `Assign`, `Redirect`, `Word`, `Part`, `Alias`, `Func`) and normalization: wrapper unwrapping (`wrapperSpecs`/`unwrap`) and symbol annotation (`annotate`).
- `front/bash/expand.go` — the abstract state Σ (`State`, `Var`, `NewState`, `Clone`, `joinStates`, `defaultVars`), word expansion, static knownness, and taint propagation.
- `front/bash/exec.go` — the abstract-execution layer: `interp`, `Resolver`/`ExecResult`, `Exec`/`ExecBash`, pipelines, control flow, redirections, sinks and budget bounds.
- `front/bash/glob.go` — the bash-faithful glob matcher used for case-arm patterns (`globMatch`): `*` matches `/` too, POSIX classes and `!`/`^` negation are honoured, extglob/collating symbols report "possibly matching".
- `front/bash/builtins.go` — code-execution sinks (matched by basename, `env`-resolved through `envSink`, exported for the binder as `IsCodeExecutionSink`), code-executing and shell-only builtins, stdout folding (`echo`/`printf`/`base64`), and builtin state transfer functions.
- `front/bash/parse_test.go`, `front/bash/normalize_test.go`, `front/bash/exec_test.go`, `front/bash/expand_resolve_test.go`, `front/bash/glob_test.go`, `front/bash/flow_test.go`, `front/bash/brace_estimator_internal_test.go` — test suites; `front/bash/testdata/program.golden.json` and `front/bash/testdata/wrappers.golden.json` are the normalized-AST regression fixtures (the latter covers the legacy wrapper set).

## Core Types

### Dialect, positions, AST

```go
type Variant string

const (
	Bash  Variant = "bash"  // GNU Bash (default)
	POSIX Variant = "posix" // POSIX shell (sh)
)

type Pos struct { Line, Col, Offset int }

type Kind string // statement classification

const (
	KindSimple   Kind = "simple"   // program invocation or assignment
	KindPipeline Kind = "pipeline" // a | b, a |& b
	KindAndOr    Kind = "andor"    // a && b, a || b
	KindBlock    Kind = "block"    // { ...; }
	KindSubshell Kind = "subshell" // ( ... )
	KindIf       Kind = "if"
	KindWhile    Kind = "while"    // while/until
	KindFor      Kind = "for"
	KindCase     Kind = "case"
	KindFunc     Kind = "func"
	KindArithm   Kind = "arithm"
	KindTest     Kind = "test"     // [[ ... ]]
	KindDecl     Kind = "decl"     // declare/local/export/readonly/typeset/nameref
	KindLet      Kind = "let"
	KindTime     Kind = "time"
	KindCoproc   Kind = "coproc"
	KindOther    Kind = "other"
)
```

`Program` is the normalized AST of a source: its statements (position-preserving) plus the `Aliases` and `Funcs` the source declares. `Stmt` is a tagged union selected by `Kind`. `Command` carries the effective `Name`/`Args`, the `Assigns` that apply to it, and the `Wrappers` peeled off the front (outermost first):

```go
type Command struct {
	Pos        Pos
	Name       string
	NameWord   *Word
	Args       []*Word
	Assigns    []*Assign
	Wrappers   []*Wrapper
	ResolveKind string // "", "func" or "alias" when Name names a declared symbol
	ResolvesTo  string
	StdinTaint engine.Taint `json:"-"`
	Redirs     []ExecRedirect `json:"-"`
}
```

`Redirs` carries the statement's I/O redirections as the abstract interpreter resolved them (operator plus expanded target text, `ExecRedirect{Op, Target, Known}`); it is attached while the statement executes to feed the report's per-command view and is not part of the serialized AST.

### Σ — the abstract state (see `expand.go`)

```go
// Σ = ⟨ vars↑taint, PWD, umask, funcs, aliases ⟩
type State struct {
	Vars    map[string]*Var
	PWD     string
	Umask   string
	Funcs   map[string]*Func
	Aliases map[string]string
}

type Var struct {
	Value    string
	Taint    engine.Taint
	Set      bool
	Known    bool // false ⇒ reads of the variable are dynamic (⊤)
	Export   bool
	Readonly bool
	Int      bool   // declare -i: assignments are arithmetic, never trusted as literals
	Ref      string // nameref target (declare -n r=a): reads carry the target's provenance
	Numeric  bool   // numeric class: unknown but bounded integer (digits cannot form path structure)
	Assumed  bool   // host default (HOME, USER, …): names paths, never decides control flow
}
```

`Int` invalidates literal reads of a `declare -i` variable (later assignments are arithmetic and are not evaluated); `Ref` records the nameref target so a credential assigned to the target after the declaration is still seen through the reference; `Numeric` confines path-shaped words to their literal directory (see [Abstract Execution](abstract-exec.md)); `Assumed` marks the host-seeded defaults, which must never decide control flow.

### Abstract-execution result (see `exec.go`)

```go
// Resolution is a call's effects plus the Derivations (concrete source atoms)
// that justify them for the composition layer's why-trace.
type Resolution struct {
	Effects     []engine.Effect
	Derivations []engine.Derivation
}

// Resolver is the seam through which the effect knowledge base is injected:
// it maps one normalized, fully-expanded command invocation to its resolution.
type Resolver func(cmd *Command, prog *Program) Resolution

type ExecResult struct {
	Variant         Variant
	File            string
	Source          string
	Top             bool   // whole analysis degraded to ⊤
	Reason          string
	Conservative    bool   // aggregate includes a ⊤ effect
	Effects         []engine.Effect
	Destructiveness engine.Destructiveness
	// Derivations justifies every reported effect with the concrete source
	// atoms (flags, operands, redirections, sinks) it rests on, for the
	// composition layer's why-trace.
	Derivations     []engine.Derivation
	State           *State
	Cmds            []*Command
	Notes           []string
}
```

## Flow

```
      shell source (dialect v)
            │
            ▼  Parse(v, name, src)                      (parse.go)
   mvdan syntax.NewParser(Variant) → Parse → syntax.Simplify
            │
            ├─ unknown variant / parse error / panic ──▶ Program{Top:true, Reason, ErrPos}
            ▼  ok
      normalizer.fill(file, prog)                       (normalize.go)
            │   ├─ stmts(...)          syntax.Command → normalized Stmt (Kind, positions)
            │   ├─ call(...)           unwrap wrappers; split Assigns / Name / Args
            │   └─ annotate(...)       mark commands naming a declared func/alias
            ▼
      Program  (Stmts, Aliases, Funcs)

================================= separately =================================

      Exec(v, name, src, r Resolver)                    (exec.go)
            │
            ▼  parse + simplify again;  newInterpVars(..., state: NewState())
      it.execStmts(f.Stmts)     Σ = ⟨vars↑taint, PWD, umask, funcs, aliases⟩
            │
            ├─ command effects   ← r (the injected binder)   [Resolver seam]
            ├─ redirections, sinks, env writes — plus credential operand/env
            │  reads, [[ -f ]] file tests, exec-bearing env assignments
            │  (ExecEnvEffect) and secret-staging joins ← emitted here directly
            └─ pipelines thread folded stdout → next stage's stdin;  state cloned per stage
            ▼
      ExecResult{Effects (normalized), Derivations, State, Cmds, Notes, Top, Conservative}
```

Two design points: ordinary command effects come through the **Resolver seam** (the binding layer imports `front/bash`, so `front/bash` cannot import it back — the caller injects the binder); and the analysis is **bounded**, degrading to ⊤ within a fixed step budget rather than diverging.

## Invariants

- `Parse` and `Exec` never panic: a parse failure, an internal error, or an exhausted budget all degrade to a ⊤ result (`Top` set, with a `Reason`).
- A ⊤ `Program` or `ExecResult` carries a reason and (for a program) no statements.
- Positions are always preserved through normalization.
- The package is a frontend: it may import the frozen core (`engine`) and never the other way around; the core likewise never imports a frontend (`TestCoreDoesNotImportFrontends`).
- Effects of ordinary commands are obtained only through the `Resolver` seam; `front/bash` emits only the shell's *own* contributions directly: redirections, sinks, env writes — and also credential operand reads (`FSRead`+`secret` for credential-shaped operand text), credential-shaped environment reads (`EnvRead`+`secret`), the `FSRead` of a `[[ -f … ]]` file test, `CodeExec` for exec-bearing environment assignments (`ExecEnvEffect`: `LD_PRELOAD`, `BASH_ENV`, `GIT_CONFIG_*`, `TAR_OPTIONS`, …), and the secret-staging joins (`engine.ApplySecretStaging`) that pair a staged credential with the egress that uploads it. Both the resolver's effects and the shell's own carry `Derivation`s (concrete source atoms), which the composition layer folds into `report.why`.
- Every statement normalizes to a declared `Kind`; an unrecognised construct normalizes to `KindOther` (with raw text) and, at execution time, `interp.execCommand` records a ⊤ effect (with a derivation) and the note `unsupported construct at <pos>`.
- Σ is cloned, never shared, across subshells, pipeline stages, background/coprocess jobs, command and process substitutions, and the arms of an undecidable branch. **Function calls are the bash-faithful exception**: `callFunc` executes the body against the *caller's* Σ — only the positional parameters (`0`, `#`, `@`, `*`, `1..9` — a fixed set, so an argument past the ninth is not restored and persists to the caller) are saved and restored, and every other state change the body performs persists to the caller. If the body contains a `shift` or a `set --` (`funcRebindsPositional`), the callee's freshly-bound `1..9` are unset and `@`/`*` reset to unknown *before* the body runs: positional rebinding is not modelled, so in-body reads degrade to ⊤ instead of holding a stale argument (the caller's saved positionals are still restored afterwards).
- Globbing is disabled: the analysis never touches the filesystem during expansion; a word with unquoted glob metacharacters is reported dynamic instead.

## Configuration

- `defaultBudget = 50000` — the interpreter step budget (redirections, statements, loop iterations, function calls all draw on it). Exhaustion ⇒ ⊤, which is what makes `while true` cheap.
- `maxFuncDepth = 64` — function-call recursion bound.
- `maxAliasDepth = 32` — alias-chain expansion bound.
- `maxRecorded = 1024` — bound on the resolved-invocation and note lists.
- `maxFindDepth = 8` — bound on the nesting of `find … -exec find …` payload analysis.
- `maxExpandedFields = 4096` — bound on the fields a single word may expand to; a word whose brace expansion the estimator (`braceCount`/`braceRange`/`matchBrace`/`splitTopComma`, nesting bounded by `maxBraceDepth = 16`) over-estimates degrades to ⊤ ("brace expansion too large"), and each materialised field is charged against the step budget (`chargeExpansion`) so a loop body costs proportionally to the data it produces.
- `defaultVars` = `{IFS: " \t\n", HOME: "/root", PATH: "/usr/bin:/bin", PWD: "/", SHELL: "/bin/sh", USER: "root"}`; `defaultUmask = "0022"`. Every default except `IFS` is `Assumed`: a host stand-in that names paths but never decides control flow. Assignments and `for` items derived from an assumed word stay assumed; any other assignment clears the flag.
- Recognised wrappers (`wrapperSpecs`, 41 entries): `sudo`, `env`, `nohup`, `command`, `nice`, `timeout`, `xargs`, `setsid`, `builtin`, `stdbuf`, `watch`, `flock`, `systemd-run`, `nsenter`, `taskset`, `ionice`, `chrt`, `unshare`, `ssh-agent`, `strace`, `ltrace`, `valgrind`, `caffeinate`, `chroot`, `runcon`, `prlimit`, `switch_root`, `setarch`, `linux32`, `linux64`, `busybox`, `toybox`, `envdir`, `softlimit`, `faketime`, `unbuffer`, `xvfb-run`, `systemd-cat`, `torsocks`, `proxychains`, `proxychains4` — plus the command-string wrappers `su`/`runuser`/`script`/`flock` (`-c CMD`) and the one multi-word wrapper `ip netns exec NS CMD`. The full inventory and consumption rules live in [Command Wrappers](wrappers.md).

## Extension Points

- **Add a command wrapper**: add a `wrapperSpec` entry (`valueOpts`/`envAssigns`/`fixedArgs`/`fixedUnless`/`fixedIfIn`/`requirePayload`/`defaultCmd` — see [Command Wrappers](wrappers.md)) to `wrapperSpecs` in `normalize.go`.
- **Add a code-execution sink or code-executing builtin**: extend `sinkSet`/`codeExecBuiltins` in `builtins.go`.
- **Add stdout folding**: extend `interp.stdoutOf` to fold a new pure command's output.
- **Add a builtin's state transfer**: extend `interp.builtinState`.
- **Add a normalizable construct**: handle the new `syntax.Command` type in `normalizer.command` and a new `Kind`.
- **Bind command effects**: supply a `Resolver` (this is how `bind.Binder.BindBash` plugs in).

## Related Specs

- [Parse & Normalize](parse-normalize.md) — detail of the parse and normalization components.
- [Abstract Execution](abstract-exec.md) — detail of the Σ-threaded abstract interpreter.
- [Command Wrappers](wrappers.md) — the wrapper inventory, consumption rules and payload channels.
- [Binding](../binding.md) — injects the effect knowledge base through the `Resolver` seam.
- [Knowledge Base](../knowledge-base.md) — the command/flag signatures the binder resolves against.
- [PowerShell Frontend](../powershell-frontend.md) — the sibling frontend with its own AST and tables.
