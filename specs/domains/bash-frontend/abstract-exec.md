# Abstract Execution

## Role

This component is the frontend's transfer-function engine: it walks the parsed syntax tree with an abstract state Σ, expanding words, interpreting redirections, pipelines, control flow and subshells, and folding the effects it discovers into a single aggregate `ExecResult`.

## Key Files

- `front/bash/exec.go` — the interpreter: `Resolver`, `ExecResult`, bounds, `interp`, `Exec`/`ExecBash`/`ExecWithVars`, statement/command execution, pipelines, control flow, redirections, substitution capture, dispatch, and the ⊤/budget machinery.
- `front/bash/expand.go` — Σ (`State`, `Var`, `NewState`, `Clone`, `joinStates`), the expansion configuration (`newCfg`), word expansion (`expandFields`/`expandLiteral`), static knownness (`wordKnown`/`partKnown`/`paramKnown`/`arithKnown`), the numeric-class predicates (`numericParam`/`knownParamText`/`numericConfinedDir`) and taint (`wordTaint`/`partTaint`).
- `front/bash/builtins.go` — the sink set (matched by basename through `commandBase`, `env`-resolved through `envSink`, exported for the binder as `IsCodeExecutionSink`), code-executing/shell-only builtins, stdout folding (`stdoutOf`, `echoOut`, `printfOut`, `base64Out`) and builtin state transfer (`builtinState`).
- `front/bash/glob.go` — the bash-faithful glob matcher (`globMatch`) used by `caseMatch`: `*` matches any run of characters *including* `/`, `?` any single one, `[…]` classes with `!`/`^` negation, ranges and POSIX classes; extglob and collating/equivalence symbols report *not faithfully decidable*, so the arm is treated as possibly matching.

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
maxFindDepth  = 8       // nesting of `find … -exec find …` payload analysis
maxRecorded   = 1024    // caps Cmds and Notes

ctlNone < (ctlBreak, ctlContinue, ctlReturn, ctlExit)
```

Each materialised expansion field additionally draws one unit on the step budget (`chargeExpansion`, bounded by `maxExpandedFields`), so a loop body costs in proportion to the data it produces. The parenthesis-nesting cap `maxNestingDepth = 4096` (`nestingTooDeep`) precedes parsing (see [Parse & Normalize](parse-normalize.md)).

`step()` charges one unit and panics with `budgetError` when the budget is exhausted; the panic is recovered and converted to ⊤. The `ctl*` signals propagate through `execStmts` until a loop or function consumes them.

### Statement and command execution

```
execStmts(ss):  for each s { if ctl != none → stop or consume (below); execStmt(s) }
execStmt(s):    step(); save/restore stdinTaint; apply s.Redirs;
                if s.Cmd == nil → return;
                if Background/Coprocess → run in a cloned Σ, status 0; else execCommand(s.Cmd)
execCommand(c): dispatch on syntax.Command type:
   CallExpr→execCall  BinaryCmd→execBinary  Block→execStmts  Subshell→(cloned Σ)
   IfClause→execIf    WhileClause→execWhile ForClause→execFor CaseClause→execCase
   FuncDecl→execFuncDecl  DeclClause→execDecl  TimeClause→execStmt  CoprocClause→(cloned Σ)
   ArithmCmd/TestClause/LetClause → status unknown
   default → ⊤ effect + note "unsupported construct at <pos>"
```

A control-flow signal no enclosing construct can consume is a no-op in bash (only `exit` is terminal everywhere): a stray `return` outside a function is ignored with the note `return outside a function; ignored`, and a `break`/`continue` outside a loop with `loop-control builtin outside a loop; ignored` — execution of the statement list continues either way. Only `exit` (and `return` at depth > 0, or loop-control inside a loop) stops the list.

### Pipelines (`execPipeline`)

Each stage runs in its own subshell copy of Σ. The interpreter threads the folded standard output of each stage into the next as its stdin (`it.stdout`/`stdoutKnown`/`stdoutTaint` → `it.stdin`/`stdinKnown`/`stdinTaint`), which is the pipeline's value flow. A stage that is a code-execution sink turns the flowing value into executed code (the sink reports ⊤ when dispatched). After the pipeline, the original stdin thread is restored and the status is set unknown.

The value flow also tracks *what* the stdin holds: `stdinFed` records that a value actually flows in (an upstream stage, an input redirection, a here-string, `<&N`), and `stdinNet`/`taintIsNetwork` record that it came from the network — `stdinNet` when an upstream pipeline stage performed a network egress (`stageHasNetEgress`), `taintIsNetwork` when the value's provenance carries the network label or is ⊤ (which conservatively includes network content). The network label is attached only where the analysis actually established the flow: a command substitution whose body itself performed a network effect. Mere `untrusted` content is deliberately **not** network content, and a `/dev/tcp` **ingress** redirection emits its `NetIngress` without marking the stdin network-sourced (`sh -c "$(cat local.txt)"` is not a cradle — the code-review #4 narrowing). A code-execution sink fed by network content is a **download cradle**: its ⊤ effect is emitted with the `FlowCradle` network-flow role (`sinkFlowRole`/`markTopEffectFlow`), distinguishing "untrusted code executed" from a plain sink. A command *language* read from stdin (heredoc or pipe into `sqlite3`, `psql`, `gdb`, `ssh`, `mysql`, … — `stdinCodeClients`) is likewise code the analysis cannot bound: the invocation degrades to ⊤ ("command language on standard input to …"), with `ssh -n` exempt because the flag refuses stdin.

### AND/OR lists (`execAndOr`)

The right-hand side runs only when the left-hand side's exit status makes it reachable; an unknown status conservatively runs it (`&&` requires status 0, `||` requires non-zero).

### Control flow

- `execIf`: if the condition's status is known, run the taken branch; otherwise run **both** branches (effects accumulate) and join the two resulting states (`joinStates`) — the least upper bound, where a variable keeps its value only when both branches agree. An `if` that runs nothing (an empty `then`, or a false condition with no `else`) exits 0.
- `execWhile`: iterate while the (statically decidable) condition holds; a non-decidable condition runs the body once and `markTop("loop condition is not statically decidable")` — the **whole analysis** degrades to ⊤ (flag + ⊤ effect + note), not merely a note. A loop that never ran exits 0; `until` inverts the test.
- `execFor`: over a statically-known word list it iterates exactly; over a dynamic list or over positional parameters it runs the body once and degrades the whole analysis to ⊤. An empty list exits 0. A C-style loop is treated like an unknown bound (iterate until the budget stops it).
- `execCase`: a known subject selects the first matching pattern using the package's own bash-faithful `globMatch` (glob.go) — `*` matches `/` too, POSIX classes and `!`/`^` negation are honoured, and extglob/collating symbols report *not faithfully decidable*, so such a pattern is treated as possibly matching (its arm runs and the analysis degrades to ⊤, never silently dropping the arm). A non-decidable subject, or one reading an `Assumed` host default (`case $HOME in …`), runs every arm and degrades to ⊤; a pattern reading an assumed default is likewise non-decidable. `;&` falls through to the next arm's body (until an arm ends in `;;`), `;;&` resumes pattern matching over the remaining arms, an arm with no patterns is the default, and a fully unmatched subject with no default exits 0.
- `execFuncDecl` records the body; `callFunc` executes it against the **caller's Σ** — bash functions share the caller's variable scope — saving and restoring only the positional parameters (`0`, `#`, `@`, `*`, `1..9`; a fixed set, so an argument past the ninth persists), with a recursion limit; every other state change the body performs persists to the caller. A body containing a `shift` or `set --` (`funcRebindsPositional`) invalidates the callee's positionals before the body executes — `1..9` unset, `@`/`*` set unknown — because rebinding is not modelled, so in-body positional reads degrade to ⊤ rather than keep a stale argument.
- `execDecl` applies the state component of `declare`/`local`/`export`/`readonly` and asks the resolver for the declaration's own effects.

### Redirections (`redir` / `redirectTarget`)

- Output (`>`, `>>`, `>|`, `&>`, `&>>`) ⇒ `FSWrite` of the target; input (`<`) ⇒ `FSRead`, and the file's provenance is joined into the statement's stdin taint so an egress fed only by the redirection is still seen to carry the data out — a target naming a credential location additionally joins the `secret` label (`engine.SecretPath`). An unknown target is ⊤ — unless the word is numeric-confined (below), in which case the effect targets the word's literal directory. A redirection word that is exactly a process substitution is not a ⊤ read: the body's own effects already report it.
- In/out (`<>`) emits both read and write.
- Dup (`>&`, `<&`) with a numeric operand ⇒ `Stdio`; `<&N` (N ≠ 0, -) feeds the command from an untracked descriptor and conservatively marks the stdin `secret`-bearing and fed. `>&N` on a descriptor an earlier `exec 3<>/dev/tcp/…` bound to a socket is a **network egress** (scoped to the remembered endpoint), not a stream dupe. `>&word`/`<&word` with a non-numeric operand is bash's synonym for a file redirection and takes the `FSWrite`/`FSRead` path.
- Heredocs (`<<`, `<<-`) ⇒ `Stdio`; a here-string (`<<<`) feeds its expanded word to the command's stdin with that word's provenance (a credential path in the literal text joins `secret`) and emits one `Stdio` effect.
- `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` pseudo-files are recognised: reading ⇒ `NetIngress`, writing ⇒ `NetEgress` (scoped to `host:port` when known, else ⊤), plus an `IPC` ambient effect. A socket egress carries the command's output provenance: the effect is queued and its taint joined at the end of the statement, once the command that writes into it has been bound (`queueEgress`/`applyEgressTaint`), and an `exec N<>`-bound descriptor remembers its endpoint for the later `>&N` pairing.

### Dispatch: sinks, builtins, and the resolver (`dispatch`)

```
dispatch(name, nameOK, nameQuoted, argv, cmd, effStart)
  1. !nameOK                     → ⊤ effect "dynamically-named command"
  2. alias expansion (≤ maxAliasDepth) — skipped when a wrapper is present
     (external exec) or the command word is quoted/backslash-escaped;
     an opaque alias table (an unresolvable `unalias` operand) → ⊤
  3. find(1) exec payloads       → analyse each payload (≤ maxFindDepth);
     an unbounded payload → ⊤ "find exec payload not analyzable"
  4. shell function declared?    → callFunc (executes the body), no resolver call
  5. sinkName(name, argv)?       → ⊤ effect "code-execution sink "name""
     (matched by BASENAME; `env <interpreter>` resolves through envSink)
  6. stdinFed && stdinCodeClient(name, argv)?
                                  → ⊤ "command language on standard input to …"
  7. builtinState(name, argv)    → mutate Σ (cd, umask, unset, alias, unalias, read)
     + assigningBuiltinState (mapfile/readarray/printf -v), positionalState
       (set --/shift), resolutionState (hash -p/unalias -a)
  8. isCodeExecBuiltin(name)?    → ⊤ effect  (eval, source, ., trap —
     trap only when trapHasAction registers an ACTION)
  9. isShellOnlyBuiltin(name)?   → set ctl for break/continue/return/exit; no external effect
 10. hash table/hashOpaque      → hashed path rebinds the name; an unresolvable
     binding → ⊤ ("name resolution unbound after a dynamic hash -p")
 11. else                        → it.res(cmd, resolutionProgram[Excluding(name)])
                                    [Resolver seam]
```

Every early-return path that skips the ordinary binding (dynamically-named command, sink, stdin code client, code-executing builtin) still consults the resolver seam for the wrappers' own effects (`elevateWrappers`) — a privilege wrapper over a sink still elevates; the consult keeps only PrivEsc-bearing results and drops a binder ⊤ `CodeExec` that an interpreter-side ⊤ from the same statement already subsumes. Before dispatch, a command-string wrapper's `-c CMD` payload (`su`/`runuser`/`script`/`flock`) is extracted, parsed as the shell line it is, and dispatched as the invocation it performs — or degraded to ⊤ ("wrapper payload is a command string the analysis cannot bound"); and a wrapper chain that consumed the whole line with no `defaultCmd` and no payload yields ⊤ ("wrapper consumed the whole command line") rather than an empty report (see [Command Wrappers](wrappers.md)). The step-2 alias loop reduces a body that is a name plus literal words textually; a body carrying a wrapper chain, environment assignments or an expansion-bearing word is re-expanded against Σ and handed over as a whole rewritten `Command` (`expandAliasBody`), so the binder sees the payload the alias really runs. A quoted or backslash-escaped command word is never alias-expanded, and the resolution view passed to the resolver excludes the alias the shell would ignore (`resolutionProgramExcluding`) and is restricted to the aliases installed by execution time (`resolutionProgram()` — aliases are never preloaded; the `alias` builtin installs them as it runs). Step 10 reflects bash's command-hash table: `hash -p PATH NAME` rebinds the name to PATH for later invocations.

`sinkSet` (closed) covers interpreters/shells (`sh`, `bash`, `zsh`, `python`, `node`, `perl`, `awk`, …) and container/orchestration tools (`docker`, `podman`); feeding data to any of them means that data is executed as code (⊤). Sink matching is by **basename** (`commandBase`: `/bin/sh` → `sh`), and an `env <interpreter>` invocation (`/usr/bin/env bash`) resolves through `envSink` to the interpreter it execs; the exported `IsCodeExecutionSink` is the binder's copy of the same rule. `codeExecBuiltins = {eval, source, ., trap}`, where `trap` fires only when a non-empty ACTION operand is registered (`trapHasAction`) — the bare listing/query/reset forms execute nothing. `shellOnlyBuiltins` covers pure shell-state builtins (`:`, `true`, `false`, `break`, `alias`, `shift`, `command`, `[`, …) that would otherwise produce a spurious ⊤ from the KB. `jobs` is deliberately not in the set: it prints the job table to stdout, an observable `Stdio` effect the KB describes (like `echo`), so it resolves through the binding layer like any KB builtin. A `[` invocation is mapped to `test` (its trailing `]` operand dropped) so its file-test operand is reported.

### Stdout folding and substitution (`stdoutOf`, `captureSubst`)

A command substitution is statically known only when the command producing its stdout is. `stdoutOf` folds commands whose output is a pure function of their expanded arguments (and, for the deliberately simple `base64` case, of stdin): `echo`, a subset of `printf` (`%s`/`%d`/`%i`/`%%` and backslash escapes), the no-output commands (`true`, `sleep`, `export`, `read`, …), and `base64` encode/decode when its stdin is known. Everything else reports unknown, which keeps the analysis sound. Command substitutions run their body in a cloned Σ and record the folded stdout (and its knownness/taint) in `it.subst`; process substitutions are recorded as unknown/untrusted. Each substitution node executes once per statement — `prescanSubsts` pre-runs a word's substitution parts, and `substDone`/`substMemo`/`procMemo` memoise the nodes already executed — so a word examined by several passes (option peeling, credential scanning, expansion) records its effects exactly once.

### Numeric-class status parameters and word confinement

Σ seeds the shell's status/identity parameters — `?`, `PIPESTATUS`, `#`, `RANDOM`, `LINENO`, `SECONDS`, `UID`, `EUID`, `PPID`, `BASHPID` (ten; the readonly seeds are `?`, `PIPESTATUS`, `#`, `UID`, `EUID`, `PPID`, which reject assignment) — as set-but-unknown with the **numeric** class: the exact digits are unknowable, but every possible value is a bounded plain integer. `Var.Numeric` records the class; an assignment replaces the value and clears it, and `joinStates` keeps it only when both branches agree.

A word whose dynamic parts are all numeric-class (`$?`, `${PIPESTATUS[*]}`, `${#x}`, a decidable arithmetic expansion, and plain reads of statically-known variables folding their literal value — but never of a `declare -i` variable, whose assignments are arithmetic and untrusted, `Var.Int`) cannot change path structure — digits never form `/`, `..` or an absolute prefix. `numericConfinedDir` therefore lowers such a word (in a redirection target, a `[[ -e … ]]` operand, or a command operand reaching the binder through `Word.Dir`/`Arg.Dir` → `argsScope`) to its **literal directory** — the text before the first numeric part, truncated at the last separator — instead of ⊤. The refusals that keep it sound: any non-numeric dynamic part (an unknown variable, a command/process substitution, an operator supplying a `/`-bearing word), any `..` segment anywhere in the literal text, any backslash escape (`\.\.` hides a real `..`), any brace syntax `{}`/`{` (brace expansion runs before parameter expansion and can fabricate a path component — `{/,$?}` expands to a root-absolute word), and a literal starting a fresh path component (`/` or `\`) immediately after a possibly-empty numeric expansion, which would splice an absolute path. All of these keep the historical ⊤. Resolution adds precision; it never loosens the degrade-to-⊤ default.

### Host-seeded bindings (`ExecWithVars`)

`ExecWithVars` runs `Exec` with the abstract state pre-seeded from a host-supplied `map[string]string`: bindings the embedding host knows from its own context (a session temp directory, a workspace root) that the script text alone does not determine. Each becomes a set, statically-known variable — exactly the state a literal in-script assignment produces — so later `$name` reads (and paths built from them) resolve concretely. Empty names and readonly collisions (the seeded status parameters) are skipped; an in-script assignment overrides a seed from the point it executes. A nil/empty table reproduces plain `Exec`.

### Taint

- Σ variables carry a `Taint` label; `partTaint` joins the taint of a word's parts (a parameter expansion takes the variable's taint; a command/process substitution carries at least `untrusted`, joined with the captured provenance). Three refinements: `${!name}` indirection takes the pointee's provenance (an unknown pointer is at least `untrusted`); a nameref (`Var.Ref`) contributes its target's provenance; and a read of an absent shell data variable (`BASH_REMATCH`, `$_`, `BASH_ARGV`, … — `shellDataVars`) is `untrusted` rather than bottom, because it holds run-time data of unknown provenance. `${x:=word}`/`${x=word}` assign the alternate word to `x` with its provenance (`applyParamAssignments`).
- `outTaintOf(effs, stdinTaint)` is a **per-command** over-approximation of a command's stdout provenance: it joins the stdin taint with the taint of the command's filesystem reads (adding `secret` when a read target is a credential path), credential access (adding `secret`), credential-shaped environment reads (`EnvRead` effects with `engine.IsSecretRead` add `secret` — only credential-shaped names qualify, so `PATH`/`HOME` taint nothing), and network ingress (`untrusted`) — but never another command's — so an egress pairing is a real per-command data flow rather than mere co-occurrence. `execCall` additionally joins the provenance of the command's own operands (`operandTaint`): `printf '%s' "$x"` writes its argument, and that provenance must reach the next pipeline stage.

### Credential dataflow

Beyond `outTaintOf`, several passes keep a credential's provenance attached to the data that carries it:

- `credentialOperandReads` emits an `FSRead` (+`secret`) for operand *text* that names a credential location even when the word is dynamic (a glob `/etc/shadow*`, a brace alternative `{/root/.ssh/id_rsa,$?}`, a path relative to the tracked `PWD` after `cd /etc && cat shadow`) — shapes the binder cannot see as literal words.
- `credentialEnvReads` inspects the invocation's words *before* expansion flattens them, emitting an `EnvRead` (+`secret`) for every credential-shaped variable name the program never assigned (`curl -d "$GITHUB_TOKEN"`); a variable the program assigned is reported by the assignment path instead.
- An xargs replacement placeholder (`-I{}`) in a path-ish operand marks the operand `FromXargs`, unknown, and widened with `secret` — the piped-in items are data the text does not prove.
- `markRootOperands` flags a literal relative operand the tracked working directory resolves to `/` (`cd / && chmod -R 777 .` — `Word.Root`), so extent grading can resolve it to the whole host without fabricating a path.
- At statement end, `engine.ApplySecretStaging` pairs a credential read *staged* into a file with the later egress of that file, and `taintEgressWithSecret` joins `secret` onto a statement's egress when the same statement read (or held, via an operand) credential material.
- Provenance is threaded through the shell's value-assigning channels: `callFunc` passes argument provenance into the callee's positional parameters, `assigningBuiltinState` (`mapfile`/`readarray`/`printf -v`) into the target variable, `positionalState` (`set --`/`shift`) into the re-bound positionals, and `arithmAssignTaint` (`((x=$(cmd)))`/`let`) into arithmetic assignment targets.

### Environment code-execution channels

An environment assignment can execute a program although the assignment itself looks inert. `ExecEnvVar`/`ExecEnvEffect` (exported; the binder lowers the same channels through them) recognise three channel families: program-valued variables (`execEnvVars`: `LD_PRELOAD`, `LD_AUDIT`, `BASH_ENV`, `ENV`, `SSH_ASKPASS`, `RSYNC_RSH`, `GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_EXTERNAL_DIFF`/`GIT_PAGER`/`GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`, `GIT_ASKPASS`, `GIT_PROXY_COMMAND`, `SUDO_ASKPASS`, `SYSTEMD_EDITOR`, `KUBECTL_EXTERNAL_DIFF`, `PAGER`/`MANPAGER`/`EDITOR`/`VISUAL`, `JAVA_TOOL_OPTIONS`/`_JAVA_OPTIONS`/`JDK_JAVA_OPTIONS`, `PERL5OPT`, `RUBYOPT`, `NODE_OPTIONS`, `LESSOPEN`, `PROMPT_COMMAND`, `GIT_CONFIG_PARAMETERS`); option channels (`optionChannelEnvVars`: `TAR_OPTIONS`, whose value is searched for tar's exec-bearing options, unresolved values degrade); and git's environment configuration family (`GIT_CONFIG_*` — `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`), whose key lives in another variable's value and is therefore always ⊤. A known program path names the executed subject; an option string or dynamic value leaves it ⊤; clearing the variable (`VAR=`) runs nothing. Separately, an assignment to a prompt variable (`PS0`–`PS4`, `PROMPT_COMMAND` — `promptVars`) whose value re-executes (contains `$(…)`, backticks or `${`) is a code sink, because the shell re-expands prompts on every traced command.

### Name-resolution invalidation

Name resolution is stateful, and a construct that rewrites it opaquely makes *later* names degrade to ⊤ rather than trust a stale table: `hash -p PATH NAME` rebinds a name (`hashState`; an unresolvable path or a dynamic operand sets `hashOpaque`), an assignment that rebinds `PATH` (`pathRebinds`) or a write to `BASH_CMDS` — the command-hash table exposed as an array — marks resolution opaque ("name resolution unbound after …"), and an `unalias` whose operand is not statically known makes the alias table opaque (`unaliasState`/`aliasOpaque` → "alias table not statically known").

### Status semantics

Bash-faithful exit statuses decide `&&`/`||`/`if`/`while` reachability: `!` inverts the command's status; launching a background/coprocess job succeeds regardless of the job's own status; an `if`/`for`/`while`/`case` that runs nothing exits 0; `true`/`:` exit 0 and `false` exits 1 (`setStatus`); case fall-through (`;&`), resume-matching (`;;&`), the default arm and the no-match exit-0 follow bash (see Control flow). Anything else leaves the status unknown, which explores both branches of a dependent operator — conservative, never a miss.

## Error Handling

- A parse failure, an unknown variant, or an internal panic ⇒ a fully-⊤ `ExecResult` (`topResult`) with a reason; `Exec` recovers panics in a `defer`.
- An exhausted budget ⇒ `budgetError`, caught by `finish`, which calls `markTop("analysis budget exhausted: …")` and preserves the effects discovered before unwinding.
- `markTop` sets the whole-analysis ⊤ flag and appends one ⊤ effect; `markTopEffect` records a ⊤ effect for one sub-computation (a sink) without claiming the whole program is unanalysable.
- Expansion is guarded: `expandFields`/`expandLiteral` recover panics, and a part the expander refuses is not a benign unknown — it may have hidden a sibling substitution — so it calls `markTop("unhandled expansion: …")` (whole-analysis ⊤) rather than degrading silently to "unknown"; `budgetError` is re-panicked so the step budget still unwinds the whole analysis. A brace expansion the estimator over-estimates degrades the whole analysis to ⊤ ("brace expansion too large"), as does a word producing more than `maxExpandedFields` fields.
- `addNote`/`addCmd` bound their lists by `maxRecorded` so a non-terminating loop cannot grow them without limit before the budget stops it.

## Invariants

- `Exec` never panics; every failure path produces a `*ExecResult` with `Top`/`Conservative` set appropriately.
- The interpreter never touches the filesystem: expansion has globbing disabled and reads nothing from disk; effects describe *intended* operations only.
- Σ is cloned (never shared) across subshells, each pipeline stage, background/coprocess jobs, command/process substitutions, and each arm of an undecidable branch. Function calls are the bash-faithful exception: `callFunc` executes the body against the caller's Σ, with only the positional parameters (`0`, `#`, `@`, `*`, `1..9` — a fixed set, so an argument past the ninth persists) saved and restored — state changes persist to the caller; a body containing `shift` or `set --` (`funcRebindsPositional`) additionally invalidates the callee's `1..9` (unset) and `@`/`*` (unknown) before the body runs, since rebinding is not modelled — in-body reads degrade to ⊤.
- The step budget strictly bounds the work: every statement, redirection and loop iteration charges `step()`.
- `isTopEffect(e)` identifies the ⊤ effect as `Kind == CodeExec` with a top (`{arbitrary}`) target; `ExecResult.HasTop()` scans for it and `Conservative` is true whenever one is present.
- The final effect set is canonicalized through `engine.NewReport().Normalize()`.
- An input redirection's taint contribution is scoped to its statement (saved/restored), so it cannot leak into a following statement.

## Related Specs

- [Bash Frontend](README.md) — domain overview.
- [Parse & Normalize](parse-normalize.md) — produces the syntax tree and `Program` this component interprets.
- [Command Wrappers](wrappers.md) — the wrapper inventory behind the peeled `Wrapper` chains and their payload channels.
- [Binding](../binding.md) — supplies the `Resolver` implementation (`bind.Binder.BindBash`).
- [Knowledge Base](../knowledge-base.md) — the effect signatures behind the resolver.
