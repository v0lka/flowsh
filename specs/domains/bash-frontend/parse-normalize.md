# Parse & Normalize

## Role

This component turns shell source text into the frontend's normalized AST: `Parse` produces a faithful, position-preserving tree with mvdan's `syntax` parser, and `normalize` lowers that tree into `bash.Program`, unwrapping command wrappers and recording the aliases and functions the source declares.

## Key Files

- `front/bash/parse.go` — `Variant` (`Bash`/`POSIX`), `Parse`, `Pos`, `fromMvdanPos`/`shiftPos`, and the ⊤ fallback (`topProgram`).
- `front/bash/normalize.go` — the normalized AST types and `normalizer` (`fill`, `stmt`, `command`, `call`, `unwrap`, `assign`, `word`, `part`, `maybeAlias`, `funcDecl`), the `Kind` constants, `wrapperSpecs`, and `annotate`.

## Behavior

### Parse pipeline

```
Parse(v, name, src)
  │  1. v.langVariant() → syntax.LangBash | syntax.LangPOSIX   (unknown ⇒ ⊤)
  │  2. defer recover()  → any panic ⇒ ⊤ ("internal parser panic: …")
  │  3. nestingTooDeep(src) → parenthesis nesting beyond maxNestingDepth = 4096
  │        ⇒ ⊤ ("input nesting too deep")   [checked before parsing: a Go
  │        stack overflow cannot be recovered]
  │  4. syntax.NewParser(syntax.Variant(lang)).Parse(src, name)
  │        parse error (syntax.ParseError) ⇒ ⊤ with ErrPos + message
  │  5. syntax.Simplify(file)     canonicalise redundant syntax
  │        (e.g. $( (a) ) and $(a) lower to the same AST)
  │  6. newNormalizer(src).fill(file, prog)
  ▼
Program{Variant, File, Source, Stmts, Aliases, Funcs}
```

The same nesting-depth cap (`maxNestingDepth = 4096`, `nestingTooDeep`) precedes parsing in the abstract executor's entry (`execVars`) as well, so neither the parser nor the recursive normalizer can exhaust the goroutine stack.

`Parse` is deliberately total: it never panics and never returns an error; failures are folded into the returned `Program` as `Top=true`.

### Syntax → normalized kind (decisive table)

| mvdan `syntax.Command` | normalized `Kind`                | key fields populated                  |
| ---------------------- | -------------------------------- | ------------------------------------- |
| `nil` (bare redirection) | `KindSimple`                   | empty `Command` (so `Cmd != nil`)     |
| `*CallExpr`            | `KindSimple`                     | `Cmd` (name, args, assigns, wrappers) |
| `*BinaryCmd` (Pipe/PipeAll) | `KindPipeline`              | `Op`, `Left`, `Right`                 |
| `*BinaryCmd` (And/Or)  | `KindAndOr`                      | `Op`, `Left`, `Right`                 |
| `*Block`               | `KindBlock`                      | `Body`                                |
| `*Subshell`            | `KindSubshell`                   | `Body`                                |
| `*IfClause`            | `KindIf`                         | `Cond`, `Body` (then), `Else` (elif = nested if) |
| `*WhileClause`         | `KindWhile`                      | `Until`, `Cond`, `Body`               |
| `*ForClause`           | `KindFor`                        | `Select`, `Name`/`Words` or `Text`, `Body` |
| `*CaseClause`          | `KindCase`                       | `Subject`, `Items`                    |
| `*FuncDecl`            | `KindFunc`                       | `Func` (style: `posix`/`function`/`function-parens`) |
| `*ArithmCmd`           | `KindArithm`                     | `Text`                                |
| `*TestClause`          | `KindTest`                       | `Text`                                |
| `*DeclClause`          | `KindDecl`                       | `Decl`, `Words`                       |
| `*LetClause`           | `KindLet`                        | `Text`                                |
| `*TimeClause`          | `KindTime`                       | `Body`                                |
| `*CoprocClause`        | `KindCoproc`                     | `Words`, `Body`                       |
| anything else          | `KindOther`                      | `Text` (raw source slice)             |

Statement-level flags (`Negated`, `Background`, `Coprocess`) and `Redirs` are captured on every `Stmt` regardless of kind.

### Word parts

A `Word` records `Value`/`Literal` when the whole word is fully literal, plus its structural `Parts` (each with a `PartKind`): `lit`, `sglQuoted`, `dblQuoted` (with inner `Parts`), `paramExp` (with `Param`/`Op`), `cmdSubst`/`procSubst` (with their `Stmts`), `arithmExp`, `extGlob`, `unknown`. `Word.Taint` and `Word.Dir` (the numeric-class confinement of a dynamic word, set by abstract execution) are analysis metadata attached later and are not serialized; so are `Word.Root` (a literal relative operand the tracked working directory resolves to the filesystem root — `.` after `cd /` — whose written form is kept) and `Word.FromXargs` (an operand xargs substitutes from its input items, whose value is data and therefore unknown), both `json:"-"`.

### Wrapper unwrapping (`wrapperSpecs` / `unwrap`)

`unwrap` peels recognised wrappers off the front of a simple command's words, returning the wrapper chain (outermost first), the environment assignments they contributed, and the index of the first word of the effective command. Each `wrapperSpec` describes how a wrapper consumes its own arguments across seven fields — `valueOpts` (options that consume the next word as their value), `envAssigns`, `fixedArgs` (positional words consumed after the options), `fixedUnless` (options whose presence replaces the fixed positional), `fixedIfIn` (consume the fixed positional only from a closed literal vocabulary), `requirePayload` (peel only when a payload word follows) and `defaultCmd`. `wrapperSpecs` is a closed set of 41 entries — `sudo`, `env`, `nohup`, `command`, `nice`, `timeout`, `xargs`, `setsid`, `builtin`, `stdbuf`, `watch`, `flock`, `systemd-run`, `nsenter`, `taskset`, `ionice`, `chrt`, `unshare`, `ssh-agent`, `strace`, `ltrace`, `valgrind`, `caffeinate`, `chroot`, `runcon`, `prlimit`, `switch_root`, `setarch`, `linux32`, `linux64`, `busybox`, `toybox`, `envdir`, `softlimit`, `faketime`, `unbuffer`, `xvfb-run`, `systemd-cat`, `torsocks`, `proxychains`, `proxychains4` — plus the command-string wrappers `su`/`runuser`/`script`/`flock` (`-c CMD` payloads, analysed at execution by `front/bash/exec.go`) and the one multi-word wrapper `ip netns exec NS COMMAND`. The table below shows the original eight; the full inventory with per-wrapper option sets and consumption rules lives in [Command Wrappers](wrappers.md):

| Wrapper   | value-taking options (`valueOpts`)                         | lifts `envAssigns` | fixed positional args | default command |
| --------- | ---------------------------------------------------------- | ------------------ | --------------------- | --------------- |
| `sudo`    | `-u/--user -g/--group -h/--host -D/--chdir -R/--chroot -p/--prompt -C/--close-from -T/--command-timeout -r/--role -t/--type -U/--other-user` | yes                | 0                     | —               |
| `env`     | `-u/--unset -C/--chdir -S/--split-string`                  | yes                | 0                     | —               |
| `nohup`   | —                                                          | no                 | 0                     | —               |
| `command` | —                                                          | no                 | 0                     | —               |
| `nice`    | `-n/--adjustment`                                          | no                 | 0                     | —               |
| `timeout` | `-k/--kill-after -s/--signal`                              | no                 | 1 (the duration)      | —               |
| `xargs`   | `-n -I -i -d -P -s -E -L -a` and long forms                | no                 | 0                     | `echo`          |
| `setsid`  | —                                                          | no                 | 0                     | —               |

`--`/`-` terminate a wrapper's options. A value attached to an option (`--user=root`, `-uroot`) is not treated as a separate value. A partially dynamic word whose literal prefix names a value-taking option records that option unsatisfied and is absorbed only when its dynamic tail is quoted (one field); an unquoted expansion field-splits, so the word ends the option run and stays the dynamically-named inner command. `takesValue` encodes these rules. When nothing remains after a wrapper chain, the wrapper's `defaultCmd` (e.g. `xargs` → `echo`) becomes the effective command.

Beyond the plain option/positional split, three spec fields refine the peel: `fixedUnless` replaces the fixed positional when a recorded option supplies it (`taskset -c LIST CMD` — the MASK positional disappears); `fixedIfIn` consumes the fixed positional only when its literal is a member of a closed vocabulary (setarch's ARCH word, from `setarchArchitectures`) so a program name is never mistaken for an operand; and `requirePayload` declines to peel a wrapper whose command-less form runs nothing (`chrt -p PID`, `ionice -p PID`, `flock FILE`) — the wrapper word stays the command and its own knowledge-base row binds it. GNU option permutation applies after a fixed positional is consumed: the option run is re-processed once (`setarch x86_64 -R cmd`, `timeout 5 -k 1 cmd`), because getopt permutes non-option words to the end; a payload command never starts with `-` and `--` still terminates.

At execution, a wrapper chain that consumed the whole command line with no `defaultCmd` and no `-c` payload leaves no effective command (`sudo -i`, `timeout 5`, a bare `env`/`xargs`), which degrades to a ⊤ effect ("wrapper consumed the whole command line") rather than to an empty report.

### Environment assignments and symbol annotation

- `call` lifts the command's own `NAME=value` assigns and the wrapper-donated ones onto the `Command`, sorted by source position (`sortAssigns`); each `Assign` records the `Via` wrapper that introduced it (empty for the command's own).
- `maybeAlias` records `alias name=value` declarations (literal only) into `Program.Aliases`; aliases are **collected, not expanded** (expansion is order-sensitive runtime behaviour).
- `funcDecl` records the function name/style/body into `Program.Funcs`.
- `annotate` walks the whole statement tree and sets `Command.ResolveKind`/`ResolvesTo` to `func`/`alias` for any command whose name matches a declared function or alias.

## Error Handling

- Unknown `Variant` ⇒ `topProgram` with reason `unknown shell variant "…"`.
- Parenthesis nesting deeper than `maxNestingDepth = 4096` (`nestingTooDeep`) ⇒ `topProgram` with reason `input nesting too deep`, checked *before* the parser runs — the parser and the recursive normalizer recurse once per level, and a Go stack overflow cannot be recovered.
- mvdan parse error ⇒ `topProgram` with the error message and, when available, the `ErrPos` derived from `syntax.ParseError.Pos`.
- Any panic during parse is recovered in `Parse`'s `defer` and converted to `topProgram("internal parser panic: …")`.
- `topProgram` attaches `ErrPos` only when the position is non-zero.
- A source that normalizes but contains constructs the normalizer cannot classify becomes `KindOther` (raw text retained) rather than an error.

## Invariants

- `Parse` never panics and never returns a Go error; the sole failure channel is `Program.Top` + `Program.Reason`.
- A ⊤ `Program` carries a reason and exactly zero statements (`Program.Validate`).
- `Program.Variant` is always valid; validation rejects an unknown variant.
- Every `Stmt` has a non-empty `Kind`; a statement with no command is `KindSimple` with a non-nil (possibly empty) `Cmd`.
- Positions are preserved on every statement, word and part; `End` is recorded for statements.
- The `Program.Aliases`/`Program.Funcs` maps are keyed by name and, being Go maps, encode deterministically (sorted keys).
- Normalization is pure with respect to the source: it reads `src` for raw slices (`slice`) and never executes anything.

## Related Specs

- [Bash Frontend](README.md) — domain overview.
- [Abstract Execution](abstract-exec.md) — consumes the `Program` this component produces.
- [Command Wrappers](wrappers.md) — the full wrapper inventory and the find(1) exec-payload extraction.
- [Binding](../binding.md) — consumes the normalized `Command`/`Program` (via `bind.Binder.BindBash`).
