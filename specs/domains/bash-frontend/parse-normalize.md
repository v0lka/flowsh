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
  │  3. syntax.NewParser(syntax.Variant(lang)).Parse(src, name)
  │        parse error (syntax.ParseError) ⇒ ⊤ with ErrPos + message
  │  4. syntax.Simplify(file)     canonicalise redundant syntax
  │        (e.g. $( (a) ) and $(a) lower to the same AST)
  │  5. newNormalizer(src).fill(file, prog)
  ▼
Program{Variant, File, Source, Stmts, Aliases, Funcs}
```

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

A `Word` records `Value`/`Literal` when the whole word is fully literal, plus its structural `Parts` (each with a `PartKind`): `lit`, `sglQuoted`, `dblQuoted` (with inner `Parts`), `paramExp` (with `Param`/`Op`), `cmdSubst`/`procSubst` (with their `Stmts`), `arithmExp`, `extGlob`, `unknown`. `Word.Taint` and `Word.Dir` (the numeric-class confinement of a dynamic word, set by abstract execution) are analysis metadata attached later and are not serialized.

### Wrapper unwrapping (`wrapperSpecs` / `unwrap`)

`unwrap` peels recognised wrappers off the front of a simple command's words, returning the wrapper chain (outermost first), the environment assignments they contributed, and the index of the first word of the effective command. Each `wrapperSpec` describes how a wrapper consumes its own arguments:

| Wrapper   | value-taking options (`valueOpts`)                         | lifts `envAssigns` | fixed positional args | default command |
| --------- | ---------------------------------------------------------- | ------------------ | --------------------- | --------------- |
| `sudo`    | `-u/--user -g/--group -h/--host -p/--prompt -C/--close-from -T/--command-timeout -r/--role -t/--type -U/--other-user` | yes                | 0                     | —               |
| `env`     | `-u/--unset -C/--chdir -S/--split-string`                  | yes                | 0                     | —               |
| `nohup`   | —                                                          | no                 | 0                     | —               |
| `command` | —                                                          | no                 | 0                     | —               |
| `nice`    | `-n/--adjustment`                                          | no                 | 0                     | —               |
| `timeout` | `-k/--kill-after -s/--signal`                              | no                 | 1 (the duration)      | —               |
| `xargs`   | `-n -I -i -d -P -s -E -L -a` and long forms                | no                 | 0                     | `echo`          |
| `setsid`  | —                                                          | no                 | 0                     | —               |

`--`/`-` terminate a wrapper's options. A value attached to an option (`--user=root`, `-uroot`) is not treated as a separate value. `takesValue` encodes these rules. When nothing remains after a wrapper chain, the wrapper's `defaultCmd` (e.g. `xargs` → `echo`) becomes the effective command.

### Environment assignments and symbol annotation

- `call` lifts the command's own `NAME=value` assigns and the wrapper-donated ones onto the `Command`, sorted by source position (`sortAssigns`); each `Assign` records the `Via` wrapper that introduced it (empty for the command's own).
- `maybeAlias` records `alias name=value` declarations (literal only) into `Program.Aliases`; aliases are **collected, not expanded** (expansion is order-sensitive runtime behaviour).
- `funcDecl` records the function name/style/body into `Program.Funcs`.
- `annotate` walks the whole statement tree and sets `Command.ResolveKind`/`ResolvesTo` to `func`/`alias` for any command whose name matches a declared function or alias.

## Error Handling

- Unknown `Variant` ⇒ `topProgram` with reason `unknown shell variant "…"`.
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
- [Binding](../binding.md) — consumes the normalized `Command`/`Program` (via `bind.Binder.BindBash`).
