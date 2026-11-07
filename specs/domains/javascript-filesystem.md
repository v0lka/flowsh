# JavaScript Filesystem Models

## Purpose

Define the source-to-report acceptance contract for the modelled Node filesystem and path API families (issue #29 and its filesystem prerequisites from #34, #36, and #33): which module/export identities are recognized, which argument shapes lower to which effects, and how destructive options and degradation are reported.

## Key Files

- `kb/data/js-filesystem.yaml`, `kb/data/js-path.yaml` — reviewed identities, selectors, operation shapes, effects, and destructive predicates.
- `kb/js.go`, `kb/js_decode.go` — the separate JS model namespace and strict schema validation.
- `front/js/modules.go`, `bind/js.go`, `bind/js_options.go`, `bind/js_path.go`, `internal/analysis/javascript.go` — identity, binding, option-shape/flag/mode validation, offline paths, and report assembly.

## Core Types

The offline models live in the KB's separate JS namespace (`kb/js.go`, loaded from the two YAML datasets via the `jsModules`/`jsCalls` maps, which require `effect-kb/v4`):

```go
type JSModule struct {        // an offline builtin namespace
	Name       string            // internal ones are reachable only via a
	Aliases    []string          // module property, never via require
	Properties map[string]string
	Constants  map[string]int64
	Internal   bool
}
type JSCall struct {          // a builtin export's arguments and effects
	Module, Export, Style, Operation, Return string
	MinArgs, MaxArgs, Options                int
	ModeArg, DataArg                         int
	OptionShape                              string
	OptionKeys                               []string
	FlagOption, FlagDefault                  string
	Effects                                  []JSEffect
	Destructive                              []JSDestructive
}
type JSEffect struct {        // selects a positional path or a generated prefix
	Kind   engine.EffectKind
	Arg    int
	Target string
}
type JSDestructive struct {   // classifies true-or-unknown boolean options
	Option string
	Class  DestructiveClass
	Reason string
}
```

## Flow

1. `front/js` evaluates the program's values and control flow; `modules.go` resolves each callee's module/export identity (CJS `require`, ESM imports, `node:` aliases, `fs/promises`, destructuring, local aliases — binding resolves evaluated identity, never callee spelling).
2. The facade injects `bind.Binder.BindJS(call, jsCtx)` through the frontend resolver seam; `bind/js.go` looks the identity up in the KB's `jsModules`/`jsCalls`, validates argument shapes and typed option selectors (`bind/js_options.go`), and computes offline POSIX paths (`bind/js_path.go`).
3. Matched models lower to `FSRead`/`FSWrite`/`FSMeta` effects with the acceptance-matrix returns below; destructive boolean options append KB destructive findings; unmatched or invalidated identities degrade conservatively.
4. `internal/analysis/javascript.go` assembles the report (bounded metadata, canonical effects from bound targets, source-located derivations).

## Behavior

The compatibility baseline is Node 22/24 POSIX filesystem semantics. Deprecated recursive `rmdir` is included conservatively for older programs; Node 25 removed the option. Default `path` and `path.posix` use explicit POSIX semantics on every analyzer host. `path.win32` remains unsupported. No host filesystem, environment, cwd, or module code is consulted. Home is the symbolic `/root` report context used by Bash: it shapes targets but comparisons treat it as unknown; cwd is unknown unless an absolute segment makes it unnecessary. Literal JavaScript `~`, `$HOME`, and `${HOME}` names — the bare spelling or one followed by `/` — remain literal evidence and targets; effects additionally include the home-normalized report abstraction. Helpers do not perform shell expansion.

| Export family | Shapes | Arguments excluding final callback | Lowering / return |
| --- | --- | --- | --- |
| `readFile` | callback, Sync, promises | path, optional encoding/options | FSRead; unknown content with read provenance |
| `writeFile`, `appendFile` | callback, Sync, promises | path, data, optional encoding/options | FSWrite; undefined |
| `unlink` | callback, Sync, promises | path | FSWrite; undefined |
| `rename` | callback, Sync, promises | oldPath, newPath | FSMeta oldPath + FSWrite newPath; undefined |
| `mkdir` | callback, Sync, promises | path, optional mode/options | FSMeta; unknown (recursive result can name a created ancestor) |
| `rmdir`, `rm` | callback, Sync, promises | path, optional options | FSMeta / FSWrite; undefined; `recursive` raises class E as Bash `rm -r`; the `rm` family's boolean-true `force` also raises class E (suppresses missing-file errors) |
| `copyFile` | callback, Sync, promises | source, destination, optional numeric mode | FSRead source + FSWrite destination; undefined |
| `chmod` | callback, Sync, promises | path, mode | FSMeta; undefined; significant/unknown modes retain uncertainty pending #33 |
| `stat` | callback, Sync, promises | path, optional options | FSRead; unknown stats |
| `mkdtemp` | callback, Sync, promises | prefix, optional encoding/options | FSWrite with unknown suffix target; unknown path |
| `existsSync` | Sync only | path | FSRead; unknown boolean, both branches feasible |
| `createReadStream`, `createWriteStream` | stream factories only | path, optional encoding/options | FSRead / FSWrite; unknown stream |
| `join`, `resolve` | pure path functions | variadic string segments | bounded exact POSIX string or unknown; resolve scans right to left and needs cwd only without an absolute segment |
| `dirname`, `basename` | pure path functions | path; basename optional suffix | bounded exact POSIX string or unknown |
| `homedir` | pure os function | none | symbolic `/root` |

Path helpers bound summed input to 65,536 bytes and yield unknown past it (or for over-long results). `join` drops empty segments but preserves a trailing slash; `dirname` keeps a leading `//` and maps all-slash inputs to `/`; `basename` trims a matching suffix, widens back into the path when the suffix extends past the basename, and yields an empty string when the suffix equals the whole path.

Builtin identities flow through CJS `require`, ESM default/namespace/named imports, `node:` aliases, `fs/promises`, `fs.promises`, destructuring, and local aliases. Binding resolves evaluated identity, never callee spelling. Shadowed loaders, reassigned values, property writes/export mutations, unknown calls, and unsupported module initialization invalidate identities conservatively. Extracted known functions keep identity until invalidation. `fs.constants` is a property-only numeric namespace: its platform-independent members (`F_OK`, `R_OK`, `W_OK`, `X_OK`, `O_RDONLY`, `O_WRONLY`, `O_RDWR`, `COPYFILE_EXCL`, `COPYFILE_FICLONE`, `COPYFILE_FICLONE_FORCE`) resolve to exact numbers, so idioms such as `copyFile(src, dst, fs.constants.COPYFILE_EXCL)` or `{flags: fs.constants.O_RDONLY}` keep precision and the namespace keeps a stable identity under `===`. Platform-specific members (`O_CREAT` and the other open flags), unknown members, and `require('fs/constants')` — not a Node builtin — stay conservative.

Options use typed selectors. Unknown recursive/force values retain possible destructive classes and explicit top diagnostics; boolean-true `force` on `rm`/`rmSync`/`fs-promises.rm` appends a class-E destructive finding — forced deletion suppresses missing-file errors — with no diagnostic. Known open flags determine additional read/write effects — the string spellings plus the numeric `0`/`1`/`2` access modes — and mode values are accepted as numbers or octal strings up to `0o777`; unsupported flags, file descriptors, custom stream `fs`/`fd`, and unsupported effect-changing options retain top. Unknown required paths become scope top with a diagnostic, never guessed names. No result fabricates file content, existence, stats, or a mkdtemp suffix.

Destination writes retain provenance from the model's data selector and source read/metadata selectors, including filesystem and secret labels for copied or renamed credential paths. `writeFile`/`appendFile` data that is neither a known string nor opaque content — unknown values or objects — keeps the write effect with the top reason `unknown or unsupported JavaScript filesystem data may invoke user code`. Options do not contribute payload taint. Source provenance reaches writes independently of YAML effect order.

Every model style except `promise` and `pure` — synchronous calls, callback models, and the `createReadStream`/`createWriteStream` factories alike — retains possible throws. Pure path/os helpers with supported known arguments do not add a throw path; unsupported arguments retain conservative degradation and possible throws. Trusted modeled promises retain rejection on sequential await, including catch/finally reachability. Arbitrary thenables remain unsupported. Callback models emit the outer filesystem effect and canonical top with a reason because callback-body execution is deferred to #34. A caller must inspect Conservative even when the outer API is known.

Reports preserve the existing `flowsh/v3` shape: bounded deterministic commands, canonical module/export resolution, typed argument projections, deduplicated destructive summaries, notes, and source-located derivations. JS canonical effects use bound targets verbatim, including `$`, `;`, leading `-`, and empty-string evidence; shell operand filtering and PATH/basename/package-runner normalization do not apply. Report evidence truncates strings at 4,096 bytes, falling back to `js:<kind>` for longer or non-string values. GuardFall A–E categories remain separate from KB A–E severity classes.

## Error Handling

Malformed models fail at KB load: unknown keys, duplicate names/aliases, invalid selectors/styles/operations/return models, and broken module references are rejected. Schema specifics: names are at most 128 bytes without whitespace or NUL; module constants must be exact integers within ±2^53; internal modules may not declare aliases. Unsupported source execution returns the existing canonical top and reason; budget exhaustion preserves earlier effects. Models and metadata share existing frontend work, string, and record limits. The facade caps each report metadata collection (call sites, command calls, notes, destructive findings) at 1,024 items; a modeled call past the cap resolves Handled with the reason `JavaScript report metadata limit reached` and a possible throw. The resolver call carries a Charge callback so context strings consume work before model materialization.

## Invariants

- Filesystem kinds remain FSRead, FSWrite, and FSMeta; the engine stays frozen.
- Frontend dependencies point toward engine; binding is injected from the facade.
- Callback precision, general closures/functions, other Node families, and aggregate epic closure remain separate work.
- Every API family requires specific effect/target/report evidence; Covered alone is insufficient.

## Configuration

| Bound | Value | Where |
| --- | --- | --- |
| Path-helper summed input | 65,536 bytes | `bind/js_path.go` |
| Report evidence truncation | 4,096 bytes (`js:<kind>` fallback) | `bind/js.go` |
| Facade metadata cap per collection | 1,024 items (`JavaScript report metadata limit reached`) | `internal/analysis/javascript.go` |
| Model name length | ≤128 bytes, no whitespace/NUL | `kb/js.go` (`validJSName`) |
| Module constants | exact integers within ±2^53 | `kb/js.go` (`maxJSConstant`) |
| Document schema | `effect-kb/v4` (JS keys require it) | `kb/schema.go` |

## Extension Points

- Add or change an API family: add rows to `kb/data/js-filesystem.yaml` (or `js-path.yaml`); the loader's strict validation (`kb/js_decode.go`) rejects unknown keys, duplicate names, invalid styles/operations/returns, and broken references at load time.
- Add a destructive boolean option: extend the model's `destructive` entries (`Option`/`Class`/`Reason`); unknown option values already retain conservative top diagnostics.
- Compatibility baseline changes (e.g. a Node release removing `rmdir` options) are data edits, not engine changes — filesystem kinds stay frozen.

## Related Specs

- [JavaScript Frontend](javascript-frontend.md) — evaluator and bounds.
- [Knowledge Base](knowledge-base.md) — versioned data.
- [Binding](binding.md) — interpretation.
- [Analysis Report](analysis-report.md) — metadata.
- [Node filesystem reference](https://nodejs.org/api/fs.html) and [Node path reference](https://nodejs.org/api/path.html) — API shapes and compatibility history.
