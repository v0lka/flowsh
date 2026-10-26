# JavaScript Filesystem Models

## Role

Define the source-to-report acceptance contract for issue #29 and its filesystem prerequisites from #34, #36, and #33.

## Key Files

- `kb/data/js-filesystem.yaml`, `kb/data/js-path.yaml` — reviewed identities, selectors, operation shapes, effects, and destructive predicates.
- `kb/js.go`, `kb/js_decode.go` — the separate JS model namespace and strict schema validation.
- `front/js/modules.go`, `bind/js.go`, `bind/js_path.go`, `internal/analysis/javascript.go` — identity, binding, offline paths, and report assembly.

## Behavior

The compatibility baseline is Node 22/24 POSIX filesystem semantics. Deprecated recursive `rmdir` is included conservatively for older programs; Node 25 removed the option. Default `path` and `path.posix` use explicit POSIX semantics on every analyzer host. `path.win32` remains unsupported. No host filesystem, environment, cwd, or module code is consulted. Home is the symbolic `/root` report context used by Bash; cwd is unknown unless an absolute segment makes it unnecessary. Literal JavaScript `~/` and `$HOME/` names remain literal evidence and targets; effects additionally include the home-normalized report abstraction. Helpers do not perform shell expansion.

| Export family | Shapes | Arguments excluding final callback | Lowering / return |
| --- | --- | --- | --- |
| `readFile` | callback, Sync, promises | path, optional encoding/options | FSRead; unknown content with read provenance |
| `writeFile`, `appendFile` | callback, Sync, promises | path, data, optional encoding/options | FSWrite; undefined |
| `unlink` | callback, Sync, promises | path | FSWrite; undefined |
| `rename` | callback, Sync, promises | oldPath, newPath | FSMeta oldPath + FSWrite newPath; undefined |
| `mkdir` | callback, Sync, promises | path, optional mode/options | FSMeta; unknown (recursive result can name a created ancestor) |
| `rmdir`, `rm` | callback, Sync, promises | path, optional options | FSMeta / FSWrite; undefined; recursive predicate raises class E as Bash `rm -r` |
| `copyFile` | callback, Sync, promises | source, destination, optional numeric mode | FSRead source + FSWrite destination; undefined |
| `chmod` | callback, Sync, promises | path, mode | FSMeta; undefined; significant/unknown modes retain uncertainty pending #33 |
| `stat` | callback, Sync, promises | path, optional options | FSRead; unknown stats |
| `mkdtemp` | callback, Sync, promises | prefix, optional encoding/options | FSWrite with unknown suffix target; unknown path |
| `existsSync` | Sync only | path | FSRead; unknown boolean, both branches feasible |
| `createReadStream`, `createWriteStream` | stream factories only | path, optional encoding/options | FSRead / FSWrite; unknown stream |
| `join`, `resolve` | pure path functions | variadic string segments | bounded exact POSIX string or unknown; resolve scans right to left and needs cwd only without an absolute segment |
| `dirname`, `basename` | pure path functions | path; basename optional suffix | bounded exact POSIX string or unknown |
| `homedir` | pure os function | none | symbolic `/root` |

Builtin identities flow through CJS `require`, ESM default/namespace/named imports, `node:` aliases, `fs/promises`, `fs.promises`, destructuring, and local aliases. Binding resolves evaluated identity, never callee spelling. Shadowed loaders, reassigned values, property writes/export mutations, unknown calls, and unsupported module initialization invalidate identities conservatively. Extracted known functions keep identity until invalidation. `fs.constants` is a property-only numeric namespace: its platform-independent members (`F_OK`, `R_OK`, `W_OK`, `X_OK`, `O_RDONLY`, `O_WRONLY`, `O_RDWR`, `COPYFILE_EXCL`, `COPYFILE_FICLONE`, `COPYFILE_FICLONE_FORCE`) resolve to exact numbers, so idioms such as `copyFile(src, dst, fs.constants.COPYFILE_EXCL)` or `{flags: fs.constants.O_RDONLY}` keep precision and the namespace keeps a stable identity under `===`. Platform-specific members (`O_CREAT` and the other open flags), unknown members, and `require('fs/constants')` — not a Node builtin — stay conservative.

Options use typed selectors. Unknown recursive/force values retain possible destructive classes and explicit top diagnostics. Known open flags determine additional read/write effects; unsupported flags, file descriptors, custom stream `fs`/`fd`, and unsupported effect-changing options retain top. Unknown required paths become scope top with a diagnostic, never guessed names. No result fabricates file content, existence, stats, or a mkdtemp suffix.

Destination writes retain provenance from the model's data selector and source read/metadata selectors, including filesystem and secret labels for copied or renamed credential paths. Options do not contribute payload taint. Source provenance reaches writes independently of YAML effect order.

Synchronous filesystem models retain possible throws. Pure path/os helpers with supported known arguments do not add a throw path; unsupported arguments retain conservative degradation and possible throws. Trusted modeled promises retain rejection on sequential await, including catch/finally reachability. Arbitrary thenables remain unsupported. Callback models emit the outer filesystem effect and canonical top with a reason because callback-body execution is deferred to #34. A caller must inspect Conservative even when the outer API is known.

Reports preserve the existing `flowsh/v3` shape: bounded deterministic commands, canonical module/export resolution, typed argument projections, deduplicated destructive summaries, notes, and source-located derivations. JS canonical effects use bound targets verbatim, including `$`, `;`, leading `-`, and empty-string evidence; shell operand filtering and PATH/basename/package-runner normalization do not apply. GuardFall A–E categories remain separate from KB A–E severity classes.

## Error Handling

Malformed models fail at KB load: unknown keys, duplicate names/aliases, invalid selectors/styles/operations/return models, and broken module references are rejected. Unsupported source execution returns the existing canonical top and reason; budget exhaustion preserves earlier effects. Models and metadata share existing frontend work, string, and record limits. The resolver call carries a Charge callback so context strings consume work before model materialization.

## Invariants

- Filesystem kinds remain FSRead, FSWrite, and FSMeta; the engine stays frozen.
- Frontend dependencies point toward engine; binding is injected from the facade.
- Callback precision, general closures/functions, other Node families, and aggregate epic closure remain separate work.
- Every API family requires specific effect/target/report evidence; Covered alone is insufficient.

## Related Specs

- [JavaScript Frontend](javascript-frontend.md) — evaluator and bounds.
- [Knowledge Base](knowledge-base.md) — versioned data.
- [Binding](binding.md) — interpretation.
- [Analysis Report](analysis-report.md) — metadata.
- [Node filesystem reference](https://nodejs.org/api/fs.html) and [Node path reference](https://nodejs.org/api/path.html) — API shapes and compatibility history.
