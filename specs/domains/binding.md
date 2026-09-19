# Binding

## Purpose

`bind` turns a normalized command invocation into the set of effects it implies. It resolves the invoked name (builtin → function → alias → PATH) and binds that command's flags, options and operands against the effect knowledge base. It is the join of the two lower layers — a frontend's normalized call on one side, the KB's command/flag signatures on the other — producing `[]engine.Effect`. Where the analysis cannot see (a dynamically-named command, or a name matching nothing), it degrades to the top element ⊤ (`CodeExec` over the any-target scope) rather than to "no effect".

## Key Files

- `bind/bind.go` — the binder: `Bind`, `BindBash`, `bindCommand`, `parseArgs` (flag/operand binding), `lowerParam` and `fileRefPath` (the `@file` convention), `taintFor`, `argsTaint`, `taintEgress`.
- `bind/resolve.go` — name resolution: `ResolveKind`, `Resolution`, `resolved`, the `resolve` chain (builtin → function → alias → PATH), `expandAliases` and `tokenizeAlias`.
- `bind/bind_test.go` — binder tests.

## Core Types

```go
type Style string

const (
	StyleBash Style = "bash" // POSIX/bash argv with -flags and --options
	StylePS   Style = "ps"   // PowerShell cmdlet syntax
)

// Arg is one normalized argument word. Literal is true when the word's text is
// fully known at analysis time; Taint is its provenance and is not serialized.
// Dir names the directory a non-literal word is provably confined to (every
// dynamic part numeric-class); such an operand lowers that directory as its
// target instead of ⊤. Analysis metadata, not serialized.
type Arg struct {
	Value   string       `json:"value"`
	Literal bool         `json:"literal"`
	Dir     string       `json:"-"`
	Taint   engine.Taint `json:"-"`
	// Pos is the source position of the word this argument was lowered from,
	// when the frontend knows it; it rides on the why-trace atoms so an effect
	// can be pinned back to the token that justified it. Analysis metadata,
	// not serialized.
	Pos engine.SourceLoc `json:"-"`
}

// EnvAssign is a NAME=value assignment applying to the invocation. Via is "" for
// an assignment written directly on the command and otherwise names the wrapper
// ("env", "sudo") that introduced it.
type EnvAssign struct {
	Name  string `json:"name"`
	Value Arg    `json:"value"`
	Via   string `json:"via,omitempty"`
	// Pos is the source position of the assignment, for the why-trace atom that
	// justifies the environment write. Analysis metadata, not serialized.
	Pos engine.SourceLoc `json:"-"`
}

// Call is a frontend-agnostic normalized invocation.
type Call struct {
	Style       Style   `json:"style"`
	Name        string  `json:"name,omitempty"` // "" when not literal
	NameOK      bool    `json:"-"`              // is Name statically known?
	NamePresent bool    `json:"-"`              // does the statement have a command word at all?
	Args        []Arg   `json:"args,omitempty"`
	Env         []EnvAssign `json:"env,omitempty"`
	Wrappers    []string    `json:"wrappers,omitempty"`  // sudo, env, … outermost first
	Funcs       map[string]bool   `json:"funcs,omitempty"`
	Aliases     map[string]string `json:"aliases,omitempty"`
	Pos         engine.SourceLoc  `json:"pos,omitempty"`
	StdinTaint  engine.Taint      `json:"-"`
}

type Binder struct{ k *kb.KB }

type Result struct {
	Style           Style                  `json:"style"`
	Resolution      Resolution             `json:"resolution"`
	Effects         []engine.Effect        `json:"effects"`
	Destructiveness engine.Destructiveness `json:"destructiveness"`
	Destructive     []kb.Destructive       `json:"destructive,omitempty"`
	// Derivations justifies every reported effect with the concrete source
	// atoms (command, flag, operand, redirect, source, sink) it rests on. It is
	// analysis metadata for the composition layer's why-trace, not part of the
	// serialized call.
	Derivations     []engine.Derivation `json:"-"`
	Conservative    bool                   `json:"conservative"`
	Notes           []string               `json:"notes,omitempty"`
}
```

Resolution types (`bind/resolve.go`):

```go
type ResolveKind string

const (
	ResolveEmpty      ResolveKind = "empty"      // bare redirection, no command
	ResolveAssignment ResolveKind = "assignment" // bare FOO=1
	ResolveBuiltin    ResolveKind = "builtin"
	ResolveFunction   ResolveKind = "function"
	ResolveAlias      ResolveKind = "alias"
	ResolveCommand    ResolveKind = "command"    // external command with a KB signature (PATH)
	ResolveUnknown    ResolveKind = "unknown"    // ⊤
)

type Resolution struct {
	Invoked    string      `json:"invoked,omitempty"`
	Kind       ResolveKind `json:"kind"`
	Name       string      `json:"name,omitempty"`
	AliasChain []string    `json:"aliasChain,omitempty"` // non-empty iff resolved through aliases
}
```

## Flow

```
                      Call  (Style, Name/NameOK, Args, Env, Wrappers, Funcs, Aliases, StdinTaint)
                        │
                        ▼  Binder.Bind(c)
   nil call / nil KB ──▶ conservative result: ⊤ CodeExec(Direct) + note
                        │
        ┌───────────────┴───────────────────────────────┐
        │ 1. env assignments (VAR=x cmd, env VAR=x cmd)  │──▶ EnvWrite effects
        └───────────────┬───────────────────────────────┘
                        │
   NamePresent == false │  bare assignment → ResolveAssignment;  else ResolveEmpty
                        │
                        ▼  resolve(c)   (bind/resolve.go)
         1. builtin   kb.Command(name).Dialect == "builtin"   ──▶ ResolveBuiltin
         2. function  c.Funcs[name]                            ──▶ ResolveFunction → ⊤ Transitive
         3. alias     c.Aliases[name] → expandAliases (≤32)    ──▶ ResolveAlias (may reach a command)
         4. command   kb.Command(name)                        ──▶ ResolveCommand
         5. otherwise                                          ──▶ ResolveUnknown → ⊤ Direct
                        │
                        ▼ (command resolved)
              bindCommand(cmd, args, StdinTaint)
                        │
                 parseArgs(cmd, argv)  ──▶ operands, matches, unknown
                        │
        ┌───────────────┼───────────────────────────────┐
        │ assign operands (dd of=FILE) → lowerParam     │
        │ matched flags/options      → lowerParam       │
        │ positional operands (last absorbs the rest)   │
        └───────────────┬───────────────────────────────┘
                        │
                        ▼  taintEgress(raw, StdinTaint)   fold per-command reads into egress effects
                        │
                        ▼  normalizeResult(r)             canonical order + destructiveness
                     Result
```

Name resolution and effect binding are reported independently: `Resolution` answers *which* command the call names; `Effects` are what that command then contributes, and `Derivations` justify each effect with its concrete source atoms for the why-trace. The composition facade aggregates both — plus the matched `Destructive` entries, the `Derivations` and `Notes` — across the program's calls into `report.resolution`, `report.destructive`, `report.why` and `report.notes` (see [Analysis Report](analysis-report.md) and the [Report Contract](../contracts/report-json.md)). The KB supplies kind and mode; the analysis supplies the concrete target scope, taint and certainty (`Effect.EngineEffect`).

### Flag / operand binding (`parseArgs`)

- `--` ends option parsing (everything after it is an operand); a lone `-` is an operand.
- `--name` (long): `--name=value` binds the value inline; `--name value` consumes the next word for an option; a flag matches with no value. An unknown long name is recorded as unrecognized.
- `-x` (short): the token is **first tried whole** (so `find -delete`, `tar -C`, `curl -o` match as options); only if it is not a declared spec is it split into a **cluster** of short flags (`-rf` → `-r`, `-f`). Inside a cluster, an option consumes the rest of the cluster as its value, else the next word.
- A non-literal word is conservatively an operand with an unknown value (its targets then go to ⊤) — unless the frontend marked it numeric-confined (`Arg.Dir`: every dynamic part is a bounded-integer expansion), in which case `argsScope` lowers the confining directory as the target.
- Positional parameters map to declared `param` specs in order; the **last** positional parameter absorbs every remaining operand.

### `@file` convention (`lowerParam` / `fileRefPath`)

For a parameter marked `fileRef` whose value uses `@file`, `@path` names a file whose *content* the command consumes, and `@-` names standard input. `name=@path` (curl's multipart syntax) is accepted too. The binder then contributes the filesystem read of the named file (unless it came from stdin), joins the payload's provenance (including `secret` when `engine.SecretPath` matches) into the parameter's own effect taint. The value is a payload *reference*, not a destination, so the declared effect keeps the payload's provenance but is lowered with an empty target scope (⊥): it does not reuse the file spec as its target.

### Egress target gate (`lowerParam` / `engine.HostShaped`)

A `NetEgress` effect may only carry a target that passes the host/URL grammar (`engine.HostShaped`, `engine.FilterEgressTargets`): a scheme-prefixed URL, an IPv4/IPv6 literal (including the `0x7f000001` hex and `2130706433` decimal obfuscations), an scp-style `[user@]host:path` remote over a host-shaped host, or a dotted DNS name optionally with `:port`. The gate runs in `lowerParam` on every parameter whose effect kind is `NetEgress`, at both target-consuming lowering sites (a plain parameter, and a `fileRef` parameter whose value does *not* use `@file`); a `fileRef` parameter that does use `@file` is exempt — its declared effect is the payload egress with a ⊥ target.

- A **literal** target that names no address (a git subcommand, a SHA, a ref, a pathspec — the words the index-order positional fallback used to force-fit onto `clone`/`fetch`/`pull`/`push` network positionals) is dropped from the target set; when nothing host-shaped remains, **the effect is not created at all**. A command whose every parameter effect is so dropped falls back to its intrinsic `ProcSpawn` (never an empty, benign report).
- An **unresolved** target (⊤ — the operand came from a dynamic word, `$URL`) passes through unchanged: it is the *unresolved egress* and keeps participating in the network controls. The safe side is never weakened.
- A ⊥ target (payload-only egress) also passes through unchanged.
- **Leniency tier**: a command of a *network-client dialect* (`curl`, `wget`, `netcat`, `openssh`, `net-tools`, `rsync`, and `util-linux` for `logger -n`) has destination positionals by construction, so its bare single-label host names (`nc evil 4444`, `ssh bastion`) are accepted via `engine.HostShapedLenient`. Every other dialect (git, VCS, package managers, systemd, gpg) is strict: its operands are subcommands/refs/pathspecs first. The dialect inventory is pinned by `kb`'s `TestNetEgressDialectInventory`.

The same gate applies at the two frontend-side egress creation points: the bash `/dev/tcp|/dev/udp` redirection (`redirectTarget` — the construct declares the destination, so the lenient grammar is used and a known-but-unaddressable token widens to ⊤ instead of being dropped) and the PowerShell cmdlet specs with `TargetURL`/`TargetName` targets (a `$variable` target is unresolved → ⊤; a non-host-shaped literal creates no egress).

### Taint egress (`taintEgress`)

`taintEgress` carries the provenance of everything a single command reads (or is fed on standard input) into its egress effects. The join is per command, never per script: an outbound request that ships data (an upload `-T`, a form field `-F`, a body read from a file or a pipeline) becomes a tainted egress, while an egress that merely accompanies an unrelated read elsewhere is left untainted.

## Invariants

- `bind` imports `engine`, `kb` and `front/bash`; **none** of those imports `bind`. `bind` is a sibling of `engine` precisely because the core must not import a frontend (`TestCoreDoesNotImportFrontends` enforces it) and `engine` cannot import `kb` (since `kb` already imports `engine`).
- `Bind` is total and deterministic: it never returns nil and never panics on a well-formed `Call`.
- A name that is not statically known (`NameOK == false`) resolves to `ResolveUnknown` → `⊤`.
- A name matching neither a builtin, a function, an alias, nor a KB command degrades to ⊤ (`CodeExec`), never to "no effect".
- A shell function resolves to ⊤ with `ModeTransitive` (its body is opaque to command binding).
- Alias expansion is bounded by `maxAliasDepth`; a cyclic or unparseable alias chain degrades to ⊤.
- `Result.Conservative` is true exactly when the outcome includes a ⊤ (`CodeExec`) effect.
- A matched destructive-flags entry folds its class severity into `Result.Destructiveness` with `Join` (max), so a destructive class raises the binder result's destructiveness even when the matched parameter's own effects are mild.
- Unrecognized flag names are surfaced as a note, not dropped silently.
- A `NetEgress` effect's target is host-shaped or ⊤/⊥ (see the egress target gate above); a literal non-host-shaped operand never becomes egress evidence. `engine.IsEgressSink` is kind-strict — an exfiltration *sink* is a tainted `NetEgress`, never a filesystem write, so a local file redirect (`git diff > $D/x.diff`) cannot fabricate an exfil pair.

## Configuration

- `maxAliasDepth = 32` — bounds alias-chain expansion so a recursive alias set cannot diverge.
- `Style` is `"bash"` or `"ps"`; the binder is frontend-agnostic and consumes the same `Call` from either frontend.
- `NewDefault` wires a binder over the embedded default KB (`internal/analysis` is its only caller).
- `Result.Encode()` returns canonical indented JSON.

## Extension Points

- **Add a resolution link**: extend `resolve` in `bind/resolve.go` (e.g. a new shell-symbol source) — keep the builtin → function → alias → PATH order and the ⊤ fallback.
- **Teach the binder a new wrapper**: wrappers are peeled by the frontend's normalizer (`front/bash/normalize.go` `wrapperSpecs`) and surfaced on `Call.Wrappers`; the binder then binds what remains.
- **Add KB-driven parameter behaviour**: extend `lowerParam`/`parseArgs` when a new `ParamKind`/`ValueSource` is introduced in the KB (bump the KB schema version).
- **New style**: add a `Style` constant; frontends emit it on the `Call`.

## Related Specs

- [Knowledge Base](knowledge-base.md) — the command/flag signatures `bind` resolves and binds against.
- [Bash Frontend](bash-frontend/README.md) — produces the normalized `bash.Command`/`Program` the binder consumes (`BindBash`).
- [PowerShell Frontend](powershell-frontend.md) — its `Lower` mirrors the binder's `Result` so the two compose uniformly.
- engine core (`engine/effect.go`) — the `Effect` IR and aggregating `Report` the binder emits into.
