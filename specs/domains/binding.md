# Binding

## Purpose

`bind` turns a normalized command invocation into the set of effects it implies. It resolves the invoked name (alias → function → builtin → PATH, then two invocation-form links that map a spelling onto a knowledge-base command: a path-qualified basename and a package runner's operand) and binds that command's flags, options and operands against the effect knowledge base. It is the join of the two lower layers — a frontend's normalized call on one side, the KB's command/flag signatures on the other — producing `[]engine.Effect`. Where the analysis cannot see (a dynamically-named command, or a name matching nothing), it degrades to the top element ⊤ (`CodeExec` over the any-target scope) rather than to "no effect".

## Key Files

- `bind/bind.go` — the binder: `Bind`, `BindBash`, `bindCommand`, `parseArgs` (flag/operand binding), `lowerParam` and `fileRefPath` (the `@file` convention), `taintFor`, `argsTaint`, `taintEgress`, `wrapperElevation`/`declaresPrivEsc` (refined -u wrapper elevation), `FromBash` (the frontend bridge).
- `bind/resolve.go` — name resolution: `ResolveKind`, `Resolution`, `resolved`, the `resolve` chain (alias → function → builtin → PATH, then the path-basename and package-runner links), `expandAliases` and `tokenizeAlias`.
- `bind/runner.go` — package-runner and project-local bin-path resolution: `IsPackageRunner`, `StripBinaryPath`, `NormalizeBinaryName` (the runner/path vocabulary the binder and the canonical form share) and the runner consumption (`runnerBinaryArgs`, `runnerBinary`).
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
	Wrappers    []Wrapper    `json:"wrappers,omitempty"`  // sudo, env, … outermost first
	Funcs       map[string]bool   `json:"funcs,omitempty"`
	Aliases     map[string]string `json:"aliases,omitempty"`
	Pos         engine.SourceLoc  `json:"pos,omitempty"`
	StdinTaint  engine.Taint      `json:"-"`
}

// Wrapper is one command wrapper peeled off a call (sudo, env, …), outermost
// first, with the option words it carried and the position of its own name
// word. Options are always literal: a wrapper's non-literal option value is
// recorded as a "@" placeholder — the option stays unsatisfied (`sudo -u $U`
// keeps `-u` plus the placeholder), so the binder's re-pairing can never glue
// a following option word as the value, and a script that literally passes
// `@` as the value is classified the same way (sudo rejects it and runs
// nothing) — and the peel continues with the following words. A partially
// dynamic word whose literal prefix names a value-taking option is recorded
// as that option, and absorbed — with a "@" placeholder for its unresolved
// value — only when its dynamic tail is quoted, and so one field
// (`sudo -u"$U" cmd` records `-u` + `@`, exactly as the separated spelling
// does; the long glued form `sudo --user"$U" cmd` records `--user` + `@`
// likewise — real bash concatenates it into an unknown option, so the
// recorded unsatisfied option and its unresolved target are the safe
// over-report; a fully literal
// misspelling like `--usernobody` stays an unknown flag and over-claims the
// root elevation instead — the same safe direction, one rung less precise; a
// short glued cluster whose last element is value-taking (`-ug"$X"`) records
// its leading elements as options (an earlier value-taking element is itself
// recorded unsatisfied), then the last value-taking option and its `@`
// placeholder — real bash attaches the whole tail to that option (`-u g$X`),
// so the unresolved target is again the safe reading). An unquoted tail (`sudo -u$U cmd`) is recorded but
// never absorbed: bash field-splits the expansion into several argv fields —
// an option value plus free-standing words sudo reads as its own command
// line — so the word stays the dynamically-named inner command and the
// analysis degrades to ⊤ over the recorded unsatisfied option.
type Wrapper struct {
	Name    string           `json:"name"`
	Options []Arg            `json:"options,omitempty"`
	Pos     engine.SourceLoc `json:"-"`
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
	ResolveCommand    ResolveKind = "command"    // external command with a KB signature (PATH), the path-basename link or the package-runner link
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
        │ 1. env assignments (VAR=x cmd, env VAR=x cmd) │──▶ EnvWrite effects
        │    + CodeExec for the exec channel            │   (+ CodeExec Direct for
        │      (LD_PRELOAD, TAR_OPTIONS, GIT_CONFIG_*)  │    the exec channel)
        │    (suppressed on an inert wrapper line — 1b) │
        └───────────────┬───────────────────────────────┘
                        │
        ┌───────────────┴───────────────────────────────┐
        │ 1b. wrapper elevation (refined -u): a wrapper   │
        │ whose KB entry declares PrivEsc (sudo) binds    │──▶ PrivEsc Direct effects (+ notes)
        │ its OWN option words via parseArgs              │
        └───────────────┬───────────────────────────────┘
                        │
   NamePresent == false │  bare assignment → ResolveAssignment;  else ResolveEmpty
                        │
                        ▼  resolve(c)   (bind/resolve.go)
         1. alias     c.Aliases[name] → expandAliases (≤32)    ──▶ ResolveAlias (may reach a command)
         2. function  c.Funcs[name]                            ──▶ ResolveFunction → ⊤ Transitive
         3. builtin   kb.Command(name).Dialect == "builtin"   ──▶ ResolveBuiltin
         4. command   kb.Command(name)                        ──▶ ResolveCommand
         4a. path     StripBinaryPath(name) → kb.Command      ──▶ ResolveCommand (./node_modules/.bin/tsc, ./mvnw)
         4b. runner   packageRunners[name] → kb.Command(operand) ──▶ ResolveCommand (npx tsc, bunx tsc)
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
- The two invocation-form links run only after the PATH link misses, and each maps a spelling onto a knowledge-base command: `4a` reduces a path-qualified name to its `StripBinaryPath` basename, so `./node_modules/.bin/tsc` and `./mvnw` bind the bare binary's signature; `4b` consumes a package runner's own words and binds its first non-flag literal operand (`npx tsc`). Both fail closed to ⊤ for a dynamic operand, an operand outside the KB, a runner that names no operand, a runner `-c`/`--call`, and a code-execution interpreter operand (`npx node -e …`, which matches the frontend's own sink rule so the runner spelling stays ⊤ like the bare `node -e …`); a path-qualified runner spelling (`./node_modules/.bin/npx …`) names no KB command and so also stays ⊤ — the runner link keys off the bare runner name, not the path basename.
- A shell function resolves to ⊤ with `ModeTransitive` (its body is opaque to command binding).
- Alias expansion is bounded by `maxAliasDepth`; a cyclic or unparseable alias chain degrades to ⊤.
- A wrapper whose knowledge-base entry declares a PrivEsc parameter (`sudo`) elevates by its own command line, before the inner command is resolved (`wrapperElevation`, predicate `declaresPrivEsc`). The wrapper's option words are bound via `parseArgs` and refined by the -u doctrine:
    - No `-u`/`--user` at all, or a literal value naming root — the name `root`, or a numeric UID spelling of 0 (`0`, `00`, `#0`; a bare number is a username by man sudo, but reading the numeric spellings by their value is the safe over-report, pinned by the elevation matrix test) — yields a certain (`Direct`) PrivEsc targeting `root`.
    - A literal value naming any other valid target (a username, or a numeric UID other than 0, with or without the `#` prefix) yields no elevation plus an explanatory note.
    - A value that is missing or not statically known yields the certain elevation over a ⊤ target user; an empty literal value (`-u ''`, `--user=`), an option-shaped one (the token `parseArgs` glued after an unsatisfied `-u`: `sudo -u -g root`; the separated dynamic spelling `sudo -u $U -g root` takes the placeholder path instead, with the same ⊤ target), or a `#`-spelling sudo would reject (`#abc`) yields the same ⊤-target elevation — with a note wherever the value would have lied about a direction. The same ⊤-target treatment covers more than one `-u`/`--user` (sudo documents value-taking options as single-use; the behavior on violation is not spelled out), so a direction is never claimed for input the doctrine cannot resolve. A bare non-numeric `-u` value is syntactically a username: it de-elevates as written (and if no such user exists, sudo runs nothing and the claim still holds); a bare numeric value is read by its value instead (the safe over-report above).
    - A line that names nothing to run never elevates and never claims a de-elevation: the `-l`/`--list` list form runs nothing even when command words follow it (sudo lists their permissions), the print-and-exit `--version`/`--help` spellings run nothing likewise, the `-v`/`-K` spellings run no command in combination with a command word, `-h` names a remote host (the sudoers policy does not run remote commands), and any inert flag-only invocation (no command word and no other wrapper inside the privileged wrapper, and no shell-implying `-i`/`-s`) decides nothing — except that a peeled wrapper inside the privileged wrapper is itself a process sudo execs (`sudo env FOO=1` runs env as root), so a wrapper chain below it keeps the elevation; a wrapper above it execs the privileged wrapper, not the other way round, and cannot keep the line alive — the inertness is decided at the privileged wrapper's own position in the chain, so `env sudo -k` and `nohup sudo -k` run nothing. The report degrades to ⊤ — the frontend's own for a consumed command line, the binder's when command words remain, whose ordinary binding would fabricate effects for a process that never starts — the accepted `sudo --version`/`sudo -l` false positive in SECURITY.md. No wrapper on such a line reports an elevation (no privileged command executes on it), and the resolution reports `ResolveUnknown` when command words remain; a consumed command line reports the frontend's `ResolveEmpty` — nothing ran, so there is no execution for a resolution to describe.
    - `-g`/`--group` never decides nor elevates: a bare `-g` runs the command as the invoking user (man sudo — only the primary group is replaced), and with `-u` present the target user decides. Group escalation is not modelled; a matched `-g` value contributes a note saying so on any line that reaches the elevation branch — an inert line returns before it (accepted residual, SECURITY.md).
    - A ⊤-targeted elevation is an unresolved target, not unknown code execution: it never sets `Result.Conservative`. A wrapper without the predicate (env, nohup, …) contributes nothing of its own. Notes are per wrapper: `sudo -u nobody sudo touch …` reports the inner wrapper's elevation beside the outer wrapper's de-elevation note — each note speaks for its own wrapper, never for the line as a whole.
- The elevation reaches every call that carries a privilege wrapper, including the four that never reach the ordinary flow: a consumed command line (no command word after the peel — `sudo -i`), a dynamically-named inner command (`sudo $X`), a wrapper over a code-execution sink (`sudo sh -c '…'`), and over a code-executing builtin (`sudo eval '…'`). All four are handed to the binder through the resolver seam by the frontend's `elevateWrappers`, which folds the result only when it carries elevation evidence — a wrapper over an effect-free line (`env true`) stays benign. When the interpreter has already derived its own ⊤ `CodeExec` for the statement, the binder's ⊤ for the same call is dropped (with its derivation) — `Report.Normalize` keys the merge on the flow role, so keeping both would report the same unknown execution twice.
- sudo's CLI grammar lives in three coupled homes, pinned against divergence by `bind.TestSudoGrammarLayers` and `kb.TestSudoInertSpellingsStayUndeclared`: the value-taking options the frontend pairs at peel time (`front/bash` `wrapperSpecs.valueOpts`, re-exported as `bash.SudoValueOpts`), the effect-bearing parameters (`kb/data/security.yaml`), and the binder's inert spellings (undeclared in the KB by design). Declaring a value-taking sudo option in the KB without adding it to `SudoValueOpts` — or an inert spelling in the KB — would silently change elevation verdicts. A wrapper over a shell-only builtin (`sudo true`) is deliberately NOT routed through the seam: the builtin is a no-op, so the report stays benign-empty — the elevation fact on it is a documented precision residual (SECURITY.md).
- A call resolved onto a command whose knowledge-base entry models its payload as a Direct PrivEsc `COMMAND` positional (`declaresWrapperPayload` — sudo) but whose wrapper the frontend did not peel (a path-qualified `/usr/bin/sudo …`, a package-runner operand naming one) degrades to ⊤ `CodeExec` with `Result.Conservative` and a note, instead of the entry's limited PrivEsc-only binding: the wrapped argv reached the binder only as that slot's value, so its own effects — filesystem, network, credentials — are beyond binding, and reporting them as a narrow confident effect set would silently under-report the payload. Commands whose PrivEsc declarations name their own operands (`install -m`, yarn's `global` positional, su's `USER`, chroot's `NEWROOT`) keep binding normally.
- Environment assignments are lowered with the shell frontend's own rules, not a private copy: whether a variable reaches the code-execution channel (program-valued variables such as `LD_PRELOAD`/`JAVA_TOOL_OPTIONS`, the option channel `TAR_OPTIONS`, git's `GIT_CONFIG_*` family) and the effect that channel implies are decided by `bash.ExecEnvVar`/`bash.ExecEnvEffect`. A `Call` handed straight to `Bind`/`BindBash` therefore reports the same `CodeExec` the interpreter emits for the same line, so a policy that denies code execution cannot pass on the binding path alone. A normalized assignment that carries no value (`VAR=`) is a known-empty value rather than an unknown one: clearing the variable runs nothing.
- `Result.Conservative` is true exactly when the outcome includes a ⊤ (`CodeExec`) effect.
- A parameter whose value is a file the **tool itself interprets**, and a bare word the tool **expands into options before it runs**, make the invocation's effect set unknown, because the analysis performs no runtime I/O: the binder degrades to ⊤ `CodeExec` (`Result.Conservative`) and reports the file's read beside it. Three spellings of that idea are enumerated: a file of options (`curl -K`, `ssh -F`/`-o`-style config files via `optionFileSpecs`), a script in the tool's own command language (`psql -f`/`--file`, `sqlite3 -init`, `gdb -x`/`--command`, `redis-cli --eval`, via `languageFileSpecs`), and an `@FILE` response file for the commands whose grammar documents it (the GCC driver `gcc`/`cc`/`clang`, `ld`, `as`, `ar`, `strip`, `nm`, `objdump`, `readelf`, `strings`, `javac` — `responseFileCommands`). The **inline** spelling of the same capability stays a bounded `CodeExec` (`psql -c`, `gdb -ex`, `sqlite3 -cmd`): visible text is not unknown. An `@` that names **data** rather than options (`curl -d @file`, `curl -F file=@file`) is untouched, so the rule keys on the command, never on the character.
- A matched destructive-flags entry folds its class severity into `Result.Destructiveness` with `Join` (max), so a destructive class raises the binder result's destructiveness even when the matched parameter's own effects are mild.
- Unrecognized flag names are surfaced as a note, not dropped silently.
- A `NetEgress` effect's target is host-shaped or ⊤/⊥ (see the egress target gate above); a literal non-host-shaped operand never becomes egress evidence. `engine.IsEgressSink` is kind-strict — an exfiltration *sink* is a tainted `NetEgress`, never a filesystem write, so a local file redirect (`git diff > $D/x.diff`) cannot fabricate an exfil pair.

## Configuration

- `maxAliasDepth = 32` — bounds alias-chain expansion so a recursive alias set cannot diverge.
- `Style` is `"bash"` or `"ps"`; the binder is frontend-agnostic and consumes the same `Call` from either frontend.
- `NewDefault` wires a binder over the embedded default KB (`internal/analysis` is its only caller).
- `Result.Encode()` returns canonical indented JSON.

## Extension Points

- **Add a resolution link**: extend `resolve` in `bind/resolve.go` (e.g. a new shell-symbol source) — keep the alias → function → builtin → PATH order and the ⊤ fallback, and add any new invocation-form link after the PATH miss.
- **Teach the binder a new wrapper**: wrappers are peeled by the frontend's normalizer (`front/bash/normalize.go` `wrapperSpecs`) and surfaced on `Call.Wrappers` (name, option words, position); the binder then binds what remains. A wrapper whose KB entry declares PrivEsc is additionally refined by its own options (`wrapperElevation`, the refined -u doctrine).
- **Add KB-driven parameter behaviour**: extend `lowerParam`/`parseArgs` when a new `ParamKind`/`ValueSource` is introduced in the KB (bump the KB schema version).
- **New style**: add a `Style` constant; frontends emit it on the `Call`.

## Related Specs

- [Knowledge Base](knowledge-base.md) — the command/flag signatures `bind` resolves and binds against.
- [Bash Frontend](bash-frontend/README.md) — produces the normalized `bash.Command`/`Program` the binder consumes (`BindBash`).
- [PowerShell Frontend](powershell-frontend.md) — its `Lower` mirrors the binder's `Result` so the two compose uniformly.
- engine core (`engine/effect.go`) — the `Effect` IR and aggregating `Report` the binder emits into.
