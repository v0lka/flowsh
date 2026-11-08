# Changelog

All notable changes to `flowsh` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

These entries track the **module release tags** (`vX.Y.Z`). They are independent of
the two *frozen* wire-contract tags that the analyser emits — `effect-ir/v2`
(the effect-IR payload) and `flowsh/v3` (the CLI report envelope). A change to a
frozen contract is called out in the entry that makes it; the contract tags move
only on a breaking shape change, not on every module release.

## [Unreleased]

### Added

- **JavaScript filesystem and path effect models.** Modelled Node `fs` and
  `path` APIs now report precise effects through a JavaScript knowledge base
  instead of degrading to ⊤: `require('fs').writeFileSync('/tmp/out', …)`
  reports `FSWrite|Direct|[/tmp/out]`, where v0.7.0 reported `CodeExec|Direct|*`
  ([ADR-0020](specs/decisions/0020-javascript-filesystem-models.md)). The
  binding lives in `bind/js.go`, `bind/js_options.go` and `bind/js_path.go`,
  the module-resolution seam in `front/js/modules.go`, and the report assembly
  in `internal/analysis/javascript.go`; `api.JavaScriptContext` supplies the
  offline POSIX home/cwd paths the models resolve against. A new
  `specs/domains/javascript-filesystem.md` records the contract, the
  knowledge-base schema moves to `effect-kb/v4` (the loader still accepts
  `effect-kb/v2` and `effect-kb/v3`), a new corpus document
  (`testdata/corpus/filesystem_js.json`) pins the models, and the latency
  baseline is re-pinned at 460 cases.

### Changed

- **Comparable form.** `CommandCall.identity()` length-prefixes every field, so
  the boundaries of the call key are injective, and a redirection's `Known`
  flag now takes part in it (`internal/analysis/canonical.go`).
- **CI.** The macOS runner is pinned to `macos-15` rather than the floating
  `macos-latest` label, which migrated to macOS 26 and would silently re-time
  the latency gates; the `macos-14` images were retired, so `macos-15` is the
  floor (`.github/workflows/ci.yml`).
- **Documentation.** The specification set is refreshed across the index, the
  architecture and contract documents and the domain specs, which gain a
  dedicated `specs/domains/bash-frontend/wrappers.md`.

### Fixed

- **A host-assumed variable no longer prunes a `case` arm.** A `case` subject
  whose value is a host-assumed default (`$HOME`, `$USER`) is no longer treated
  as known, so every arm is executed instead of only the one the assumed value
  appears to match — and a pattern that is itself host-assumed makes the match
  unknown. The assumed marker follows the value through a copy (`H=$HOME`), a
  `for` loop's items, a declaration and a `+=` append, so
  `case $HOME in /root) ;; *) … ;; esac` reports the fall-through arm's effects
  rather than nothing (three GuardFall `E` witnesses pin it).

## [v0.7.0] - 2026-10-24

A dialect-and-hardening release. A third frontend joins the analyser — a
bounded JavaScript value and control-flow evaluator — and a wide security
review closes findings across the binder, the engine and both existing
frontends. The frozen contract tags stay at `effect-ir/v2` and `flowsh/v3`.

### Added

- **JavaScript dialect (`front/js`).** `flowsh --lang js` analyses a JavaScript
  program through a new bounded frontend: tree-sitter parsing with
  position-preserving normalization (`front/js/parse.go`), typed values and
  immutable container snapshots over a case-sensitive lexical state
  (`front/js/value.go`), expressions, literals and destructuring inputs
  (`front/js/expr.go`), and statements, scope, hoisting, completion states,
  loops, `switch` and exceptions (`front/js/exec.go`). It evaluates a bounded
  statement/expression subset and produces values and control flow; function
  invocation, module resolution and Node API effect knowledge remain later
  milestones, and unsupported execution degrades to the shared ⊤
  ([ADR-0018](specs/decisions/0018-javascript-semantic-kernel.md),
  `specs/domains/javascript-frontend.md`). The dialect's canonical spelling is
  `js`, with the aliases `javascript`, `node` and `nodejs`
  (`api.LangJavaScript`, `api.ParseLang`, trimmed and case-insensitive);
  `--lang auto` still selects bash or PowerShell only. Evaluation stays bounded
  on every host: source size and raw delimiter depth are checked before
  parsing, a two-second parser deadline is kept in every build including
  `-race`, and normalization and evaluation carry depth, node, step, value-size
  and recording limits. The conformance corpus gains a JavaScript bundle
  (`testdata/corpus/guardfall_js.json`, GuardFall A–E conservative coverage)
  and the latency baseline is re-pinned at 394 cases. `policy.Evaluate` accepts
  a `js` report language instead of denying it as `invalid_report`, and
  SECURITY.md names the new frontend's degradation and bounds.
- **Supply-chain gates.** CI verifies the module graph against `go.sum`
  (`go mod verify`) and runs `govulncheck@v1.9.0`, which exits non-zero on a
  vulnerability reachable from this module and so blocks the merge. The scan
  deliberately runs on every runner rather than on Linux only, because the
  scanner resolves the call graph for the host `GOOS`/`GOARCH` and the release
  matrix ships more than one platform; the release workflow runs the same
  pinned scan before GoReleaser, so a reachable vulnerability blocks a release
  and not only a merge (`.github/workflows/ci.yml`,
  `.github/workflows/release.yml`).

### Changed

- **The CLI reads no caller-named file: `--file` is removed.** The input
  surface is the positional argument and stdin only, so the CLI cannot be
  turned into an arbitrary-file-read primitive; `--batch` reads its lines from
  stdin. The exit-code descriptions narrow with it — exit 2 is now "unknown
  flag or unknown `--lang`", exit 3 "stdin could not be read, or the command
  was empty" — while the exit-code numbers themselves and the report contract
  are unchanged.
- **`--lang auto` falls back across dialects.** The sniffed dialect is analysed
  first and, when its report is not `Covered()`, the other one is analysed too;
  when neither dialect can bound the input the report is forced to ⊤ and
  conservative with the reason "no dialect could bound the input", instead of
  returning the first dialect's uncovered report (`cmd/flowsh/main.go`).
- **Knowledge-base schema `effect-kb/v3`.** Per-parameter `also` effects and
  value-gated destructive rows let one parameter contribute a second effect and
  a destructive row fire only on a matching value; the loader still accepts
  `effect-kb/v2` (`kb/schema.go`).

### Fixed

- **Security-review findings closed across the binder, the engine and both
  frontends.** The binder gains mode-dependent operation handling for
  single-file compressors and for tar's old-style option bundle, and
  chmod/install SUID escalation detection, plus corrections for the `sed`
  script sub-language, `ssh -o` exec directives, attached short options,
  long-option prefixes, curl's file grammars, option/script/response files,
  upload source reads, whole-environment dumps, subcommand remote egress and
  exec-bearing `git config` keys. The engine gains UNC/host-path remote-write
  sinks, secret staging across commands, environment credential sources,
  block-device breadth, normalized secret-path matching and linear
  canonicalisation. The bash frontend is hardened (wrapper peeling, alias
  expansion, the hash table, `PATH` rebinding, xargs placeholders, credential
  reads, stdin command languages, the brace estimator) and so is the PowerShell
  frontend (alias state, drive mappings, session channels, launchers, parse
  bounds, host-agnostic registry persistence). Regression tests pin each
  finding.
- **Refined effect targets for a SUID install and for `nc -e`.**
  `install -m 4755 "$STAGE" /usr/bin/svc` now reports the mode on `FSMeta`
  (`FSMeta|Direct|[4755]`) and the installed path on `PrivEsc`
  (`PrivEsc|Conditional|[/usr/bin/svc]`) — v0.6.0 reported the two the other
  way round — and gains the `FSWrite|Direct|[/usr/bin/svc]` the install
  performs; and `nc -e /bin/sh HOST PORT` reports `CodeExec|Direct|[/bin/sh]`
  rather than a bare `ProcSpawn|Direct|[/bin/sh]`.
- **A direct `Bind` call reports the `env` exec channel.** The binder's copy of
  the shell's environment-assignment channels lowers exec-bearing assignments
  (`LD_PRELOAD`, `JAVA_TOOL_OPTIONS`, `TAR_OPTIONS`, `GIT_CONFIG_*`) to
  `CodeExec` through the exported `bash.ExecEnvVar`/`bash.ExecEnvEffect`, so a
  `Call` handed directly to `Bind`/`BindBash` reports the same sink the
  interpreter emits. A normalized assignment with no value is treated as
  known-empty, so clearing the variable runs nothing.
- **One wording for both parse-budget clocks (PowerShell).** An exhausted
  budget that the parser's own clock observed (`SetTimeoutMicros` →
  `ParseStoppedEarly` with `ParseStopTimeout`) now carries the same canonical
  "µs budget" reason as the wall-clock wrapper `parseWithBudget`, instead of
  "parse stopped early (timeout)"; other stop reasons keep the generic wording.
  Which clock observes the budget first is a scheduling race, so the split
  wording let the timeout wording pin and the determinism gate's classifier
  disagree about the same run on a loaded host.
- **The determinism gate tolerates a host-load parse-budget trip.** The
  concurrent gate asserted byte-identity for every result, but a PowerShell
  parse runs under a wall-clock budget, so a loaded host can turn a benign
  source into a ⊤ result. Such a mismatch is now classified as a host-load trip
  and tolerated only when a sequential re-analysis reproduces the reference; a
  concrete difference, a failure, or a ⊤ for any other reason still fails
  ([ADR-0019](specs/decisions/0019-determinism-gate-parse-budget-trip.md)).

## [v0.6.0] - 2026-10-15

A policy-and-privilege release. A new optional public policy package turns a
report into an allow/review/deny decision, and the bash binder learns to
elevate a command through the `sudo` wrapper.

### Added

- **Report policy package.** The optional public package
  `github.com/v0lka/flowsh/policy` evaluates an `api.Report` under trusted,
  caller-owned Go configuration and returns an `Allow`, `Review` or `Deny`
  decision with deterministic, sorted reason codes
  ([ADR-0017](specs/decisions/0017-report-policy-package.md)). `New` validates
  the configuration and copies its maps, defaulting `Unknown` to `Deny`,
  `Conservative` to `Review`, `Exfiltration` to `Deny`, `Cradle` to `Review`
  and `Ingest` to `Allow`, with empty `Effects`/`Grades` maps; `Evaluate`
  validates the report's tool name/version, schema version, canonical language
  and grade before applying rules, so a missing, invalid or incompatible report
  denies with `invalid_report`, an otherwise-valid report whose `Covered()` is
  false denies with `uncovered_report`, and a nil or zero policy denies with
  `invalid_policy`. All matching restrictions combine with
  `Deny > Review > Allow`; unknown (`Top || HasTop()`) and conservative
  analysis always require Review or Deny, and an Allow rule never overrides
  another restriction. Decisions carry only the stable signal names
  (`unknown`, `conservative`, `exfiltration`, `cradle`, `ingest`),
  `effect:<kind>` and `grade:<grade>`, never analysed text. The package depends
  only on `api` and `engine`, performs no I/O or command execution, and leaves
  analysis, scoring, the CLI report and the report contract unchanged; it amends
  ADR-0010's framing of `api` as the sole public surface while `api` remains the
  analysis entry point. A new `specs/domains/policy.md` records the contract,
  and `docs/embedding.md`, `README.md`, `SECURITY.md`,
  `specs/architecture/layers.md` and `specs/INDEX.md` name the decision layer.
- **sudo wrapper elevation (refined -u).** The bash frontend now carries each
  peeled wrapper's option words and source position into `bind.Call`
  (`Wrapper{Name, Options, Pos}` — a source-breaking type change for code that
  imported `bind` directly and read `Wrappers` as `[]string`; the serialized
  report contract is unchanged), and the binder runs a wrapper-elevation pass
  before resolving the inner command: a wrapper whose knowledge-base record
  declares a PrivEsc parameter (`sudo`, new in `kb/data/security.yaml`) binds
  its own command line via `parseArgs` and elevates by the refined -u doctrine —
  no `-u`/`--user`, or a literal value naming root (`root`, or the numeric
  spellings `0`, `00`, `#0`), yields a certain (`Direct`) `PrivEsc` targeting
  `root`; a literal non-root target (`sudo -u nobody …`, `sudo -u '#1000' …`)
  yields no elevation plus an explanatory note; a missing, dynamic, repeated
  (`sudo -u a -u b`) or option-shaped value keeps the certain elevation over an
  unresolved (⊤) target user without touching `Result.Conservative`. A line
  that names nothing to run (the inert flag-only forms `sudo -l`, `-v`, `-k`,
  `-h`, `--version`, `--help`, `--list`, … — including `-l`/`--list` with a
  command word, which sudo only lists permissions for, and the print-and-exit
  `--version`/`--help`; `-h`/`-v`/`-K` are likewise inert with a command word,
  whereas `-k` with a command still runs it, only invalidating the cached
  credentials first) neither elevates, nor claims a de-elevation, nor
  binds the words that follow: the report degrades to ⊤ instead.
  `-g`/`--group` never decides nor elevates: a bare `-g` runs the command as
  the invoking user (man sudo), and the unmodelled group membership is named by
  a note. Unrecognized wrapper flags surface in the notes, and
  `sudo sudo cmd` reports exactly one elevation. Every elevation is justified
  in the why-trace by the wrapper's own tokens (`command(sudo)` at the
  wrapper's position, `flag(-u)`, `operand(root)`, rule `priv.escalate`).
  The conformance corpus gains a sudo bundle (`testdata/corpus/sudo_bash.json`;
  the latency baseline is re-pinned at 359 cases), and the accepted precision
  trade-offs — the flag-only ⊤ verdict, the unpeeled path-qualified wrapper,
  group escalation, `doas`/`pkexec` and the wrapper-less PowerShell path — are
  recorded in SECURITY.md. The elevation also covers the call shapes that
  never reach the ordinary binding flow: a wrapper that consumed the whole
  command line (`sudo -i` runs a root shell with no inner command), a wrapper
  over a dynamically-named command (`sudo $X`), over a code-execution sink
  (`sudo sh -c '…'`), over a code-executing builtin (`sudo eval '…'`) — the
  interpreter routes all four through the resolver seam (`elevateWrappers`),
  folding a result only when it carries elevation evidence, so a wrapper over
  an effect-free line stays benign; when it does carry evidence, the report
  gains `PrivEsc` alongside the interpreter's ⊤, and a ⊤ the interpreter
  already derived is not duplicated by the binder's own.

### Fixed

- **Policy coverage diagnostics (2026-10 code review).** The coverage gate is
  applied to the validated report as its own step instead of being folded into
  the report-validation check, so an otherwise-valid report with no effects and
  neither the `Top` nor the `Conservative` flag — Bash `true` and `:` — denies
  with the distinct `uncovered_report` code rather than being reported as
  malformed. Validation still precedes coverage, so an invalid report always
  uses `invalid_report`.
- **Review hardening of the sudo elevation (2026-10 code review).**
  `sudo -u '#0' …` (and the `00` spelling) is classified numerically instead of
  falling into a false "not root" de-elevation note; `#1000` is classified by
  the same numeric reading and keeps its correct de-elevation; a repeated
  `-u`/`--user` no longer resolves by the first match — the elevation
  stays certain over an unresolved target with an ambiguity note; an option
  token glued after an unsatisfied dynamic `-u` (`sudo -u $U -g root …`) is
  never read as the target user; `sudo -u"$U" cmd` / `sudo -u$U cmd` keep the
  same -u semantics as the separated spelling (the recorded unsatisfied
  option) instead of reporting a confident root escalation; and a
  path-qualified `/usr/bin/sudo …` degrades to ⊤ like the unpeeled spelling it
  is, instead of the knowledge-base record's narrow PrivEsc-only binding that
  silently dropped the wrapped command's own effects. Under a download-cradle
  flow (`curl … | sudo $X`) the report now carries a single ⊤ `CodeExec` row.
  Inertness is decided at the privileged wrapper's own position in the chain,
  not chain-wide: a wrapper above it execs the privileged wrapper, not the
  other way round, so `env sudo -k` / `nohup sudo -k` — and `sudo sudo -k` —
  no longer report `PrivEsc` with a "the command still runs" note for a line
  that executes nothing; `sudo env FOO=1` keeps its elevation (the inner
  wrapper is a process sudo execs), and `bind`'s package documentation now
  names both deliberate empty-result shapes of a direct `Bind` call. A
  trailing bare `-u`/`--user` with no value on an inert line carries its own
  explanatory note (real sudo usage-errors on the missing argument) instead
  of staying silent.

### Changed

- **CI.** The `golangci-lint` GitHub Action is pinned to a version compatible
  with Go 1.27.2 (`.github/workflows/ci.yml`).

## [v0.5.0] - 2026-09-30

A corpus-and-recall release. An external balanced sample joins the conformance
corpus, and the four recall gaps it surfaced while screening the pool are
closed so the sample passes with zero silent misses.

### Added

- **External balanced corpus sample.** A balanced sample (26+26 bash, 54+54
  PowerShell) drawn from public labeled datasets under permissive licenses
  joins `testdata/corpus/` (`external_bash.json`, `external_posh.json`), with
  the new `external_malicious`/`external_benign` groups gated by the same
  invariants as the rest of the corpus: no silent misses on the malicious side
  and no ⊤ on the benign side. A PowerShell case may now set `"windows": true`
  to run under the Windows-native provider profile, since registry effects are
  host-gated by design. The latency baseline is re-pinned at 348 cases and the
  domain specs are updated accordingly.

### Fixed

- **Four recall gaps closed** so the external sample passes with zero misses:
  - `Write-Output` — and a top-level string-literal statement, which the parser
    now normalizes to `Write-Output` — carries `Stdio` when the pipeline is
    unconsumed; a redirection suppresses it.
  - `Get-Command <name>` and `Get-Module -ListAvailable` lower to `FSRead`
    probes of the command path / module directories.
  - bash `jobs` is no longer a shell-only builtin; the KB now describes its
    stdout job-table output as `Stdio`.

## [v0.4.0] - 2026-09-21

A knowledge-base and binding release. It rolls up the changes made since
`v0.3.2`, whose full detail is recorded in the `v0.3.3` and `v0.3.4` entries
below.

### Added

- **Expanded ecosystem coverage in the knowledge base.** `kb/data/toolchain.yaml`
  and `kb/data/linting.yaml` gain 114 commands across the Go, Node.js, Python,
  JVM, Rust and Zig toolchains — with eleven class-C removals in
  `kb/data/destructive.yaml` and dedicated `go` subcommand specs in
  `kb/data/pkgmgr.yaml` — so their everyday build, test and lint loops bind
  deterministically instead of degrading to ⊤. The common-binary inventory gate
  grows to 116 entries and the conformance corpus gains eighteen cross-ecosystem
  benign cases.
- **Package-runner and project-local bin-path resolution.** The binder resolves
  `npx`/`bunx` and the `./node_modules/.bin/<bin>` path forms to the bare binary
  and binds the resolved binary's own knowledge-base signature, so the everyday
  JS-stack verification loop (`npx vitest run …`, `npx tsc -b`,
  `./node_modules/.bin/vitest run`) binds deterministically instead of degrading
  to ⊤. The fail-closed shapes — an operand outside the knowledge base, a
  dynamic operand, a runner that names no operand, `-c`/`--call` and a
  code-execution interpreter operand — are unchanged. The comparable form
  (`commandCalls[].resolved`) reports the knowledge-base command the binder
  resolved to, so every spelling of one binary shares one identity (`npx mvnw`,
  `./mvnw` and `mvnw` all report `resolved: "mvn"`).

### Changed

- **Documentation.** The command→dialect map in
  `specs/domains/knowledge-base.md` now lists the complete inventory of every
  command in the knowledge base, and the `toolchain.yaml` / `linting.yaml`
  descriptions name the expanded ecosystems.

## [v0.3.4] - 2026-09-21

### Added

- **Expanded ecosystem coverage in the knowledge base.** `kb/data/toolchain.yaml`
  (dialect `pkgmgr`) and `kb/data/linting.yaml` (dialect `build`) grow by 114
  commands across six toolchains, so the everyday Go, Node.js, Python, JVM, Rust
  and Zig build/test/lint loops bind deterministically instead of degrading to ⊤:
  - **Go** — developer tooling (`gopls`, `dlv`, `goreleaser`, `air`, `mockgen`,
    `swag`, `wire`, `stringer`) and linters/formatters/reporters (`goimports`,
    `gofumpt`, `govulncheck`, `gotestsum`, `errcheck`, `revive`, `ineffassign`,
    `gosec`, `benchstat`, `go-junit-report`, `ginkgo`).
  - **Node.js** — package managers/runtimes (`corepack`, `deno`), bundlers
    (`vite`, `webpack`, `rollup`, `esbuild`, `swc`, `parcel`), meta-frameworks
    (`next`, `nuxt`, `react-scripts`), task runners (`turbo`, `nx`, `lerna`,
    `gulp`, `grunt`), process/runtime helpers (`pm2`, `node-gyp`, `tsx`,
    `ts-node`, `nodemon`) and test/build drivers (`mocha`, `ava`, `playwright`,
    `cypress`, `biome`, `oxlint`, `tsd`, `typedoc`, `uvu`, `rimraf`,
    `concurrently`, `cross-env`, `serve`).
  - **Python** — packaging and env tooling (`uvx`, `pipenv`, `pdm`, `hatch`,
    `tox`, `nox`, `conda`, `mamba`, `virtualenv`, `pipx`, `ipython`, `jupyter`,
    `twine`, `pyinstaller`) and checkers (`pytest`, `flake8`, `isort`, `pylint`,
    `pyright`, `bandit`, `coverage`, `sphinx`, `autopep8`, `pydocstyle`).
  - **JVM** — JDK/build tooling (`javac`, `javadoc`, `jar`, `jshell`, `keytool`,
    `mvnd`, `scala`/`scalac`/`sbt`/`scala-cli`/`mill`,
    `kotlin`/`kotlinc`/`kotlinc-jvm`/`kscript`, `ant`, `jbang`, `coursier`,
    `groovy`, `clojure`, `lein`).
  - **Rust/Zig** — `rustup`, `rustdoc`, `rust-analyzer`, `nextest`, the `cargo-*`
    family (`cargo-audit`, `cargo-deny`, `cargo-watch`, `cargo-expand`,
    `cargo-tarpaulin`), `wasm-pack`, `trunk`, `cross`, `bacon`, `rustfmt`, `zig`,
    `zls`.

  `kb/data/destructive.yaml` gains eleven class-C entries covering content-
  discarding removals among the new commands, mirroring the existing
  `gem`/`cargo`/`snap`/`flatpak` removal precedent (`conda`/`mamba` `remove`
  and `clean`, `pdm remove`, `pipenv uninstall` and `clean`, `pipx uninstall`,
  `coursier uninstall`, `rustup uninstall`, `lerna clean`).
  `kb/data/pkgmgr.yaml` gives the remaining `go` subcommands their own specs
  (`work`, `tool`, `fmt`, `doc`, `list`, `fix`), so those invocations carry a
  specific effect (`go fmt` writes, `go doc`/`go list` read) instead of the
  generic positional fallback.
  The common-binary inventory gate (`kb/coverage_test.go`) grows by the 114
  command names plus the `mvnw`/`cargo-fmt` wrapper aliases (116 entries, with
  representative family probes across the new ecosystems), the conformance
  corpus gains eighteen benign cases spanning the six ecosystems (Go, Node.js,
  Python, JVM, Rust, Zig) pinning that the new surface stays non-⊤, and the
  latency baseline follows the enlarged corpus.
- **Documentation.** The command→dialect map in `specs/domains/knowledge-base.md`
  now lists the complete inventory of every command in the knowledge base, and the
  `toolchain.yaml` / `linting.yaml` descriptions name the expanded ecosystems.

## [v0.3.3] - 2026-09-21

### Added

- **Package-runner and project-local bin-path resolution (bind).** The binder
  resolves `npx`/`bunx` to their first non-flag literal operand and the
  `./node_modules/.bin/<bin>` path forms to the bare binary, then binds the
  resolved binary's own knowledge-base signature: `npx vitest run …`,
  `npx tsc -b` and `./node_modules/.bin/vitest run` now bound deterministically
  instead of degrading to ⊤ — the everyday JS-stack verification loop the
  silent-mode audit recorded as C6 false denies (events 959718, 961162, 961231,
  962610, 963134, 964220, 968408). The fail-closed shapes are unchanged: an
  operand outside the knowledge base (a registry fetch whose code the analysis
  cannot see), a dynamic operand, a runner that names no operand,
  `-c`/`--call` (an arbitrary shell string), and a code-execution interpreter
  operand (`npx node -e …`, ⊤ like the bare `node -e …`) all stay ⊤. The
  conditional
  registry fetch is deliberately not modelled, matching the `npm run`/`exec`
  and `bun` entries. `NormalizeBinaryName` moves to `bind` as the single
  runner/path vocabulary shared with the canonical form (the audited
  963134/963140 retry pair keeps one canonical key). The comparable form now
  also fails closed on a runner's `-c`/`--call` flag, exactly as the binder
  does, so `npx -c 'X' Y` reports `commandCalls[].resolved` as the runner's own
  name (`npx`) instead of the shell string's word (`Y`); and it reports the
  binder's resolved identity for every spelling, so `npx mvnw`, `./mvnw` and
  `mvnw` all report `resolved: "mvn"` (the wrapper alias). Together these are
  the comparable-form changes from the pre-change `npx` handling. The coverage
  gate grows the runner/path family probes.

## [v0.3.2] - 2026-09-21

### Fixed

- **Knowledge-base corrections.** A service or operation selector is now
  `valueFrom: env` rather than `args`, so a subcommand word (`kubectl get pods`,
  `aws s3 ls`) can no longer become a phantom egress target while an address
  written on the command line still lowers concretely; output and selector
  parameters (`--json`, `-o`, `--output`) become `Stdio` instead of a fabricated
  file read; and the incorrect effect directions of the `redis-cli` and `psql`
  flags are fixed.
- **Binder download handling.** The binder synthesises wget's implicit download
  sink once per URL operand, folds `-P`/`--directory-prefix` into the written
  path, treats a `-` output value as standard output rather than a file named
  `-`, and names curl `-O`'s local file after the URL.
- **Flow-evidence isolation.** `Report.Normalize` merges on
  (kind, mode, netFlow), so the flow evidence of one effect cannot bleed onto
  another's targets; the flow detectors now document their deliberate
  many-to-one over-approximation.
- **bash frontend.** Matches a code-execution sink by basename and through
  `env`, and treats only network-labelled provenance as network content rather
  than every command substitution.
- **PowerShell frontend.** Lowers control-flow headers, fixes condition
  truthiness and splat/member/index targets, expands literal `foreach` ranges,
  and closes the rest of the round-two code-review findings.

### Changed

- Aligned the SECURITY.md threat model, the README report-field table (effects
  merge by kind, mode and network-flow role) and the CONTRIBUTING corpus and
  knowledge-base inventories (170 cases across seven documents; 23 reviewed
  `kb/data/*.yaml` documents) with the code, and added
  [ADR-0015](specs/decisions/0015-per-host-latency-reference.md) (per-host
  latency reference).
- Raised the knowledge-base load-latency budget to 150 ms after the tagged-commit
  release runner (the same `ubuntu-latest` that passes in CI) measured a worst
  average of 52.3 ms — above the earlier 50 ms ceiling — and recorded the
  decision in
  [ADR-0016](specs/decisions/0016-kb-load-budget-release-headroom.md).

## [v0.3.1] - 2026-09-20

### Fixed

- **PowerShell download-cradle flow.** The PowerShell frontend now establishes
  the network→code-execution flow through a pipeline, so a fetch piped into a
  code-execution sink (`Invoke-WebRequest … | Invoke-Expression`, `curl … | iex`)
  is reported as a cradle flow exactly like its bash counterpart. Pipeline
  stages now carry a shared group id so the lowerer can key the flow on the
  value flow between stages — never on the mere co-occurrence of a `NetEgress`
  and a code-execution sink — and the sink `CodeExec` is marked with the
  additive `netFlow: cradle` role.

## [v0.3.0] - 2026-09-20

### Added

- **Network data-flow fields (`flowsh/v3`, `effect-ir/v2`).** The report now
  asserts two network data flows so a consumer can key on the flow rather than
  infer it from the co-occurrence of a `NetEgress` and a sink:
  `score.cradleFlows` (network content reaching code execution — `curl … | sh`,
  `source <(curl …)`, `sh -c "$(curl …)"`; a download-then-execute chain is not
  currently asserted, because no frontend establishes that flow) and
  `score.ingestFlows` (a download client writing fetched content to a file —
  `curl -o`/`-O`, wget default/`-O`). The sink is marked by the additive
  effect-level `netFlow` role (`cradle` on a `CodeExec`, `ingest` on an
  `FSWrite`), which bumps the effect IR to `effect-ir/v2`; a program with no
  network flow serialises byte-for-byte as before. `DetectCradleFlows` /
  `DetectIngestFlows` live in `engine/taint.go`, the binder marks the curl/wget
  output parameters (and synthesises wget's implicit download), and the bash
  frontend marks a code-execution sink fed by network content. VCS sync (`git
  clone`/`fetch`/`pull`) is never an ingest. The CLI envelope tag moves to
  `flowsh/v3`.

- **PowerShell abstract variable state (Σ).** The PowerShell frontend now
  interprets a script through its own bounded abstract variable state Σ
  instead of lowering raw parse-tree text, mirroring the bash frontend at the
  frontend's own layer (`front/ps/state.go`, `front/ps/wordeval.go`, and a
  structured-control-flow `front/ps/parse.go`). Fabricated literal targets are
  gone — `$dir/file.txt` no longer lands as a confidently-`Certain` concrete
  path: an effect target is the evaluated value when the word is known and ⊤
  otherwise, a URL with a literal host prefix keeps a host-scoped egress
  instead of widening to ⊤, and a word's provenance (including `secret`)
  flows onto the egress effect so exfiltration pairs on real per-command
  dataflow rather than a program-level co-occurrence heuristic. Unset reads
  degrade to ⊤ (never the empty string), `if`/`foreach`/`for`/`while`/`do`/
  `try` fork and join Σ per branch, session-state cmdlets (`Set-Location`,
  `Set-Variable`, `Clear-Variable`, …) update Σ, `@{…}` splat literals expand
  to their parameter bindings, and lowering is bounded by a deterministic step
  counter that unwinds to ⊤. See
  [ADR-0014](specs/decisions/0014-ps-abstract-state.md).

## [v0.2.1] - 2026-09-20

### Changed

- **Report-contract tag bumped to `flowsh/v2`** across the docs, specs and ADR
  pointers. A new CI guard asserts that the frozen tag spelled in the live docs
  matches `analysis.ToolVersion`, so a future bump cannot silently drift; the
  ADRs keep their historical `flowsh/v1` spellings with a pointer to the live
  contract.
- The canonical staging fold is now order-aware, and the canonical form is
  emitted only when the report actually has effects. Live egress and
  bottom-targeted effects are kept verbatim, and `commandCalls` are
  de-duplicated so a loop body contributes a single entry.

### Fixed

- Hardened the host-shaped grammar feeding the egress gate: reject non-network
  URL schemes (`file:`, `data:`, `mailto:`), Windows drive paths and VCS-like
  dotted local names; accept UNC/SMB authorities, the trailing-dot absolute
  name, scp paths over IPv6 hosts and the clients' own protocol-prefixed address
  spellings; bound ports to 1–65535.
- A confined numeric-class operand that feeds a `NetEgress` destination now
  degrades to unresolved egress instead of contributing a directory literal, and
  `systemctl -H/--host` is tiered as a destination dialect.
- Fixed numeric-class confinement so an expansion that can splice a fresh,
  possibly absolute, path component (an alternate/replacement, a zero-length
  slice, an out-of-range index or a backslash-escaped `..`) degrades to ⊤ rather
  than claiming a directory.
- On the PowerShell path, fall back to the command's intrinsic `ProcSpawn` when
  the egress gate drops its only effect, and keep a sub-expression destination
  as unresolved egress.

## [v0.2.0] - 2026-09-19

### Added

- **Host-shaped egress grammar (Track A — evidence validity).** `NetEgress`
  targets must pass a URL/IPv4/IPv6/scp-style `HostShaped` grammar before
  binding, so git subcommands, commit SHAs, pathspecs and awk regexes no longer
  fabricate network effects, and secret-tainting can no longer pair with a
  phantom egress (C5 consistency).
- **Canonical effect form and an additive per-command `CommandCall` view
  (Track D — determinism).** A canonical effect set folds staging-file
  lifecycles onto the final target, giving downstream consumers a stable,
  retry-recognizing signature.

### Changed

- Hardened argument-scope binding and bash expansion resolution; extended the
  benign corpus.
- Fixed a stale description in the README.

## [v0.1.0] - 2026-09-16

### Added

- Initial implementation (`feat(init): initial implementation`): the
  frontend-agnostic effect-analysis engine (`engine/`), the bash/POSIX and
  PowerShell frontends (`front/`), the embedded YAML knowledge base
  (`kb/data/*.yaml`), command resolution and flag/operand binding (`bind/`), the
  composition facade (`internal/analysis/`) and the `flowsh` CLI (`cmd/flowsh/`).
- The conformance corpus under `testdata/corpus/` (GuardFall, destructive, benign
  and PowerShell cases) with a no-silent-miss regression gate.
- A tag-triggered release pipeline (`.github/workflows/release.yml` and
  `.goreleaser.yaml`): it validates the `vX.Y.Z` tag shape, re-runs `go vet` and
  the test gates on the tagged commit, cross-compiles linux/amd64, linux/arm64,
  darwin/arm64 and windows/amd64 with GoReleaser, emits a SHA-256
  `checksums.txt` and publishes a GitHub Release, followed by an SLSA
  build-provenance attestation verifiable with `gh attestation verify`. The
  build is reproducible (no injected date or commit hash, `mod_timestamp` pinned
  to the commit time) and stamps the tag into the binary through the additive
  `main.buildVersion`, so `flowsh --version` reports the release without
  affecting the frozen report-contract versions.

### Changed

- Hardened the knowledge-base loader to tolerate CRLF/CR input and pinned
  repository line endings with a `.gitattributes` (`* text=auto eol=lf`).
- Enforced lint and dead-code gates (pinned `.golangci.yml`, a deadcode gate and
  documentation hygiene) and dropped the unreachable exported symbols they flag;
  the whole-program binder walkers and the corpus harness moved into test-only
  files and the new `internal/corpus` package, and the CLI's terminal output is
  routed through a single `fprint`/`fprintln` helper.
- Refined prose and punctuation across the contributor guide, README and user
  documentation.
- Refreshed the README effect-report examples and CLI usage: documented the
  `--file` flag in the synopsis and options table and updated the annotated
  examples (the `root` provenance line, the expanded score dimensions, the
  `resolution`/`destructive` lines and proven `exfil:` pairs; `why`,
  `resolution` and `destructive` fields in the JSON sample; the `rm -rf $HOME`
  score corrected to `Critical`).

### Fixed

- Closed the silent-miss soundness gaps found in code review across the binder,
  both frontends, the engine and the knowledge base. The dominant class violated
  the no-silent-miss invariant: a command whose invocation matched no
  effect-contributing parameter produced neither an effect nor ⊤, so the report
  failed open to a benign result (bare `reboot`, `kill -9 -1`, `xargs rm`,
  builtin `eval`).
  - **Binder.** Matches a leading positional operand by value before falling
    back to index order, emits an intrinsic `ProcSpawn` for a resolved command
    that matched nothing, lowers `kind:self` parameters unconditionally, keeps a
    declared numeric flag as a flag rather than an operand, and derives the
    conservative flag from a ⊤ effect.
  - **bash frontend.** Confines control-flow signals to subshells, background
    jobs and speculative branches; inverts `!`; resets the status per statement;
    runs substitutions inside arithmetic/conditional/`let` and C-style `for`;
    executes array-element and subscript substitutions; unwraps `builtin`; treats
    `>&word` as a file redirect; and matches `case` patterns with a
    bash-compatible glob matcher.
  - **PowerShell frontend.** Resolves aliases in source order and
    case-insensitively, shadows a cmdlet by a declared alias or function,
    degrades comma lists and `switch` to ⊤, and models no-space redirections,
    data-file parameters and remote-execution cmdlets.
  - **Engine.** Made the effect key injective, kept `Normalize`'s why-traces in
    step with the merged effects, and recognized private-key paths and Windows
    volume roots.
  - **Knowledge base.** Added an intrinsic `self` effect for the power-control
    commands, the long spellings and siblings of the destructive flags, and
    rejected the contradictory `option`+`valueFrom:args` combination.
- Made the PowerShell per-parse wall-clock budget advisory under the race
  detector (build-tagged constants disable the deadline check under `-race`
  while termination stays guaranteed by the parser's deterministic limits;
  ADR-0012).
- Widened the CI load-latency budget to 50 ms after measuring the hermetic,
  in-memory knowledge-base load on shared runners, superseding ADR-0004's 5 ms
  threshold while leaving the embed-and-version decision intact (ADR-0011).
- Skipped the sub-tick parse-budget assertions on hosts whose monotonic clock is
  too coarse to observe the deadline, and widened the repeated-statement source
  so the timeout-to-⊤ path stays covered everywhere (ADR-0013).

[v0.7.0]: https://github.com/v0lka/flowsh/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/v0lka/flowsh/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/v0lka/flowsh/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/v0lka/flowsh/compare/v0.3.2...v0.4.0
[v0.3.2]: https://github.com/v0lka/flowsh/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/v0lka/flowsh/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/v0lka/flowsh/compare/v0.2.1...v0.3.0
[v0.2.1]: https://github.com/v0lka/flowsh/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/v0lka/flowsh/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/v0lka/flowsh/releases/tag/v0.1.0
