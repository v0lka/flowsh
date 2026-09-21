# Changelog

All notable changes to `flowsh` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

These entries track the **module release tags** (`vX.Y.Z`). They are independent of
the two *frozen* wire-contract tags that the analyser emits — `effect-ir/v2`
(the effect-IR payload) and `flowsh/v3` (the CLI report envelope). A change to a
frozen contract is called out in the entry that makes it; the contract tags move
only on a breaking shape change, not on every module release.

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

  `kb/data/destructive.yaml` gains eleven class-C entries for the new commands
  whose subcommand discards installed or downloaded content, mirroring the
  existing `gem`/`cargo`/`snap`/`flatpak` removal precedent (`conda`/`mamba`
  `remove` and `clean`, `pdm remove`, `pipenv uninstall` and `clean`,
  `pipx uninstall`, `coursier uninstall`, `rustup uninstall`, `lerna clean`).
  The common-binary inventory gate (`kb/coverage_test.go`) grows by the 114 names
  (with a representative family probe per ecosystem), the conformance corpus
  gains eighteen benign cases (three per ecosystem) pinning that the new surface
  stays non-⊤, and the latency baseline follows the enlarged corpus.
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
  cannot see), a dynamic operand, a runner that names no operand, and
  `-c`/`--call` (an arbitrary shell string) all stay ⊤. The conditional
  registry fetch is deliberately not modelled, matching the `npm run`/`exec`
  and `bun` entries. `NormalizeBinaryName` moves to `bind` as the single
  runner/path vocabulary shared with the canonical form (comparable form
  unchanged: the audited 963134/963140 retry pair keeps one canonical key).
  The coverage gate grows the runner/path family probes.

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

[v0.3.2]: https://github.com/v0lka/flowsh/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/v0lka/flowsh/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/v0lka/flowsh/compare/v0.2.1...v0.3.0
[v0.2.1]: https://github.com/v0lka/flowsh/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/v0lka/flowsh/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/v0lka/flowsh/releases/tag/v0.1.0
