# Changelog

All notable changes to `flowsh` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

These entries track the **module release tags** (`vX.Y.Z`). They are independent of
the two *frozen* wire-contract tags that the analyser emits — `effect-ir/v1`
(the effect-IR payload) and `flowsh/v2` (the CLI report envelope). A change to a
frozen contract is called out in the entry that makes it; the contract tags move
only on a breaking shape change, not on every module release.

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

[v0.2.1]: https://github.com/v0lka/flowsh/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/v0lka/flowsh/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/v0lka/flowsh/releases/tag/v0.1.0
