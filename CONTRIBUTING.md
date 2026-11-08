# Contributing to flowsh

Thanks for your interest in `flowsh`. This document describes the
architecture, the build/test workflow, and the conventions a change must follow.
For user-facing usage, see [`README.md`](README.md).

Before making any change, read [`SECURITY.md`](SECURITY.md): it contains the
threat model, trust boundaries, secure-coding guidelines, and hard constraints
(including agentic controls). A contribution that violates those rules will be
rejected. For deep structural changes, also read the relevant document in
[`specs/`](specs/), starting at [`specs/INDEX.md`](specs/INDEX.md).

## Repository layout

| Path | Layer | Responsibility |
| ---- | ----- | -------------- |
| `engine/` | Core | The frozen, frontend-agnostic core: effect IR, value lattices, `Report` format, scoring, taint/exfil, why-traces. Standard library only. Golden fixtures in `engine/testdata/`. |
| `kb/` | Knowledge base | The embedded YAML command/parameter→effect dataset and the destructive-flags table (the 25 documents under `kb/data/*.yaml`, loaded by `kb/loader.go`); the JS namespace lives in `kb/js.go` and `kb/js_decode.go`. |
| `front/bash/` | Frontend | Parse POSIX/bash source and abstractly execute it; emit the effects the shell contributes and delegate ordinary commands through a resolver seam. Golden fixtures in `front/bash/testdata/`. |
| `front/ps/` | Frontend | Parse PowerShell (tree-sitter) and lower it into the effect IR using its own alias/cmdlet tables. |
| `front/js/` | Frontend | Bounded JavaScript values/control flow and builtin identities; reviewed filesystem calls delegate through an injected resolver, and unsupported execution degrades to top. |
| `bind/` | Binding | Resolve an invoked name and bind flags/operands against the knowledge base, producing `[]engine.Effect`. |
| `internal/analysis/` | Composition | The single facade wiring frontends + binder + core into a deterministic `Report`. |
| `internal/corpus/` | Tests | The test-only regression-corpus harness: the on-disk document format, its loader, and the group selectors used by the conformance tests and the benchmark harness. Deliberately not re-exported by `api/`. |
| `api/` | Public API | The embedding surface: a thin type-alias/forwarding re-export of `internal/analysis` (`api/api.go`), so an external Go module can embed the analyser without importing anything under `internal/`. Holds no behaviour of its own. |
| `policy/` | Public policy | Turn an `api.Report` into an `Allow`/`Review`/`Deny` decision under caller-owned, trusted Go configuration (`policy/policy.go`). Reads the report; it never changes or executes the analysis. |
| `cmd/flowsh/` | CLI | Arg parsing, input reading, and printing the text/JSON report. Reaches the facade through `api/`. |
| `testdata/corpus/` | Tests | The conformance corpus (GuardFall / destructive / benign / resolution / PowerShell / JavaScript filesystem / external labelled sample), plus a `README.md` recording its provenance. |
| `specs/` | Docs | The full system specification: `architecture/`, `contracts/`, `decisions/` and `domains/`. |
| `docs/` | Docs | User- and integrator-facing prose (`README.md`, `cli.md`, `embedding.md`, `report-json.md`, `kb-howto.md`) and `docs/development/roadmap.md`. |

## Architecture

### Layers and dependency direction

Each layer is a Go package (or package tree) with an exclusive responsibility.
Imports point strictly downward, with no cycles and no upward edges:

```
cmd/flowsh
      │
      ▼
     api
      │
      ▼
internal/analysis
   │        │        │
   ▼        ▼        ▼
front/bash  bind   front/ps
      │       │  │       │
      │       ▼  │       │
      │      kb  │       │
      ▼          ▼       ▼
        engine
```

`policy` is the second public consumer: it sits beside `cmd/flowsh`, imports
`api` (for `Report`) and `engine` (for the lattice types its rules match on),
and no package imports it — configuration can therefore never reach parsing,
effects or scoring. The JavaScript sibling adds
`internal/analysis -> front/js -> engine`, and `bind` additionally imports
`front/js` so that `bind.BindJS` can consume the frontend's typed call values
against the separate JS YAML namespace; `internal/analysis/javascript.go`
injects that binder as the JS resolver.

`cmd/flowsh` reaches the facade *only* through `api/` — it does not import
`internal/analysis` directly — and additionally imports `engine` for the frozen
IR types it prints.

Module-internal imports per layer (production code; the deliberate external
test-package exceptions are listed in
[`specs/architecture/layers.md`](specs/architecture/layers.md)):

| Layer | Path | Imports (this module) |
| ----- | ---- | --------------------- |
| Core | `engine/` | *(none)* |
| Knowledge base | `kb/` | `engine` |
| Shell frontend | `front/bash/` | `engine` |
| PowerShell frontend | `front/ps/` | `engine` |
| JavaScript frontend | `front/js/` | `engine` |
| Binding | `bind/` | `engine`, `kb`, `front/bash`, `front/js` |
| Composition | `internal/analysis/` | `engine`, `kb`, `bind`, `front/bash`, `front/ps`, `front/js` |
| Corpus harness | `internal/corpus/` | *(none)* |
| Public API | `api/` | `internal/analysis` |
| Policy | `policy/` | `api`, `engine` |
| CLI | `cmd/flowsh/` | `api`, `engine` |

### The two invariants

Most changes must respect both, and tests enforce them:

1. **One-way dependency.** The core (`engine`) never imports a frontend or the
   knowledge base. `TestCoreDoesNotImportFrontends` (`engine/report_test.go`)
   fails if `engine` gains any import beyond the standard library and the
   module's own core packages. This is what lets a new frontend be added without
   touching the core. The one deliberate exception is the *external* test package
   (`package engine_test`, in `engine/bench_test.go`), which imports
   `internal/analysis` and the test-only `internal/corpus` to benchmark the whole
   pipeline end to end; it adds no edge to the core package itself and introduces
   no cycle.
2. **Degrade to ⊤.** Every layer degrades to the top element (⊤) rather than
   guessing or crashing. Analysis is total and deterministic: the frontends
   never fail on hard input, so `(*Analyzer).AnalyzeWith` always returns a
   non-nil report. The package-level `Analyze`/`AnalyzeWith` (and their `api`
   forwarders) return an error only when the embedded knowledge base itself
   fails to load.

The composition of frontends, binder and core can therefore live only *above*
them, which is why the facade is in `internal/`; `api/` is the thin public
re-export the CLI and every embedder go through.

### The analysis pipeline

```
source text
   │  front/bash.Parse + abstract exec   (bash, posix)
   │  front/ps.Parse + Lower             (posh — its own tables, no binder)
   │  front/js parse + bounded evaluate  (js)
   ▼
normalized command ── bind (kb + engine) ──▶ []engine.Effect
   ▼
engine.Report ──Normalize──▶ merge by (Kind,Mode,NetFlow), ComputeDestructiveness, Sort
              ──Encode────▶ canonical indented JSON (Validate first)
   ▼
internal/analysis.Report  (engine report + CLI metadata + Score)
   ▼
api.Report  (a type alias: the same value the CLI and every embedder see)
   ▼
cmd/flowsh: text summary or JSON        policy: Allow / Review / Deny
```

## Build and test

```sh
go build ./...         # build everything
go test ./...          # corpus gate (no-silent-miss) + latency + recall gates
go vet ./...           # static checks
gofmt -l .             # formatting check (must print nothing)
golangci-lint run      # lint with the pinned .golangci.yml (CI runs v2.14.0)
go mod verify          # the module graph matches go.sum

# Dead code: every symbol must be reachable from a command path or a test.
# Pinned to the version CI runs; it must print nothing.
go run golang.org/x/tools/cmd/deadcode@v0.50.0 -test ./...

# Smoke-run the benchmarks, so one that no longer compiles (or panics) fails
# here too.
go test ./engine/ -run '^$' -bench . -benchtime=50x

# Supply-chain scan: no vulnerability reachable from this module. Pinned to the
# version CI runs; it downloads the vulnerability database, so it needs network
# access.
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

The latency and recall gates live in `engine/bench_test.go`
(`TestPerCommandLatencyBudget`, `TestRecallNoRegression`) and compare against
the committed per-host reference `engine/testdata/latency_baseline.json`, which
also pins the corpus size; the knowledge-base load budget lives in
`kb/loader_test.go` (`TestLoadUnderBudget`). The two *timing* gates skip under
`-race`, where wall-clock budgets are not meaningful; the recall gate does not.
All of them still run in the ordinary `go test ./...`.

Run the CLI from source:

```sh
go run ./cmd/flowsh --lang bash --json 'rm -rf $HOME'
```

### CI gates

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push to
`main`/`master` and on every pull request. It is a single job (`gate`, displayed
as "build, corpus gate, bench gate (<os>)", `fail-fast: false`, 20-minute
timeout) across a three-OS matrix (`ubuntu-latest`, `windows-latest`, and
`macos-15`). macOS is pinned to the `macos-15` image rather than the floating
`macos-latest` label, which drifts and would silently re-time the latency gates
(see `specs/decisions/0019`). The Go toolchain comes from `go-version-file:
go.mod` (`go 1.27`) with `check-latest: true`, and every step runs under an
explicitly selected POSIX `bash`, so the same steps run verbatim on all three
runners — the `-race` step excepted, which runs on Linux only for the reason
given in step 11:

1. **gofmt** — the tree must be `gofmt`-clean.
2. **build** — `go build ./...`.
3. **vet** — `go vet ./...`.
4. **module integrity** — `go mod verify`: the checked-out module graph must
   match `go.sum`.
5. **govulncheck** — `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`
   must report no vulnerability reachable from this module; a reachable finding
   exits non-zero and blocks the merge. Unlike the `-race` step it runs on every
   runner, because the scanner resolves the call graph for the host
   `GOOS`/`GOARCH` and the release matrix ships more than one platform. The pin
   is shared with `.github/workflows/release.yml`, so both paths judge the module
   with the same scanner version.
6. **lint** — `golangci/golangci-lint-action@v9` at `version: v2.14.0`, using the
   repository's pinned [`.golangci.yml`](.golangci.yml) (errcheck, govet,
   ineffassign, staticcheck, unused, misspell; gofmt/goimports as formatters).
7. **deadcode** — `go run golang.org/x/tools/cmd/deadcode@v0.50.0 -test ./...`
   must print nothing: every symbol is reachable from a command path or a test.
8. **docs hygiene** — [SECURITY.md](SECURITY.md) carries no `TODO` placeholder,
   every relative Markdown link in **every tracked `*.md` file** resolves (fenced
   code blocks and inline code are stripped first, so illustrative format
   examples are not mistaken for links), and the frozen report-contract tag is
   consistent: the step reads `ToolVersion` out of `internal/analysis/analyze.go`
   and fails if `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/*.md` or
   `specs/architecture/data-flow.md` mentions a `flowsh/vN` tag other than that
   one. (The ADRs are historical records and are deliberately exempt.) A
   `ToolVersion` bump must therefore update this file too.
9. **corpus + latency/recall gates** — `go test ./... -count=1` (a latency or
   recall regression fails this step). This step also runs the **CLI smoke**
   test [`cmd/flowsh/smoke_test.go`](cmd/flowsh/smoke_test.go): it builds the
   binary and checks that it emits a valid JSON report for the registered dialects, from
   an argument and from stdin, plus `--version`, `--batch` (NDJSON),
   `--lang auto`, and the exit-code contract, across the process boundary.
10. **bench smoke** — `go test ./engine/ -run '^$' -bench . -benchtime=50x`.
11. **race** — `go test -race ./... -count=1`, run once on `ubuntu-latest` only
    (the race detector instruments every memory access, so wall-clock latency
    budgets are not meaningful under it; those timing tests skip under `-race`
    and still run in step 9).

[`.gitattributes`](.gitattributes) pins `* text=auto eol=lf`, so all three
runners check the tree out with LF line endings. Keep that file: Git for Windows
defaults to `core.autocrlf=true`, and without it `windows-latest` would rewrite
every `.go` file to CRLF (breaking the `gofmt` gate) and hand the knowledge
base's strict YAML reader CRLF documents (breaking the `kb` load).

Run all of these locally before opening a pull request.

## Releasing

Module releases follow Semantic Versioning and are tagged `vX.Y.Z`
(`v0.1.0` … `v0.8.0` so far). These are *release* tags and are independent of
the two frozen wire-contract tags the analyser emits (`effect-ir/v2`,
`flowsh/v3`), which move only on a breaking shape change.

Before tagging, add the release's section to [`CHANGELOG.md`](CHANGELOG.md). It
is maintained by hand in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
form — one `## [vX.Y.Z] - YYYY-MM-DD` section per module release tag, grouped
under the standard `### Added` / `### Changed` / `### Fixed` headings — and a
change to a frozen contract is called out in the entry that makes it. Nothing
regenerates it.

Then cut the release by pushing the tag:

```sh
git tag -a v0.8.0 -m "v0.8.0"
git push origin v0.8.0
```

The push triggers [`.github/workflows/release.yml`](.github/workflows/release.yml)
(the workflow starts with `permissions: contents: read` and each job widens only
what it needs), which:

1. validates the tag matches `^v[0-9]+\.[0-9]+\.[0-9]+$` (the `on: push: tags`
   filter is the broader glob `v*.*.*`, so this step is what makes a tag such as
   `v1.2`, `v1.2.3-rc1` or `vNext` fail fast instead of publishing a broken
   release);
2. re-runs the security-relevant gates on the tagged commit — `go mod download`
   and `go mod verify`, `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`
   (the same pin as CI, and run *before* publishing: a scan afterwards is a
   report, not a gate), then `go vet ./...` and `go test ./... -count=1` — a tag
   can point at a commit that never went through pull-request CI;
3. runs [GoReleaser](https://goreleaser.com) (`goreleaser/goreleaser-action@v7`,
   `version: "~> v2"`, `args: release --clean`; config
   [`.goreleaser.yaml`](.goreleaser.yaml)) to cross-compile the supported matrix
   — `linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64` (the
   `darwin/amd64` and `windows/arm64` cells of the `goos × goarch` product are
   excluded) — package each binary into `flowsh_<version>_<os>_<arch>.tar.gz`
   (`.zip` on Windows) together with `LICENSE` and `README.md`, write
   `checksums.txt` (SHA-256), and publish a non-draft GitHub Release named after
   the tag; and
4. in a separate `provenance` job (`actions/attest-build-provenance@v4`,
   `subject-path: dist/*`), downloads the published assets and attests SLSA build
   provenance over the exact released bytes, storing it in the repository's
   attestation store.

The build is deliberately reproducible: `CGO_ENABLED=0`, `-trimpath`, a pinned
`mod_timestamp` (the commit time), and no build date or commit hash injected, so
the same tag produces byte-identical binaries and therefore stable checksums.

The tag *is* stamped into the binary (`main.buildVersion`, injected with
`-ldflags "-s -w -X main.buildVersion={{ .Version }}"`), so a release binary's
`flowsh --version` prints it below the frozen contract tags:

```sh
$ flowsh --version
flowsh/v3
effect-ir/v2
flowsh 0.8.0
```

A build from source carries no stamp and prints only the two contract lines.
The stamp is additive build metadata and never affects the frozen report
contract.

Verify a downloaded release:

```sh
shasum -a 256 -c checksums.txt   # sha256sum -c on Linux
gh attestation verify flowsh_0.8.0_linux_amd64.tar.gz --repo v0lka/flowsh
```

To build the release artifacts locally without publishing anything (this needs
the GoReleaser CLI installed; CI provides it through the action):

```sh
goreleaser release --snapshot --clean
```

Note that GoReleaser also writes the GitHub Release *notes* from the commit log
(`changelog: sort: asc`, excluding `^docs:`, `^test:`, `^chore:`, `^ci:`,
`^style:` and merge commits). Those generated notes are not `CHANGELOG.md` and
do not replace it.

## The knowledge base

`kb/` holds the embedded, hand-verified dataset of command and parameter effects.
It is stored as YAML documents under `kb/data/` — one document per command
tradition, discovered automatically by the loader, so the set grows by adding
files. There are currently 25:

| File | Covers |
| ---- | ------ |
| `archive.yaml` | Archivers and compressors (`gzip`, `bzip2`, `xz`, `zstd`, `zip`, `7z`, `cpio`, `pax`, `ar`, `isoinfo`, …) |
| `bsd.yaml` | BSD-flavoured utilities (`chflags`, `sysctl -w`, `launchctl`, `defaults`, `open`, `pbcopy`, …) |
| `build.yaml` | Build drivers, compilers/linkers, binary inspectors and debuggers (`make`, `cmake`, `gcc`, `ld`, `nm`, `objdump`, `readelf`, `strip`, `gdb`, `strace`, `patch`, `diff`, …) |
| `builtins.yaml` | Shell builtins (POSIX `sh` plus common bash extensions) |
| `cloud.yaml` | Cloud provider clients (`aws`, `gcloud`, `az`) |
| `codehost.yaml` | Code-host and modern version-control clients (`gh`, `glab`, `jj`) |
| `containers.yaml` | Container and infrastructure tooling (`docker`, `docker-compose`, `kubectl`, `helm`, `terraform`, `ansible`) |
| `coreutils.yaml` | Coreutils commands (POSIX utilities and GNU extensions) |
| `datatools.yaml` | Data and query tools (`jq`, `yq`, `sqlite3`, `psql`, `redis-cli`, `rg`, `fd`, `ag`) |
| `destructive.yaml` | The destructive-flags table |
| `findutils.yaml` | `find` and friends (`find`, `xargs`) plus `tar` |
| `gnu.yaml` | The extended GNU coreutils set (informational, checksum/encoding, text filters, filesystem utilities) |
| `js-filesystem.yaml` | The JavaScript filesystem API shapes (`jsModules`/`jsCalls`) |
| `js-path.yaml` | The JavaScript offline path/home operations |
| `linting.yaml` | Build/test/lint drivers across the JS/TS, Go, Python, Rust and shell toolchains |
| `net.yaml` | Network clients: network, remote-access and security tooling (net-tools, `curl`, `wget`, `nc`, openssh, `rsync`) |
| `pkgmgr.yaml` | Package managers (`apt`, `dpkg`, `rpm`, `pacman`, `pip`, `npm`, `cargo`, `go`, …) |
| `plumbing.yaml` | Command discovery and file inspection (`which`, `file`) and the `markitdown` converter |
| `procps.yaml` | procps-ng process and system inspection (`ps`, `top`, `free`, `vmstat`, `pgrep`, `pkill`, `lsof`, `watch`, …) |
| `remote.yaml` | Remote fetch/exec patterns (`rsync`, `git`) |
| `security.yaml` | Users, permissions, security policy and auditing (`passwd`, `useradd`, `setfacl`, `chcon`, `auditctl`, `sudo`, `gpg`, …) |
| `systemd.yaml` | Processes, services and system control (`systemctl`, `journalctl`, `service`, `crontab`, `at`, `screen`, `tmux`, …) |
| `toolchain.yaml` | Language runtimes and ecosystem tooling (`node`, `bun`, `python`, `uv`, `ruby`, `java`, `mvn`, `gradle`, `dotnet`, `gopls`, `dlv`, `goreleaser`, bundlers, test runners, …) |
| `util-linux.yaml` | util-linux utilities (`mount`, `umount`, `wipefs`, `fdisk`, `losetup`, `chroot`, `su`, `mkfs`, …) |
| `vcs.yaml` | Version-control clients other than git (`svn`, `hg`, `bzr`, `fossil`, `darcs`) |

The whole directory is embedded with `go:embed data` and parsed at start-up
without touching the filesystem. The loader lives in `kb/loader.go`; the frozen,
versioned document schema (`SchemaVersion = "effect-kb/v4"`, with
`effect-kb/v2` and `effect-kb/v3` still accepted) lives in `kb/schema.go`; the
JavaScript namespace is decoded and indexed in `kb/js.go` and `kb/js_decode.go`.
[`specs/domains/knowledge-base.md`](specs/domains/knowledge-base.md) carries the
complete command → dialect inventory.

**To add or change a command/parameter → effect mapping:** edit the relevant
`kb/data/*.yaml` document (or add a new one) following the existing schema, and
add a corpus case that exercises it (below). To add or change a destructive
flag/class, edit `destructive.yaml`. Read
[`specs/domains/knowledge-base.md`](specs/domains/knowledge-base.md) and the
[`bind ↔ kb` contract](specs/contracts/bind-kb.md) first.

## The conformance corpus

`testdata/corpus/*.json` is the regression corpus, loaded by
`internal/corpus/corpus.go` and exercised by
`internal/analysis/corpus_test.go`. It currently holds 460 cases across twelve
documents:

| File | Group(s) | Role |
| ---- | -------- | ---- |
| `guardfall_bash.json` | `guardfall` | Adversarial bash inputs that evade a surface-level scanner (classes A–E). |
| `guardfall_posh.json` | `guardfall` | The same, for PowerShell. |
| `guardfall_js.json` | `guardfall`, `benign` | JavaScript A–E examples and semantic regressions asserting conservative coverage and bounded evaluation. |
| `guardfall_posix.json` | `guardfall` | The same, for the POSIX shell dialect (`lang: posix`). |
| `filesystem_js.json` | `benign`, `destructive`, `guardfall`, `resolution` | JavaScript filesystem API shapes, path/home helpers, named imports, hidden callback effects and read-failure witnesses. |
| `destructive_bash.json` | `destructive` | Canonical destructive commands (recall; must reach at least the Medium grade). |
| `sudo_bash.json` | `destructive`, `benign` | The `sudo` wrapper-elevation doctrine (the refined `-u`), including the unpeeled path-qualified wrapper and the accepted ⊤ false positives. |
| `ps_cases.json` | `ps` | PowerShell-specific recall cases. |
| `resolution_bash.json` | `resolution` | Name-resolution recall: each case exercises one link of the chain (alias → function → builtin → external command → path basename / package-runner operand → unknown). |
| `benign_bash.json` | `benign` | Ordinary commands (precision control). |
| `external_bash.json` | `external_malicious`, `external_benign` | A balanced bash sample drawn from public labelled datasets (attribution and licensing are recorded per case in `note`). |
| `external_posh.json` | `external_malicious`, `external_benign` | The same, for PowerShell. |

The group selectors are the `Group*` constants in `internal/corpus/corpus.go`:
`guardfall`, `destructive`, `benign`, `ps`, `resolution`, `external_malicious`
and `external_benign`.

Every non-benign case must be classified as **effect present or ⊤** (the
"no silent miss" invariant, `Case.RequiresCoverage`). Benign cases may
legitimately yield no effect, so they are excluded from that invariant; they are
instead the precision control, and must never raise ⊤/conservative. The
`external_benign` cases carry both obligations: they must be covered *and* must
not raise ⊤.

The GuardFall class letters are: `A` quoting/escaping fragments, `B` separator
injection (`$IFS`, …), `C` indirection (command substitution, dynamic names),
`D` encoded payloads fed to an interpreter (`base64 | sh`, `eval`, `sh -c`),
`E` unbounded/opaque work that must degrade to ⊤.

**To add a corpus case:** drop a new `{"name", "description", "cases":[…]}` JSON
document into `testdata/corpus/` (or extend an existing one); `LoadCorpus` picks
it up automatically. Each case carries `id` (unique across the whole corpus —
duplicate IDs are rejected), `group`, `lang` (`bash`, `posix`, `posh` or `js`),
`input`, and optionally `note` and `windows`. GuardFall cases must carry a valid
`category` (`A`–`E`); non-GuardFall cases must not. `windows: true` forces the
Windows-native provider profile (the PowerShell Registry) and is only permitted
on a `posh` case — provider effects are host-gated by design, so a
registry-writing script is otherwise skipped with a note on a non-Windows host.

Adding or removing cases changes the corpus size, which
`engine/testdata/latency_baseline.json` pins in its `cases` field:
`TestRecallNoRegression` fails until that field is re-pinned (and the worst
per-command p95 re-checked against the larger set). The same file carries the
per-host latency reference and its `hostOverrides`; see
[`specs/decisions/0015-per-host-latency-reference.md`](specs/decisions/0015-per-host-latency-reference.md).

Read [`specs/domains/analysis-report.md`](specs/domains/analysis-report.md), and
[`testdata/corpus/README.md`](testdata/corpus/README.md) for the provenance and
licensing of the `external_*` sample.

## Common extension recipes

- **Add a CLI flag or output format** — add a `case` in `parseArgs` (and a field
  on `options`) in `cmd/flowsh/main.go`, a branch in `run`, and document it in
  the `usage` constant. Update `cmd/flowsh/main_test.go`; if the flag changes the
  stdout framing or the exit-code contract, also update the process-boundary
  smoke test `cmd/flowsh/smoke_test.go`. See
  [`specs/domains/cli.md`](specs/domains/cli.md).
- **Add an effect kind or mode** — extend the `const` block and `EffectKinds` /
  `EffectModes` in `engine/effect.go`, and add a case to `KindDestructiveness` in
  `engine/report.go`. Changing the *shape* of an emitted field is a breaking
  change (below): bump `engine.SchemaVersion` and regenerate the golden fixtures
  with `go test ./engine -run <TestName> -update` (they live in
  `engine/testdata/effect.golden.json` and `engine/testdata/report.golden.json`;
  the bash frontend's own fixtures are in `front/bash/testdata/` and regenerate
  with `go test ./front/bash -run <TestName> -update`). See
  [`specs/domains/engine/effect-ir.md`](specs/domains/engine/effect-ir.md).
- **Add a value lattice / source class / taint label** — follow
  `engine/lattice.go` and `engine/taint.go`. See
  [`specs/domains/engine/lattices.md`](specs/domains/engine/lattices.md).
- **Tune scoring / destructiveness / exfil** — adjust the policy tables
  (`KindDestructiveness` in `engine/report.go`, `secretPathMarkers` in
  `engine/taint.go`, `irreversibleTokens` and the weightings in `ScoreEffects` in
  `engine/score.go`). See
  [`specs/domains/engine/scoring.md`](specs/domains/engine/scoring.md).
- **Add a knowledge-base command or parameter** — edit the matching
  `kb/data/*.yaml` document and add a corpus case (above); the binder needs no
  change unless the parameter introduces a new effect shape. See
  [`specs/domains/knowledge-base.md`](specs/domains/knowledge-base.md) and the
  [`bind ↔ kb` contract](specs/contracts/bind-kb.md).
- **Add a frontend (new language)** — implement a lifter that emits
  `engine.Effect` values and wire it in `internal/analysis`. A new *dialect* also
  has to be registered everywhere the language is switched on: the `Lang`
  constants and `Langs` plus `ParseLang` and the `AnalyzeWith` dispatch in
  `internal/analysis/analyze.go`; the matching `api` re-exports (`api/api.go`);
  the language switch in `(*Policy).Evaluate` (`policy/policy.go`), which denies
  an unrecognised `lang` as `invalid_report`; and the CLI's `usage` text and
  `detectLang`/`analyzeAuto` in `cmd/flowsh/main.go`. See
  [`specs/architecture/layers.md`](specs/architecture/layers.md) and the
  [`frontend ↔ engine` contract](specs/contracts/frontend-engine.md).
- **Embed the analyser, or add a report rule** — an external module imports
  `github.com/v0lka/flowsh/api` (`Analyze`, `AnalyzeWith`, `NewAnalyzer`,
  `ParseLang`, `Bool` and the `Report`/`Options`/`Analyzer` aliases) and never
  anything under `internal/`. Caller-owned allow/review/deny rules belong in a
  `policy.Config` passed to `policy.New`, evaluated with
  `(*Policy).Evaluate(*api.Report)`; `policy` performs no I/O and never changes
  the analysis. See [`specs/domains/policy.md`](specs/domains/policy.md),
  [`docs/embedding.md`](docs/embedding.md) and
  [ADR-0017](specs/decisions/0017-report-policy-package.md).

## Frozen contracts

The JSON report is a frozen wire contract, tagged by three constants declared in
`internal/analysis/analyze.go` and re-exported verbatim by `api`:

| Constant | Value | Tags |
| -------- | ----- | ---- |
| `ToolName` | `"flowsh"` | the `tool` field |
| `SchemaVersion` (`= engine.SchemaVersion`, `engine/report.go`) | `"effect-ir/v2"` | the effect payload and the report's effect schema |
| `ToolVersion` | `"flowsh/v3"` | the CLI report envelope as a whole |

**Changing the shape of an emitted field is a breaking change** and requires
bumping the corresponding version tag, regenerating the golden fixtures
(`engine/testdata/*.golden.json`) and updating every consumer. `Encode`'s
indentation and key ordering are byte-frozen by those fixtures, as is the CLI's
exit-code contract (`0` report produced or `--help`/`--version`, `1` internal
failure, `2` usage error, `3` input error) and its stdout framing (the
human-summary lines, and the one-report-per-line NDJSON form of `--batch`).

A tag bump is not local:

- `policy.Evaluate` denies a report whose `Tool`, `ToolVersion` or
  `SchemaVersion` differs from the `api` constants (`invalid_report`), so an
  embedder's policy stops deciding until it is rebuilt.
- The CI **docs hygiene** gate parses `ToolVersion` out of
  `internal/analysis/analyze.go` and fails if `README.md`, `CONTRIBUTING.md`,
  `SECURITY.md`, `docs/*.md` or `specs/architecture/data-flow.md` mentions any
  other `flowsh/vN` tag. This file is one of the checked documents.

The knowledge-base document schema is frozen and versioned the same way
(`kb.SchemaVersion = "effect-kb/v4"`, with `KnownVersions` listing the revisions
the loader still accepts); an unknown `version` in a `kb/data/*.yaml` document is
rejected at load rather than silently mis-read.

The four boundary contracts and their breaking-change checklists live in
[`specs/contracts/`](specs/contracts/):
[`report-json.md`](specs/contracts/report-json.md) (analyser ↔ CLI/CI),
[`frontend-engine.md`](specs/contracts/frontend-engine.md) (frontends → engine),
[`bind-kb.md`](specs/contracts/bind-kb.md) (bind ↔ kb) and
[`exec-resolver.md`](specs/contracts/exec-resolver.md) (the `front/bash` ↔
caller resolver seam).

## Specification system

`specs/` is the source of truth for system structure and contracts:

- [`specs/INDEX.md`](specs/INDEX.md) — task → spec navigation; start here.
- [`specs/META.md`](specs/META.md) — spec formats and update rules.
- [`specs/WORKFLOW.md`](specs/WORKFLOW.md) — how to use the spec system.
- [`specs/architecture/`](specs/architecture/) — `layers.md` (the layer
  hierarchy and import rules), `data-flow.md` (the end-to-end pipeline) and
  `conservatism.md` (the degrade-to-⊤ semantics).
- [`specs/domains/`](specs/domains/) — one document per conceptual domain:
  `engine/`, `bash-frontend/`, `knowledge-base.md`, `binding.md`,
  `powershell-frontend.md`, `javascript-frontend.md`,
  `javascript-filesystem.md`, `analysis-report.md`, `policy.md` and `cli.md`.
- [`specs/contracts/`](specs/contracts/) — the four cross-boundary contracts.
- [`specs/decisions/`](specs/decisions/) — the ADRs, `0001`–`0020` (frozen IR,
  one-way dependency, conservative ⊤, embedded KB, two frontends, bounded
  execution, lattice model, single module, the rename to `flowsh`, the public
  embedding API, the CI/load/parse/latency budgets, the PS abstract state, the
  report-policy package, the JavaScript semantic kernel and its filesystem
  models) plus `_template.md`. Accepted ADRs are immutable: supersede with a new
  one, or amend a drifted claim with a `> **Historical record.**` note.

Update the relevant spec alongside any structural change, and update
`specs/INDEX.md` whenever a spec file is added or removed.

## Commit and PR expectations

- Keep changes focused; update specs, corpus cases and `CHANGELOG.md` together
  with code.
- Run every gate locally before opening the pull request: `gofmt -l .` empty,
  `go build ./...`, `go vet ./...`, `go mod verify`, `go test ./...`,
  `golangci-lint run`, the pinned `deadcode` scan, the docs-hygiene link check
  and the pinned `govulncheck`.
- Do not weaken an invariant to make a test pass; fix the analysis instead. In
  particular, do not relax the no-silent-miss corpus gate, the benign precision
  control, or a latency/recall budget — re-pin `latency_baseline.json` only with
  a measured justification.
- Never delete [`.gitattributes`](.gitattributes) (see the CI gates above).
  `go build ./cmd/flowsh` writes a `flowsh` binary into the repository root and
  `goreleaser` writes `dist/`; `.gitignore` already excludes both, so leave them
  untracked.
