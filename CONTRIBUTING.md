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
| `engine/` | Core | The frozen, frontend-agnostic core: effect IR, value lattices, `Report` format, scoring, taint/exfil, why-traces. Standard library only. |
| `kb/` | Knowledge base | The embedded YAML command/parameter→effect dataset and the destructive-flags table (`kb/data/*.yaml`, loaded by `kb/loader.go`). |
| `front/bash/` | Frontend | Parse POSIX/bash source and abstractly execute it; emit the effects the shell contributes and delegate ordinary commands through a resolver seam. |
| `front/ps/` | Frontend | Parse PowerShell (tree-sitter) and lower it into the effect IR using its own alias/cmdlet tables. |
| `bind/` | Binding | Resolve an invoked name and bind flags/operands against the knowledge base, producing `[]engine.Effect`. |
| `internal/analysis/` | Composition | The single facade wiring frontends + binder + core into a deterministic `Report`. |
| `internal/corpus/` | Tests | The test-only regression-corpus harness: the on-disk document format, its loader, and the group selectors used by the conformance tests and the benchmark harness. |
| `cmd/flowsh/` | CLI | Arg parsing, input reading, and printing the text/JSON report. |
| `testdata/corpus/` | Tests | The conformance corpus (GuardFall / destructive / benign / PowerShell). |
| `specs/` | Docs | The full system specification. |

## Architecture

### Layers and dependency direction

Each layer is a Go package (or package tree) with an exclusive responsibility.
Imports point strictly downward, with no cycles and no upward edges:

```
cmd/flowsh
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

Module-internal imports per layer:

| Layer | Path | Imports (this module) |
| ----- | ---- | --------------------- |
| Core | `engine/` | *(none)* |
| Knowledge base | `kb/` | `engine` |
| Shell frontend | `front/bash/` | `engine` |
| PowerShell frontend | `front/ps/` | `engine` |
| Binding | `bind/` | `engine`, `kb`, `front/bash` |
| Composition | `internal/analysis/` | `engine`, `bind`, `front/bash`, `front/ps` |
| CLI | `cmd/flowsh/` | `internal/analysis` |

### The two invariants

Most changes must respect both, and tests enforce them:

1. **One-way dependency.** The core (`engine`) never imports a frontend or the
   knowledge base. `TestCoreDoesNotImportFrontends` fails if `engine` gains any
   import beyond the standard library and the module's own core packages. This is
   what lets a new frontend be added without touching the core.
2. **Degrade to ⊤.** Every layer degrades to the top element (⊤) rather than
   guessing or crashing. Analysis is total and deterministic: the frontends
   never fail on hard input, so `Analyze` always returns a non-nil report.

The composition of frontends, binder and core can therefore live only *above*
them, which is why the facade is in `internal/`.

### The analysis pipeline

```
source text
   │  front/bash.Parse + abstract exec        (or)  front/ps.Parse + Lower
   ▼
normalized command ── bind (kb + engine) ──▶ []engine.Effect
   ▼
engine.Report ──Normalize──▶ merge by (Kind,Mode), ComputeDestructiveness, Sort
              ──Encode────▶ canonical indented JSON (Validate first)
   ▼
internal/analysis.Report  (engine report + CLI metadata + Score)
   ▼
cmd/flowsh: text summary or JSON
```

## Build and test

```sh
go build ./...         # build everything
go test ./...          # corpus gate (no-silent-miss) + latency + recall gates
go vet ./...           # static checks
gofmt -l .             # formatting check (must print nothing)
golangci-lint run      # lint with the pinned .golangci.yml (see below)
```

Run the CLI from source:

```sh
go run ./cmd/flowsh --lang bash --json 'rm -rf $HOME'
```

### CI gates

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and PR
across a three-OS matrix (`ubuntu-latest`, `windows-latest`, and `macos-latest`),
so the same steps run on all three runners:

1. **gofmt** — the tree must be `gofmt`-clean.
2. **build** — `go build ./...`.
3. **vet** — `go vet ./...`.
4. **lint** — `golangci-lint run` with the repository's pinned
   [`.golangci.yml`](.golangci.yml) (errcheck, govet, ineffassign, staticcheck,
   unused, misspell; gofmt/goimports as formatters).
5. **deadcode** — `deadcode -test ./...` must print nothing: every symbol is
   reachable from a command path or a test.
6. **docs hygiene** — [SECURITY.md](SECURITY.md) carries no unresolved
   placeholders, and every relative Markdown link in the README, `docs/` and
   `specs/` resolves (fenced code blocks and inline code are skipped).
7. **corpus + latency/recall gates** — `go test ./... -count=1` (a latency or
   recall regression fails this step). This step also runs the **CLI smoke**
   test [`cmd/flowsh/smoke_test.go`](cmd/flowsh/smoke_test.go): it builds the
   binary and checks that it emits a valid JSON report for both dialects, from
   an argument and from stdin, plus `--version`, `--batch` (NDJSON),
   `--lang auto`, and the exit-code contract, across the process boundary.
8. **bench smoke** — `go test ./engine/ -run '^$' -bench . -benchtime=50x`.
9. **race** — `go test -race ./... -count=1`, run once on `ubuntu-latest` only
   (the race detector instruments every memory access, so wall-clock latency
   budgets are not meaningful under it; those timing tests skip under `-race`
   and still run in step 7).

[`.gitattributes`](.gitattributes) pins `* text=auto eol=lf`, so all three
runners check the tree out with LF line endings. Keep that file: Git for Windows
defaults to `core.autocrlf=true`, and without it `windows-latest` would rewrite
every `.go` file to CRLF (breaking the `gofmt` gate) and hand the knowledge
base's strict YAML reader CRLF documents (breaking the `kb` load).

Run all of these locally before opening a pull request.

## The knowledge base

`kb/` holds the embedded, hand-verified dataset of command and parameter effects.
It is stored as YAML documents under `kb/data/`:

| File | Covers |
| ---- | ------ |
| `coreutils.yaml` | Coreutils commands |
| `builtins.yaml` | Shell builtins |
| `bsd.yaml` | BSD-flavoured utilities |
| `util-linux.yaml` | util-linux utilities |
| `findutils.yaml` | `find` and friends |
| `net.yaml` | Network clients |
| `remote.yaml` | Remote fetch/exec patterns |
| `destructive.yaml` | The destructive-flags table |

The loader and schema live in `kb/loader.go` and `kb/schema.go`.

**To add or change a command/parameter → effect mapping:** edit the relevant
`kb/data/*.yaml` document (or add a new one) following the existing schema, and
add a corpus case that exercises it (below). To add or change a destructive
flag/class, edit `destructive.yaml`. Read
[`specs/domains/knowledge-base.md`](specs/domains/knowledge-base.md) and the
[`bind ↔ kb` contract](specs/contracts/bind-kb.md) first.

## The conformance corpus

`testdata/corpus/*.json` is the regression corpus, loaded by
`internal/corpus/corpus.go` and exercised by
`internal/analysis/corpus_test.go`. It currently holds 58 cases across five
documents:

| File | Group | Role |
| ---- | ----- | ---- |
| `guardfall_bash.json` | `guardfall` | Adversarial bash inputs that evade a surface-level scanner (classes A–E). |
| `guardfall_posh.json` | `guardfall` | The same, for PowerShell. |
| `destructive_bash.json` | `destructive` | Canonical destructive commands (recall; must reach at least the Medium grade). |
| `ps_cases.json` | `ps` | PowerShell-specific recall cases. |
| `benign_bash.json` | `benign` | Ordinary commands (precision control). |

Every non-benign case must be classified as **effect present or ⊤** (the
"no silent miss" invariant). Benign cases may legitimately yield no effect, so
they are excluded from that invariant.

The GuardFall class letters are: `A` quoting/escaping fragments, `B` separator
injection (`$IFS`, …), `C` indirection (command substitution, dynamic names),
`D` encoded payloads fed to an interpreter (`base64 | sh`, `eval`, `sh -c`),
`E` unbounded/opaque work that must degrade to ⊤.

**To add a corpus case:** drop a new `{"name", "description", "cases":[…]}` JSON
document into `testdata/corpus/` (or extend an existing one); `LoadCorpus` picks
it up automatically. GuardFall cases must carry a valid `category` (`A`–`E`);
non-GuardFall cases must not. Read
[`specs/domains/analysis-report.md`](specs/domains/analysis-report.md).

## Common extension recipes

- **Add a CLI flag or output format** — add a `case` in `parseArgs` (and a field
  on `options`) in `cmd/flowsh/main.go`, a branch in `run`, and document it in
  the `usage` constant. Update `cmd/flowsh/main_test.go`. See
  [`specs/domains/cli.md`](specs/domains/cli.md).
- **Add an effect kind or mode** — extend the `const` block and `EffectKinds` /
  `EffectModes` in `engine/effect.go`, and add a case to `KindDestructiveness` in
  `engine/report.go`. Regenerate the golden fixtures. See
  [`specs/domains/engine/effect-ir.md`](specs/domains/engine/effect-ir.md).
- **Add a value lattice / source class / taint label** — follow
  `engine/lattice.go` and `engine/taint.go`. See
  [`specs/domains/engine/lattices.md`](specs/domains/engine/lattices.md).
- **Tune scoring / destructiveness / exfil** — adjust the policy tables
  (`KindDestructiveness`, `secretPathMarkers`, `irreversibleTokens`, and the
  weightings in `ScoreEffects`) in `engine/`. See
  [`specs/domains/engine/scoring.md`](specs/domains/engine/scoring.md).
- **Add a frontend (new language)** — implement a lifter that emits
  `engine.Effect` values and wire it in `internal/analysis`. See
  [`specs/architecture/layers.md`](specs/architecture/layers.md).

## Frozen contracts

The JSON report is a frozen wire contract. The effect payload is tagged by
`engine.SchemaVersion = "effect-ir/v1"`; the CLI envelope by
`analysis.ToolVersion = "flowsh/v1"`. **Changing the shape of an emitted field
is a breaking change** and requires bumping the corresponding version tag and
regenerating the golden fixtures (`engine/testdata/*.golden.json`) and every
consumer. See
[`specs/contracts/report-json.md`](specs/contracts/report-json.md) for the
breaking-change checklist.

## Specification system

`specs/` is the source of truth for system structure and contracts:

- [`specs/INDEX.md`](specs/INDEX.md) — task → spec navigation; start here.
- [`specs/META.md`](specs/META.md) — spec formats and update rules.
- [`specs/WORKFLOW.md`](specs/WORKFLOW.md) — how to use the spec system.
- [`specs/decisions/`](specs/decisions/) — the ADRs (frozen IR, one-way
  dependency, conservative ⊤, embedded KB, two frontends, bounded execution,
  lattice model, single module).

Update the relevant spec alongside any structural change.

## Commit and PR expectations

- Keep changes focused; update specs and corpus cases together with code.
- Ensure `gofmt -l .` is empty, and `go build ./...`, `go vet ./...` and
  `go test ./...` all pass locally.
- Do not weaken an invariant to make a test pass; fix the analysis instead.
