# Analysis Report (flowsh facade)

## Purpose

`internal/analysis` is the shared analysis facade behind the `flowsh` CLI and the embedding API. It is the single place that composes the two frontends (`front/bash`, `front/ps`), the knowledge-base binder (`bind`) and the frozen core (`engine`) into one deterministic, serialisable `Report`. It lives under `internal/` because the frozen core (`engine`) must stay frontend-free — the composition of frontends + binder + engine can only live above them. External Go programs reach it through the sibling `api/` embedding package (see [Public Embedding Surface](#public-embedding-surface-api)).

## Key Files

- `internal/analysis/analyze.go` — the facade: `Lang`, `ParseLang`, `Report`, `DestructiveFinding`, `Analyzer`, `NewAnalyzer`, `defaultAnalyzer`, `Options` (incl. `Root`, `Windows`, `Vars`), `Bool`, `RootArgument`/`RootStdin`, `Analyze`, `AnalyzeWith`.
- `internal/corpus/corpus.go` — the test-only corpus harness: `Case`, group constants, `GuardFallClasses`, `LoadCorpus`, `Filter`, `CorpusDir`, `CorpusDirFrom` (language resolution stays in `internal/analysis`).
- `internal/analysis/corpus_test.go` — conformance tests over the corpus (GuardFall coverage, destructive recall, PowerShell recall, benign precision, why-trace coverage).
- `internal/analysis/exfil_test.go` — exfiltration regression tests.
- `internal/analysis/destructive_test.go` — knowledge-base destructive-class raising (a class-E entry raises to Critical; a KB class never lowers the effect-derived severity).
- `internal/analysis/loc_test.go` — why-trace source locations and `Options.Root` → `Report.Root`.
- `internal/analysis/analyze_ps_test.go` — PowerShell provider options (`Options.Windows` toggles the Registry independently of the host OS).
- `internal/analysis/vars_test.go` — host-table option (`Options.Vars`) end to end: seeded bindings resolve `$name`-derived targets, and the option never loosens the unseeded ⊤ default.
- `internal/analysis/canonical.go` — the per-command resolution view (`CommandCall`, `CallRedirect`) with binary-name normalization (`normalizeBinary`), and the effect-based canonical form (`Canonical`, `buildCanonical`: staging fold + non-path target filter + deterministic key).
- `internal/analysis/canonical_test.go` — the retry-splitting repros (npx vs `node_modules/.bin` binary path; staged write + `mv` vs `sed -i`), the normalization table, the staging-fold boundary rules and the ⊤-survival invariant.
- `cmd/flowsh/main.go` — the CLI front-end that consumes this facade (see [CLI](cli.md)).
- `api/api.go` — the public embedding surface: a thin type-alias re-export of this facade for external Go modules (see [Public Embedding Surface](#public-embedding-surface-api)).
- `testdata/corpus/*.json` — the corpus documents loaded by `LoadCorpus` (`benign_bash.json`, `destructive_bash.json`, `guardfall_bash.json`, `guardfall_posix.json`, `guardfall_posh.json`, `resolution_bash.json`, `ps_cases.json`).
- `engine/effect.go`, `engine/score.go`, `engine/report.go` — the frozen core types embedded in `Report`.

## Core Types

### Language selection

`Lang` names the command-line dialect a source is written in; its three values are exactly the ones the CLI accepts on `--lang`.

```go
type Lang string

const (
	LangBash       Lang = "bash"  // GNU bash argv with -flags and --options
	LangPOSIX      Lang = "posix" // the POSIX shell (sh); the bash frontend in POSIX mode
	LangPowerShell Lang = "posh"  // PowerShell cmdlet syntax; canonical name "posh"
)

var Langs = []Lang{LangBash, LangPOSIX, LangPowerShell} // canonical order
```

`ParseLang` maps a user-supplied name onto a `Lang`, accepting the canonical spellings plus common aliases:

| Input (case-insensitive, trimmed) | Result |
| --- | --- |
| `bash`, `shell` | `LangBash` (`"bash"`) |
| `posix`, `sh` | `LangPOSIX` (`"posix"`) |
| `posh`, `ps`, `pwsh`, `powershell` | `LangPowerShell` (`"posh"`) |
| anything else | error `flowsh: unknown language %q (want bash\|posix\|posh)` |

### Report — the JSON contract

```go
type Report struct {
	SchemaVersion string `json:"schemaVersion"`
	Tool          string `json:"tool"`
	ToolVersion   string `json:"toolVersion"`
	Lang          string `json:"lang"`
	Input         string `json:"input"`
	// Root names the source the input was read from (the path of the analysed
	// file, or RootArgument/RootStdin). It is set from Options.Root and omitted
	// when the caller did not name a source.
	Root            string                 `json:"root,omitempty"`
	Effects         []engine.Effect        `json:"effects"`
	Destructiveness engine.Destructiveness `json:"destructiveness"`
	Score           engine.Score           `json:"score"`
	Why             []engine.WhyTrace      `json:"why,omitempty"`
	Conservative    bool                   `json:"conservative"`
	Top             bool                   `json:"top"`
	Reason          string                 `json:"reason,omitempty"`
	Commands        int                    `json:"commands"`
	Resolution      bind.Resolution        `json:"resolution"`
	Destructive     []DestructiveFinding   `json:"destructive,omitempty"`
	Notes           []string               `json:"notes,omitempty"`
}
```

The JSON field contract (a flowsh report is an engine report plus CLI metadata):

| Field | JSON type | Source / meaning |
| --- | --- | --- |
| `schemaVersion` | string | Always `effect-ir/v2` (`engine.SchemaVersion`). |
| `tool` | string | Always `flowsh` (`ToolName`). |
| `toolVersion` | string | Always `flowsh/v3` (`ToolVersion`; v2 added the additive `commandCalls` and `canonical` fields, v3 the `score.cradleFlows`/`score.ingestFlows` network-flow fields). |
| `lang` | string | `"bash"`, `"posix"` or `"posh"`. |
| `input` | string | The analysed source text verbatim. |
| `root` | string | The source name the input was read from (a file path, or `RootArgument`/`RootStdin`); present (`omitempty`) only when the caller named one via `Options.Root`. |
| `effects` | array of `engine.Effect` | Normalised effects (merged by kind+mode, canonically sorted). Never `null` — always at least `[]`. |
| `destructiveness` | `engine.Destructiveness` | `"None"`\|`"Low"`\|`"Medium"`\|`"High"`\|`"Critical"`; join (max) over effect kinds. |
| `score` | `engine.Score` | Composition score (see below). |
| `why` | array of `engine.WhyTrace` | Why-trace: for each effect, the ordered rule steps and concrete source atoms that justify it (`omitempty`). |
| `conservative` | bool | Analysis could not bound the input but did not fully degrade to ⊤. |
| `top` | bool | Analysis degraded to ⊤ (unknown/unbounded). |
| `reason` | string | Present (`omitempty`) only when `top`/`conservative`; explains the degradation. |
| `commands` | int | Number of commands/statements analysed. |
| `resolution` | `bind.Resolution` | Aggregated name-resolution outcome across the calls (`kind` `alias`/`function`/`builtin`/`command`/…); `name` is the resolved target name and differs from `invoked` for aliases/functions and for the package-runner / path-linked forms that map onto a knowledge-base command. The zero value (`kind: ""`) on the PowerShell path. |
| `commandCalls` | array of `CommandCall` | Per-command resolution view: every distinct call the binder saw (a repeated call site, such as a loop body, contributes one entry) with its `invoked` name (as written), its `resolved` binary — the knowledge-base command the invocation resolved to, so every spelling of one binary shares one identity (`npx tsc -b` and `./node_modules/.bin/tsc -b` both resolve to `tsc`; a wrapper alias resolves to its target, so `npx mvnw` and `./mvnw` report `mvn`), or, when it resolved to no knowledge-base command, the basename of the resolved name with any `node_modules/.bin` segment stripped, its non-empty argument values and its statement's resolved `redirs` (`omitempty`; absent on the PowerShell path and when no call reached the binder). |
| `canonical` | `Canonical` | The effect-based canonical form for signature comparison: the report's effects normalized (a staged temp write folded onto the destination of the trailing `mv` — `sed … > tmp && mv tmp file` ≡ `sed -i … file`; non-path operand targets such as a sed script or a grep pattern dropped) plus the deterministic `key` (sorted `Effect.Key()` values joined by `;`). Present whenever the report has effects. |
| `destructive` | array of `DestructiveFinding` | Matched knowledge-base destructive-flags entries (`command`, `spec`, `class` `A`–`E`, `reason`), de-duplicated and sorted (`omitempty`). |
| `notes` | array of string | Frontend diagnostics (`omitempty`). |

Nested `engine.Effect` fields: `kind`, `target`, `mode`, `certainty`, `taint`, `reversible`, `netFlow` (`omitempty` — present only for a network-flow sink: `cradle` on a `CodeExec`, `ingest` on an `FSWrite`).

Nested `engine.Score` fields: `destructiveness`, `irreversibility`, `breadth`, `influence`, `exfil`, `confidence` (int, `[0,100]`), `reversible`, `grade`, `exfilPairs` (array of `{source, sink}`, `omitempty`), `cradleFlows` (array of `{source, sink}` for network→code-execution flows, `omitempty`), `ingestFlows` (array of `{source, sink}` for network→filesystem flows, `omitempty`).

`Report` methods:

```go
func (r *Report) Validate() error       // schema version + lang set, every effect valid
func (r *Report) Encode() ([]byte, error) // Validate then json.MarshalIndent(r, "", "  ")
func (r *Report) Covered() bool         // len(Effects) > 0 || Top || Conservative
func (r *Report) HasTop() bool          // any KindCodeExec effect with an ⊤ (Top) target
```

### Analyzer and the process-wide singleton

```go
type Analyzer struct { binder *bind.Binder } // safe for concurrent use

func NewAnalyzer() (*Analyzer, error) // loads the embedded KB via bind.NewDefault()

// defaultAnalyzer memoises the process-wide analyser so repeated calls reuse
// one loaded knowledge base.
var defaultAnalyzer = sync.OnceValues(NewAnalyzer)

// Options tunes the analysis. The zero value is the host default; Windows is
// tri-state — nil keeps the host default (Registry active only on Windows),
// a non-nil value forces the PowerShell Registry provider on or off
// independently of the host OS. Vars seeds the bash/POSIX abstract state with
// host-known variable bindings (a session temp directory, a workspace root)
// that behave exactly like literal in-script assignments; nil is identical to
// Analyze.
type Options struct {
	Windows *bool             // tri-state Registry toggle: nil = host default
	Root    string            // source name stamped into Report.Root; empty = unset
	Vars    map[string]string // host-known shell variable bindings (bash/POSIX only)
}

func Bool(v bool) *bool // helper for the tri-state Options.Windows field

// Package-level entry points: run the full pipeline with the process-wide analyser.
func Analyze(lang Lang, src string) (*Report, error)                 // == AnalyzeWith(lang, src, Options{})
func AnalyzeWith(lang Lang, src string, opts Options) (*Report, error)

// Method forms on an explicit analyser.
func (a *Analyzer) Analyze(lang Lang, src string) *Report             // == AnalyzeWith(lang, src, Options{})
func (a *Analyzer) AnalyzeWith(lang Lang, src string, opts Options) *Report
```

`sync.OnceValues` (Go 1.21+) evaluates `NewAnalyzer` at most once and returns the same `(*Analyzer, error)` pair on every call — the KB load is paid once per process.

### Corpus harness types

```go
type Case struct {
	ID       string `json:"id"`
	Group    string `json:"group"`
	Category string `json:"category,omitempty"` // GuardFall class "A".."E"; empty otherwise
	Lang     string `json:"lang"`               // the dialect the input is written in
	Input    string `json:"input"`
	Note     string `json:"note,omitempty"`
}
```

Group constants and semantics:

| Constant | Value | Role | `RequiresCoverage` |
| --- | --- | --- | --- |
| `GroupGuardFall` | `"guardfall"` | Adversarial guard-evading inputs (classes A–E). | true |
| `GroupDestructive` | `"destructive"` | Canonical destructive commands (recall). | true |
| `GroupBenign` | `"benign"` | Ordinary commands (precision control). | false |
| `GroupPS` | `"ps"` | PowerShell-specific adversarial/recall cases. | true |
| `GroupResolution` | `"resolution"` | Recall cases for the A2 name-resolution chain: every case's report must expose the command its invocation actually named (alias/function/builtin/external/unknown). | true |

`Case.RequiresCoverage()` is `Group != GroupBenign`: benign commands may legitimately yield no effect, so they are excluded from the "effect present or ⊤" invariant.

`GuardFallClasses = []string{"A", "B", "C", "D", "E"}` — the guarded-evasion categories, in order:

| Class | Evasion technique |
| --- | --- |
| `A` | Quoting/escaping fragments (`r''m`, `"r"m`, `\rm`). |
| `B` | Separator injection (`$IFS`, `${IFS}`, `printf`-built words). |
| `C` | Indirection: command substitution and dynamically-named programs. |
| `D` | Encoded payloads fed to an interpreter (`base64\|sh`, `eval`, `sh -c`). |
| `E` | Unbounded/opaque work that must degrade to ⊤ (budget exhaustion, unknown). |

## Flow

Primary happy path — one call through the package-level facade:

```
Analyze(lang, src)                       analyze.go (package func)
        │
        ├─ defaultAnalyzer()             sync.OnceValues(NewAnalyzer)
        │      └─ NewAnalyzer → bind.NewDefault()   (KB loaded once per process)
        │
        └─ (*Analyzer).Analyze(lang, src)
                 │
                 ├─ lang == LangPowerShell ──► analyzePS(src, opts.psOptions(), opts.Root)
                 │        ps.Parse → ps.LowerWith(opts) → normalizeEffects
                 │
                 ├─ lang == LangPOSIX ───────► analyzeBash(bash.POSIX, LangPOSIX, src, opts.Root)
                 │
                 └─ otherwise (LangBash) ────► analyzeBash(bash.Bash, LangBash, src, opts.Root)
                          binder != nil → bash.Exec(v, sourceName(root, "script"), src, resolver)
                                 resolver = b.BindBash(cmd, prog) → Resolution{Effects, Derivations}
                          then normalizeEffects → ComputeDestructiveness
                                              → ScoreEffects(effects, tokens...)
                 │
                 └─ newReport(lang, src, root)  → fills SchemaVersion/Tool/ToolVersion/Lang/Input/Root
                                                 → *Report (never nil, Effects never nil)
```

`Encode()` (CLI `--json`) validates and marshals the report with two-space indent.

## Invariants

- `Analyze` is total and deterministic: the frontends degrade to ⊤ rather than fail, so the returned `*Report` is never nil.
- `Report.Effects` is never `null`: `normalizeEffects` replaces a nil slice with `[]engine.Effect{}`, so JSON always carries `[]`.
- `Report.Covered()` is true iff the analysis produced at least one effect, degraded to ⊤ (`Top`), or is `Conservative` — the "no silent miss" property the GuardFall corpus checks.
- `Report.SchemaVersion`, `Report.Tool` and `Report.ToolVersion` always equal `engine.SchemaVersion` (`effect-ir/v2`), `"flowsh"`, `"flowsh/v3"` respectively.
- `Report.Destructiveness` is the join (max) of `engine.ComputeDestructiveness(effects)` and the join of the binder's per-call `Destructiveness` (which already folds each matched destructive-table class severity); the same KB-class severity is joined into `Score.Destructiveness` and `Score.Grade`, so a matched destructive class can only raise — never lower — the reported severity.
- `ParseLang` returns `LangBash`, `LangPOSIX` or `LangPowerShell`, otherwise a non-nil error; it never returns an unknown `Lang` with a nil error.
- `defaultAnalyzer` loads the knowledge base at most once per process (`sync.OnceValues`), and every `Analyze` call shares that analyser.
- `LoadCorpus` returns cases sorted by `ID`, with duplicate `ID`s rejected, so iterations are stable and unambiguous.
- The `flowsh` package is the only composition point of frontends + binder + engine; `engine` imports no frontend.

## Configuration

Compile-time constants in `internal/analysis/analyze.go`:

| Name | Value | Role |
| --- | --- | --- |
| `ToolName` | `"flowsh"` | Stamped into `report.tool`. |
| `SchemaVersion` | `engine.SchemaVersion` = `"effect-ir/v2"` | Stamped into `report.schemaVersion`. |
| `ToolVersion` | `"flowsh/v3"` | Stamped into `report.toolVersion`. |
| `RootArgument` | `"<argument>"` | `report.root` when the command came from the positional argument. |
| `RootStdin` | `"<stdin>"` | `report.root` when the command came from stdin (`-` or no argument). |

Corpus location resolution (`internal/corpus/corpus.go`):

- `CorpusDir()` walks up from the current working directory until a `go.mod` is found, then returns `<root>/testdata/corpus`.
- `CorpusDirFrom(start)` is the testable core that resolves the same path relative to an explicit starting directory (absolute-ised first).
- Failure to find `go.mod` above the start yields `flowsh: go.mod not found above <dir>`.

The facade reads no environment variables; its only runtime configuration is the `lang` argument and the optional `Options` — notably `Options.Windows` (the tri-state PowerShell Registry toggle) and `Options.Vars` (host-known shell variable bindings seeded into the bash/POSIX abstract state; the PowerShell path ignores the table).

## Public Embedding Surface (`api/`)

The facade is consumed by external Go programs through the sibling top-level package `api/` (import path `github.com/v0lka/flowsh/api`) — the CLI and the API are equal first-class entry points, differing only in how they render the `*Report` ([ADR-0010](../decisions/0010-public-embedding-api.md)).

`api/` is a thin type-alias re-export of `internal/analysis`: it defines no types, constants or logic of its own. Its surface is exactly:

| Kind | `api/` name | Alias of |
| --- | --- | --- |
| type | `Lang`, `Report`, `DestructiveFinding`, `Analyzer`, `Options` | the same `analysis` types (`=`) |
| var | `Langs` | `analysis.Langs` |
| const | `ToolName`, `SchemaVersion`, `ToolVersion`, `RootArgument`, `RootStdin`, `LangBash`, `LangPOSIX`, `LangPowerShell` | the same `analysis` constants |
| func | `ParseLang`, `Analyze`, `AnalyzeWith`, `NewAnalyzer`, `Bool` | one-line forwarders to `analysis` |

Because every exported type is a type **alias**, the boundary is transparent — an embedding caller passes `api.Options` where an `analysis.Options` is expected and reads the same `Report` the CLI emits. A consequence of the alias (and not duplicating types) is that a change to an internal type is, by construction, a change to the public API.

The embedding contract is versioned by the two report constants, not by the module version: a consumer pins to `Report.SchemaVersion` (`effect-ir/v2`, the effect IR shape) and `Report.ToolVersion` (`flowsh/v3`, the document as a whole), as described in [Report Contract](../contracts/report-json.md).

The corpus harness is deliberately **not** re-exported: `Case`, `LoadCorpus`, `CorpusDir`, `CorpusDirFrom`, `Filter`, the `Group*` constants and `GuardFallClasses` live in the test-only `internal/corpus` package — testing aids, not part of the embedding surface (in-module tests, including the external `engine_test` benchmark, reach them there).

## Extension Points

- **Add a dialect**: add a `Lang` constant (and to `Langs`), extend `ParseLang`'s switch with its canonical name + aliases, add a `case` in `(*Analyzer).AnalyzeWith`, and implement `<lang>Analyze` producing a normalized report.
- **Add a corpus group**: add a `Group*` constant, accept it in `Case.validate`'s group switch, and add the matching conformance test using `Filter`.
- **Add corpus cases**: drop a new `*.json` document (`{name, description, cases[]}`) into `testdata/corpus`; `LoadCorpus` picks it up automatically. GuardFall cases must carry a valid `Category` (`A`–`E`); non-GuardFall cases must not.
- **Add a report field**: extend `Report` with a JSON tag and, if it affects validity, `Report.Validate`. Consumers pin to `schemaVersion`, so additive fields are the safe path — but a new `Report` field is a change to the CLI envelope, so bump `ToolVersion` (v1 carried `why`, `resolution` and `destructive`; v2 added `commandCalls` and `canonical`) and update [Report Contract](../contracts/report-json.md).
- **Rebind the knowledge base**: swap `NewAnalyzer`'s `bind.NewDefault()` for another binder; the rest of the pipeline is unchanged.

## Related Specs

- [CLI](cli.md) — the `cmd/flowsh` command-line front-end over this facade.
- [Report Contract](../contracts/report-json.md) — the emitted JSON document boundary.
- [Layer Architecture](../architecture/layers.md) — the layer table and import graph, including the `api/` public-API layer.
- [ADR-0010: Public embedding API](../decisions/0010-public-embedding-api.md) — why the embedding surface exists and how it is versioned.
- [Spec System](../META.md) — document formats and update rules.
- [Index](../INDEX.md) — task-to-spec navigation.
