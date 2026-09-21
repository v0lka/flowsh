# Contract: Analyzer <-> CLI/CI (JSON Report)

## Boundary Rule

The JSON the CLI prints to stdout is a frozen wire contract: the effect payload is tagged by the core schema version `engine.SchemaVersion = "effect-ir/v2"`, and the CLI envelope is tagged by `analysis.ToolVersion = "flowsh/v3"` (with `analysis.ToolName = "flowsh"`). Consumers — the CLI's own human summary, the CLI smoke test (`cmd/flowsh/smoke_test.go`), and the regression harness — read these documents without importing the Go packages, so they pin to the two version tags. Any change to the shape of an emitted field is a breaking change and requires bumping the corresponding version tag; the analyzer never renames or removes a field silently.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |
| `const SchemaVersion = "effect-ir/v2"` | `engine` (`report.go`) | `internal/analysis`, CI, golden fixtures | Tags the frozen effect schema carried in every report. |
| `type Effect struct{ Kind EffectKind \`json:"kind"\`; Target Scope \`json:"target"\`; Mode EffectMode \`json:"mode"\`; Certainty Certainty \`json:"certainty"\`; Taint Taint \`json:"taint"\`; Reversible bool \`json:"reversible"\`; NetFlow FlowRole \`json:"netFlow,omitempty"\` }` | `engine` (`effect.go`) | consumers of `effects[]` | The serialized effect atom; `NetFlow` (`""` \| `cradle` \| `ingest`) is the additive `effect-ir/v2` field marking the effect as the sink of a network data flow. |
| `func (Scope) MarshalJSON` → `{"targets":[…],"arbitrary":bool}` / `func (Taint) MarshalJSON` → `{"labels":[…],"arbitrary":bool}` | `engine` (`lattice.go`) | consumers of `target`/`taint` | Frozen lattice encoding (`arbitrary` marks the ⊤/top element). |
| `type Destructiveness int` + `func (Destructiveness) MarshalJSON` (string: `"None"`…`"Critical"`) | `engine` (`lattice.go`) | consumers of `destructiveness`/`score` | Severity encoded as a JSON string, not a number. |
| `type Report struct{ SchemaVersion string \`json:"schemaVersion"\`; Root string \`json:"root,omitempty"\`; Effects []Effect \`json:"effects"\`; Destructiveness Destructiveness \`json:"destructiveness"\`; Why []WhyTrace \`json:"why,omitempty"\`; Notes []string \`json:"notes,omitempty"\` }` | `engine` (`report.go`) | fixtures, harness | The core effect report. |
| `func (r *Report) Encode() ([]byte, error)` | `engine` (`report.go`) | harness | `Validate` then `json.MarshalIndent(r, "", "  ")` — canonical, deterministic bytes. |
| `const ToolName = "flowsh"` + `const SchemaVersion = engine.SchemaVersion` + `const ToolVersion = "flowsh/v3"` | `internal/analysis` (`analyze.go`) | `cmd/flowsh`, CI | The CLI envelope's identity and version tags. |
| `type Report struct{ SchemaVersion, Tool, ToolVersion, Lang, Input, Root string; Effects []engine.Effect; Destructiveness engine.Destructiveness; Score engine.Score; Why []engine.WhyTrace; Conservative, Top bool; Reason string; Commands int; Resolution bind.Resolution; CommandCalls []CommandCall; Canonical *Canonical; Destructive []DestructiveFinding; Notes []string }` | `internal/analysis` (`analyze.go`) | `cmd/flowsh`, CI | The CLI's JSON contract: the frozen IR plus CLI metadata, the why-trace, the aggregated resolution, the per-command resolution view, the effect-based canonical form, the matched destructive entries and the score. |
| `type CommandCall struct{ Invoked, Resolved string; Args []string; Redirs []CallRedirect }` + `type CallRedirect struct{ Op, Target string; Known bool }` | `internal/analysis` (`canonical.go`) | consumers of `commandCalls[]` | One command invocation for effect-based comparison: the invoked name as written, the normalized binary (`npx tsc -b` and `./node_modules/.bin/tsc -b` both resolve to `tsc`), the surviving argument values, and the statement's resolved redirections. |
| `type Canonical struct{ Effects []engine.Effect; Key string }` | `internal/analysis` (`canonical.go`) | consumers of `canonical` | The effect-based canonical form: the report's effects with staged temp writes folded onto the destination of the trailing `mv` (`sed … > tmp && mv tmp file` ≡ `sed -i … file`) and non-path operand targets dropped, plus the deterministic `key` (sorted `Effect.Key()` values joined by `;`) a signature compares across retries that differ in form but not in effect. |
| `type DestructiveFinding struct{ Command string \`json:"command"\`; Spec string \`json:"spec"\`; Class string \`json:"class"\`; Reason string \`json:"reason"\` }` | `internal/analysis` (`analyze.go`) | `cmd/flowsh`, CI | One matched knowledge-base destructive-flags entry as surfaced in `destructive[]` (class `A`–`E`). |
| `type Resolution struct{ Invoked, Name string; Kind ResolveKind; AliasChain []string }` | `bind` (`resolve.go`) | consumers of `resolution` | The aggregated name-resolution outcome across the program's calls (`kind` ∈ `empty`\|`assignment`\|`builtin`\|`function`\|`alias`\|`command`\|`unknown`). |
| `type Score struct{ Destructiveness, Irreversibility, Breadth, Influence, Exfil Destructiveness; Confidence int; Reversible bool; Grade Destructiveness; ExfilPairs []Exfil; CradleFlows []CradleFlow; IngestFlows []IngestFlow }` | `engine` (`score.go`) | consumers of `score` | Composite, orderable risk assessment; `CradleFlows` (network → code execution) and `IngestFlows` (network → file write) are the additive `flowsh/v3` network data flows, each omitted when empty. |
| `func (r *Report) Validate() error` / `func (r *Report) Covered() bool` / `func (r *Report) HasTop() bool` | `internal/analysis` (`analyze.go`) | `cmd/flowsh`, harness | Well-formedness and the "no silent miss" / ⊤ invariants. |
| `func (r *Report) Encode() ([]byte, error)` | `internal/analysis` (`analyze.go`) | `cmd/flowsh` | Canonical indented JSON of the CLI report. |
| `func Analyze(lang Lang, src string) (*Report, error)` / `func ParseLang(s string) (Lang, error)` | `internal/analysis` (`analyze.go`) | `cmd/flowsh` | The pipeline producing the report from `(lang, src)`. |
| CLI: `--lang bash\|posix\|posh\|auto`, `--file PATH`, `--batch`, `--json`, `--explain`/`--why`, `--windows[=bool]`, `--version`, `-h/--help`; exit `0`/`1`/`2`/`3` | `cmd/flowsh` (`main.go`) | CI, users | Entry point; writes the report to stdout (`--file` names the input file — also setting `report.root`), `--batch` writes one NDJSON report per input line, and `--version` prints `flowsh/v3` + `effect-ir/v2` and exits `0`. |

## Initialization

`cmd/flowsh/main.go` parses flags, maps `--lang` through `analysis.ParseLang` (`"bash"`/`"shell"` → bash; `"posix"`/`"sh"` → posix; `"posh"`/`"ps"`/`"pwsh"`/`"powershell"` → posh; `"auto"` → sniffed by `detectLang`), reads the command from `--file`, the positional argument, or stdin (stamping the source name `Root`), and calls `analysis.AnalyzeWith`. `--version` (like `--help`) short-circuits before the language and input stages, printing `flowsh/v3` and `effect-ir/v2` on stdout and exiting `0`. With `--lang auto` the dialect is resolved after the input is read: `detectLang` scores PowerShell cmdlet/parameter/syntax markers (`psVerbs`/`psParams`/`psSyntax`) against shell markers (`shellTokens`/`shSyntax`) and falls back to `bash`, so it never fails. With `--batch` the selected source is split into non-blank lines (`splitBatch`); each line is analysed (with `detectLang` re-run per line when `--lang auto`) and written as one compact, single-line JSON object via `encodeCompact` (validate + `json.Marshal`), so the output is NDJSON. The report is built by `newReport(lang, src, root)` — which stamps `SchemaVersion`, `Tool`, `ToolVersion`, `Lang` and `Root` and initialises `Effects` to `[]engine.Effect{}` (so the JSON carries `[]`, never `null`) — then filled by `analyzeBash`/`analyzePS` and encoded with `Report.Encode`. The process-wide analyzer is memoised via `sync.OnceValues(NewAnalyzer)` so the KB is loaded once. Fixed golden fixtures — `engine/testdata/report.golden.json` and `engine/testdata/effect.golden.json` — pin the encoding.

## Data Flow Across Boundary

```
  argv / stdin / --file ──▶ parseArgs ──▶ ParseLang (or detectLang for auto)
                                                                          │
                                                                          ▼
                       front/bash | front/ps ──▶ bind ──▶ engine (effects, destructiveness, score)
                                                                          │
                                                                          ▼
                                                            *analysis.Report (Validate)
                                                                          │  Encode()          [single]
                                                                          │  encodeCompact()   [--batch, per line]
                                                                          ▼
                                                     stdout JSON / NDJSON  ──▶  consumers:
                                                                       • writeText() human summary
                                                                       • CLI smoke: cmd/flowsh/smoke_test.go
                                                                       • regression harness
```

The emitted document has the envelope:

```json
{
  "schemaVersion": "effect-ir/v2",
  "tool": "flowsh",
  "toolVersion": "flowsh/v3",
  "lang": "bash",
  "input": "rm -rf $HOME",
  "effects": [ { "kind": "FSWrite", "target": { "targets": ["/root"], "arbitrary": false },
                 "mode": "Direct", "certainty": "Certain",
                 "taint": { "labels": [], "arbitrary": false }, "reversible": false } ],
  "destructiveness": "High",
  "score": { "destructiveness": "High", "irreversibility": "High", "breadth": "High",
             "influence": "None", "exfil": "None", "confidence": 100,
             "reversible": false, "grade": "High" },
  "conservative": false,
  "top": false,
  "commands": 1,
  "resolution": { "kind": "command", "invoked": "rm", "name": "rm" },
  "commandCalls": [ { "invoked": "rm", "resolved": "rm", "args": [ "-rf", "/root" ] } ],
  "canonical": { "effects": [ { "kind": "FSWrite", "target": { "targets": [ "/root" ], "arbitrary": false },
                               "mode": "Direct", "certainty": "Certain",
                               "taint": { "labels": [], "arbitrary": false }, "reversible": false } ],
                 "key": "FSWrite|Direct|[/root]" }
}
```

(Field names follow the struct tags; `reason`, `why`, `root`, `notes`, `destructive` and `exfilPairs` are omitted when empty. `resolution` is always present — it carries the aggregated outcome across the program's calls, and is the zero value `{"kind":""}` whenever no call reached the binder: on the PowerShell path (which resolves through its own alias/cmdlet tables rather than the binder) and on the bash path for a program made only of non-command statements — a bare assignment, a redirection, or a pure shell-state builtin. The `assignment` and `empty` kinds surface only when such a statement is passed to the binder directly. `commandCalls` and `canonical` are omitted when empty: `commandCalls` is absent exactly when `resolution` is the zero value (no call reached the binder), and `canonical` is present whenever the report has effects. The canonical form is deliberately coarse — its normalizations can merge two invocations an exhaustive comparison would distinguish, never split two that differ only in form — because the failure mode it exists to remove is the split of every retry.) A consumer that needs only the effect set reads `effects[]`; each effect is keyed by `Effect.Key()` = `kind|mode|[targets]`, where the `[targets]` element backslash-escapes `\`, `,` and `]` so the key is injective — a Windows target such as `C:\Windows` renders as `C:\\Windows`, while POSIX targets containing none of those three bytes are unchanged (e.g. `FSWrite|Direct|[/root]`). A consumer that needs the comparable form for a signature reads `canonical.key` (and `canonical.effects[]` to explain it); a consumer that needs to know which binary each invocation actually runs reads `commandCalls[].resolved`. A consumer that needs bounding information reads `conservative`, `top`, and `reason`.

## Error Propagation

Encoding is guarded: `Report.Encode` calls `Report.Validate` first and returns an `error` if the report is malformed (empty `schemaVersion`, empty `lang`, or an invalid effect), so a bad report is never written. The CLI maps failures to exit statuses: `0` for a produced report (or the `--help`/`--version` short-circuits), `1` for an internal failure (analyzer construction or `Encode`/`encodeCompact` failure, printed as `flowsh: encode report: …`), `2` for a usage error (unknown `--lang`, a bad flag, conflicting sources, no input), and `3` for an input error (the named source could not be read — a missing/unreadable file, a directory — or was empty, including an empty batch). Because the frontends degrade to ⊤ rather than fail, an analysis of unparseable input still exits `0` with a well-formed report whose `top` is `true` and whose `reason` explains why — exit `1` therefore signals an internal error, never "hard input".

## Breaking Change Checklist

- **Change an `Effect` field/JSON tag, a lattice's `MarshalJSON`, or `Destructiveness`'s encoding** — you MUST bump `engine.SchemaVersion` (`effect-ir/v2`), regenerate `engine/testdata/effect.golden.json` and `engine/testdata/report.golden.json`, and update every consumer (see [frontend-engine.md](frontend-engine.md)).
- **Add/remove/rename a `analysis.Report` field or its JSON tag** — you MUST bump `analysis.ToolVersion` (currently `flowsh/v3`; v1 was the starting public contract carrying `why`, `resolution` and `destructive`, v2 added the additive `commandCalls` and `canonical` fields, and v3 the `score.cradleFlows`/`score.ingestFlows` network-flow fields), update `newReport`/`Validate`, and update the consumers that read those keys: the CLI smoke test in `cmd/flowsh/smoke_test.go` (run by `go test ./...` in `.github/workflows/ci.yml`) asserts `lang`, `effects`, `input`, and `toolVersion`.
- **Change `ToolName` or `SchemaVersion`** (`internal/analysis/analyze.go`) — consumers pin to `"flowsh"` and to `engine.SchemaVersion`; bump deliberately and update this spec.
- **Change the exit-code contract** (`0`/`1`/`2`/`3`) or the stdout framing (the human-summary lines, or the batch NDJSON one-report-per-line form) — you MUST update `cmd/flowsh/main.go`, `cmd/flowsh/main_test.go`, and the CLI smoke test `cmd/flowsh/smoke_test.go`.
- **Change `Encode`'s indentation or key ordering** — it is byte-frozen by the golden fixtures; regenerate them and update consumers that diff the output.
- **Change `ParseLang`'s accepted spellings** — update the CLI contract here and any script relying on an alias.

**Related specs:** [frontend-engine.md](frontend-engine.md) — the `engine.Effect`/`Report` types whose JSON this document freezes; [bind-kb.md](bind-kb.md) — the destructiveness folded into `destructiveness`/`score`; [exec-resolver.md](exec-resolver.md) — how the effects that populate `effects[]` are produced.
