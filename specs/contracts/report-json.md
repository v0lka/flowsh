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
| `const ToolName = "flowsh"` + `const SchemaVersion = engine.SchemaVersion` + `const ToolVersion = "flowsh/v3"` | `internal/analysis` (`analyze.go`) | `api` (re-exported), `cmd/flowsh` (via `api`), CI | The CLI envelope's identity and version tags. |
| `type Report struct{ SchemaVersion, Tool, ToolVersion, Lang, Input, Root string; Effects []engine.Effect; Destructiveness engine.Destructiveness; Score engine.Score; Why []engine.WhyTrace; Conservative, Top bool; Reason string; Commands int; Resolution bind.Resolution; CommandCalls []CommandCall; Canonical *Canonical; Destructive []DestructiveFinding; Notes []string }` | `internal/analysis` (`analyze.go`) | `api` (aliased as `api.Report`), `cmd/flowsh` (via `api`), CI | The CLI's JSON contract: the frozen IR plus CLI metadata, the why-trace, the aggregated resolution, the per-command resolution view, the effect-based canonical form, the matched destructive entries and the score. |
| `type CommandCall struct{ Invoked, Resolved string; Args []string; Redirs []CallRedirect }` + `type CallRedirect struct{ Op, Target string; Known bool }` | `internal/analysis` (`canonical.go`) | consumers of `commandCalls[]` | One command invocation for effect-based comparison: the invoked name as written, the normalized binary — the knowledge-base command the invocation resolved to (`npx tsc -b` and `./node_modules/.bin/tsc -b` both resolve to `tsc`; a wrapper alias resolves to its target, so `npx mvnw` and `./mvnw` report `mvn`) — the surviving argument values, and the statement's resolved redirections. |
| `type Canonical struct{ Effects []engine.Effect; Key string }` | `internal/analysis` (`canonical.go`) | consumers of `canonical` | The effect-based canonical form: the report's effects with staged temp writes folded onto the destination of the trailing `mv` (`sed … > tmp && mv tmp file` ≡ `sed -i … file`) and non-path operand targets dropped, plus the deterministic `key` (sorted `Effect.Key()` values joined by `;`) a signature compares across retries that differ in form but not in effect. |
| `type DestructiveFinding struct{ Command string \`json:"command"\`; Spec string \`json:"spec"\`; Class string \`json:"class"\`; Reason string \`json:"reason"\` }` | `internal/analysis` (`analyze.go`) | `cmd/flowsh`, CI | One matched knowledge-base destructive-flags entry as surfaced in `destructive[]` (class `A`–`E`). |
| `type Resolution struct{ Invoked, Name string; Kind ResolveKind; AliasChain []string }` | `bind` (`resolve.go`) | consumers of `resolution` | The aggregated name-resolution outcome across the program's calls (`kind` ∈ `empty`\|`assignment`\|`builtin`\|`function`\|`alias`\|`command`\|`unknown`). `name` is the resolved target name and differs from `invoked` for aliases/functions and for the two invocation forms that map onto a knowledge-base command — a package runner (`npx`, `bunx`) and a project-local bin path (`./node_modules/.bin/…`, `./mvnw`): `npx vitest run` resolves as `kind: "command"`, `invoked: "npx"`, `name: "vitest"`, while the shapes the analysis cannot bound stay `unknown` (⊤). |
| `type Score struct{ Destructiveness, Irreversibility, Breadth, Influence, Exfil Destructiveness; Confidence int; Reversible bool; Grade Destructiveness; ExfilPairs []Exfil; CradleFlows []CradleFlow; IngestFlows []IngestFlow }` | `engine` (`score.go`) | consumers of `score` | Composite, orderable risk assessment; `CradleFlows` (network → code execution) and `IngestFlows` (network → file write) are the additive `flowsh/v3` network data flows, each omitted when empty. |
| `func (r *Report) Validate() error` / `func (r *Report) Covered() bool` / `func (r *Report) HasTop() bool` | `internal/analysis` (`analyze.go`) | `cmd/flowsh`, harness | Well-formedness and the "no silent miss" / ⊤ invariants. |
| `func (r *Report) Encode() ([]byte, error)` | `internal/analysis` (`analyze.go`) | `cmd/flowsh` | Canonical indented JSON of the CLI report. |
| `api` package — type aliases (`Lang`, `Report`, `Options`, `JavaScriptContext`, …) plus forwarded constants and functions (`api.ParseLang`, `api.Analyze`/`api.AnalyzeWith`, `api.Bool`) | `api` (`api.go`) | `cmd/flowsh`, external embedders | The public embedding surface the CLI consumes instead of `internal/analysis` directly (ADR-0010, ADR-0017; see [domains/analysis-report.md](../domains/analysis-report.md)) — an embedding caller sees exactly the report contract the CLI emits. |
| `func Analyze(lang Lang, src string) (*Report, error)` / `func ParseLang(s string) (Lang, error)` | `internal/analysis` (`analyze.go`) | `api` (forwarded), `cmd/flowsh` (via `api`) | The pipeline producing the report from `(lang, src)`. |
| CLI: `--lang bash\|posix\|posh\|js\|auto`, `--batch`, `--json`, `--explain`/`--why`, `--windows[=bool]`, `--version`, `-h/--help`; exit `0`/`1`/`2`/`3` | `cmd/flowsh` (`main.go`) | CI, users | Entry point; the command comes from the positional argument or stdin only — there is no `--file` (a SECURITY.md hard constraint; `TestFinding001NoFileInput` pins `--file` to unknown-flag exit 2); `--batch` writes one NDJSON report per non-blank input line; `--version` prints `flowsh/v3` + `effect-ir/v2` and exits `0`. |

## Initialization

`cmd/flowsh/main.go` parses flags, maps `--lang` through `api.ParseLang` (`"bash"`/`"shell"` → bash; `"posix"`/`"sh"` → posix; `"posh"`/`"ps"`/`"pwsh"`/`"powershell"` → posh; `"js"`/`"javascript"`/`"node"`/`"nodejs"` → js; `"auto"` → sniffed by `detectLang`), reads the command from the positional argument or stdin only — there is no named-file input (the root is stamped `RootArgument` or `RootStdin`) — and calls `api.AnalyzeWith`: the CLI consumes the public `api` package (ADR-0010, ADR-0017), never `internal/analysis` directly. `--version` (like `--help`) short-circuits before the language and input stages, printing `flowsh/v3` and `effect-ir/v2` on stdout and exiting `0`. With `--lang auto` the dialect is resolved after the input is read: `detectLang` scores PowerShell cmdlet/parameter/syntax markers (`psVerbs`/`psParams`/`psSyntax`) against shell markers (`shellTokens`/`shSyntax`) and falls back to `bash`, so it never fails; when the sniffed dialect's report is uncovered, `analyzeAuto` re-analyses the input under the alternate dialect (auto selects Bash or PowerShell only), and when neither covers it the report degrades to ⊤/conservative with reason `"no dialect could bound the input"`. With `--batch` the selected source is split into non-blank lines (`splitBatch`); each line is analysed (`analyzeAuto` per line when `--lang auto`) and written as one compact, single-line JSON object via `encodeCompact` (validate + `json.Marshal`), so the output is NDJSON; a line that references a variable or positional assigned on an earlier line (`batchState`) or is a fragment of a multi-line program (`lineContinues`: a trailing backslash or open quote, plus the line that follows) degrades to ⊤/conservative rather than being analysed against an empty state. The report is built by `newReport(lang, src, root)` — which stamps `SchemaVersion`, `Tool`, `ToolVersion`, `Lang` and `Root` and initialises `Effects` to `[]engine.Effect{}` (so the JSON carries `[]`, never `null`) — then filled by `analyzeBash`/`analyzePS`/`analyzeJS` and encoded with `Report.Encode`. The process-wide analyzer is memoised via `sync.OnceValues(NewAnalyzer)` so the KB is loaded once. Fixed golden fixtures — `engine/testdata/report.golden.json` and `engine/testdata/effect.golden.json` — pin the encoding.

## Data Flow Across Boundary

```
  argv / stdin ──▶ parseArgs ──▶ ParseLang (or detectLang/analyzeAuto for auto)
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
  "root": "\u003cargument\u003e",
  "effects": [
    {
      "kind": "FSWrite",
      "target": {
        "targets": [
          "/root"
        ],
        "arbitrary": false
      },
      "mode": "Direct",
      "certainty": "Certain",
      "taint": {
        "labels": [],
        "arbitrary": false
      },
      "reversible": false
    }
  ],
  "destructiveness": "Critical",
  "score": {
    "destructiveness": "Critical",
    "irreversibility": "High",
    "breadth": "Low",
    "influence": "None",
    "exfil": "None",
    "confidence": 100,
    "reversible": false,
    "grade": "Critical"
  },
  "why": [
    {
      "effect": "FSWrite|Direct|[/root]",
      "because": [
        {
          "rule": "fs.write",
          "premises": [
            "command:rm"
          ],
          "note": "derived from command",
          "loc": {
            "file": "\u003cargument\u003e",
            "line": 1,
            "col": 1
          }
        },
        {
          "rule": "fs.write",
          "premises": [
            "flag:-r"
          ],
          "note": "derived from flag",
          "loc": {
            "file": "\u003cargument\u003e",
            "line": 1,
            "col": 5
          }
        },
        {
          "rule": "fs.write",
          "premises": [
            "flag:-f"
          ],
          "note": "derived from flag",
          "loc": {
            "file": "\u003cargument\u003e",
            "line": 1,
            "col": 6
          }
        },
        {
          "rule": "fs.write",
          "premises": [
            "operand:/root"
          ],
          "note": "derived from operand",
          "loc": {
            "file": "\u003cargument\u003e",
            "line": 1,
            "col": 8
          }
        }
      ]
    }
  ],
  "conservative": false,
  "top": false,
  "commands": 1,
  "resolution": {
    "invoked": "rm",
    "kind": "command",
    "name": "rm"
  },
  "commandCalls": [
    {
      "invoked": "rm",
      "resolved": "rm",
      "args": [
        "-rf",
        "/root"
      ]
    }
  ],
  "canonical": {
    "effects": [
      {
        "kind": "FSWrite",
        "target": {
          "targets": [
            "/root"
          ],
          "arbitrary": false
        },
        "mode": "Direct",
        "certainty": "Certain",
        "taint": {
          "labels": [],
          "arbitrary": false
        },
        "reversible": false
      }
    ],
    "key": "FSWrite|Direct|[/root]"
  },
  "destructive": [
    {
      "command": "rm",
      "spec": "-f",
      "class": "E",
      "reason": "forced removal that suppresses prompts and hides errors on missing files"
    },
    {
      "command": "rm",
      "spec": "-r",
      "class": "E",
      "reason": "recursively removes a whole directory tree, with no confirmation by default"
    }
  ]
}
```

(Field names follow the struct tags; `reason`, `why`, `root`, `notes`, `destructive` and `exfilPairs` are omitted when empty. `resolution` is always present — it carries the aggregated outcome across the program's calls, and is the zero value `{"kind":""}` whenever no call reached the binder: on the PowerShell path (which resolves through its own alias/cmdlet tables rather than the binder) and on the bash path for a program made only of non-command statements — a bare assignment, a redirection, or a pure shell-state builtin — and on the JavaScript path when no call reaches its injected binder. The `assignment` and `empty` kinds surface only when such a statement is passed to the binder directly. `commandCalls` and `canonical` are omitted when empty: `commandCalls` is absent exactly when `resolution` is the zero value (no call reached the binder), and `canonical` is present whenever the report has effects. The canonical form is deliberately coarse — its normalizations can merge two invocations an exhaustive comparison would distinguish, never split two that differ only in form — because the failure mode it exists to remove is the split of every retry.) A consumer that needs only the effect set reads `effects[]`; each effect is keyed by `Effect.Key()` = `kind|mode|[targets]`, where the `[targets]` element backslash-escapes `\`, `,` and `]` so the key is injective — a Windows target such as `C:\Windows` renders as `C:\\Windows`, while POSIX targets containing none of those three bytes are unchanged (e.g. `FSWrite|Direct|[/root]`). A consumer that needs the comparable form for a signature reads `canonical.key` (and `canonical.effects[]` to explain it); a consumer that needs to know which binary each invocation actually runs reads `commandCalls[].resolved`. A consumer that needs bounding information reads `conservative`, `top`, and `reason`.

For every dialect (bash, POSIX, PowerShell, and JavaScript), `why` traces retain separate evidence for distinct source sites. Atoms deduplicate by kind, text, and source location (file, line, column); atoms without a location deduplicate by kind and text. Equal rule/premise text can therefore recur at different locations within a trace.

JavaScript retains the same report shape and version tags. Understood pure programs have `effects: []`, no uncertainty flags, and no canonical form; they validate but remain uncovered and deny under policy. A leading shebang is inert and retains source positions. Unsupported reached execution, literal decoding, primitive coercions, and callback invocation emit CodeExec(⊤) with Conservative, a reason, and source-located why-traces. Parse/budget failures additionally set Top and use the location-free `literal:js-opaque` failure marker. Supported abstract results, including opaque file contents and unknown booleans, preserve uncertainty as values without fabricating content or existence.

JS `commands` counts distinct reached call locations, excluding module/property lookups. The existing `resolution.kind: builtin` carries the canonical module/export name, such as `fs.readFileSync` or `fs/promises.readFile`; unknown calls use `unknown`. `commandCalls` retains the invoked spelling and canonical resolved identity without shell normalization. Arguments retain literal strings (including empty strings), primitive spellings, or compact JSON for small plain records; unknown/opaque/oversized values use bounded typed markers. Per-value projection is limited to 4096 bytes, records to 32 scalar fields, and metadata collections to 1024 entries. Repeated identical call views deduplicate. Destructive findings use the existing deduplicated command/spec/class/reason shape. JS canonical effects retain bound targets verbatim, including literal `$`, `;`, and leading `-`; shell operand filtering and staging folds do not apply. No report fields are added. See [JavaScript Filesystem Models](../domains/javascript-filesystem.md). `--lang auto` still selects Bash or PowerShell only.

## Error Propagation

Encoding is guarded: `Report.Encode` calls `Report.Validate` first and returns an `error` if the report is malformed (empty `schemaVersion`, empty `lang`, or an invalid effect), so a bad report is never written. The CLI maps failures to exit statuses: `0` for a produced report (or the `--help`/`--version` short-circuits), `1` for an internal failure (analyzer construction or `Encode`/`encodeCompact` failure, printed as `flowsh: encode report: …`), `2` for a usage error (unknown `--lang`, an unknown flag — there is no `--file` — or conflicting sources: `--batch` with a positional argument, `--explain` with `--batch`, `-` with a positional argument), and `3` for an input error (stdin could not be read, or the command was empty: an empty positional argument, empty stdin, or an empty batch — no named input source exists). Because the frontends degrade to ⊤ rather than fail, an analysis of unparseable input still exits `0` with a well-formed report whose `top` is `true` and whose `reason` explains why — exit `1` therefore signals an internal error, never "hard input".

## Breaking Change Checklist

- **Change an `Effect` field/JSON tag, a lattice's `MarshalJSON`, or `Destructiveness`'s encoding** — you MUST bump `engine.SchemaVersion` (`effect-ir/v2`), regenerate `engine/testdata/effect.golden.json` and `engine/testdata/report.golden.json`, and update every consumer (see [frontend-engine.md](frontend-engine.md)).
- **Add/remove/rename a `analysis.Report` field or its JSON tag** — you MUST bump `analysis.ToolVersion` (currently `flowsh/v3`; v1 was the starting public contract carrying `why`, `resolution` and `destructive`, v2 added the additive `commandCalls` and `canonical` fields, and v3 the `score.cradleFlows`/`score.ingestFlows` network-flow fields), update `newReport`/`Validate`, and update the consumers that read those keys: the CLI smoke test in `cmd/flowsh/smoke_test.go` (run by `go test ./...` in `.github/workflows/ci.yml`) asserts `lang`, `effects`, `input`, and `toolVersion`.
- **Change `ToolName` or `SchemaVersion`** (`internal/analysis/analyze.go`) — consumers pin to `"flowsh"` and to `engine.SchemaVersion`; bump deliberately and update this spec.
- **Change the exit-code contract** (`0`/`1`/`2`/`3`) or the stdout framing (the human-summary lines, or the batch NDJSON one-report-per-line form) — you MUST update `cmd/flowsh/main.go`, `cmd/flowsh/main_test.go`, and the CLI smoke test `cmd/flowsh/smoke_test.go`.
- **Change `Encode`'s indentation or key ordering** — it is byte-frozen by the golden fixtures; regenerate them and update consumers that diff the output.
- **Change `ParseLang`'s accepted spellings** — update the CLI contract here and any script relying on an alias.

**Related specs:** [frontend-engine.md](frontend-engine.md) — the `engine.Effect`/`Report` types whose JSON this document freezes; [bind-kb.md](bind-kb.md) — the destructiveness folded into `destructiveness`/`score`; [exec-resolver.md](exec-resolver.md) — how the effects that populate `effects[]` are produced.
