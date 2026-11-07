# CLI (flowsh)

## Purpose

`cmd/flowsh` is the public entry point of the effect analyser: it takes a shell, PowerShell, or JavaScript program (as a single positional argument or on stdin — one command per line in batch mode; the input surface is the argument and stdin only, the analyser reads no caller-named file, deliberately, per SECURITY.md Hard Constraint 2), runs it through the `internal/analysis` facade, and prints the resulting effects as a human-readable summary or as a JSON report (a single document, or one NDJSON line per command). It is a thin arg-parsing / I/O shell over the facade — all analysis lives in [Analysis Report](analysis-report.md). Dialect sniffing (`--lang auto`), batch iteration (including the cross-line-state and fragment degradation below) and output framing are the CLI's own concern.

## Key Files

- `cmd/flowsh/main.go` — the command: the `exitOK`/`exitInternal`/`exitUsage`/`exitInput` exit codes, the `usageError`/`inputError` types + `exitCode`/`errorLine`, `run`, `parseArgs`, `readInput`, `readStdin`, `runBatch`, `splitBatch`, `encodeCompact`, `analyzeAuto`, the `batchState` cross-line tracker + `lineContinues`/`degrade`, `detectLang`/`isAutoLang`, the `input` type, `optsFor`, `writeText`, `writeWhy`, `oneLine`, `sanitize`, and the `usage` text.
- `cmd/flowsh/main_test.go` — in-process tests of `run` (flags, stdin/`-`, `--lang auto`, `--batch`, `--version`, exit codes, the extended summary) and the pinned findings: no `--file` input (`TestFinding001NoFileInput`), sanitised output.
- `cmd/flowsh/smoke_test.go` — compiled CLI reports and exit statuses.
- `cmd/flowsh/root_test.go` — `TestRootDistinctPerInputSource` (the `report.root` marker per input source: argument, stdin, `-`) and `TestExplainPositions` (why-step source positions rendered by `--explain`). No `--file` handling exists.
- `cmd/flowsh/posix_test.go` — `TestRunPosixDialect`, the CLI acceptance for `--lang posix`/`sh` (the POSIX variant of the bash frontend).

## Core Types

### Parsed options

```go
type options struct {
	lang       string
	json       bool
	explain    bool
	batch      bool
	windows    bool
	windowsSet bool
	help       bool
	version    bool
	command    string
	commandSet bool
	useStdin   bool
}
```

`parseArgs` initialises `lang` to `string(api.LangBash)`, so the default dialect is `bash`. `lang` may also be `auto`, which defers the dialect choice until the input is known (see `detectLang`).

### Program entry points

```go
// Exit codes: the stable return-value contract of run (0 ok / 1 internal /
// 2 usage / 3 input).
const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInput    = 3
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// run is the whole program as a testable function: it parses args, reads the
// command, analyses it and writes the report. It returns the process exit status.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int

// input is the command to analyse plus the name of its source: the
// RootStdin/RootArgument marker stamped into the report's root (no file path —
// there is no file input).
type input struct{ src, root string }

// usageError maps to exitUsage (2); inputError to exitInput (3).
type usageError struct{ err error }
type inputError struct{ err error }
func exitCode(err error) int                          // err → 0/1/2/3

func parseArgs(args []string) (options, error)      // flags in any position
func readInput(o options, stdin io.Reader) (input, error) // arg if given, else stdin
func readStdin(stdin io.Reader) (string, error)     // read + trim stdin, reject empty
func runBatch(o options, in input, lang api.Lang, auto bool, stdout io.Writer) error // NDJSON: one report per line
func splitBatch(src string) []string                // batch source → non-blank commands
func encodeCompact(r *api.Report) ([]byte, error) // validate + compact single-line JSON
func detectLang(src string) api.Lang           // --lang auto: cmdlet/alias heuristic
func isAutoLang(s string) bool                      // whether --lang asked for "auto"
func writeText(w io.Writer, r *api.Report)     // human-readable summary
func writeWhy(w io.Writer, r *api.Report)      // why-trace (after writeText, with --explain/--why)
func oneLine(s string) string                        // collapse CR/LF to spaces, trim
```

### Usage text

`usage` documents the three invocation forms and the exit statuses:

```
flowsh — effect report for shell, PowerShell, or JavaScript source

usage:
  flowsh [--lang bash|posix|posh|js|auto] [--json] [--windows] '<command>'
  echo '<command>' | flowsh [--lang bash|posix|posh|js|auto] [--json] [--windows]
  flowsh --batch [--lang bash|posix|posh|js|auto] [--windows]

options:
  --lang bash|posix|posh|js|auto
                     dialect of the input (default: bash); "auto" sniffs the
                     input for PowerShell cmdlets/aliases and picks bash or posh;
                     js (aliases: javascript, node, nodejs) evaluates a bounded
                     subset; calls and unsupported execution report ⊤
  --batch            read many commands (one per line) from stdin and write one
                     JSON report per line (NDJSON) instead of a single report;
                     a line that uses a variable an earlier line assigned is
                     degraded to top/conservative (cross-line state is not
                     modelled), so a script should be analysed as one command
  --json             emit the full JSON report instead of a summary
  --explain, --why   print the why-trace explaining each effect
  --windows[=bool]   enable PowerShell Registry semantics on any host OS
                     (default: the host's OS decides)
  --version          print the tool and engine versions and exit
  -h, --help         show this help and exit

exit status:
  0  analysis produced a report
  1  analysis failed internally
  2  usage error (unknown flag or unknown --lang)
  3  input error (stdin could not be read, or the command was empty)
```

## Flow

```
run(args, stdin, stdout, stderr)
   │
   ├─ parseArgs(args) ── error ──► stderr "<err>" + usage ──► return 2
   │
   ├─ o.help ────────────────────► stdout usage ────────────► return 0
   │
   ├─ o.version ─────────────────► stdout api.ToolVersion +
   │                               engine.SchemaVersion (+ a third
   │                               "flowsh <buildVersion>" line when a
   │                               release ldflags stamp is set) ► return 0
   │
   ├─ !auto: api.ParseLang(o.lang) ─ error ──► stderr ──► return 2
   │
   ├─ readInput(o, stdin) ──────── error ──► stderr ────────► return 3
   │
   ├─ o.batch ──► runBatch(o, in, lang, auto, stdout)
   │                 │  splitBatch(in.src) ─ empty ─► stderr ► return 3
   │                 │  per line: auto ? analyzeAuto(line, opts)
   │                 │            : api.AnalyzeWith(lang, line, opts)
   │                 │            lineContinues(line) → degrade the fragment
   │                 │            and its successor; batchState.check →
   │                 │            degrade cross-line variable/positional refs
   │                 │            encodeCompact(rep) ───── err ► return 1
   │                 └─ Fprintln(stdout, line) ──────────────► return 0
   │
   ├─ opts := Options{Root: in.root, …}
   ├─ auto: rep ← analyzeAuto(in.src, opts) — detectLang, then the
   │        alternate dialect if uncovered; neither covers → ⊤
   │        ("no dialect could bound the input")
   ├─ else: rep ← api.AnalyzeWith(lang, in.src, opts) ─ err ► return 1
   │
   ├─ o.json:
   │     rep.Encode() ────────────── error ──► stderr ──────► return 1
   │     Fprintln(stdout, json) ────────────────────────────► return 0
   │
   └─ else: writeText(stdout, rep) ─────────────────────────► return 0
         (+ writeWhy(stdout, rep) when o.explain)
```

Argument parsing (`parseArgs`) applies each token in order, so flags may appear before or after the command:

| Token | Effect |
| --- | --- |
| `--lang <v>`, `-lang <v>` | Set `lang` to the next token (`bash`/`posix`/`posh`/`js`, an alias, or `auto`); error `"%s needs a value"` if it is last. |
| `--lang=<v>`, `-lang=<v>` | Set `lang` to the value after `=`. |
| `--json`, `-json` | Set `json = true`. |
| `--batch`, `-batch` | Set `batch = true` (read many commands, one per line, and emit NDJSON). |
| `--explain`, `--why`, `-explain`, `-why` | Set `explain = true` (print the why-trace after the summary). |
| `--windows`, `-windows` | Set `windows = true` and `windowsSet = true`. |
| `--windows=<bool>`, `-windows=<bool>` | Set `windows` to the `strconv.ParseBool` value and `windowsSet = true`; error `"--windows: %q is not a boolean"` on a bad value. |
| `-h`, `--help`, `-help` | Set `help = true`. |
| `--version`, `-version` | Set `version = true`. |
| `-` | Set `useStdin = true`. |
| other `-…` | Error `unknown flag %q` — this is how `--file` is rejected: there is no such flag, so `--file <path>` is a usage error (exit `2`). |
| bare word | Set `command`; a second bare word errors `unexpected extra argument %q`. |

After the token loop, the `-` stdin argument is rejected together with a positional command (`the "-" stdin argument and a positional command are mutually exclusive`); `--batch` is rejected together with a positional command (`--batch and a positional command are mutually exclusive`) or with `--explain`/`--why` (`--explain cannot be combined with --batch`). There are no `--file` cases in `parseArgs` at all — no file is ever opened.

Input selection (`readInput`, returning an `input{src, root}`) — the analyser reads no caller-named file: the input surface is the single positional argument and stdin only, so the CLI cannot be turned into an arbitrary-file-read primitive by a wrapper that forwards untrusted paths (SECURITY.md Hard Constraint 2; pinned by `TestFinding001NoFileInput`, which requires `--file` to exit `2` with an unknown-flag diagnostic and nothing on stdout):

- If `useStdin` is set (a `-` positional) **or** no positional command was given, read all of stdin; `root` is `api.RootStdin`.
- Otherwise `root` is `api.RootArgument` and `src` is the positional command, `TrimSpace`d; an all-whitespace argument errors `empty command argument`.
- stdin text is trimmed of trailing newlines (`TrimRight(s, "\r\n")` — both CR and LF); whitespace-only stdin errors `no command given and stdin is empty`.
- A failure to read stdin, empty stdin, or an empty positional argument is an `inputError` and exits `3`, distinct from a usage error (`2`). No file is read, so there is no file-failure class.
- In batch mode (`--batch`) the selected source is split on newlines (via `splitBatch`), blank lines are dropped, and each remaining line is analysed in turn; `root` is the shared source name for every line.

Explicit `--lang js` (aliases `javascript`, `node`, `nodejs`, trimmed and case-insensitive) routes source to the [bounded JavaScript evaluator](javascript-frontend.md). Calls and unsupported execution degrade to top with a reason. Pure understood programs may have no effects and remain uncovered under policy. `--lang auto` continues to choose bash or PowerShell only. Existing input validation and batch line splitting apply to JS too.

## Invariants

- The exit status is exactly one of `0`, `1`, `2`, `3`: `0` for a produced report, `--help`, or `--version`; `1` for an internal analysis/encode failure; `2` for a usage error (a malformed invocation: unknown flag, unknown `--lang`, flag/argument conflicts — `--batch` + positional, `--batch` + `--explain`/`--why`, `-` + positional); `3` for an input error (stdin could not be read, or the command was empty — "no input" is exit `3`, not `2`).
- `--version` prints `api.ToolVersion` and `engine.SchemaVersion`, one per line, to **stdout** and exits `0`, before language validation, input reading and analysis; when the release build stamps `main.buildVersion` via ldflags, a third line `flowsh <buildVersion>` is printed after the two contract lines — additive build metadata only, the frozen contract versions are unaffected. Like `--help` it never reads stdin and never requires a command; `--help` takes precedence when both are present (the `help` check precedes the `version` check).
- Usage errors (exit `2`) and input errors (exit `3`) always write a diagnostic to stderr; the argument-parse error additionally appends the `usage` text, while the language and input errors do not.
- When argument parsing succeeds and `help` is set, `run` writes the usage text to **stdout** and exits `0`, before language validation, input reading and analysis. A later usage error during parsing still yields exit `2`.
- The default dialect is `bash` when `--lang` is omitted; `--lang auto` analyses under the dialect `detectLang` sniffs (per source, per line in batch mode — `detectLang` itself never fails and falls back to `bash` when no marker is found) and, when that report is uncovered (no effects, no ⊤, not conservative), `analyzeAuto` re-analyses the same text under the alternate dialect (`bash` ⇄ `posh`); if neither dialect covers, the report degrades to ⊤/conservative with reason `no dialect could bound the input`. The sniffer may choose the presentation, never the bound.
- With `--lang auto`, an explicit dialect is still validated before the input is read, but `auto` itself is resolved only after the input is known — so `--lang auto` never reads stdin merely to validate a language, and `--lang fish` still exits `2` without consuming input.
- `--lang posix` (alias `sh`) selects the POSIX (`sh`) dialect: the bash frontend parses and executes the source in POSIX mode, so bash-only constructs (e.g. `[[ … ]]`, `${x//a/b}`, `<(...)`, `<<<word`) are not recognised as their bash special forms — a construct that POSIX rejects degrades to ⊤, and `[[ … ]]` becomes an ordinary (unknown) command that degrades to ⊤ rather than the bash `[[ ]]` test clause.
- A positional `-` reads stdin, exactly like omitting the command.
- Flags are position-independent; `flowsh --lang posh 'x'` and `flowsh 'x' --lang posh` behave identically.
- stdin input has trailing `\r\n` removed (both CR and LF), so the rendered `report.input`/summary carries no trailing newline.
- Exactly one command source is analysed: the single positional argument or the whole of stdin — never more than one, and never a file (`-` and `--batch` are mutually exclusive with the positional command; `--batch` also with `--explain`/`--why`). The analyser reads no caller-named file, so the CLI cannot be turned into an arbitrary-file-read primitive by a wrapper that forwards untrusted paths (SECURITY.md Hard Constraint 2); `--file` is an unknown flag (exit `2`), pinned by `TestFinding001NoFileInput`.
- In batch mode (`--batch`) every non-blank input line is analysed and each report is written as one compact, single-line JSON object (NDJSON), in input order. `encodeCompact` (validate + `json.Marshal`) is used rather than the indented `Encode`, so a consumer can split the stream on newlines; the whole batch shares the source's `root`. An empty batch (`no commands in batch input`) and any per-line analysis/encode failure are mapped onto the stable exit codes (`3`/`1`).
- Batch cross-line state (`batchState`): each line is analysed against its own abstract state, so a line that references a variable an earlier line assigned — matched as a parameter expansion (`$T`, `${T}`, …), never a bare substring — or a positional parameter after an earlier line's `set --`/`shift`, degrades to ⊤/conservative (`cross-line state: $X was assigned on an earlier batch line`; the positional variant names the positional parameters) instead of silently analysing against an empty state. Assigned names are collected from the line's own `EnvWrite` effect targets plus a scan for assignment, loop-variable and `getopts` forms.
- Batch fragments (`lineContinues`): a line ending in an odd number of backslashes or leaving a quote open is only the first fragment of a program that spans lines, and so is the line that follows it; both are degraded (`batch line is a fragment of a program that spans lines`) — the one-command-per-line contract is enforced, not assumed.
- `sanitize` is applied to all report-derived text output (`writeText`, `writeWhy`, `oneLine`): C0 controls (0x00–0x1F, including ESC and CR/LF), DEL (0x7F) and C1 controls (0x80–0x9F) are dropped, a tab is rendered as the two characters `\t`, and Unicode bidi overrides (U+202A–U+202E, U+2066–U+2069) are dropped, so an analysed command cannot forge report lines or drive the terminal.
- `report.root` is only ever `RootStdin` or `RootArgument` (stdin/argument input); there is no file input, so no path is ever stamped.

## Configuration

The CLI has no config file or environment variables; all configuration is command-line flags and the embedded defaults.

| Flag / form | Default | Valid values | Domain |
| --- | --- | --- | --- |
| `--lang`, `-lang`, `--lang=`, `-lang=` | `bash` | `bash`, `posix`, `posh`, `js`, `auto` (+ aliases via `ParseLang`) | Analysis dialect |
| `--batch`, `-batch` | off (single report) | — | Emit one NDJSON report per input line (read from stdin) |
| `--json`, `-json` | off (summary) | — | Output format |
| `--explain`, `--why`, `-explain`, `-why` | off | — | Print the why-trace after the summary |
| `--windows`, `-windows`, `--windows=` | host OS (`GOOS == "windows"`) | any `strconv.ParseBool` value (`true`/`false`, and also `1`/`0`/`t`/`f`/`T`/`F`/`TRUE`/`FALSE`) | PowerShell Registry provider |
| `--version`, `-version` | off | — | Print the tool and engine versions and exit |
| `-h`, `--help`, `-help` | off | — | Help |
| `-` (positional) | off | — | Read stdin |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Analysis produced a report (or `--help`/`--version`). |
| `1` | Analysis failed internally, or the report could not be encoded. |
| `2` | Usage error: unknown flag (`--file` included — there is no such flag), missing flag value, extra argument, `--batch` + positional, `--batch` + `--explain`/`--why`, `-` + positional, or unknown language. |
| `3` | Input error: stdin could not be read (`read stdin: …`), empty stdin (`no command given and stdin is empty`), empty positional argument (`empty command argument`), or empty batch (`no commands in batch input`). No file is ever opened. |

## Extension Points

- **Add a flag**: add a `case` in `parseArgs`, a field on `options`, and a branch in `run` (or `runBatch`); document it in the `usage` constant. A new error class must be wrapped as a `usageError`/`inputError` so `exitCode` maps it onto `0`/`1`/`2`/`3` — do not invent ad-hoc exit codes.
- **Add a dialect to `--lang auto`**: extend `detectLang`'s marker tables (`psVerbs`, `psParams`, `shellTokens`, `psSyntax`, `shSyntax`); keep it a total function that falls back to `bash`.
- **Extend the summary**: add a line in `writeText`; keep it one line per field (use `oneLine` for multi-line values). The summary already carries the score dimensions (`destructiveness`, `irreversibility`, `breadth`, `influence`, `exfil`), the resolution and the matched destructive entries. The two network-flow signals `score.cradleFlows` and `score.ingestFlows` are deliberately **JSON-only**: `writeText` does not render them, so a text-mode consumer must use `--json` (or the `--batch` NDJSON) to read them.
- **Add an output format**: add a branch after `api.Analyze` (mirroring the `o.json` branch) and render from the `*api.Report`.
- **Change the summary header**: the tests assert on `flowsh effect report` and `lang:            bash`, so update both `writeText` and `main_test.go` together.

## Related Specs

- [Analysis Report](analysis-report.md) — the facade this CLI drives (`lang`/`ParseLang`/`Report`/`Analyze`).
- [Report Contract](../contracts/report-json.md) — the emitted JSON document this CLI prints.
- [Spec System](../META.md) — document formats and update rules.
- [Index](../INDEX.md) — task-to-spec navigation.
