# CLI (flowsh)

## Purpose

`cmd/flowsh` is the public entry point of the effect analyser: it takes one or more shell or PowerShell commands (as a positional argument, on stdin, from a file, or one-per-line in batch mode), runs them through the `internal/analysis` facade, and prints the resulting effects as a human-readable summary or as a JSON report (a single document, or one NDJSON line per command). It is a thin arg-parsing / I/O shell over the facade — all analysis lives in [Analysis Report](analysis-report.md). Dialect sniffing (`--lang auto`), batch iteration and output framing are the CLI's own concern.

## Key Files

- `cmd/flowsh/main.go` — the command: the `exitOK`/`exitInternal`/`exitUsage`/`exitInput` exit codes, the `usageError`/`inputError` types + `exitCode`, `run`, `parseArgs`, `readInput`, `readStdin`, `runBatch`, `splitBatch`, `encodeCompact`, `detectLang`/`isAutoLang`, the `input` type, `writeText`, `writeWhy`, `oneLine`, and the `usage` text.
- `cmd/flowsh/main_test.go` — in-process tests of `run` (flags, stdin/`-`, `--lang auto`, `--batch`, `--version`, exit codes, the extended summary).
- `cmd/flowsh/root_test.go` — tests of source naming (`report.root` per input source) and `--file` handling.

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
	file       string
	fileSet    bool
	command    string
	commandSet bool
	useStdin   bool
}
```

`parseArgs` initialises `lang` to `string(analysis.LangBash)`, so the default dialect is `bash`. `lang` may also be `auto`, which defers the dialect choice until the input is known (see `detectLang`).

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

// input is the command to analyse plus the name of its source: the file path,
// or the RootStdin/RootArgument marker stamped into the report's root.
type input struct{ src, root string }

// usageError maps to exitUsage (2); inputError to exitInput (3).
type usageError struct{ err error }
type inputError struct{ err error }
func exitCode(err error) int                          // err → 0/1/2/3

func parseArgs(args []string) (options, error)      // flags in any position
func readInput(o options, stdin io.Reader) (input, error) // --file, else arg, else stdin
func readStdin(stdin io.Reader) (string, error)     // read + trim stdin, reject empty
func runBatch(o options, in input, lang analysis.Lang, auto bool, stdout io.Writer) error // NDJSON: one report per line
func splitBatch(src string) []string                // batch source → non-blank commands
func encodeCompact(r *analysis.Report) ([]byte, error) // validate + compact single-line JSON
func detectLang(src string) analysis.Lang           // --lang auto: cmdlet/alias heuristic
func isAutoLang(s string) bool                      // whether --lang asked for "auto"
func writeText(w io.Writer, r *analysis.Report)     // human-readable summary
func writeWhy(w io.Writer, r *analysis.Report)      // why-trace (after writeText, with --explain/--why)
func oneLine(s string) string                        // collapse CR/LF to spaces, trim
```

### Usage text

`usage` documents the four invocation forms and the exit statuses:

```
flowsh — effect report for a shell or PowerShell command

usage:
  flowsh [--lang bash|posix|posh|auto] [--json] [--windows] '<command>'
  echo '<command>' | flowsh [--lang bash|posix|posh|auto] [--json] [--windows]
  flowsh --file <path> [--lang bash|posix|posh|auto] [--json]
  flowsh --batch [--lang bash|posix|posh|auto] [--file <path>] [--windows]

options:
  --lang bash|posix|posh|auto
                     dialect of the input (default: bash); "auto" sniffs the
                     input for PowerShell cmdlets/aliases and picks the dialect
  --file PATH        read the command from PATH ("-" for stdin); the report's
                     root names the file
  --batch            read many commands (one per line) and write one JSON report
                     per line (NDJSON) instead of a single report
  --json             emit the full JSON report instead of a summary
  --explain, --why   print the why-trace explaining each effect
  --windows[=bool]   enable PowerShell Registry semantics on any host OS
                     (default: the host's OS decides)
  --version          print the tool and engine versions and exit
  -h, --help         show this help and exit

exit status:
  0  analysis produced a report
  1  analysis failed internally
  2  usage error (bad flags or no input)
  3  input error (the source could not be read, or was empty)
```

## Flow

```
run(args, stdin, stdout, stderr)
   │
   ├─ parseArgs(args) ── error ──► stderr "<err>" + usage ──► return 2
   │
   ├─ o.help ────────────────────► stdout usage ────────────► return 0
   │
   ├─ o.version ─────────────────► stdout flowsh/vN +
   │                               engine.SchemaVersion ─────► return 0
   │
   ├─ !auto: analysis.ParseLang(o.lang) ─ error ──► stderr ──► return 2
   │
   ├─ readInput(o, stdin) ──────── error ──► stderr ────────► return 3
   │
   ├─ o.batch ──► runBatch(o, in, lang, auto, stdout)
   │                 │  splitBatch(in.src) ─ empty ─► stderr ► return 3
   │                 │  per line: lang ← auto ? detectLang(line) : lang
   │                 │            analysis.AnalyzeWith … ─ err ► return 1
   │                 │            encodeCompact(rep) ───── err ► return 1
   │                 └─ Fprintln(stdout, line) ──────────────► return 0
   │
   ├─ auto: lang = detectLang(in.src)
   │     src := in.src;  opts := Options{Root: in.root, …}
   ├─ analysis.AnalyzeWith(lang, src, opts) ─ error ──► stderr ───────► return 1
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
| `--lang <v>`, `-lang <v>` | Set `lang` to the next token (`bash`/`posix`/`posh`, an alias, or `auto`); error `"%s needs a value"` if it is last. |
| `--lang=<v>`, `-lang=<v>` | Set `lang` to the value after `=`. |
| `--file <v>`, `-file <v>` | Set `file` to the next token and `fileSet = true`; error `"%s needs a value"` if it is last. |
| `--file=<v>`, `-file=<v>` | Set `file` and `fileSet = true`. |
| `--json`, `-json` | Set `json = true`. |
| `--batch`, `-batch` | Set `batch = true` (read many commands, one per line, and emit NDJSON). |
| `--explain`, `--why`, `-explain`, `-why` | Set `explain = true` (print the why-trace after the summary). |
| `--windows`, `-windows` | Set `windows = true` and `windowsSet = true`. |
| `--windows=<bool>`, `-windows=<bool>` | Set `windows` to the `strconv.ParseBool` value and `windowsSet = true`; error `"--windows: %q is not a boolean"` on a bad value. |
| `-h`, `--help`, `-help` | Set `help = true`. |
| `--version`, `-version` | Set `version = true`. |
| `-` | Set `useStdin = true`. |
| other `-…` | Error `unknown flag %q`. |
| bare word | Set `command`; a second bare word errors `unexpected extra argument %q`. |

After the token loop, `--file` is rejected together with a positional command (`--file and a positional command are mutually exclusive`) or with the `-` stdin argument (`--file and the "-" stdin argument are mutually exclusive`); `--batch` is rejected together with a positional command (`--batch and a positional command are mutually exclusive`) or with `--explain`/`--why` (`--explain cannot be combined with --batch`).

Input selection (`readInput`, returning an `input{src, root}`):

- `--file PATH` with `PATH != "-"`: read the file, trim trailing newlines, error `<path>: empty command` when empty; `root` is the file path.
- `--file -`: read stdin; `root` is `analysis.RootStdin`.
- Otherwise, if `useStdin` is set (a `-` positional) **or** no positional command was given, read all of stdin; `root` is `analysis.RootStdin`.
- Otherwise `root` is `analysis.RootArgument` and `src` is the positional command verbatim.
- stdin/file text is trimmed of trailing newlines (`TrimRight(s, "\n")`); whitespace-only stdin errors `no command given and stdin is empty`.
- A failure to read the source (a missing/unreadable file, a directory, an empty file or stdin) is an `inputError` and exits `3`, distinct from a usage error (`2`).
- In batch mode (`--batch`) the selected source is split on newlines (via `splitBatch`), blank lines are dropped, and each remaining line is analysed in turn; `root` is the shared source name for every line.

## Invariants

- The exit status is exactly one of `0`, `1`, `2`, `3`: `0` for a produced report, `--help`, or `--version`; `1` for an internal analysis/encode failure; `2` for a usage error (a malformed invocation: flags, language, mutually exclusive sources, no input); `3` for an input error (the named source could not be read, or was empty).
- `--version` writes the report-contract tag (`flowsh/vN`) and `engine.SchemaVersion`, one per line, to **stdout** and exits `0`, before language validation, input reading and analysis; like `--help` it never reads stdin and never requires a command. `--help` takes precedence when both are present (the `help` check precedes the `version` check).
- Usage errors (exit `2`) and input errors (exit `3`) always write a diagnostic to stderr; the argument-parse error additionally appends the `usage` text, while the language and input errors do not.
- When argument parsing succeeds and `help` is set, `run` writes the usage text to **stdout** and exits `0`, before language validation, input reading and analysis. A later usage error during parsing still yields exit `2`.
- The default dialect is `bash` when `--lang` is omitted; `--lang auto` selects the dialect per source (per line in batch mode) via `detectLang`, which never fails and falls back to `bash` when no marker is found.
- With `--lang auto`, an explicit dialect is still validated before the input is read, but `auto` itself is resolved only after the input is known — so `--lang auto` never reads stdin merely to validate a language, and `--lang fish` still exits `2` without consuming input.
- `--lang posix` (alias `sh`) selects the POSIX (`sh`) dialect: the bash frontend parses and executes the source in POSIX mode, so bash-only constructs (e.g. `[[ … ]]`, `${x//a/b}`, `<(...)`, `<<<word`) are not recognised as their bash special forms — a construct that POSIX rejects degrades to ⊤, and `[[ … ]]` becomes an ordinary (unknown) command that degrades to ⊤ rather than the bash `[[ ]]` test clause.
- A positional `-` reads stdin, exactly like omitting the command.
- Flags are position-independent; `flowsh --lang posh 'x'` and `flowsh 'x' --lang posh` behave identically.
- stdin input has trailing `\n` removed, so the rendered `report.input`/summary carries no trailing newline.
- Exactly one command source is analysed: the `--file` file, the single positional argument, or the whole of stdin — never more than one (`--file` is mutually exclusive with both the positional command and `-`; `--batch` is mutually exclusive with the positional command and with `--explain`/`--why`).
- In batch mode (`--batch`) every non-blank input line is analysed and each report is written as one compact, single-line JSON object (NDJSON), in input order. `encodeCompact` (validate + `json.Marshal`) is used rather than the indented `Encode`, so a consumer can split the stream on newlines; the whole batch shares the source's `root`. An empty batch and any per-line analysis/encode failure are mapped onto the stable exit codes (`3`/`1`).
- `report.root` names the source: the `--file` path, or `RootStdin`/`RootArgument` for stdin/argument input.

## Configuration

The CLI has no config file or environment variables; all configuration is command-line flags and the embedded defaults.

| Flag / form | Default | Valid values | Domain |
| --- | --- | --- | --- |
| `--lang`, `-lang`, `--lang=`, `-lang=` | `bash` | `bash`, `posix`, `posh`, `auto` (+ aliases via `ParseLang`) | Analysis dialect |
| `--file`, `-file`, `--file=`, `-file=` | off (use arg/stdin) | a path, or `-` for stdin | Input source; sets `report.root` |
| `--batch`, `-batch` | off (single report) | — | Emit one NDJSON report per input line |
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
| `2` | Usage error: unknown flag, missing flag value, extra argument, `--file`/`--batch` conflict, unknown language, or no input. |
| `3` | Input error: the named source could not be read (missing/unreadable file, a directory), or was empty (empty file, empty stdin, empty batch). |

## Extension Points

- **Add a flag**: add a `case` in `parseArgs`, a field on `options`, and a branch in `run` (or `runBatch`); document it in the `usage` constant. A new error class must be wrapped as a `usageError`/`inputError` so `exitCode` maps it onto `0`/`1`/`2`/`3` — do not invent ad-hoc exit codes.
- **Add a dialect to `--lang auto`**: extend `detectLang`'s marker tables (`psVerbs`, `psParams`, `shellTokens`, `psSyntax`, `shSyntax`); keep it a total function that falls back to `bash`.
- **Extend the summary**: add a line in `writeText`; keep it one line per field (use `oneLine` for multi-line values). The summary already carries the score dimensions (`destructiveness`, `irreversibility`, `breadth`, `influence`, `exfil`), the resolution and the matched destructive entries.
- **Add an output format**: add a branch after `analysis.Analyze` (mirroring the `o.json` branch) and render from the `*analysis.Report`.
- **Change the summary header**: the tests assert on `flowsh effect report` and `lang:            bash`, so update both `writeText` and `main_test.go` together.

## Related Specs

- [Analysis Report](analysis-report.md) — the facade this CLI drives (`lang`/`ParseLang`/`Report`/`Analyze`).
- [Report Contract](../contracts/report-json.md) — the emitted JSON document this CLI prints.
- [Spec System](../META.md) — document formats and update rules.
- [Index](../INDEX.md) — task-to-spec navigation.
