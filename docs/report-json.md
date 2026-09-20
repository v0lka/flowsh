# JSON report reference

`flowsh --json '<command>'` writes a single JSON document to stdout. That
document is a **frozen wire contract**: consumers read it without importing the
Go packages, so they pin to its version tags. This guide describes that document
field by field and explains how to read it. The normative statement of the
contract, and the breaking-change checklist, is
[`specs/contracts/report-json.md`](../specs/contracts/report-json.md).

For the command line itself, see the [CLI user-guide](cli.md).

## Version tags

Every report carries three identity fields:

| Key | Value | Meaning |
| --- | ----- | ------- |
| `schemaVersion` | `effect-ir/v1` | Tags the **effect payload** (`effects[]` and its atoms). Equal to `engine.SchemaVersion`. |
| `tool` | `flowsh` | The tool name (`analysis.ToolName`). |
| `toolVersion` | `flowsh/v2` | Tags the **CLI report shape**: the envelope plus the additive `why`, `resolution`, `destructive`, `commandCalls` and `canonical` fields over v1. Equal to `analysis.ToolVersion`. |

A consumer that parses the effect set pins to `effect-ir/v1`; a consumer that
reads the CLI-specific fields pins to `flowsh/v2`. Any change to the shape of an
emitted field bumps the corresponding tag; the analyser never renames or removes
a field silently.

## Example document

```sh
$ flowsh --json 'rm -rf $HOME'
```

```json
{
  "schemaVersion": "effect-ir/v1",
  "tool": "flowsh",
  "toolVersion": "flowsh/v2",
  "lang": "bash",
  "input": "rm -rf $HOME",
  "root": "<argument>",
  "effects": [
    {
      "kind": "FSWrite",
      "target": { "targets": ["/root"], "arbitrary": false },
      "mode": "Direct",
      "certainty": "Certain",
      "taint": { "labels": [], "arbitrary": false },
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
        { "rule": "fs.write", "premises": ["command:rm"], "note": "derived from command",
          "loc": { "file": "<argument>", "line": 1, "col": 1 } },
        { "rule": "fs.write", "premises": ["flag:-f"], "note": "derived from flag",
          "loc": { "file": "<argument>", "line": 1, "col": 6 } }
      ]
    }
  ],
  "conservative": false,
  "top": false,
  "commands": 1,
  "resolution": { "invoked": "rm", "kind": "command", "name": "rm" },
  "commandCalls": [ { "invoked": "rm", "resolved": "rm", "args": [ "-rf", "/root" ] } ],
  "canonical": {
    "effects": [
      {
        "kind": "FSWrite",
        "target": { "targets": ["/root"], "arbitrary": false },
        "mode": "Direct",
        "certainty": "Certain",
        "taint": { "labels": [], "arbitrary": false },
        "reversible": false
      }
    ],
    "key": "FSWrite|Direct|[/root]"
  },
  "destructive": [
    { "command": "rm", "spec": "-f", "class": "E",
      "reason": "forced removal that suppresses prompts and hides errors on missing files" },
    { "command": "rm", "spec": "-r", "class": "E",
      "reason": "recursively removes a whole directory tree, with no confirmation by default" }
  ]
}
```

(The `why` trace is shortened here for width; a real trace carries one step per
supporting flag/operand/source/sink. Keys are emitted in the struct's declaration
order, and the encoding is indent-frozen; the golden fixtures under
[`engine/testdata/`](../engine/testdata/) pin the exact bytes.)

## Envelope fields

Present on every report:

| Key | Type | Meaning |
| --- | ---- | ------- |
| `schemaVersion` | string | Frozen effect-schema tag (`effect-ir/v1`). |
| `tool` | string | `flowsh`. |
| `toolVersion` | string | CLI report-contract tag (`flowsh/v2`). |
| `lang` | string | Dialect actually analysed: `bash`, `posix`, or `posh`. |
| `input` | string | The command source text that was analysed. |

| Key | Type | Present when | Meaning |
| --- | ---- | ------------ | ------- |
| `root` | string | the CLI set it | Name of the source: a file path, or the marker `<argument>` / `<stdin>`. Omitted only when unset (library use). |

## Analysis fields

| Key | Type | Present when | Meaning |
| --- | ---- | ------------ | ------- |
| `effects` | array of effect | always (never `null`) | The implied effects, merged by (kind, mode). May be empty. |
| `destructiveness` | string | always | Worst-case severity of the effects: `None` \| `Low` \| `Medium` \| `High` \| `Critical`. |
| `score` | object | always | Composite, orderable risk — see [score](#score). |
| `conservative` | bool | always | The analysis could not bound the input but did not fully degrade to ⊤. |
| `top` | bool | always | The analysis degraded to the top element ⊤ (unknown/unbounded). |
| `reason` | string | `conservative` or `top` | Why the analysis degraded. |
| `commands` | integer | always | Number of commands/statements analysed. |
| `resolution` | object | always | Aggregated name resolution — see [resolution](#resolution). |
| `commandCalls` | array of call | a call reached the binder | Per-command resolution view — see [commandCalls](#commandcalls). |
| `canonical` | object | the report has effects | Effect-based canonical form — see [canonical](#canonical). |
| `why` | array of trace | trace non-empty | Per-effect derivation — see [why](#why). |
| `destructive` | array of finding | matches non-empty | Matched destructive-flags entries — see [destructive](#destructive). |
| `notes` | array of string | notes non-empty | Frontend diagnostics. |

### effects

Each element of `effects[]` is one implied effect:

| Key | Type | Meaning |
| --- | ---- | ------- |
| `kind` | string | The effect kind, from the closed set (see [Effect kinds](../README.md#effect-kinds)). |
| `target` | object | `{ "targets": [string], "arbitrary": bool }` — the concrete targets; `arbitrary: true` marks the any-target (⊤) scope. |
| `mode` | string | How the effect happens: `Direct` \| `Transitive` \| `Ambient` \| `Conditional` (see [Effect modes](../README.md#effect-modes)). |
| `certainty` | string | Confidence it occurs: `Unknown` \| `Unlikely` \| `Possible` \| `Likely` \| `Certain`. |
| `taint` | object | `{ "labels": [string], "arbitrary": bool }` — provenance labels; `arbitrary: true` marks ⊤ provenance. |
| `reversible` | bool | Whether the effect can be undone. |

An effect's stable identity, used as the key in `why[].effect` and `score.exfilPairs`, is `kind|mode|[targets]`. The `[targets]` part is the target set with each target's `\`, `,` and `]` backslash-escaped, so a target containing them cannot forge a set boundary and the key stays injective: a Windows target `C:\Windows` renders as `C:\\Windows`, and a single target `a,b` renders as `[a\,b]` (distinct from the two-target set `[a,b]`). For targets containing none of those three bytes (ordinary POSIX text), the spelling is unchanged (e.g. `FSWrite|Direct|[/root]`).

### score

| Key | Type | Meaning |
| --- | ---- | ------- |
| `destructiveness` | string | Severity of the effects themselves. |
| `irreversibility` | string | How hard the worst effect is to undo. |
| `breadth` | string | Extent of what is affected (secret paths raise it). |
| `influence` | string | Attacker control over the data. |
| `exfil` | string | Credential/data exfiltration risk. |
| `confidence` | integer | Weakest-link confidence across effects, `0`–`100`. |
| `reversible` | bool | True iff every effect is reversible. |
| `grade` | string | The joined headline grade across the dimensions above. |
| `exfilPairs` | array | Detected credential-egress pairings (omitted when none; see below). |

Each `exfilPairs[]` element is `{ "source": effect, "sink": effect }`, where
`source` is the secret read (a `CredAccess`, or an `FSRead`/`FSMeta` of a
secret-bearing path) and `sink` is the tainted egress carrying it out. Both are
full effect objects in the shape of [effects](#effects).

### resolution

| Key | Type | Meaning |
| --- | ---- | ------- |
| `kind` | string | How the invoked name resolved: `empty` \| `assignment` \| `builtin` \| `function` \| `alias` \| `command` \| `unknown`. |
| `invoked` | string | The name as written at the call site. |
| `name` | string | The resolved target name (differs from `invoked` for aliases/functions). |
| `aliasChain` | array of string | The alias-expansion chain, when the name resolved through aliases. |

The object always carries the *most informative* resolution observed across the
program's calls. It is the zero value `{ "kind": "" }` whenever no call reached
the binder: on the PowerShell path (which resolves through its own alias/cmdlet
tables), and on the bash path for a program whose statements are not command
invocations (a bare assignment, a redirection, or a pure shell-state builtin
such as `true` or `:`), none of which are routed to the binder. The `assignment` and
`empty` kinds are emitted only when such a statement is passed to the binder
directly (e.g. through `bind.Bind`); the bash frontend executes them itself.

### commandCalls

The per-command companion of `resolution`: one entry per distinct call the
binder saw, in traversal order (a loop body contributes one entry). It is
omitted when no call reached the binder (the same condition as a zero-value
`resolution`).

| Key | Type | Meaning |
| --- | ---- | ------- |
| `invoked` | string | The name exactly as written at the call site. |
| `resolved` | string | The normalized binary: the basename of the resolved name with a `node_modules/.bin` segment stripped, and for a package runner (`npx`, `bunx`) the first non-flag operand. |
| `args` | array of string | The invocation's argument values after normalization (the runner's own words consumed; empty values dropped). |
| `redirs` | array of redirect | The statement's resolved redirections (`{ "op": string, "target": string, "known": bool }`), the ordering witness the canonical staging fold reads. |

### canonical

The effect-based canonical form: the report's effect set normalized for
signature comparison, plus the deterministic key derived from it. It is present
whenever the report has effects. Two invocations that differ in form but not in
effect — a blocked command retried through an equivalent form — carry the same
key. The normalizations are deliberately coarse (staged temp files fold onto the
destination the trailing `mv` names; non-path operand targets drop out).

| Key | Type | Meaning |
| --- | ---- | ------- |
| `effects` | array of effect | The normalized effect set, in the shape of [effects](#effects). |
| `key` | string | The effects' frozen `Effect.Key()` values, sorted and joined by `;`. Empty when there are no canonical effects. |

### destructive

Each element is one matched entry of the knowledge base's destructive-flags table:

| Key | Type | Meaning |
| --- | ---- | ------- |
| `command` | string | The KB command the entry belongs to. |
| `spec` | string | The parameter spec (flag/option/operand) that matched. |
| `class` | string | Severity class `A`–`E` (`A`=None … `E`=Critical). |
| `reason` | string | Why the entry is destructive. |

The entries are de-duplicated by `(command, spec)` and sorted. A matched class
joins (raises) the report's `destructiveness` and `score.grade`; it never lowers
them.

### why

Each element explains one reported effect:

| Key | Type | Meaning |
| --- | ---- | ------- |
| `effect` | string | The `Effect.Key()` of the explained effect. |
| `because` | array of step | The ordered chain of inference steps. |

Each step:

| Key | Type | Present when | Meaning |
| --- | ---- | ------------ | ------- |
| `rule` | string | always | The rule that fired (e.g. `fs.write`). |
| `premises` | array of string | premises non-empty | The tokens it consumed (`command:rm`, `flag:-f`, `operand:/root`, `source:File`, `sink:NetEgress`, …). |
| `note` | string | note non-empty | A human hint about the atom. |
| `loc` | object | position known | `{ "file": string, "line": int, "col": int }` — the 1-based source position. |

## Reading the result

- `effects` is always an array, never `null`; it may be empty (`[]`). A non-empty
  list means the analyser resolved the command against its knowledge base.
- `top: true` (or `conservative: true`) means the analyser could not fully bound
  the input: treat it as "unknown, potentially anything". `reason` explains why.
- The invariant the corpus enforces is no silent miss. Every analysed command
  yields at least one effect or a ⊤/conservative report, never an empty "all
  clear". A consumer can replicate the check with `len(effects) > 0 || top ||
  conservative`.

## Stability and breaking changes

The document is frozen. The effect payload is pinned by the golden fixtures
[`engine/testdata/report.golden.json`](../engine/testdata/report.golden.json) and
[`engine/testdata/effect.golden.json`](../engine/testdata/effect.golden.json);
the envelope is pinned by the CLI smoke test
[`cmd/flowsh/smoke_test.go`](../cmd/flowsh/smoke_test.go). Changing the shape of an emitted
field is a breaking change: bump the relevant tag (`effect-ir/v1` or
`flowsh/v2`), regenerate the fixtures, and update the consumer. The full
checklist is in the
[report contract](../specs/contracts/report-json.md#breaking-change-checklist).

## See also

- [CLI user-guide](cli.md) — flags, exit codes, and the human summary that maps
  onto these fields.
- [Report contract](../specs/contracts/report-json.md) — the normative boundary
  and the breaking-change checklist.
- [Effect IR](../specs/domains/engine/effect-ir.md) and
  [Scoring](../specs/domains/engine/scoring.md) — how the payload is produced.
- [Documentation index](README.md) — the other guides.
