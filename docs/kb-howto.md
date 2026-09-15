# Adding a command to the knowledge base

The knowledge base (KB) is the effect dataset behind every analysis: a
hand-verified mapping from a command's command-line parameters to the effects
those parameters contribute, plus a separate destructive-flags table. It is
authored as YAML under [`kb/data/`](../kb/data/), embedded into the binary, and
parsed at start-up without ever touching the filesystem.

This guide is the practical workflow for adding or changing an entry. The
**authoritative** schema, types and invariants live in
[`specs/domains/knowledge-base.md`](../specs/domains/knowledge-base.md); the
binder that consumes the KB is described in
[`specs/domains/binding.md`](../specs/domains/binding.md) and the
[`bind ↔ kb` contract](../specs/contracts/bind-kb.md). Read those three first.

## How it fits together

```
kb/data/*.yaml  ──▶  effects on a bound command  ──▶  a corpus case  ──▶  go test ./kb/ ./bind/
   (author)              (bind)                          (regression)        (validate)
```

- `kb/schema.go` — the frozen document schema and its types.
- `kb/loader.go` — the loader: `go:embed data/*.yaml`, the decode/merge/build/validate pipeline.
- `kb/data/*.yaml` — one document per command tradition; discovery is automatic, so the set grows by adding files.

Every document declares the same frozen schema version, `effect-kb/v2`; a
document authored against an unknown version is rejected rather than mis-read.
The full list of documents and the commands each covers is in the
[knowledge-base spec](../specs/domains/knowledge-base.md) — the files remain the
single source of truth.

## Workflow

### 1. Pick the document

Choose the `kb/data/*.yaml` document for the command's tradition (e.g.
`coreutils.yaml` for POSIX/GNU utilities, `net.yaml` for network clients,
`destructive.yaml` for the destructive table). Adding a **new** `*.yaml` file is
also fine — discovery is automatic — but keep one tradition per document.

### 2. Add the command entry

A command entry declares a name, exactly one dialect, optional aliases, and its
parameters. Each parameter maps a written `spec` to an effect:

```yaml
commands:
  - name: rm
    dialect: posix
    aliases:
      - remove
    params:
      - spec: "-r"
        kind: flag
        effect: {kind: FSWrite, mode: Direct, valueFrom: args}
      - spec: "-i"
        kind: flag
        effect: {kind: FSWrite, mode: Conditional, valueFrom: args}
      - spec: FILE
        kind: positional
        effect: {kind: FSWrite, mode: Direct, valueFrom: args}
```

| Field | Values | Notes |
| ----- | ------ | ----- |
| `name` | string | Unique across the whole KB. |
| `dialect` | a dialect name | Exactly one per command (e.g. `posix`, `gnu`, `netcat`, `builtin`). Every dialect must be exercised by at least one command. |
| `aliases` | list of string | Optional; also unique across the KB. |
| `params[].spec` | string | Written exactly as typed. `flag`/`option` specs start with `-`; `assign` specs end with `=`; `positional` specs do not start with `-`. |
| `params[].kind` | `flag` \| `option` \| `positional` \| `assign` | How the parameter is written. |
| `params[].effect.kind` | effect kind | From the core's closed set (`FSRead`, `FSWrite`, `NetEgress`, `CredAccess`, …). |
| `params[].effect.mode` | `Direct` \| `Transitive` \| `Ambient` \| `Conditional` | How the effect happens. |
| `params[].effect.valueFrom` | `args` \| `flagValue` \| `stdin` \| `env` \| `cwd` \| `self` \| `literal` | Which token of the invocation becomes the effect's target. |
| `params[].effect.fileRef` | bool | Optional; `@file` convention — only valid with `valueFrom: flagValue`. |

Use the conservative default when unsure: leave the parameter unmapped and the
analysis degrades to ⊤, rather than claiming a narrower effect than is true.

### 3. Record destructive flags (if any)

A flag known to be destructive gets an entry in the
[`destructive.yaml`](../kb/data/destructive.yaml) table. The classes `A`–`E` line
up with the core severity lattice (`A`=None … `E`=Critical):

```yaml
destructive:
  - command: rm
    spec: "-r"
    class: E
    reason: recursively removes a whole directory tree, with no confirmation by default
```

Every entry **must reference a parameter that is actually declared on a known
command** — the loader enforces this referential integrity. A matched entry joins
(raises) the report's `destructiveness` and `grade`; it never lowers them.

### 4. Add a corpus case

Add a case that exercises the new command to [`testdata/corpus/`](../testdata/corpus/)
(the regression corpus). Drop a new named document or extend an existing one; the
loader picks it up automatically. Each case is:

```json
{ "id": "ben-newcmd", "group": "benign", "lang": "bash", "input": "newcmd -x file", "note": "purpose of the case" }
```

| Field | Notes |
| ----- | ----- |
| `id` | Stable and unique across the whole corpus. |
| `group` | One of `guardfall`, `destructive`, `benign`, `ps`. |
| `category` | `A`–`E` **iff** `group` is `guardfall`; must be absent otherwise. |
| `lang` | The dialect the input is written in (`bash`, `posix`, `posh`). |
| `input` | The command source text. |
| `note` | Free-form documentation of the case's intent. |

Every non-`benign` case must be classified as **effect present or ⊤** (the
"no silent miss" invariant); `benign` cases are the precision control and may
legitimately yield nothing. See the
[conformance corpus section](../CONTRIBUTING.md#the-conformance-corpus) in
`CONTRIBUTING.md` for the groups and GuardFall classes.

### 5. Validate

Run the focused checks while iterating, then the full gate before opening a pull
request:

```sh
go test ./kb/ ./bind/     # schema, loader and binding for the new entry
go build ./...            # everything still builds
go vet ./...              # static checks
gofmt -l .                # must print nothing
go test ./...             # corpus gate (no-silent-miss) + latency + recall gates
```

`go test ./kb/ ./bind/` exercises the loader (version rejection,
referential-integrity, dialect coverage) and the binder against your change; the
full `go test ./...` additionally runs the corpus, latency and recall gates. The
CI gates are listed in
[`CONTRIBUTING.md`](../CONTRIBUTING.md#ci-gates).

## Invariants to respect

The loader enforces these, and a violation fails the build or the tests:

- every data document declares exactly one schema version, and all documents in a
  load agree on it;
- command names and aliases are unique across the whole KB;
- destructive entries are unique by `(command, spec)` and each references a
  declared parameter;
- a parameter's `spec` syntax matches its `kind` (`flag`/`option` start with `-`,
  `assign` ends with `=`, `positional` does not start with `-`);
- an effect's `kind`/`mode` are members of the core's closed sets, and `fileRef`
  is set only with `valueFrom: flagValue`;
- a command belongs to exactly one dialect, and every dialect is exercised by at
  least one command.

The guiding rule is **degrade to ⊤, never guess**: a parameter you cannot map is
better left unmapped than approximated.

## See also

- [Knowledge Base spec](../specs/domains/knowledge-base.md) — the authoritative
  schema, types and full command→document map.
- [`bind ↔ kb` contract](../specs/contracts/bind-kb.md) — how the binder consumes
  the KB to produce effects.
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — architecture, build/test, CI gates,
  and the conformance corpus.
- [Documentation index](README.md) — the other guides.
