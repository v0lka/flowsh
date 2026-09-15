# Embedding the analyser (Go library)

`flowsh` is usable as a **Go library**, not only as a CLI: an external Go
program imports one package and gets the same analyse → report operation the
binary performs. The supported import path is:

```go
import "github.com/v0lka/flowsh/api"
```

`api` is the **only** public embedding surface. Everything under `internal/` —
including the composition facade `internal/analysis/` and the corpus harness it
carries — is not importable by a module outside `github.com/v0lka/flowsh`
(Go's `internal/` rule) and is **not** a supported API. The CLI and the API are
**equal, first-class entry points** over the same facade; the CLI is simply the
first consumer of it (see
[ADR-0010](../specs/decisions/0010-public-embedding-api.md)).

This guide shows the embedding workflow. For the report *document* a consumer
parses, see the [JSON report reference](report-json.md); for the command line,
the [CLI user-guide](cli.md).

## Quick start

Analyse one command and emit the same canonical JSON `flowsh --json` writes:

```go
package main

import (
	"fmt"
	"os"

	"github.com/v0lka/flowsh/api"
)

func main() {
	// Analyze runs the full pipeline: parse → bind → abstract-execute → score.
	rep, err := api.Analyze(api.LangBash, `rm -rf $HOME`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "flowsh:", err)
		os.Exit(1)
	}

	// Encode validates the report and returns its canonical indented JSON.
	data, err := rep.Encode()
	if err != nil {
		fmt.Fprintln(os.Stderr, "flowsh:", err)
		os.Exit(1)
	}
	os.Stdout.Write(data)

	// A guardrail consumer must treat ⊤ / conservative as deny-or-inspect:
	// the analysis could not bound the input. Covered() is the "no silent
	// miss" invariant — always true here, but a good place to branch.
	if rep.Top || rep.Conservative {
		os.Exit(3)
	}
}
```

`api.Analyze(lang, src)` returns a `*api.Report` (the frozen effect IR plus the
score and the conservative/⊤ flags) or an error. `(*api.Report).Encode()`
validates the report and returns its indented JSON — the exact document the CLI
emits and the [JSON report reference](report-json.md) documents.

## Reusing the analyser

`api.Analyze` uses a process-wide analyser, so repeated calls reuse one loaded
knowledge base. To make that explicit (and to hold a handle you can share), use
`api.NewAnalyzer`:

```go
a, err := api.NewAnalyzer()
if err != nil {
	return err
}

// Reuse `a` across many commands; it is safe for concurrent use.
rep := a.Analyze(api.LangPowerShell, `Get-Content ~/.aws/credentials`)
data, err := rep.Encode()
```

The `*api.Analyzer` methods return a `*Report` **without an error**: a fully
unanalysable input does not fail, it degrades to ⊤ and sets `Report.Top`. Only
`NewAnalyzer` (the one-time knowledge-base load) and `Encode` (report
validation) return errors.

## Choosing the dialect

The dialect is an `api.Lang`. Use the constants, or map a user-supplied name
through `api.ParseLang` (which accepts the canonical spellings and their
aliases — `sh`/`shell`, `ps`/`pwsh`/`powershell` — trimmed and case-insensitive):

```go
lang, err := api.ParseLang("ps") // → api.LangPowerShell
...

rep, err := api.Analyze(lang, src)
```

`api.Langs` lists every supported dialect in canonical order; the constants are
`api.LangBash`, `api.LangPOSIX` and `api.LangPowerShell`.

## Options: source marker and provider selection

`api.AnalyzeWith(lang, src, opts)` is `Analyze` with explicit
`api.Options`. The zero `Options` is identical to `Analyze`:

```go
rep, err := api.AnalyzeWith(api.LangPowerShell, src, api.Options{
	Root:    api.RootArgument,          // stamps Report.Root ("<argument>"/"<stdin>")
	Windows: api.Bool(true),            // force PowerShell Registry semantics on any host
})
```

- `Options.Root` records where the command came from; it is stamped into
  `Report.Root` and defaults (via `Analyze`) to the file marker. Pass
  `api.RootArgument` or `api.RootStdin` when you feed a command from memory.
- `Options.Windows` is tri-state: `nil` (default) lets the host OS decide,
  `api.Bool(true)`/`api.Bool(false)` forces the Registry provider on/off
  regardless of the host.

## Exported surface

Every symbol below is a **type alias**, a **copied constant**, or a
**one-line forwarder** over `internal/analysis` — `api` adds no behaviour of its
own, so an embedding caller sees exactly the CLI's report contract.

| Kind | Symbols |
| ---- | ------- |
| Types (aliases) | `Lang`, `Report`, `DestructiveFinding`, `Analyzer`, `Options` |
| Constants | `ToolName`, `SchemaVersion`, `ToolVersion`, `RootArgument`, `RootStdin`, `LangBash`, `LangPOSIX`, `LangPowerShell` |
| Variables | `Langs` |
| Functions | `ParseLang`, `Analyze`, `AnalyzeWith`, `NewAnalyzer`, `Bool` |
| Methods | `(*Report).Encode`, `(*Report).Validate`, `(*Report).Covered`, `(*Report).HasTop`, `(*Analyzer).Analyze`, `(*Analyzer).AnalyzeWith` |

## Stability and versioning

The embedding surface is versioned by the **report-contract constants**, not by
the module version or the package's shape. Both are re-exported and stamped into
every report:

| Constant | Value | Tags |
| -------- | ----- | ---- |
| `api.SchemaVersion` | `effect-ir/v1` | The shape of the effect IR and the report's effect payload. |
| `api.ToolVersion` | `flowsh/v1` | The report document as a whole (envelope + CLI fields). |

**Pin to a contract revision by checking `Report.SchemaVersion` and
`Report.ToolVersion`, not by relying on a module version.** A change to the
shape of an emitted field bumps the corresponding tag; the analyser never
renames or removes a field silently.

Because every exported type is an **alias**, an internal change in
`internal/analysis` is *itself* a change to the public API — the alias gives no
encapsulation barrier. The contract is held by these two version constants and
by review, not by the type system; treat a bump of either tag as the signal that
your integration must be re-checked.

## Limits

- **Only `api` is public.** Do not import `internal/analysis` (or any other
  `internal/...` path) from another module — the compiler will reject it, and it
  is not a stable contract.
- **The corpus harness is not part of the embedding surface.** `Case`,
  `LoadCorpus`, `CorpusDir`, `Filter`, the `Group*` constants and
  `GuardFallClasses` stay internal: they are a testing aid, not an API.
- **No runtime dependencies.** The knowledge base is compiled into the binary,
  so an embedding program needs nothing at run time, and the analyser is a pure
  function from command text to report — it never executes, fetches, or writes
  anything it analyses.

## Related

- [JSON report reference](report-json.md) — the document `Report.Encode` emits.
- [CLI user-guide](cli.md) — the other first-class consumer of the facade.
- [ADR-0010: Public embedding API](../specs/decisions/0010-public-embedding-api.md) — why `api/` is a type-alias re-export and how it is versioned.
- [Layer Architecture](../specs/architecture/layers.md) — where `api/` sits relative to the facade and the CLI.
- [Analysis Report](../specs/domains/analysis-report.md) — the facade `api` re-exports.
- [Report Contract](../specs/contracts/report-json.md) — the `flowsh/v1` envelope pinned across the boundary.
