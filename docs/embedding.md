# Embedding the analyser (Go library)

Besides the CLI, `flowsh` can be embedded as a **Go library**: an external Go
program imports one package and gets the same analyse → report operation the
binary performs. The supported import path is:

```go
import "github.com/v0lka/flowsh/api"
```

`api` is the public analysis surface; the optional `policy` package evaluates its reports. Everything under `internal/`, including the composition facade `internal/analysis/` and the test-only corpus harness `internal/corpus/`, cannot be imported by a module outside `github.com/v0lka/flowsh` (Go's `internal/` rule) and is **not** a supported API. The CLI and the API are equal entry points over the same facade; the CLI is the first consumer of it (see [ADR-0010](../specs/decisions/0010-public-embedding-api.md)).

This guide shows the embedding workflow. For the report *document* a consumer
parses, see the [JSON report reference](report-json.md); for the command line,
the [CLI user-guide](cli.md).

## Quick start

Analyse one command and emit the canonical JSON report:

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
validates the report and returns its two-space-indented JSON: the document the
CLI writes and the [JSON report reference](report-json.md) describes, byte for
byte apart from the source name and the CLI's trailing newline. `Analyze` leaves
`Options.Root` empty, so the report omits `root` and the why-trace positions name
the dialect's default source (`script` for bash/POSIX and JavaScript, `flowsh`
for PowerShell) rather than the `<argument>` marker the CLI stamps. Passing
`api.RootArgument` through `AnalyzeWith` (see
[below](#options-source-marker-providers-and-javascript-context)) reproduces the
CLI's document exactly.

## Reusing the analyser

`api.Analyze` uses a process-wide analyser, so repeated calls reuse one loaded
knowledge base. To make that explicit (and to hold a handle you can share), use
`api.NewAnalyzer`:

```go
func analyseMany() error {
	a, err := api.NewAnalyzer()
	if err != nil {
		return err
	}

	// Reuse `a` across many commands; it is safe for concurrent use.
	rep := a.Analyze(api.LangPowerShell, `Get-Content ~/.aws/credentials`)
	data, err := rep.Encode()
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}
```

The `*api.Analyzer` methods return a `*Report` **without an error**: a fully
unanalysable input does not fail, it degrades to ⊤ and sets `Report.Top`. Only
`NewAnalyzer` (the one-time knowledge-base load) and `Encode` (report
validation) return errors. The snippet above also imports `os`.

## Choosing the dialect

The dialect is an `api.Lang`. Use the constants, or map a user-supplied name
through `api.ParseLang` (which accepts the canonical spellings and their aliases
(`sh`/`shell`, `ps`/`pwsh`/`powershell`, `javascript`/`node`/`nodejs`), trimmed and case-insensitive):

```go
func analyse(src string) error {
	lang, err := api.ParseLang("ps") // → api.LangPowerShell
	if err != nil {
		return err
	}

	rep, err := api.Analyze(lang, src)
	if err != nil {
		return err
	}
	return rep.Validate()
}
```

`api.Langs` lists every supported dialect in canonical order; the constants are
`api.LangBash`, `api.LangPOSIX`, `api.LangPowerShell`, and `api.LangJavaScript`.

`api.LangJavaScript` (`"js"`) evaluates a bounded statement/expression subset. Modeled Node filesystem/path calls produce precise effects and populate `commandCalls` and `resolution` with the canonical builtin identity (`kind: "builtin"`). Callback execution and general function invocation remain conservative: unmodelled calls and execution return `CodeExec(⊤)` with `Conservative` true; parse/budget failures also set `Top`. Pure understood source (including empty library source) returns `effects: []` without uncertainty flags: it validates, but `Covered()` is false and policy denies it with `uncovered_report`. The report uses shared scoring and source-located explanations. Uncertainty still denies by default and can require Review, never Allow.

## Options: source marker, providers, and JavaScript context

`api.AnalyzeWith(lang, src, opts)` is `Analyze` with explicit
`api.Options`. The zero `Options` is identical to `Analyze`:

```go
func analyseWith(src string) error {
	rep, err := api.AnalyzeWith(api.LangPowerShell, src, api.Options{
		Root:    api.RootArgument, // stamps Report.Root ("<argument>"/"<stdin>")
		Windows: api.Bool(true),   // force PowerShell Registry semantics on any host
	})
	if err != nil {
		return err
	}
	return rep.Validate()
}
```

- `Options.Root` records where the command came from; it is stamped into
  `Report.Root` and used as the source name the why-trace positions are reported
  against. Under `Analyze` it is empty, so the report omits `root` and positions
  name the dialect default instead. Pass `api.RootArgument` or `api.RootStdin`
  when you feed a command from memory, or a path when you read one from a file.
- `Options.Windows` is tri-state: `nil` (default) lets the host OS decide,
  `api.Bool(true)`/`api.Bool(false)` forces the Registry provider on/off
  regardless of the host.
- `Options.Vars` seeds the shell's abstract state with variable bindings the host
  knows from its own context — a session temp directory, a workspace path, a run
  identifier — that the script text alone does not determine. Each binding
  behaves as though the script had assigned it a literal value before its first
  statement, so a later `$name` read resolves to that value instead of degrading
  its word (and every path derived from it) to ⊤. The zero value (`nil`) seeds
  nothing.
- `Options.JavaScript` accepts `*api.JavaScriptContext` with explicit offline POSIX `Home` and `Cwd` paths. A nil context uses symbolic home `/root` (it names path targets but never decides a branch) and unknown cwd; empty fields in a supplied context are unknown. JavaScript analysis reads no host home directory, cwd, environment, or module contents.

`Options.Root` is honored for every dialect. `Options.Windows` remains PowerShell-only and `Options.Vars` remains bash/POSIX-only; JS ignores both. `Options.JavaScript` is JavaScript-only and is ignored by bash/POSIX and PowerShell.

## Exported surface

Every `api` symbol below is a **type alias**, a **copied constant**, or a
**one-line forwarder** over `internal/analysis`. `api` adds no behaviour of its
own, so an embedding caller sees exactly the CLI's report contract.

| Kind | Symbols |
| ---- | ------- |
| Types (aliases) | `Analyzer`, `CallRedirect`, `Canonical`, `CommandCall`, `DestructiveFinding`, `JavaScriptContext`, `Lang`, `Options`, `Report` |
| Constants | `ToolName`, `SchemaVersion`, `ToolVersion`, `RootArgument`, `RootStdin`, `LangBash`, `LangPOSIX`, `LangPowerShell`, `LangJavaScript` |
| Variables | `Langs` |
| Functions | `ParseLang`, `Analyze`, `AnalyzeWith`, `NewAnalyzer`, `Bool` |
| Methods | `(*Report).Encode`, `(*Report).Validate`, `(*Report).Covered`, `(*Report).HasTop`, `(*Analyzer).Analyze`, `(*Analyzer).AnalyzeWith` |

The methods are reached through the aliases: `go doc` lists them on the facade
types they belong to (`internal/analysis.Report` and `internal/analysis.Analyzer`)
rather than on `api` itself. `CallRedirect`, `Canonical` and `CommandCall` are the
report sub-objects the [JSON report reference](report-json.md) documents as
`commandCalls[]` and `canonical`, aliased so a caller can decode those fields into
named types.

`policy` is not a re-export: it is a real package with its own behaviour, and it
exports the decision layer and nothing else:

| Kind | Symbols |
| ---- | ------- |
| Types | `Action` (a `string`), `Config`, `Decision`, `Match`, `Policy` |
| Constants | `Allow` (`"allow"`), `Review` (`"review"`), `Deny` (`"deny"`) |
| Functions | `New` |
| Methods | `(Decision).Allowed`, `(*Policy).Evaluate` |

`Decision` (`action`, `matches`) and `Match` (`code`, `action`) carry JSON tags, so
a decision is itself serialisable; `Config` and `Policy` do not.

## Stability and versioning

The embedding surface is versioned by the **report-contract constants** rather
than by the module version or the package's shape. Both are re-exported and
stamped into every report:

| Constant | Value | Tags |
| -------- | ----- | ---- |
| `api.SchemaVersion` | `effect-ir/v2` | The shape of the effect IR and the report's effect payload. |
| `api.ToolVersion` | `flowsh/v3` | The report document as a whole (envelope + CLI fields). |

**Pin to a contract revision by checking `Report.SchemaVersion` and
`Report.ToolVersion` rather than by relying on a module version.** A change to
the shape of an emitted field bumps the corresponding tag; the analyser never
renames or removes a field silently.

Because every exported type is an **alias**, an internal change in
`internal/analysis` is *itself* a change to the public API: the alias gives no
encapsulation barrier. The contract is held by these two version constants and
by review rather than by the type system; treat a bump of either tag as the
signal that your integration must be re-checked.

## Applying a policy

Import `github.com/v0lka/flowsh/policy` to turn a report into an `allow`, `review`, or `deny` decision. Analysis and policy are separate calls: the policy does not change effects, scoring, or the CLI's JSON report.

```go
func guard(source string) error {
	p, err := policy.New(policy.Config{
		Unknown:      policy.Deny,
		Conservative: policy.Review,
		Exfiltration: policy.Deny,
		Cradle:       policy.Deny,
		Effects: map[engine.EffectKind]policy.Action{
			engine.KindCredAccess: policy.Deny,
			engine.KindPrivEsc:    policy.Deny,
			engine.KindNetEgress:  policy.Review,
		},
	})
	if err != nil {
		return err
	}
	rep, err := api.Analyze(api.LangBash, source)
	if err != nil {
		return err // Do not execute when analysis fails.
	}
	decision := p.Evaluate(rep)
	if !decision.Allowed() {
		return fmt.Errorf("script requires %s", decision.Action)
	}
	return nil
}
```

The example also imports `fmt` and `github.com/v0lka/flowsh/engine` for effect-kind constants. Reuse the constructed policy across calls; it copies its maps and is safe for concurrent evaluation of reports that callers leave unchanged.

Configuration defaults are `Unknown: Deny`, `Conservative: Review`, `Exfiltration: Deny`, `Cradle: Review`, and `Ingest: Allow`. `Effects` and `Grades` are copied as supplied and default to nil, which matches nothing. Grade entries match exact grades; to restrict High and Critical, list both. These defaults are a starting point, **not a complete security policy**: valid, compatible reports with `Covered() == true` and no restrictive match return Allow, including operations whose effects the caller has not configured. Choose rules for the caller's environment and threat model.

All matching restrictions apply, with `deny > review > allow`. An Allow entry disables only that rule; it cannot override another restriction. Unknown and conservative analysis cannot be configured to Allow. Unknown includes both `Report.Top` and `Report.HasTop()`. Missing, incompatible, invalid, or uncovered reports always deny. A nil or zero policy also denies; a zero decision is never allowed. Flow rules use the report's `exfilPairs`, `cradleFlows`, and `ingestFlows`, not just co-occurring effect kinds. Each `Match.Code` names the rule that fired: `unknown`, `conservative`, `exfiltration`, `cradle` and `ingest` for the five signals, `grade:<Grade>` (say `grade:Critical`) and `effect:<Kind>` (say `effect:CredAccess`) for the two map rules, and — for a policy or report rejected before any rule runs — the single denial code `invalid_policy`, `invalid_report` or `uncovered_report`.

Valid no-effect reports can be uncovered: `api.Analyze(api.LangBash, "true")` and `api.Analyze(api.LangBash, ":")` return zero effects with `Top == false` and `Conservative == false`, so `Covered()` is false. Policy denies these benign no-op commands with `uncovered_report`. This coverage requirement applies even when analysis reports no uncertainty. Missing, incompatible, or invalid reports use `invalid_report`; nil or zero policies use `invalid_policy`. Report validity is checked before coverage, so an invalid report with no effects still uses `invalid_report`.

Decisions contain sorted reason codes and actions without copying script text, targets, or report reasons. Inspect the original report for evidence and treat it as sensitive. A report received from an untrusted party is not authenticated by validation; use the report from your own analysis call.

Policy cannot recover behaviour absent from analysis, inspect referenced files, or establish runtime confinement. For example, a container command with an unbounded CodeExec effect still requires review or denial. Command semantics belong in the analyser; tenant permissions, approval, runtime isolation, and enforcement remain the embedding application's responsibilities. Keep policy configuration outside the analysed source and the agent being guarded.

See the [policy specification](../specs/domains/policy.md) for the full contract and [ADR-0017](../specs/decisions/0017-report-policy-package.md) for the decision to add a public policy layer alongside `api`.

## Limits

- **Use `api` for analysis and `policy` for decisions.** Do not import `internal/analysis` (or any other `internal/...` path) from another module; the compiler will reject it, and it is not a stable contract.
- **The corpus harness is not part of the embedding surface.** `Case` (and its
  `RequiresCoverage` method), `LoadCorpus`, `CorpusDir`, `CorpusDirFrom`,
  `Filter`, the `Group*` constants and `GuardFallClasses` live in the test-only
  `internal/corpus` package: they are a testing aid rather than a public API.
- **`engine` is the one non-`api` package a policy caller needs.**
  `policy.Config`'s rule maps are keyed by `engine.EffectKind` and
  `engine.Destructiveness`, so configuring an effect or grade rule means also
  importing `github.com/v0lka/flowsh/engine` for constants such as
  `engine.KindCredAccess`. It sits outside `internal/`, and the shape it freezes
  is the effect payload the
  [report contract](../specs/contracts/report-json.md) pins.
- **No runtime dependencies.** The knowledge base is compiled into the binary,
  so an embedding program needs nothing at run time, and the analyser is a pure
  function from command text to report: it never executes, fetches, or writes
  anything it analyses.

## Related

- [JSON report reference](report-json.md) — the document `Report.Encode` emits.
- [CLI user-guide](cli.md) — the other supported consumer of the facade.
- [ADR-0010: Public embedding API](../specs/decisions/0010-public-embedding-api.md) — why `api/` is a type-alias re-export and how it is versioned.
- [ADR-0017: Report policy package](../specs/decisions/0017-report-policy-package.md) — the optional public decision layer and its amendment to ADR-0010's sole-public-surface framing.
- [Layer Architecture](../specs/architecture/layers.md) — where `api/` sits relative to the facade and the CLI.
- [Analysis Report](../specs/domains/analysis-report.md) — the facade `api` re-exports.
- [Report Contract](../specs/contracts/report-json.md) — the `flowsh/v3` envelope pinned across the boundary.
