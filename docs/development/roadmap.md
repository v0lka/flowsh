# Development roadmap

This is the working taxonomy of flowsh's build-out: the work items referenced
across the code, tests, knowledge-base data and specifications by short IDs
(`A2`, `B6`, `C4`, `D6`, …). Each item records what the ID means and its status.
The IDs are stable identifiers rather than priorities: they exist so that a
comment, test name or KB document can cite a single, unambiguous item.

The leading letter groups the work by area:

| Letter | Area |
| ------ | ---- |
| `A` | Analysis pipeline and the public embedding API |
| `B` | Knowledge-base coverage (commands, dialects, destructive flags) |
| `C` | Reliability and security hardening (fuzzing, bounded execution) |
| `D` | Scoring and invariants |
| `J` | JavaScript dialect (`front/js`) |

## A — Analysis pipeline and embedding API

| ID | Item | Status |
| -- | ---- | ------ |
| A2 | **Name-resolution chain.** Every invocation's resolution (builtin / function / alias / external command / unknown) is computed *and* surfaced on the report, with a `resolution` corpus group pinning it so resolution cannot be computed and silently dropped. | Done |
| A3 | **Destructive-class surfacing.** Knowledge-base destructive entries are surfaced on the report and raise its destructiveness. | Done |
| A3.1 | A matched class-E destructive entry raises destructiveness to `Critical`. | Done |
| A3.2 | A knowledge-base class never lowers the effect-derived severity (raise-only). | Done |
| A3.3 | A destructive flag that leaves no effect trail is still surfaced. | Done |
| A6 | **POSIX variant.** A case declared `posix` is analysed in the POSIX variant, and the report is stamped `posix`. | Done |
| A9 | **Public embedding API.** The `api` package re-exports the facade as the supported analysis import path for external Go modules ([ADR-0010](../../specs/decisions/0010-public-embedding-api.md)). | Done |
| A11 | **Report policy package.** The `policy` package evaluates a report against trusted caller rules (`Allow`/`Review`/`Deny`), centralising the uncertainty, exfiltration, download-cradle, ingest, effect-kind and grade checks an embedding application would otherwise repeat. It fails closed — a missing, invalid, incompatible or uncovered report denies, and so does a nil or zero policy — and no analysed content can configure it ([ADR-0017](../../specs/decisions/0017-report-policy-package.md), `specs/domains/policy.md`). | Done |
| A12 | **Wrapper privilege elevation.** A peeled wrapper whose knowledge-base entry declares a PrivEsc parameter (`sudo`) elevates by its own command line, before the inner command is resolved. The refined `-u` doctrine yields a certain (`Direct`) PrivEsc targeting root, a certain elevation over a ⊤ target user when the value is not statically known, or a recorded de-elevation; `-g` never elevates, and a line that names nothing to run never elevates and degrades to ⊤ (`specs/domains/binding.md`). | Done |

## B — Knowledge-base coverage

| ID | Item | Status |
| -- | ---- | ------ |
| B2 | **GNU coreutils, extended set** (`kb/data/gnu.yaml`). | Done |
| B2–B9 | **Command → dialect map.** Every command is assigned its dialect(s) across the knowledge base (`specs/domains/knowledge-base.md`). | Done |
| B6 | **Package managers and build tooling** (`kb/data/pkgmgr.yaml`, `kb/data/build.yaml`) together with their destructive entries. | Done |
| B10 | **Curated destructive-flags coverage.** A test pins that every curated `(command, spec)` has a destructive entry with the right class and a non-empty reason. | Done |

## C — Reliability and security

| ID | Item | Status |
| -- | ---- | ------ |
| C4 | **Fuzzing** for the binder (`bind/fuzz_test.go`) and the PowerShell frontend (`front/ps/fuzz_test.go`). | Done |
| C4.3 | **Adversarial inputs are bounded:** no panic, no unbounded run; a failure degrades to the top element ⊤. | Done |

## D — Scoring and invariants

| ID | Item | Status |
| -- | ---- | ------ |
| D6 | **Raise-only destructiveness.** The knowledge-base class may only raise the report's destructiveness, never lower it. | Done |
| D7 | **Network-flow roles.** The score carries the two network data flows as additive `flowsh/v3` fields, each omitted when empty: `cradleFlows` pairs every `NetEgress` with every `CodeExec` marked `FlowCradle` (network content reaches code execution), and `ingestFlows` pairs every `NetEgress` with every download `FSWrite` marked `FlowIngest` (a VCS sync is not an ingest). A flow is asserted only where the effect carries the matching `FlowRole` — never from the mere co-occurrence of an egress and a sink (`specs/domains/engine/scoring.md`). | Done |

## J — JavaScript dialect

| ID | Item | Status |
| -- | ---- | ------ |
| J1 | **Dialect foundation.** The `js` dialect is registered end to end — the `LangJavaScript` value, CLI aliases (`js`/`javascript`/`node`/`nodejs`), facade routing, and the policy/embedding surface — and the initial conservative stub established the no-silent-miss invariant before semantic evaluation (`specs/domains/javascript-frontend.md`). | Done |
| J2 | **Core statement/expression layer (#28).** Bounded parsing, typed values, lexical state, control flow, completion paths, explicit degradation, and source-located explanations. Function invocation (#34) and the remaining Node effect families (#30–#32) remain separate. | Done |
| J3 | **Filesystem and path models (#29).** The modelled Node filesystem and path API families, declared in reviewed embedded YAML (`kb/data/js-filesystem.yaml`, `kb/data/js-path.yaml`) under the separate `jsModules`/`jsCalls` namespaces that require `effect-kb/v4`. Module and export identity follows evaluated values through imports, destructuring and aliases, and is conservatively invalidated by unknown execution or export mutation; argument shapes lower to the existing `FSRead`/`FSWrite`/`FSMeta` kinds over an explicit POSIX abstract path context (symbolic home `/root`, unknown cwd, embedder-suppliable), and recursive or forced deletion carries destructive class E. Callback APIs emit the outer filesystem effects plus canonical ⊤ and a reason while #34 owns callback execution ([ADR-0020](../../specs/decisions/0020-javascript-filesystem-models.md), `specs/domains/javascript-filesystem.md`). | Done |

## Future work

Every item above is implemented and pinned by the CI gates: the conformance
corpus for the items observable in a report, and the package regression suites
(loader, binder, engine, policy) for the rest. New work is added as the next free
ID in the relevant letter group; when an item lands, its status moves to `Done`
here and the code, tests and specs that cite it are updated together.
