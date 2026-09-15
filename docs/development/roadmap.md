# Development roadmap

This is the working taxonomy of flowsh's build-out: the work items referenced
across the code, tests, knowledge-base data and specifications by short IDs
(`A2`, `B6`, `C4`, `D6`, …). Each item records what the ID means and its status.
The IDs are stable identifiers, not priorities — they exist so that a comment,
test name or KB document can cite a single, unambiguous item.

The leading letter groups the work by area:

| Letter | Area |
| ------ | ---- |
| `A` | Analysis pipeline and the public embedding API |
| `B` | Knowledge-base coverage (commands, dialects, destructive flags) |
| `C` | Reliability and security hardening (fuzzing, bounded execution) |
| `D` | Scoring and invariants |

## A — Analysis pipeline and embedding API

| ID | Item | Status |
| -- | ---- | ------ |
| A2 | **Name-resolution chain.** Every invocation's resolution (builtin / function / alias / external command / unknown) is computed *and* surfaced on the report, with a `resolution` corpus group pinning it so resolution cannot be computed and silently dropped. | Done |
| A3 | **Destructive-class surfacing.** Knowledge-base destructive entries are surfaced on the report and raise its destructiveness. | Done |
| A3.1 | A matched class-E destructive entry raises destructiveness to `Critical`. | Done |
| A3.2 | A knowledge-base class never lowers the effect-derived severity (raise-only). | Done |
| A3.3 | A destructive flag that leaves no effect trail is still surfaced. | Done |
| A6 | **POSIX variant.** A case declared `posix` is analysed in the POSIX variant, and the report is stamped `posix`. | Done |
| A9 | **Public embedding API.** The `api` package re-exports the facade as the sole supported import path for external Go modules ([ADR-0010](../../specs/decisions/0010-public-embedding-api.md)). | Done |

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

## Future work

Every item above is implemented and covered by the conformance corpus and the CI
gates. New work is added as the next free ID in the relevant letter group; when
an item lands, its status moves to `Done` here and the code, tests and specs that
cite it are updated together.
