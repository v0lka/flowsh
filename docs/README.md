# Documentation index

User-facing guides for `flowsh`. For an introduction to the tool, start at the
[project README](../README.md). For the normative specification of the system
(IR, schemas, import rules and decisions), see
[`specs/`](../specs/INDEX.md).

| Guide | Covers |
| ----- | ------ |
| [CLI user-guide](cli.md) | Running the `flowsh` binary: flags, input sources, exit codes and output framing. |
| [JSON report reference](report-json.md) | The `flowsh --json` wire contract, field by field, and its version tags. |
| [Embedding the analyser (Go library)](embedding.md) | Using `github.com/v0lka/flowsh/api` to analyse a command in-process. |
| [Adding a command to the knowledge base](kb-howto.md) | The author workflow for the effect dataset under `kb/data/`. |
| [Development roadmap](development/roadmap.md) | The work taxonomy (`A`/`B`/`C`/`D`) and the status of each item. |

These guides are descriptive. Where they and
[`specs/`](../specs/INDEX.md) disagree, the specification is authoritative.
Contributor-facing material (architecture, layering rules, the conformance
corpus, and how to extend the project) lives in
[`CONTRIBUTING.md`](../CONTRIBUTING.md).
