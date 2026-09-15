# Specification Index

Navigation entry point for the `flowsh` specification system. Start here: find your task in the table, then open the listed spec.

For formats and update rules, see [META.md](META.md). For how to use the system, see [WORKFLOW.md](WORKFLOW.md).

## Task -> Specs

| Task | Read |
| ---- | ---- |
| Add a command or parameter to the knowledge base | [Knowledge Base](domains/knowledge-base.md), [bind <-> kb Contract](contracts/bind-kb.md) |
| Add or change a destructive flag/class | [Knowledge Base](domains/knowledge-base.md) |
| Add an effect kind or mode | [Effect IR](domains/engine/effect-ir.md), [frontend <-> engine Contract](contracts/frontend-engine.md), [ADR-0001](decisions/0001-frozen-effect-ir.md) |
| Add or change a value lattice | [Lattices](domains/engine/lattices.md), [ADR-0007](decisions/0007-lattice-based-effect-model.md) |
| Tweak scoring / destructiveness / exfil | [Scoring](domains/engine/scoring.md), [Report Contract](contracts/report-json.md) |
| Add a frontend (new language) | [Layer Architecture](architecture/layers.md), [frontend <-> engine Contract](contracts/frontend-engine.md), [Analysis Facade](domains/analysis-report.md) |
| Change bash parsing / abstract execution | [bash Frontend](domains/bash-frontend/README.md), [Parse & Normalize](domains/bash-frontend/parse-normalize.md), [Abstract Execution](domains/bash-frontend/abstract-exec.md) |
| Change PowerShell parsing / lowering | [PowerShell Frontend](domains/powershell-frontend.md) |
| Change command resolution or flag binding | [Binding](domains/binding.md), [bind <-> kb Contract](contracts/bind-kb.md) |
| Change the frontend/binder seam (`Resolver`) | [Resolver Contract](contracts/exec-resolver.md), [Layer Architecture](architecture/layers.md) |
| Add a CLI flag or change output | [CLI](domains/cli.md), [Report Contract](contracts/report-json.md) |
| Bump the report/tool version tag (`flowsh/vN`) or add `--version` | [Report Contract](contracts/report-json.md), [CLI](domains/cli.md) |
| Embed the analyser in another Go program | [Analysis Facade](domains/analysis-report.md), [ADR-0010](decisions/0010-public-embedding-api.md) |
| Add or change a corpus case | [Analysis Facade](domains/analysis-report.md) |
| Understand the end-to-end pipeline | [Data Flow](architecture/data-flow.md) |
| Understand the layering / import rules | [Layer Architecture](architecture/layers.md) |
| Understand degrade-to-⊤ semantics | [Conservatism](architecture/conservatism.md) |
| Understand why the IR is frozen / the KB is embedded / ⊤ is used / one module / the tool is named `flowsh` / a public embedding API exists | [Decisions](decisions/_template.md) (ADR-0001 … ADR-0013) |
| Add a new spec document | [META.md](META.md), [WORKFLOW.md](WORKFLOW.md) |

## Dependency Graph

Spec-level view of the layered system (arrows point from a layer to what it depends on):

```
  META.md ── INDEX.md ── WORKFLOW.md        (governance / navigation)

  architecture/layers.md ── architecture/data-flow.md ── architecture/conservatism.md
        │                        │
        │  describe               │  trace
        v                        v
  ┌──────────────────────────────────────────────────────────┐
  │ domains/                                                 │
  │                                                          │
  │  analysis-report.md, cli.md   (L4/L5: facade + CLI +      │
  │        │                       corpus)                    │
  │        │ compose                                          │
  │        v                                                  │
  │  binding.md  (L3)                                        │
  │        │ bind                                             │
  │        v                                                  │
  │  knowledge-base.md            bash-frontend/,            │
  │    (L2)                       powershell-frontend.md     │
  │        │                    │     (L2)                    │
  │        └────────┬───────────┘                             │
  │                 v                                         │
  │        engine/  (L1 core)                                 │
  │          README, effect-ir.md, lattices.md, scoring.md    │
  └──────────────────────────────────────────────────────────┘
        │                    │                    │
        v                    v                    v
  contracts/           contracts/           contracts/
   frontend-engine.md   bind-kb.md           report-json.md
   exec-resolver.md

  decisions/  0001 frozen-IR   0002 one-way-dep   0003 conservative-top
              0004 embedded-KB 0005 two-frontends 0006 bounded-exec
              0007 lattice-model 0008 single-module 0009 rename-identity
              0010 public-api 0011 ci-load-budget 0012 race-parse-budget
              0013 windows-clock-tick
```

## Directory Listing

```
specs/
├── META.md                                    spec formats, rules, update protocol
├── INDEX.md                                   this file
├── WORKFLOW.md                                how to use the spec system
│
├── architecture/
│   ├── layers.md                              layer hierarchy + import rules
│   ├── data-flow.md                           end-to-end analysis pipeline
│   └── conservatism.md                        degrade-to-⊤ (top element) semantics
│
├── domains/
│   ├── engine/
│   │   ├── README.md                          the frozen core (domain overview)
│   │   ├── effect-ir.md                       Effect / EffectKind / EffectMode / Report
│   │   ├── lattices.md                        certainty/destructiveness/scope/taint/...
│   │   └── scoring.md                         score composition, exfil, why-traces
│   ├── knowledge-base.md                      KB types, loading, YAML document schema
│   ├── binding.md                             resolution chain + flag/operand binding
│   ├── bash-frontend/
│   │   ├── README.md                          bash frontend (domain overview)
│   │   ├── parse-normalize.md                 parse + normalize detail
│   │   └── abstract-exec.md                   abstract execution detail
│   ├── powershell-frontend.md                 PowerShell parse (tree-sitter) + lower
│   ├── analysis-report.md                     composition facade + report + corpus
│   └── cli.md                                 CLI behavior
│
├── contracts/
│   ├── frontend-engine.md                     frontends -> engine boundary
│   ├── bind-kb.md                             bind <-> kb boundary
│   ├── exec-resolver.md                       front/bash <-> caller resolver seam
│   └── report-json.md                         analyzer <-> CLI/CI JSON report boundary
│
└── decisions/
    ├── _template.md                           ADR template
    ├── 0001-frozen-effect-ir.md
    ├── 0002-one-way-dependency.md
    ├── 0003-conservative-top.md
    ├── 0004-embedded-versioned-kb.md
    ├── 0005-two-separate-frontends.md
    ├── 0006-bounded-abstract-execution.md
    ├── 0007-lattice-based-effect-model.md
    ├── 0008-single-go-module.md
    ├── 0009-rename-identity-to-flowsh.md
    ├── 0010-public-embedding-api.md
    ├── 0011-ci-tolerant-load-budget.md
    ├── 0012-race-advisory-parse-budget.md
    └── 0013-windows-clock-tick-parse-budget.md
```

## Full File List

Every spec file, by path relative to `specs/`:

- `META.md`
- `INDEX.md`
- `WORKFLOW.md`
- `architecture/conservatism.md`
- `architecture/data-flow.md`
- `architecture/layers.md`
- `contracts/bind-kb.md`
- `contracts/exec-resolver.md`
- `contracts/frontend-engine.md`
- `contracts/report-json.md`
- `decisions/_template.md`
- `decisions/0001-frozen-effect-ir.md`
- `decisions/0002-one-way-dependency.md`
- `decisions/0003-conservative-top.md`
- `decisions/0004-embedded-versioned-kb.md`
- `decisions/0005-two-separate-frontends.md`
- `decisions/0006-bounded-abstract-execution.md`
- `decisions/0007-lattice-based-effect-model.md`
- `decisions/0008-single-go-module.md`
- `decisions/0009-rename-identity-to-flowsh.md`
- `decisions/0010-public-embedding-api.md`
- `decisions/0011-ci-tolerant-load-budget.md`
- `decisions/0012-race-advisory-parse-budget.md`
- `decisions/0013-windows-clock-tick-parse-budget.md`
- `domains/analysis-report.md`
- `domains/bash-frontend/README.md`
- `domains/bash-frontend/abstract-exec.md`
- `domains/bash-frontend/parse-normalize.md`
- `domains/binding.md`
- `domains/cli.md`
- `domains/engine/README.md`
- `domains/engine/effect-ir.md`
- `domains/engine/lattices.md`
- `domains/engine/scoring.md`
- `domains/knowledge-base.md`
- `domains/powershell-frontend.md`
