# Specification System

This document defines the format, rules, and procedures for creating and maintaining project specifications. It is the source of truth for how specs are structured.

## Purpose

Specifications provide AI coding agents with deterministic context about system behavior, interfaces, and architectural decisions. They enable agents to make safe, informed changes without extensive codebase exploration.

## Principles

1. **Self-standing documents** — specs are NOT generated from code. They describe intended behavior; a discrepancy between spec and code indicates a bug (in the code or the spec — determine by context).
2. **Agent-optimized** — predictable structure, explicit cross-references, no filler prose. Every section has a purpose.
3. **Living documents** — updated after code changes that alter documented behavior. Never silently drifting.
4. **Domain-based** — organized by conceptual domains, NOT by file/directory structure.
5. **Contracts are first-class** — cross-boundary interfaces deserve their own documents.

## File Organization

The tree below is the concrete structure for flowsh (`github.com/v0lka/flowsh`). It covers the frozen core (`engine`), the knowledge base, command binding, the two frontends (`bash-frontend`, `powershell-frontend`), the analysis facade, and the CLI.

```
specs/
├── META.md                         this file
├── INDEX.md                        navigation: task -> spec file(s)
├── WORKFLOW.md                     reference guide for spec system usage
│
├── architecture/                   system-level (layers, flows, conservatism)
│   ├── layers.md                   layer hierarchy, one-way import rules, the resolver seam
│   ├── data-flow.md                the end-to-end analysis pipeline
│   └── conservatism.md             what each layer does when it cannot bound an input (⊤)
│
├── domains/                        by concept (NOT by file structure)
│   ├── engine/                     core: the frozen effect IR (engine package)
│   │   ├── README.md               domain overview (entry point)
│   │   ├── effect-ir.md            Effect / EffectKind / EffectMode / Report detail
│   │   ├── lattices.md             Certainty, Destructiveness, Scope, Taint, Breadth, ...
│   │   └── scoring.md              Score composition, exfil detection, why-traces
│   ├── knowledge-base.md           the effect knowledge base (kb package)
│   ├── binding.md                  bind: resolution chain + flag/operand binding
│   ├── bash-frontend/              the bash frontend (front/bash)
│   │   ├── README.md               bash frontend overview
│   │   ├── parse-normalize.md      parse + normalize detail
│   │   └── abstract-exec.md        abstract execution detail
│   ├── powershell-frontend.md      the PowerShell frontend (front/ps)
│   ├── analysis-report.md          composition facade + report + corpus harness
│   └── cli.md                      the CLI (cmd/flowsh)
│
├── contracts/                      interfaces between layers
│   ├── frontend-engine.md          frontends -> engine boundary
│   ├── bind-kb.md                  bind <-> kb boundary
│   ├── exec-resolver.md            front/bash <-> caller resolver seam
│   └── report-json.md              analyzer <-> CLI/CI JSON report boundary
│
└── decisions/                      Architecture Decision Records
    ├── _template.md                ADR template
    ├── 0001-frozen-effect-ir.md
    ├── 0002-one-way-dependency.md
    ├── 0003-conservative-top.md
    ├── 0004-embedded-versioned-kb.md
    ├── 0005-two-separate-frontends.md
    ├── 0006-bounded-abstract-execution.md
    ├── 0007-lattice-based-effect-model.md
    ├── 0008-single-go-module.md
    ├── 0009-rename-identity-to-flowsh.md
    └── 0010-public-embedding-api.md
```

Specs are organized by domain, never by this layout. The mapping of a domain to the source packages it documents is:

| Domain spec | Source packages |
| ----------- | --------------- |
| `domains/engine/` | `engine/` |
| `domains/knowledge-base.md` | `kb/` (including `kb/data/*.yaml`) |
| `domains/binding.md` | `bind/` |
| `domains/bash-frontend/` | `front/bash/` |
| `domains/powershell-frontend.md` | `front/ps/` |
| `domains/analysis-report.md` | `internal/analysis/`, `api/` |
| `domains/cli.md` | `cmd/flowsh/` |

## Naming Conventions

- Files: `kebab-case.md`
- Directories within `domains/`: created when a domain requires multiple files
- `README.md` inside a domain directory: overview and entry point for that domain
- `_template.md` prefix: template files (not actual specs)
- ADR files: `NNN-kebab-case-slug.md` (three-digit number, kebab-case slug)

## Document Formats

### Domain README (`domains/*/README.md` or `domains/*.md`)

Required sections in order:

```markdown
# [Domain Name]

## Purpose

1-3 sentences. What this domain does in the system.

## Key Files

- `path/from/repo/root/file.ext` — role description

## Core Types

Key type definitions (code blocks) with brief explanations.

## Flow

ASCII diagram or numbered sequence showing the primary happy path.

## Invariants

Bullet list of properties that ALWAYS hold. Use affirmative phrasing.

## Configuration

Key parameters from configuration with defaults and valid values.

## Extension Points

How to add new behavior without breaking existing functionality.

## Related Specs

- [link](relative/path.md) — context of relationship
```

### Domain Detail (`domains/*/<name>.md`)

For individual components within a domain:

```markdown
# [Component Name]

## Role

1 sentence: what this component does within its domain.

## Key Files

- `path/to/file.ext` — description

## Behavior

Detailed description. May include:
- State machines (ASCII)
- Decision tables
- Pseudocode
- Sequence diagrams

## Error Handling

How this component handles and propagates errors.

## Invariants

Properties that always hold for this component.

## Related Specs

- [link](relative/path.md) — relationship context
```

### Contract (`contracts/*.md`)

```markdown
# Contract: [Layer A] <-> [Layer B]

## Boundary Rule

One sentence: direction of dependency and what is NOT allowed.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |

## Initialization

How components are wired together at startup.

## Data Flow Across Boundary

What data crosses the boundary, in what form, in which direction.

## Error Propagation

Rules for wrapping/transforming errors at this boundary.

## Breaking Change Checklist

If you change X, you MUST also update Y.
```

### Architecture (`architecture/*.md`)

```markdown
# [Topic]

## Context

Why this architectural aspect matters.

## [Main Content]

Diagrams, rules, descriptions. Structure varies by topic.

## Invariants

Architectural rules that must never be violated.

## Anti-Patterns

What NOT to do, with brief explanation of why.
```

### ADR (`decisions/NNN-slug.md`)

```markdown
# ADR-NNN: [Title]

## Status

Accepted | Superseded by [NNN](./NNN-slug.md)

## Context

The problem or question that required a decision.

## Decision

What was decided.

## Consequences

Positive and negative impacts on the codebase.

## Alternatives Considered

What was evaluated and why it was rejected.
```

## Cross-References

- Always use relative paths from `specs/` directory
- Format: `[display text](relative/path.md)`
- For intra-file section references: `[display text](relative/path.md#section-name)` (lowercase, hyphens)
- When referencing source code: backtick path from repo root, e.g. `front/bash/exec.go`

## Update Protocol

### When to update specs

- After any change that alters documented behavior
- After adding/removing/renaming interfaces that appear in a contract
- After changing architectural boundaries or invariants
- After making a new architectural decision (create ADR)

### How to update

1. Read the current spec fully before modifying
2. Preserve the document format (sections, ordering) defined in this META.md
3. Update cross-references if file paths changed
4. After adding or removing a spec file, update `INDEX.md`
5. ADRs with `Status: Accepted` are immutable; create a new ADR to supersede

### Validation checklist

- [ ] All sections from the template are present
- [ ] Cross-references point to existing files
- [ ] Code paths in Key Files are accurate
- [ ] Invariants are stated affirmatively
- [ ] INDEX.md reflects the current file set
