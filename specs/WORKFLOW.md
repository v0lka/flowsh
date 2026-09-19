# Specification Workflow

A reference guide for developers and AI agents on effective use of this project's specification system. The system documents **flowsh** (`github.com/v0lka/flowsh`), the shell/PowerShell command effect analyser (`flowsh`).

---

## 1. General Philosophy

Specifications are the **source of truth** about the intended behavior of the system. They are not generated from code; they are maintained manually. Key implications:

- A discrepancy between a spec and the code = a bug (in the code or in the spec — determine by context).
- Specs are optimized for **AI agents**: predictable structure, explicit cross-references, no filler prose.
- Organized by **domains** (conceptual areas), NOT by repository file structure. flowsh's domains are `engine` (the frozen core), `knowledge-base`, `binding`, `bash-frontend` and `powershell-frontend` (the two frontends), `analysis-report`, and `cli`.
- **Contracts** are a separate first-class entity for describing boundaries between layers.

---

## 2. Getting Started: Navigation

### Step 1: INDEX.md

Open `specs/INDEX.md`. It contains a "task → specs" table that maps common tasks to the spec files you should read.

### Step 2: Domain README

Every domain with multiple files has a `README.md` — the entry point. In flowsh those are `domains/engine/README.md` and `domains/bash-frontend/README.md`; the single-file domains are `domains/knowledge-base.md`, `domains/binding.md`, `domains/powershell-frontend.md`, `domains/analysis-report.md` and `domains/cli.md`. A domain README contains:

- Purpose
- Key Files (key source files)
- Core Types (main types with code blocks)
- Flow (flow diagram)
- Invariants (what ALWAYS holds true)
- Extension Points (how to extend)

### Step 3: Detail Files

When you need details about a specific component — for example the PowerShell lowering in `domains/powershell-frontend.md`, or the value lattices in `domains/engine/lattices.md` — navigate to the corresponding detail file.

---

## 3. Document Formats

The system uses 5 strictly defined formats. Every new document MUST follow the corresponding template from `META.md`.

1. **Domain README** — `domains/*/README.md` or `domains/*.md` (9 required sections)
2. **Domain Detail** — `domains/*/<component>.md` (7 required sections)
3. **Contract** — `contracts/*.md` (7 required sections)
4. **Architecture** — `architecture/*.md` (4+ required sections)
5. **ADR** — `decisions/NNN-slug.md` (5 required sections)

---

## 4. Cross-References

Rules for linking between specs:

```markdown
<!-- To another spec (relative path from specs/) -->
[Frontends <-> Engine Contract](contracts/frontend-engine.md)

<!-- To a section within another spec -->
[Lattice Laws](domains/engine/lattices.md#lattice-laws)

<!-- To source code (backticks, path from repo root) -->
`bind/bind.go`
```

Rule: all links are **relative from `specs/`**. Section anchors — lowercase, hyphen-separated.

---

## 5. Update Protocol

### When to Update

- After any change that alters documented behavior
- After adding/removing/renaming interfaces from contracts
- After changing architectural boundaries or invariants
- After a new architectural decision → create an ADR

### How to Update

1. **Read** the current spec fully before modifying
2. **Preserve the format** — sections and their order are defined in META.md
3. **Update cross-references** if file paths changed
4. **Update INDEX.md** after adding or removing a spec file
5. **ADRs are immutable** — if `Status: Accepted`, create a new ADR with a `Superseded by` link

### Validation Checklist

After updating, verify:

- [ ] All sections from the template are present
- [ ] Cross-references point to existing files
- [ ] Paths in Key Files are accurate
- [ ] Invariants are stated affirmatively
- [ ] INDEX.md reflects the current file set

---

## 6. Workflow for Typical Tasks

### "Add a command or parameter to the knowledge base" (domain: `knowledge-base`)

1. Read `domains/knowledge-base.md` — understand the frozen schema (`effect-kb/v2`), `Dialect`, `ParamKind`, `ValueSource` and the destructive-flags table.
2. Read `domains/binding.md` and `contracts/bind-kb.md` — see how a resolved invocation is matched against command signatures, so you author params the binder will actually match.
3. Add the command to the appropriate dataset under `kb/data/*.yaml` (`coreutils.yaml`, `net.yaml`, …) and, when it is destructive, an entry to `kb/data/destructive.yaml`.
4. **After implementation**: update `domains/knowledge-base.md`; run `go test ./kb/ ./bind/` (the loader and `KB.Validate` enforce referential integrity).

### "Add a bash builtin, wrapper, or code-execution sink" (domain: `bash-frontend`)

1. Read `domains/bash-frontend/README.md` and `domains/bash-frontend/abstract-exec.md` — understand abstract execution over Σ, the `Resolver` seam, and the closed `sinkSet` / `codeExecBuiltins` / `shellOnlyBuiltins` tables.
2. Read `architecture/layers.md` (the resolver seam) and `contracts/frontend-engine.md` — everything the shell contributes itself (redirections, code-exec sinks, environment writes) is emitted in `front/bash` directly; ordinary commands come back through the injected resolver.
3. Edit `front/bash/builtins.go` (sinks/builtins) or `front/bash/normalize.go` (wrapper unwrapping: `sudo`, `env`, `nohup`, …).
4. **After implementation**: update `domains/bash-frontend/README.md`; run `go test ./front/bash/` and refresh `front/bash/testdata/*.golden.json` if the normalized AST changed.

### "Extend PowerShell cmdlet coverage" (domain: `powershell-frontend`)

1. Read `domains/powershell-frontend.md` — understand parsing via tree-sitter, lowering, and the alias/cmdlet tables.
2. Add or adjust the cmdlet→effect mapping and alias expansion in `front/ps/aliases.go`; lower it in `front/ps/lower.go`.
3. **After implementation**: update `domains/powershell-frontend.md`; run `go test ./front/ps/`.

### "Add or change an effect kind, lattice level, or IR field" (domain: `engine` — the frozen core)

1. Read `domains/engine/README.md`, `domains/engine/effect-ir.md` and `domains/engine/lattices.md`.
2. Read ADR-0001 (`decisions/0001-frozen-effect-ir.md`) — the IR is frozen and versioned; a change here is a deliberate schema break.
3. Change `engine/effect.go` / `engine/lattice.go` and bump `engine.SchemaVersion` (currently `effect-ir/v1`).
4. Update every producer (`bind`, `front/bash`, `front/ps`) and the golden fixtures `engine/testdata/effect.golden.json` / `report.golden.json`.
5. **After implementation**: update the `engine` specs, add an ADR for the schema break, and run `go test ./... -count=1`.

### "Change the report JSON contract" (domains: `engine` and `analysis-report`)

1. Read `domains/engine/effect-ir.md`, `domains/engine/scoring.md` and `domains/analysis-report.md`.
2. Read `contracts/report-json.md` — the outward report is the `flowsh` JSON contract (`ToolVersion = flowsh/v2`).
3. Change `engine/report.go` and the `Report` type in `internal/analysis/analyze.go` together, and bump the version tags.
4. **After implementation**: update the affected specs and the CLI smoke assertions in `cmd/flowsh/smoke_test.go` (run by `go test ./...`, gated in `.github/workflows/ci.yml`).

### "Add a corpus case to the GuardFall / recall gate" (domain: `analysis-report`)

1. Read `domains/analysis-report.md` — understand the corpus `Case`, the GuardFall classes A–E, and the groups (`guardfall`, `destructive`, `benign`, `ps`, `resolution`).
2. Add the case to the relevant fixture under `testdata/corpus/*.json` with a stable `id`, `group` and `lang`.
3. **After implementation**: update `domains/analysis-report.md`; the "no silent miss" invariant (`Report.Covered`) must hold: a case yields at least one effect or degrades to ⊤.

### "Investigate why an effect was reported" (domain: `engine`)

1. Run the CLI: `go run ./cmd/flowsh --lang bash --json '<command>'`.
2. Read `domains/engine/scoring.md` — the `WhyTrace`/`WhyStep`/`Atom` vocabulary explains each effect. If the reasoning is undocumented, look at `domains/binding.md` (name resolution) and the frontend spec that emitted it.

### "Add a new input dialect" (domains: `bash-frontend`/`powershell-frontend` and `analysis-report`)

1. Read `domains/bash-frontend/README.md` and `domains/powershell-frontend.md` — the frontend contract (parse → normalize/lower → `[]engine.Effect`, degrade to ⊤ on failure).
2. Read `domains/analysis-report.md` and `contracts/frontend-engine.md` — dialects are registered as `Lang` values and routed in the facade.
3. **After implementation**: add a domain spec for the dialect, update `domains/analysis-report.md`, and update INDEX.md.

### "Understand why X is designed a certain way"

1. Search in `decisions/` — there may already be an ADR (ADR-0001 … ADR-0010).
2. If not — look at the `## Invariants` section of the corresponding domain spec.

---

## 7. Working with ADRs

### Creating a New ADR

1. Determine the next sequential number (check existing ones in `decisions/`)
2. Copy the template from `decisions/_template.md`
3. Fill in all sections
4. Add an entry to `INDEX.md`

### Superseding a Decision

1. Create a new ADR with the updated decision
2. In the old ADR, change `## Status` to `Superseded by [NNN](./NNN-slug.md)`
3. This is the only permissible edit to an accepted ADR

---

## 8. Content Formatting Principles

### Invariants — Affirmative Only

```markdown
<!-- Correct -->
- The engine package imports only the standard library or other engine packages.
- A frontend emits the top element ⊤ instead of failing when it cannot bound the input.
- The binder resolves a name through builtin, function, alias, then PATH, in that order.

<!-- Incorrect -->
- The engine should not import a frontend.
- Don't crash on an unparseable program.
```

### Key Files — From Repository Root

```markdown
## Key Files

- `engine/effect.go` — the effect IR (Effect, EffectKind, EffectMode)
- `bind/bind.go` — the invocation → effects binder
```

### Tables for Reference Information

Tables are the preferred format for: interface catalogs, tool registries, configuration mappings, decision tables. In flowsh, use them for the `EffectKind`/`EffectMode` sets, the `Dialect` list, the `ValueSource` list, and the destructive classes A–E.

### ASCII Diagrams

For flows and architecture — ASCII art (not Mermaid), to work without a renderer. Show the analysis pipeline as the layering:

```
source text
   │  parse + normalize / lower
   ▼
front/bash   front/ps
   │  normalized Call            │  lowered effects
   ▼                             │
bind  ◀── kb (command signatures)│
   │  []engine.Effect            │
   ▼                             ▼
        engine (frozen IR, lattices, Report)
                      │
                      ▼
        internal/analysis (composition + CLI)
```

---

## 9. Anti-Patterns

| Anti-pattern | Why it's bad | What to do instead |
| --- | --- | --- |
| Mirror file structure in specs | One file may participate in multiple domains (see the domain→package mapping in META.md) | Organize by domains |
| Generate specs from code | Loses the ability to detect discrepancies | Write manually, compare with code |
| Skip updating INDEX.md | Agent won't find the new spec | Always update when adding/removing |
| Edit an accepted ADR | Loses decision history | Create a new ADR with `Superseded by` |
| State invariants negatively | Harder to verify compliance | Use affirmative phrasing |
| Add filler and human-oriented explanations | Wastes the agent's context window | Only necessary and sufficient information |

---

## 10. Quick Start (TL;DR)

1. **Need to learn something** → `specs/INDEX.md` → find task → go to spec
2. **Need to change code** → read domain spec + contract → implement → update spec
3. **Need a new decision** → create ADR → update INDEX.md
4. **Need to add a spec** → take format from META.md → create file → update INDEX.md
5. **Formats, rules, templates** → `specs/META.md`
