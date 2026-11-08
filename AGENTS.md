# AGENTS.md

## Project

`flowsh` — a Go effect-analysis engine that takes a shell, PowerShell, or JavaScript program and reports the observable effects it implies (filesystem, environment, network, process, credential, code-execution, ...), a composite risk score, and credential-exfiltration findings. The module is `github.com/v0lka/flowsh`; the public binary is `flowsh`.

## Layout

- `engine/` — frozen, frontend-agnostic core: effect IR, value lattices, scoring, report format
- `front/bash/`, `front/ps/`, `front/js/` — bash, PowerShell, and the bounded JavaScript frontend (values, control flow, and modelled Node filesystem/path effects; anything unmodelled degrades to ⊤)
- `kb/` — the embedded YAML knowledge base (`kb/data/*.yaml`) plus the offline JavaScript builtin namespaces (`kb/js.go`)
- `bind/` — command resolution and flag/operand binding
- `internal/analysis/` — the composition facade (frontends + binder + core → `Report`)
- `internal/corpus/` — the test-only regression-corpus harness (loader + group selectors)
- `cmd/flowsh/` — the CLI
- `api/` — the public embeddable Go library: type aliases over `internal/analysis`, so an external module can embed the analyser without importing anything under `internal/`
- `policy/` — optional report evaluation for an embedding application: turns an `api.Report` into an `Allow`, `Review` or `Deny` decision under trusted, caller-owned rules
- `testdata/corpus/` — the conformance corpus: bash, POSIX, PowerShell and JavaScript cases across the `guardfall` / `destructive` / `benign` / `ps` / `resolution` / `external_malicious` / `external_benign` groups
- `docs/` — the user-facing guides (CLI, JSON report reference, embedding, knowledge-base how-to, roadmap); descriptive only — where they and `specs/` disagree, the specification is authoritative
- `specs/` — the normative system specification (see Specifications below)

## Build & Test

- `go build ./...`
- `go test ./...` — runs the corpus gate (no-silent-miss) plus the latency and recall gates
- `go vet ./...` and `gofmt -l .` are part of CI

## Specifications

Detailed system specs live in `specs/`. Before making structural changes, read the relevant spec:

- Start with `specs/INDEX.md` to find the right document for your task.
- `specs/META.md` defines spec formats and update rules.

The two invariants that most changes must respect are documented there: dependencies flow one way (the core never imports a frontend or the knowledge base), and every layer degrades to the top element ⊤ rather than guessing or crashing.

## Security Policy

This project maintains a security policy in [SECURITY.md](./SECURITY.md).
All AI coding agents MUST read and follow SECURITY.md before making changes.
It contains:

- Threat model and trust boundaries
- Secure coding guidelines specific to this project's stack
- Hard constraints and forbidden patterns for AI agents
- Vulnerability reporting procedures
- Agentic security controls (OWASP Top 10 for Agentic Applications ASI01–ASI10), where applicable

Any code contribution that violates the rules in SECURITY.md will be rejected.
