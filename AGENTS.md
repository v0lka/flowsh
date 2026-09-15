# AGENTS.md

## Project

`flowsh` — a Go effect-analysis engine that takes a shell or PowerShell command and reports the observable effects it implies (filesystem, environment, network, process, credential, code-execution, ...), a composite risk score, and credential-exfiltration findings. The module is `github.com/v0lka/flowsh`; the public binary is `flowsh`.

## Layout

- `engine/` — frozen, frontend-agnostic core: effect IR, value lattices, scoring, report format
- `front/bash/`, `front/ps/` — the bash and PowerShell frontends
- `kb/` — the embedded YAML knowledge base (`kb/data/*.yaml`)
- `bind/` — command resolution and flag/operand binding
- `internal/analysis/` — the composition facade (frontends + binder + core → `Report`)
- `internal/corpus/` — the test-only regression-corpus harness (loader + group selectors)
- `cmd/flowsh/` — the CLI
- `testdata/corpus/` — the GuardFall / destructive / benign / ps conformance corpus

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
