# ADR-0005: Two separate frontends — bash and PowerShell resolve differently

## Status

Accepted

## Context

bash and PowerShell share token *spellings* but not *semantics*. The same word
means different things in the two languages: in bash `rm`, `curl` and `iex` are
(respectively) the coreutils binary, the curl binary, and an unknown command; in
PowerShell they are aliases for `Remove-Item`, `Invoke-WebRequest` and
`Invoke-Expression`
(`front/ps/aliases.go`). A single shared resolution table
would therefore produce *wrong* effects for one language or the other.

## Decision

Maintain **two independent frontends**, each owning its own resolution:

- `front/bash` — a bash frontend built on the `mvdan.cc/sh/v3` grammar plus the
  abstract-execution layer, resolving ordinary commands through the `kb`/`bind`
  command knowledge base.
- `front/ps` — a PowerShell frontend built on the embedded tree-sitter
  Powershell grammar, with **its own alias table and its own cmdlet→effect
  mapping** (`front/ps/aliases.go`,
  `front/ps/lower.go`).

The boundary is explicit in the code: the `ps` package "does not import the bash
frontend or the binder: PowerShell resolution has its own alias table and its own
cmdlet→effect mapping" (`front/ps/parse.go`). The three
aliases the task pins are present and tested — `rm → Remove-Item`,
`curl → Invoke-WebRequest`, `iex → Invoke-Expression` — and the tests assert that
`rm -Recurse -Force $HOME` lowers to PowerShell's `Remove-Item` semantics (not
bash effects) and that `curl` lowers to `NetEgress` via `Invoke-WebRequest`
(`front/ps/lower_test.go`).

Both frontends converge only at the shared IR: each lowers into `engine.Effect`
(e.g. `kb.Effect.EngineEffect`), which is what makes their outputs comparable
despite independent resolution.

## Consequences

- Positive: each dialect is analysed on its own terms; PowerShell-only semantics
  (providers/drives, cmdlet switches, alias and function declarations) are
  representable; a change in one frontend cannot silently alter the other;
  failures in one language's resolution stay local to it.
- Negative: duplicated infrastructure — two parse layers and two lowering
  tables to maintain; shared-looking behaviour must be decided twice; the only
  common currency between the frontends is the IR, so any cross-frontend
  reasoning must go through `engine.Effect` rather than a shared resolver.

## Alternatives Considered

- **One frontend with a dialect flag and a merged command table** — rejected:
  the same token would need two entries plus disambiguation logic, which is
  exactly the ambiguity the alias table demonstrates.
- **Share the bash knowledge base with PowerShell through the binder** —
  rejected: PowerShell resolution is an alias/cmdlet model, not the KB's
  command/`dialect`/parameter model, and `ps` must not couple to the binder or
  the bash frontend.
- **Treat PowerShell as bash with different flag spellings** — rejected: alias
  and cmdlet semantics (e.g. the `Remove-Item` verb, `Invoke-Expression`) are not
  expressible in the bash parameter model, and would misresolve `rm`/`curl`/`iex`.
