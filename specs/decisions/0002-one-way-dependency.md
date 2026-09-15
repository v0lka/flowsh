# ADR-0002: Keep the core one-way — `engine` depends on the standard library only

## Status

Accepted

## Context

The core (`github.com/v0lka/flowsh/engine`) is shared by the frontends
(`front/bash`, `front/ps`), the binder (`bind`), the knowledge base (`kb`) and
the composition facade (`internal/cmdscope`). Those layers already form a
dependency *chain*: `kb` imports `engine`, and `bind` imports `engine`, `kb`
and `front/bash`. If the core ever imported a frontend (or `kb`), the chain
would close into an import cycle and the "frozen core" of
[ADR-0001](0001-frozen-effect-ir.md) would become impossible to reason about or
test in isolation. The direction therefore has to be a *checked invariant*, not
a convention that relies on diligence.

## Decision

Dependency direction is strictly one-way: frontends, the binder and the
knowledge base import the core; the core imports **nothing but the Go standard
library** (and, prospectively, other core packages of the same module). The
package doc of `engine/effect.go` states the rule, and
`kb`'s package doc restates it ("the core never imports kb").

The invariant is enforced by an automated test rather than discipline:
`TestCoreDoesNotImportFrontends` in
`engine/report_test.go` parses every `.go` file of the
package and fails on any import that is neither standard library nor a
same-module path; a frontend import is caught both structurally and by an
explicit marker check. `TestFrontendDetection` exists specifically to guard
against the import test passing *vacuously*.

Consequences of failure are visible in the code: because the core must stay
frontend-free, the composition of frontends + binder + engine cannot live in the
core and instead lives above it in `internal/cmdscope`
(`internal/cmdscope/analyze.go`). The reverse seam
is inverted too: the shell frontend cannot call the binder (which imports it),
so it accepts an injected `Resolver` instead
(`front/bash/exec.go`).

## Consequences

- Positive: `engine` remains a leaf package, so the IR and report can be
  reasoned about and tested with no frontend present; cycles are impossible by
  construction; a machine—not a reviewer—catches a violation.
- Negative: anything that must *combine* layers is forced to live above the core
  (hence `internal/cmdscope`); dependencies that would naturally point "up"
  (the shell wanting the binder) must be inverted through an injected seam,
  which adds a small amount of indirection at each boundary.

## Alternatives Considered

- **Move `bind` into `engine`** — rejected: `bind` imports `front/bash`, and the
  core may not import a frontend.
- **Merge `engine` and `kb` into one package** — rejected: `kb` already imports
  `engine`; the core cannot import `kb`, and merging would blur the frozen IR
  with a mutable dataset.
- **Rely on code review / documentation only** — rejected: the constraint is too
  easy to break accidentally, and a broken direction manifests as a confusing
  import cycle far from the offending change.
