# Report Policy

## Purpose

`policy` is an optional public Go package for evaluating an analysis report. It centralises reusable decision rules while leaving analysis unchanged and execution, approval, and isolation with the embedding application.

## Key Files

- `policy/policy.go` — configuration validation and pure report evaluation.
- `policy/policy_test.go` — fail-closed behaviour, precedence, and integration tests.
- `policy/example_test.go` — executable public API example.
- `docs/embedding.md` — consumer workflow and limitations.

## Core Types

- `Action`: `Allow`, `Review`, `Deny`; empty is invalid.
- `Config`: actions for unknown, conservative, exfiltration, cradle, and ingest signals, plus maps from effect kind and exact score grade to an action.
- `Policy`: immutable copy of validated configuration, created with `New`.
- `Decision`: strongest action and sorted, deduplicated restrictive `Match` values.
- `Match`: stable code and action, with no source-derived text.

## Flow

1. The caller constructs a policy from trusted configuration; invalid actions, effect kinds, and grades return an error.
2. The caller analyses source through `api` and handles any error.
3. `Evaluate` checks the report's tool, tool/schema versions, canonical language, effect validation, and grade. Failure returns Deny with `invalid_report`. It then checks `Covered()`; failure returns Deny with `uncovered_report`.
4. For a valid, compatible, covered report, all applicable rules contribute restrictions. Deny wins over Review, which wins over Allow. No restrictive match means Allow.
5. The caller enforces the decision and retains the original sensitive report as evidence if needed. `Allowed()` is true only for explicit Allow.

## Invariants

- Evaluation is deterministic, side-effect-free, and leaves the report intact.
- Existing analysis, CLI output, report versions, and effect semantics stay unchanged.
- Unknown (`Top || HasTop()`) and conservative analysis always require Review or Deny, regardless of effect/grade rules.
- Missing, invalid, incompatible, and uncovered reports always deny.
- Nil/zero policies deny; zero decisions never grant permission.
- An Allow rule never overrides a restriction from another rule.
- Matches contain only fixed signal names or validated kind/grade names.
- Policies own their maps and are safe for concurrent evaluation when callers do not mutate reports. No analysed content can configure a policy.
- Flow rules consume reported flows rather than inferring them from co-occurrence.
- Evaluation cost is linear in the report's effects; match storage is bounded by the finite set of signals, effect kinds, and grades.

## Configuration

| Field | Default | Accepted values / meaning |
| --- | --- | --- |
| `Unknown` | Deny | Review or Deny for Top or unbounded CodeExec |
| `Conservative` | Review | Review or Deny for conservative analysis |
| `Exfiltration` | Deny | Any action for nonempty exfilPairs |
| `Cradle` | Review | Any action for nonempty cradleFlows |
| `Ingest` | Allow | Any action for nonempty ingestFlows |
| `Effects` | Empty | Valid effect kind to action |
| `Grades` | Empty | Exact valid score grade to action; no implicit threshold |

Signal reason codes are `unknown`, `conservative`, `exfiltration`, `cradle`, and `ingest`. Other matches use `effect:<kind>` and `grade:<grade>`. Nil/zero policies return `invalid_policy`; missing, invalid, or incompatible reports return `invalid_report`. Otherwise-valid reports with `Covered() == false` return `uncovered_report`. Validation precedes coverage, so invalid reports always use `invalid_report` even when uncovered. Empty scalar configuration fields receive defaults; empty map actions are errors.

`Covered()` requires at least one effect, `Top`, or `Conservative`. Authentic reports for benign no-op commands such as Bash `true` and `:` have zero effects and neither flag; they pass validation but deny with `uncovered_report`. The coverage gate applies regardless of configured rules or the absence of uncertainty.

Canonical languages are `bash`, `posix`, `posh`, and `js`. JavaScript pure understood programs may produce valid empty-effect reports and deny with `uncovered_report`. Unmodelled JS execution remains top/conservative: defaults deny it with uncertainty matches, while configuring both signals as Review yields Review unless another rule denies. Effect/grade Allow rules cannot override these signals.

Configuration is supplied in Go by the trusted caller; the package loads no files, environment variables, plugins, or remote rules. Default rules do not constitute a complete threat-model-specific policy. Allow means no configured restriction matched, not proof of safety. Review is not execution permission.

## Extension Points

New reusable report predicates can be added here with validation, deterministic reason codes, and regression tests. Command interpretation belongs in the frontends/binder, not in policy source-text heuristics. Filesystem confinement, network enforcement, and authorisation remain outside the package. Report validation does not authenticate caller-supplied reports or fill analysis gaps.

## Related Specs

- [Analysis Report](analysis-report.md) — the input report and its uncertainty signals.
- [Layers](../architecture/layers.md) — policy depends on api and engine only.
- [Conservatism](../architecture/conservatism.md) — unknown analysis remains visible.
- [ADR-0017: Report policy package](../decisions/0017-report-policy-package.md) — the public policy layer and amendment to ADR-0010's sole-public-surface framing.
