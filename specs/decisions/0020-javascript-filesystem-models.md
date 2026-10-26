# ADR-0020: YAML-backed JavaScript filesystem slice

## Status

Accepted

## Context

Issue #29 requires Node filesystem coverage and report parity. The semantic kernel in ADR-0018 supplies bounded values and control flow but deliberately leaves builtin identity and API knowledge to later milestones. Filesystem coverage needs the relevant identity and YAML infrastructure from #34/#36, plus recursive-delete severity from #33. The core vocabulary and report field shapes remain frozen.

## Decision

Use effect-kb/v4 with separate JS module/call namespaces. Declare real API shapes, module aliases/properties, typed selectors, effects, return operations, and destructive predicates in reviewed embedded YAML. The facade injects BindJS through the frontend resolver seam; front/js retains its downward dependency on engine. Resolution follows evaluated values through imports, destructuring, and aliases. Unknown execution or export mutation invalidates identity conservatively.

Use an explicit POSIX abstract path context on every host. Nil facade context uses symbolic home `/root`, matching Bash, and unknown cwd; embedders can supply Home/Cwd explicitly. Literal `~`/`$HOME` filenames remain literal targets/evidence and also contribute their home-normalized report abstraction. Helpers retain Node path semantics without reading host state. Include deprecated recursive rmdir for the Node 22/24 compatibility baseline and document its removal in Node 25.

Model possible synchronous throws and trusted promise rejection under sequential await. Callback APIs emit the outer filesystem effects plus canonical top and a reason while #34 owns callback execution. Use existing FSRead/FSWrite/FSMeta kinds and shared destructive class E for recursive/forced deletion. Report metadata uses existing fields; JS canonical effects preserve bound filename characters without shell filters. Model work and report metadata obey the existing frontend limits.

## Consequences

Filesystem API coverage ships through the intended architecture with specific effect, target, metadata, source-location, exception, and corpus assertions. The report remains flowsh/v3 and the engine remains unchanged. Callback precision, general functions/closures, broader permission classes, other Node families, and aggregate epic closure remain separate work. Conservative callback diagnostics are part of this slice's completion contract and cannot be counted as precise callback execution.

## Alternatives Considered

Matching raw callee text would misidentify shadowed/reassigned values. Hardcoding filesystem API names in the evaluator would duplicate the later knowledge-model layer. Reading analyzer host home/cwd or using host-dependent filepath behavior would violate offline determinism. Treating handled callbacks or unknown options as harmless would hide reachable behavior. Reusing shell canonical filtering would discard valid JavaScript filenames.
