# JavaScript Frontend

## Purpose

`front/js` parses JavaScript targeting Node.js and evaluates a bounded statement/expression subset. It produces values and control flow; builtin module identity and filesystem/path knowledge flow through an injected YAML-backed binder; general function invocation and the remaining Node families belong to later milestones. Unsupported execution degrades to the shared top effect.

## Key Files

- `front/js/analyze.go` — entry points, resolver boundary, results, and degradation.
- `front/js/parse.go` — pinned tree-sitter parsing and position-preserving normalization.
- `front/js/value.go` — typed values, immutable container snapshots, case-sensitive lexical state, joins, and taint.
- `front/js/expr.go` — expressions, literals, destructuring inputs, and conservative calls.
- `front/js/modules.go` — trusted module/import bindings and model work charging.
- `front/js/exec.go` — statements, scope, hoisting, completion states, loops, switch, and exceptions.
- `front/js/analyze_test.go` — semantic matrix, resolver witnesses, bounds, concurrency, and fuzz seeds.
- `front/js/regressions_test.go` — reachable-call, signed-zero, key, and identifier regressions.
- `internal/analysis/analyze.go`, `internal/analysis/analyze_javascript_test.go` — report assembly and source locations.
- `api/api_test.go`, `cmd/flowsh/smoke_test.go`, `policy/policy_test.go` — consumer contracts.
- `testdata/corpus/guardfall_js.json` — GuardFall A–E conservative coverage.

## Core Types

```go
type Result struct {
    Effects      []engine.Effect
    Derivations  []engine.Derivation
    Top          bool
    Conservative bool
    Reason       string
}

type Call struct {
    Kind, Module, Export, Callee string
    Args []Value
    ArgLocs []engine.SourceLoc
    Loc engine.SourceLoc
    Charge func(int) // context work, charged before model materialization
}
type Resolution struct {
    Handled     bool
    Value       Value
    Effects     []engine.Effect
    Derivations []engine.Derivation
    MayThrow bool
    Reason string
}
type Resolver func(Call) Resolution

func Analyze(src string) *Result
func AnalyzeWith(name, src string, resolver Resolver) *Result
```

`Value` is a frontend-local lattice, separate from the frozen effect IR. Its zero value is unknown; exact elements include strings, numbers, booleans, null, undefined, function bodies, bounded plain objects/arrays, builtin modules/exports, trusted modeled promises, opaque filesystem content, and unknown booleans. A join preserves equal primitive values or identical immutable snapshots; disagreement becomes unknown. Taint always joins, independently of knownness. Unknown is distinct from JavaScript `undefined`.

Numeric lattice equivalence follows [ECMAScript SameValue](https://tc39.es/ecma262/multipage/ecmascript-data-types-and-values.html#sec-numeric-types-number-sameValue): signed zeros differ and NaNs agree. JavaScript strict equality still equates the zero signs and rejects NaN equality. Unsupported primitive update conversions return unknown for both the stored value and the postfix result, preserving taint, and emit a conservative top effect with a reason; numeric updates remain exact.

Escaped identifiers are explicitly unsupported during normalization. Their raw spelling differs from the [identifier name](https://tc39.es/ecma262/multipage/ecmascript-language-lexical-grammar.html#sec-names-and-keywords), so treating the spelling as a lexical binding could bypass shadowing. Unescaped `undefined` first resolves lexical bindings and uses the built-in value only when unbound.

Catch parameters and each lexical loop iteration predeclare their pattern names before defaults run, preserving the temporal dead zone. Catch-parameter initialization throws join the catch's throwing outcomes before its lexical frame is removed. Finalizers run on those outcomes before an enclosing catch observes their state.

Builtin imports initialize exact reviewed module/export identities during predeclaration, including hoisted ESM locals. Unsupported imports retain initialized unknown bindings and conservative initialization effects. Unshadowed `require` and extracted loader aliases resolve reviewed module spellings through the injected resolver. Module/property lookup uses evaluated identity; export mutation and unknown execution invalidate identities conservatively. Classes retain lexical initialization, and generators retain their binding. Array spread widens mutable state because unmodeled iterators can execute user code.

State stores case-sensitive bindings in lexical frames, with initialization and constness. `var` declarations hoist to the analyzed unit's variable frame; `let`/`const` are predeclared in their block. Reads before lexical initialization and invalid writes degrade rather than invent a value. Branch clones share immutable container snapshots; unmodelled calls/writes invalidate potentially mutable state.

`var` initializers and iteration assignments resolve the active binding, including
a shadowing catch parameter; hoisting alone targets the variable frame.
`typeof` on a name absent from lexical state yields unknown because the host may
provide it. Possible host accessor throws remain catchable; known local values
and the unshadowed built-in `undefined` retain exact types.

## Flow

```text
explicit --lang js/javascript/node/nodejs
    -> facade -> js.AnalyzeWith(source label, source, BindJS resolver)
    -> pinned JavascriptLanguage parser -> owned normalized tree
    -> bounded evaluator (values + state + completion paths)
    -> Result{effects, derivations, Top/Conservative/Reason}
    -> shared normalization / scoring / why / canonical -> Report
```

### Supported subset

| Construct | Evaluation | Test coverage |
| --- | --- | --- |
| `var`/`let`/`const`, assignment, comments, leading shebang, empty statements | Case-sensitive state, block scope, var hoisting, TDZ/constant degradation; shebangs are inert and preserve source positions | `TestValuesAndStatements`, `TestDegradeRules`, `TestHashbangIsInert` |
| Object/array destructuring, defaults, rest, holes | Exact own literal fields/elements; missing properties and unknown receivers/iterables degrade | `TestValuesAndStatements`, `TestDegradeRules` |
| String/number/boolean/null/undefined literals | Exact primitive values; unsupported encodings/numeric forms yield unknown and conservative top with a reason | `TestValuesAndStatements`, `TestUnsupportedValuesDegrade` |
| Plain object/array and JSON-shaped literals | Immutable bounded snapshots; literal property/index reads | `TestValuesAndStatements` |
| Templates and string concatenation | Known primitive components fold; unknown/coercible components yield unknown, with top for unmodelled conversion | `TestUnknownTemplateIsNotLiteral`, `TestDegradeRules` |
| Numeric arithmetic, bitwise `&`/`\|`/`^`, numeric comparisons, equality, unary operations | Fold documented primitive cases; unsupported coercions yield unknown and top | `TestValuesAndStatements`, `TestDegradeRules`, `TestUnsupportedValuesDegrade` |
| `&&`, `\|\|`, `??`, ternary | Respect known reachability; unknown alternatives join state and values | `TestValuesAndStatements`, `TestHeadersAndUnknownExceptions` |
| `if`/`else` | Select a known branch; fork and join unknown branches | `TestValuesAndStatements` |
| `for`, `while`, `do-while` | Evaluate initializer/test/update/body in order; charge each iteration; unknown bounds widen mutable state and degrade | `TestValuesAndStatements`, `TestBudgetPreservesEffects` |
| `for-of`, `for-in` | Exact finite array elements / plain-object own keys (integer keys first); other iterables degrade | `TestValuesAndStatements`, `TestDegradeRules` |
| `break`, `continue` | Separate completion paths consumed by the enclosing loop/switch | `TestValuesAndStatements` |
| `switch` | Test expressions in order, snapshot each possible entry, preserve fallthrough and default; shared case lexical frame | `TestSwitchEntryStates`, `TestValuesAndStatements` |
| `try`/`catch`/`finally`, `throw`, `return` | Distinct normal/break/continue/return/throw outcomes; catch consumes throws; finally runs on every outcome and can override it | `TestFinallyOverridesAbruptCompletion`, `TestFunctionBodiesUseStatementEvaluator` |
| Function declarations/expressions and arrows | Retain bodies as values; declarations produce no body effects; the statement evaluator can evaluate bodies in an isolated supplied state | `TestFunctionBodiesUseStatementEvaluator` |
| `import`/`export` | Evaluate local exported declarations; reviewed builtin namespaces/exports retain identity; unsupported external initialization degrades and binds unknown names | `TestValuesAndStatements`, `TestDegradeRules` |
| `async`/`await` | Preserve async function bodies; sequential primitive/modeled-promise await with possible rejection; unknown thenables degrade | `TestValuesAndStatements`, `TestDegradeRules` |

Function **invocation** always remains conservative in this milestone. Parameter binding, caller return propagation, recursion, closures, precise callback invocation, defaults, and IIFEs belong to #34. Builtin module aliases are implemented for the filesystem slice. The production evaluator does not traverse a dormant function as though it ran. `return` handling is exercised through the same body evaluator without implementing calls.

### Explicit degradation table

| Construct | Result |
| --- | --- |
| Source size/raw delimiter depth limit, parse timeout/error, missing syntax, stopped parse, parser/normalizer failure | Whole-unit top with fixed diagnostic; no salvaged prefix treated as complete |
| Unsupported numeric literals, failed string decoding, unsupported primitive unary/update coercions | Unknown + top with Conservative, a fixed reason, and a source-located derivation |
| Exhausted execution budget or internal evaluator panic | Whole-unit top; previously discovered effects retained |
| Unknown loop bound/iterable (incl. `for await`) | Top effect; mutable state widened; possible body, zero-iteration, and TypeError throw outcomes retained |
| Classes/methods, generators/async iterators, accessors, Proxy, `with` | Affected value unknown and top for unsupported execution |
| Escaped identifier tokens | Whole-unit top with an explicit unsupported-syntax reason; raw spelling is never used as a binding name |
| Labels beyond an empty labelled statement | Top; labelled abrupt completion is unsupported |
| Unknown literal property keys | Unknown + top; containers, reads, destructured values, and rest objects lose precision; exact empty-string keys remain supported |
| Computed property keys beyond literal member/index keys | Evaluate the key's expressions, then unknown + top |
| Prototype-dependent property access, object spread, property writes/export mutation | Unknown + top; mutable state invalidated |
| Unresolved calls/constructors, including user functions and unmodeled Node APIs | Evaluate callee/arguments, return unknown + top unless an injected trusted resolver handles the call |
| Unknown-value/object coercion or await of an unknown thenable | Unknown + top; retain possible throw path |
| External module initialization | Unknown imported names + top; no runtime file resolution |

The public facade injects `BindJS`. The function-valued seam accepts module/property requests and typed calls, and returns values/effects/derivations, possible throws, and conservative reasons without importing bind/KB into front/js. Constructors remain unmodeled. Work is charged before model execution, including reused strings and option records. Models share the existing 1024 argument/effect/derivation limits. `Value.String`, Kind, Boolean, Number, Property, and Keys expose bounded read-only model inputs; constructors create exact strings/undefined, reviewed builtin identities, opaque content, unknown booleans, and modeled promises. Projection supplies bounded report arguments. See the [filesystem contract](javascript-filesystem.md) and [ADR-0020](../decisions/0020-javascript-filesystem-models.md).

### Console and asynchronous policy

`console.log` stdout does **not** fold into expression values. The evaluator does not capture stdout, inspect a Node process, or execute logging. Until a data-driven model exists, `console.log` is an unmodelled call and degrades. This explicitly differs from Bash command-substitution stdout folding. No Node API is special-cased in Go.

`await` uses sequential value semantics and trusted modeled-promise fulfillment/rejection. Event-loop ordering, scheduling, arbitrary thenables, and async callback execution are outside this milestone.

### Report behavior

An understood effect-free program (including empty library input, declarations, finite pure loops, and dormant functions) returns `effects: []`, no uncertainty flags, and no canonical form. It validates but `Covered()` is false; policy denies it with `uncovered_report`, matching existing benign Bash no-ops. The frontend manufactures neither an effect nor a conservative flag to satisfy coverage.

Unsupported reached execution, literal decoding, and primitive coercions emit Direct `CodeExec(ScopeTop())`, certain and irreversible, with a fixed reason and a source-located derivation. `Conservative` is true; `Top` marks a whole-unit failure, not every local unknown call or value. Abstract unknowns produced by supported operations, such as joining different branch values, remain valid lattice results and do not by themselves imply unsupported analysis. Shared scoring supplies Critical severity for top. The facade preserves input/root and version tags. The facade carries filesystem binding metadata, destructive classes, source evidence, and bound-target canonical effects.

Whole-unit failures without a parsed source location use the fixed `literal:js-opaque` marker without a location; the diagnostic stays in `reason`. Earlier derivations retain their source locations when evaluation exhausts its budget.

## Invariants

- Every analysis owns its result, state, and effect slice; shared parser grammar data remains immutable.
- Unknown values preserve joined provenance and remain distinct from exact empty strings and undefined.
- Reachable expression headers and keys are evaluated before their bodies/values; known dead expressions remain unevaluated.
- Completion kinds retain their own joined states; a return/throw path remains separate from a continuing path.
- Every unsupported execution carries the canonical top effect and a nonempty reason; prior effects survive exhaustion.
- Analysis is offline, bounded, and side-effect-free; source labels are data.
- `front/js` depends on `engine` and the pinned parser, with the binder supplied through a function value.
- Pure empty-effect reports retain the existing fail-closed uncovered-report policy.

## Configuration

| Bound | Value |
| --- | --- |
| Source bytes | 1 MiB |
| Raw delimiter nesting before parsing | 256 |
| Parser wall-clock timeout | 2 seconds in every build, including `-race` |
| Normalization nodes / depth | 50,000 / 256 |
| Evaluation steps / expression depth | 50,000 / 256 |
| Container entries / recorded effects or derivations | 1,024 |
| Materialized string bytes | 65,536 |

Before invoking the parser, a linear scan checks raw `(`/`[`/`{` nesting with
a fixed-size stack. Matching closing delimiters pop the stack; mismatched
closers do not. This is a conservative byte-level admission check: delimiters
inside strings, comments, templates, and regex literals also count, so deeply
delimited data may degrade even when its syntax-tree depth would be small.
The parser's two-second deadline is an additional safety net for other input
shapes; its polling and cleanup can overrun that deadline. Normalization's
node/depth limits apply only after the parser returns. A stopped or timed-out
parse yields whole-unit top, never a partially analyzed prefix. The deadline
can make a heavily contended host degrade earlier; availability takes
precedence over precision at that boundary. No timeout goroutine is created.
String decoding/concatenation and state copying also consume the step budget.
Invalid UTF-8 source degrades before parsing. Bounds are compile-time constants,
not source-controlled settings.

`Options.Root` labels report/why locations. `Options.Vars` remains Bash/POSIX-only and `Options.Windows` remains PowerShell-only. `Options.JavaScript` supplies explicit POSIX Home/Cwd context; nil uses symbolic home `/root` and unknown cwd. JS reads no host environment, files, runtime state, or module contents. CLI `--lang auto` still chooses Bash or PowerShell only; existing input validation and batch splitting apply.

## Extension Points

#34 adds invocation semantics over retained function bodies and precise callback flows. #36 grows the YAML namespace beyond the filesystem/path slice; #30–#32 add the remaining Node effect families. Each first effect family carries its report metadata, provenance, and corpus witnesses. The core IR and report field shapes retain their existing versions.

## Related Specs

- [ADR-0018](../decisions/0018-javascript-semantic-kernel.md) — evaluator and milestone boundary.
- [Analysis Report](analysis-report.md) — facade and report.
- [Frontend/Engine Contract](../contracts/frontend-engine.md) — dependency and effect boundary.
- [Layers](../architecture/layers.md) — import direction.
- [Conservatism](../architecture/conservatism.md) — shared top representation.
- [CLI](cli.md) — routing and input behavior.
- [Report Policy](policy.md) — uncertainty and uncovered-report decisions.
