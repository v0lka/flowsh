# PowerShell Frontend

## Purpose

`ps` is the PowerShell frontend of the effect IR. It has three responsibilities: `Parse` turns PowerShell source text into a faithful, position-preserving normalized AST using the pure-Go tree-sitter runtime (`gotreesitter`) and its embedded PowerShell grammar under a wall-clock budget that the race detector disables; the walker additionally normalizes structured control flow (`if`/`foreach`/`for`/`while`/`do`/`try`) and assignment right-hand sides into structured statements; `Lower` folds that AST into the frontend-agnostic effect IR **through an abstract variable state Σ** (`front/ps/state.go` + `front/ps/wordeval.go`), consulting the PowerShell alias and cmdlet tables — never the bash knowledge base. A failing parse, an unknown construct, an exhausted budget, or an unresolved variable reference degrades to the top element ⊤ (`CodeExec`) rather than guessing or crashing — a target is either the evaluated value or ⊤, never a fabricated literal (see [ADR-0014](../decisions/0014-ps-abstract-state.md)).

## Key Files

- `front/ps/parse.go` — the parser and the normalized AST: `Pos`, `Word`, `Param`, `Binding`, `Redirect`, `Command`, `Assign`, `Branch`/`IfStmt`, `LoopStmt`, `TryStmt`, `Kind`, `Stmt`, `Program`, `DefaultTimeoutMicros`, `Parse`/`ParseTimeout`, and the CST `walker`.
- `front/ps/budget_race.go` / `front/ps/budget_norace.go` — the build-tagged per-parse budget `parseBudgetMicros` (and `raceDetectorEnabled`) `Parse` applies: `DefaultTimeoutMicros` in an ordinary build, `0` (disabled) under the race detector (see [ADR-0012](../decisions/0012-race-advisory-parse-budget.md)).
- `front/ps/state.go` — the abstract variable state Σ: `Var{Value, Set, Known, Taint, Hash}`, `State` with the variable map plus the drive lattice (`Drives`, `DriveUnknown`, `AllDrivesUnknown`), `NewState` (automatic-variable seeds), `Clone`, `Set`/`SetUnknown`/`SetHash`/`Unset`, `SetDrive`/`SetDriveUnknown`/`UnsetDrive`/`RewriteDrive`, and `JoinStates` (the branch least upper bound).
- `front/ps/wordeval.go` — word evaluation against Σ: `evalWordText` (parts → {text, known, taint, envReads}), the interpolation scanner, env/using/scope qualifiers, member-access mode, splat classification.
- `front/ps/lower.go` — lowering to the IR: `Lower`/`LowerWith`, `lowerer` (Σ + step budget), `topReason`, `emitSpec`/`emitOne`, `assignment`, `ifStmt`/`loopStmt`/`tryStmt`, `mutateState`, `expandSplat`, `bumpFor`, `finish`, and credential-material detection.
- `front/ps/aliases.go` — the built-in `Aliases` table, `LookupAlias`, the `Cmdlets` command→effect table, `TargetKind`/`Spec`, the parameter-classification tables and predicates (`isSwitch`/`isSwitchPrefix`, `pathParam`, `patternParam`, `nameParam`, `urlParam`, the data-file classes `readDataNames`/`writeDataNames`/`catalogOutputNames`), and the drive/provider helpers.
- `front/ps/aliasstate.go` — the order-aware alias state: `applyAliasDecl` (a `Set-Alias`/`New-Alias` declaration only rewrites the calls that follow it), `ScopedItemOptions` immutability (`Constant`/`ReadOnly`/`mayImmutable` — a refused rebinding keeps the original), `Alias:` provider rebinding (`Set-Item`/`New-Item`/`Copy-Item`/`Rename-Item`/`Remove-Item`/`Clear-Item`), `Remove-Alias`, `Import-Alias` (definitions come from a file → resolution unknown), wildcard/whole-drive removal (→ ⊤), and pipeline-fed removals (`Get-Alias | Remove-Item`).
- `front/ps/lower_test.go` — lowering tests; `state_test.go`, `wordeval_test.go`, `assign_test.go`, `cf_test.go`, `integration_test.go`, `state_cmdlets_test.go`, `splat_test.go`, `aliases_test.go`, `findings_test.go`, `findings2_test.go`, `flow_test.go`, `fuzz_test.go` — the Σ, word-evaluation, assignment, control-flow, integration, session-state, splatting, alias-state/cmdlet-table, findings-regression, pipeline-value-flow and fuzz/adversarial-input tests.

## Core Types

### AST and parse result (`parse.go`)

```go
// DefaultTimeoutMicros bounds a single parse: 250 ms in an ordinary build.
// Parse disables it under the race detector (see budget_race.go).
const DefaultTimeoutMicros uint64 = 250_000

type Word struct {
	Pos     Pos    `json:"pos"`
	Text    string `json:"text"`
	Literal bool   `json:"literal"`
	EnvName string `json:"envName,omitempty"`
	VarName string `json:"varName,omitempty"`
	Splat   bool   `json:"splat,omitempty"`
}

type Command struct {
	Pos          Pos         `json:"pos"`
	Text         string      `json:"text"`
	Name         string      `json:"name"`
	NameWord     *Word       `json:"nameWord,omitempty"`
	ComputedName bool        `json:"computedName,omitempty"`
	CallOperator bool        `json:"callOperator,omitempty"`
	DotSource    bool        `json:"dotSource,omitempty"`
	Params       []*Param    `json:"params,omitempty"`
	Args         []*Word     `json:"args,omitempty"`
	Bindings     []*Binding  `json:"bindings,omitempty"`
	Redirs       []*Redirect `json:"redirs,omitempty"`
	// ArrayComma marks a comma-separated argument list (a,b): the grammar
	// cannot split it into elements, so the operands cannot be bounded and
	// the command lowers to ⊤.
	ArrayComma bool `json:"arrayComma,omitempty"`
}

type Kind string

const (
	KindCommand    Kind = "command"
	KindAssignment Kind = "assignment"
	KindTop        Kind = "top"      // opaque code execution (⊤)
	KindIf         Kind = "if"       // if/elseif…else
	KindLoop       Kind = "loop"     // foreach/for/while/do
	KindTry        Kind = "try"      // try/catch…/finally
	KindRedirect   Kind = "redirect" // a redirection-only pipeline ($x > f)
)

// Stmt is one normalized statement. The structured forms carry their head
// statements (an if condition pipeline, a loop header) in place; Redirs serves
// a redirection-only pipeline; Pipe is the group id shared by the stages of
// one PowerShell pipeline.
type Stmt struct {
	Kind   Kind        `json:"kind"`
	Pos    Pos         `json:"pos"`
	Cmd    *Command    `json:"cmd,omitempty"`
	Assign *Assign     `json:"assign,omitempty"`
	If     *IfStmt     `json:"if,omitempty"`
	Loop   *LoopStmt   `json:"loop,omitempty"`
	Try    *TryStmt    `json:"try,omitempty"`
	Reason string      `json:"reason,omitempty"` // KindTop only
	Redirs []*Redirect `json:"redirs,omitempty"` // KindRedirect only
	Pipe   int         `json:"pipe,omitempty"`   // pipeline group id
}

type Program struct {
	File    string            `json:"file,omitempty"`
	Source  string            `json:"source"`
	Top     bool              `json:"top"`
	Reason  string            `json:"reason,omitempty"`
	ErrPos  *Pos              `json:"errPos,omitempty"`
	Errors  bool              `json:"errors,omitempty"`
	Stmts   []*Stmt           `json:"stmts"`
	Aliases map[string]string `json:"aliases,omitempty"`
	Funcs   map[string]bool   `json:"funcs,omitempty"`
}
```

### Lowering result (`lower.go`)

```go
const StylePS = "ps"

type Options struct {
	Windows bool // enables the Registry provider; defaults to runtime.GOOS == "windows"
}

type Result struct {
	Style           string                 `json:"style"`
	Effects         []engine.Effect        `json:"effects"`
	Destructiveness engine.Destructiveness `json:"destructiveness"`
	// Derivations justifies every reported effect with the concrete source
	// atoms (command, operand, redirect, source, sink) it rests on, for the
	// composition layer's why-trace.
	Derivations     []engine.Derivation `json:"-"`
	Conservative    bool                   `json:"conservative"`
	Notes           []string               `json:"notes,omitempty"`
}
```

### Cmdlet table (`aliases.go`)

```go
type TargetKind string

const (
	TargetNone TargetKind = "none"
	TargetPath TargetKind = "path" // -Path/-LiteralPath/-Destination/… values combined with the operands
	TargetURL  TargetKind = "url"  // the -Uri/-Url/-ConnectionUri/-Proxy values, else operands
	TargetName TargetKind = "name" // the -Name/-Id/-*Name values, else operands
	TargetSelf TargetKind = "self" // the invoked command's own name
	TargetCwd  TargetKind = "cwd"  // the current directory
)

type Spec struct {
	Kind       engine.EffectKind
	Mode       engine.EffectMode
	Target     TargetKind
	Reversible bool
	Op         string // human-readable verb surfaced in notes ("read", "write", …)
}

// Cmdlets maps a canonical cmdlet name to the effects it contributes. A name
// present with an empty spec list is KNOWN TO HAVE NO EXTERNAL EFFECT; a name
// absent is unknown and lowers to ⊤.
var Cmdlets = map[string][]Spec{ /* … */ }
```

The table covers the default PowerShell 7 modules (Management, Utility, Security, Archive, Diagnostics, Host, ScheduledTasks, CimCmdlets, NetTCPIP, Storage, PackageManagement/PowerShellGet, PSSession, Modules, LocalAccounts, WSMan); the built-in `Aliases` map mirrors the default PowerShell 7 alias set. Read-only and in-memory cmdlets are registered with an empty spec list so they lower to "no external effect" rather than ⊤. The only default aliases left out are the PowerShell 5 snap-in aliases (`asnp`/`gsnp`/`rsnp`) and `md` → `mkdir` (a snap-in cmdlet and a session function respectively, neither boundable); `ise` resolves to an executable and is registered as a `ProcSpawn`.

Several entries deviate from the flat table because their effect depends on their arguments or on redirection, and are handled by dedicated lowering paths:

- **`Write-Output`** (alias `echo`) carries `Stdio`: an unconsumed top-level pipeline is written to the host's stdout — the PowerShell counterpart of the bash builtin `echo` (`Stdio Direct` over args, `kb/data/builtins.yaml`). The `Stdio` effect is suppressed when the command carries a redirection (`echo hi >> log.txt` writes the file, not stdout). The stream cmdlets (`Write-Verbose`/`-Debug`/`-Warning`/`-Information`/`-Error`) stay effect-free: their streams are not the process's standard output.
- **`Get-Command`** with a name (`Get-Command mitmdump`, `Get-Command -Name x`) probes the command search path for it — the counterpart of `which(1)`, which the bash KB models as `FSRead` (`kb/data/plumbing.yaml`) — and lowers through `probeCmdlet` to `FSRead Direct` over the named command. A bare `Get-Command` lists the session's callables and keeps its empty (in-session) table entry.
- **`Get-Module -ListAvailable`** scans the module directories of `$env:PSModulePath` on disk and lowers to `FSRead Direct` over the named modules (an unnamed scan reads an unknown, ⊤ set of directories). Without `-ListAvailable` a `Get-Module` query is in-session and stays effect-free.
- **`Start-Process`/`Invoke-Item`** (`launcher`) spawn a *parameter*, not the cmdlet: `ProcSpawn` over the launched program (`-FilePath`/`-Path` or the first operand), `PrivEsc` for `-Verb RunAs`, and ⊤ `CodeExec` when the program is an interpreter whose argument list carries the payload (`cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `bash`, `sh`), a script-host file type (`.ps1`/`.psm1`/`.bat`/`.cmd`/`.vbs`/`.js`/`.hta`/`.lnk`…), or not statically known.
- **`ForEach-Object`** in its PropertyAndMethodSet form (`-MemberName Delete`, the positional `% Delete`, or `-ArgumentList`) calls the named method on every pipeline object, so the call is ⊤ `CodeExec`; the script-block form is walked instead.
- **`Invoke-History`/`Trace-Command`** sit in `Cmdlets` with empty spec lists yet are intercepted by `topReason` before the table is consulted — the former re-executes a previous command, the latter evaluates an arbitrary expression string — so both lower to ⊤.

For the same reason the parser normalizes a top-level expression statement whose value is a plain string literal (no embedded `$(…)`, no command) to its semantic equivalent `Write-Output <literal>` (`walker.literalOutput`): PowerShell writes such a statement's value to the output pipeline, and unconsumed output is the host's stdout. Inside an assignment's right-hand side, a control-flow header or an argument the value is consumed, never printed, so the normalization applies to top-level pipelines only.

### Parameter recognition (`aliases.go`)

Because a parameter that is not a *switch* binds the token that follows it, the predicates decide both what a target is and whether a cmdlet keeps a target at all:

- `isSwitch`/`isSwitchPrefix` — a flag that takes no value (`switchNames`); `switchCanon` additionally resolves PowerShell's parameter-name abbreviation (`-Rec` → recurse, `-Forc` → force; the synonym `recursive` → `recurse`). A missing switch swallows the following operand (often the effect target) into a bogus binding and widens an ordinary cmdlet to ⊤ (`Get-Content -Raw app.log`, `Get-ChildItem -File /tmp`).
- `pathParam` — the `TargetPath` source (`pathNames`: `-Path`/`-LiteralPath`/`-PSPath`/`-Destination`/`-DestinationPath`/`-FilePath`/`-Target`/`-Source`/`-FullName`). `TargetPath` **combines** the named path parameters with all positional operands (`Move-Item C:\a -Destination C:\b` acts on both); only `TargetURL`/`TargetName` use the parameter-then-operand fallback.
- `patternParam` — the filesystem *selection* patterns (`patternNames`: `-Filter`/`-Include`/`-Exclude`). They filter a query rather than naming the item the effect applies to, so they are never a `TargetPath` source; a command that carries only patterns (no path parameter, no operand) contributes no target and widens to ⊤ rather than fabricating a path from the pattern.
- data-file classes — parameters of a cmdlet that is otherwise about something else (`dataFiles` in `lower.go`): `readDataNames` (`-InFile`/`-Attachments`/`-Attachment`) → `FSRead`, `writeDataNames` (`-OutFile`) → `FSWrite` — the `-OutFile` write of `Invoke-WebRequest`/`Invoke-RestMethod` is the fetch's ingest sink (`NetFlow = FlowIngest`) — and `catalogOutputNames` (`-CatalogFilePath`/`-CatalogPath`) a write only for `New-FileCatalog` (`Test-FileCatalog` merely reads the catalog it verifies). `inNamesPrefix` applies the shortest-unique-prefix abbreviation here (`-OutF` → `-OutFile`).
- `nameParam` — the `TargetName` source: named peers (`-Name`/`-Id`/`-ComputerName`/`-ServiceName`/…), the WMI/CIM class and method (`-Class`/`-ClassName`/`-MethodName`), and the Storage/NetTCPIP identifiers (`-DriveLetter`/`-Number`/`-DiskNumber`/`-PartitionNumber`/`-LocalPort`/`-IPAddress`/`-InterfaceAlias`), plus `-ResourceURI`/`-Role`/`-LogName`/`-Group`/`-Member`.
- `urlParam` — the `TargetURL` source (`-Uri`/`-Url`/`-ConnectionUri`/`-Proxy`/`-SmtpServer`). When no URL-ish parameter is present the host-style parameters above are consulted (a probe such as `Test-NetConnection -ComputerName …` names its peer there), and only then the operands (`Invoke-WebRequest https://…`). An explicit parameter wins over a stray operand, so the egress is reported at the parameter's endpoint rather than at a decoy operand.

Value-taking parameters are matched with their abbreviation too: `paramValuePrefix`/`paramWords` (`front/ps/aliasstate.go`) accept a canonical-name prefix (`-Opt` → `-Option`, `-Member` → `-MemberName`), and `hasSwitchCanon` recognises abbreviated switches where the destructive escalation reads them.

Element splitting (`walker.elements`, `front/ps/parse.go`) also recognises two PowerShell spellings that would otherwise corrupt the operand set: a switch parameter followed by a colon separator (`-Confirm:$false`) makes the next token that switch's inline value (`colonValue`) — the token is consumed and never leaks into the operand list as a spurious target — and a redirection written without a separating space (`>file`, `>>file`, `2>file`, `*>file`) arrives as a single operand token rather than a redirection node, so `inlineRedirect` recognises the operator and target file name before the token can be treated as an operand; a bare operator or a stream merge (`2>&1`, whose target is a file descriptor, not a path) is not a file write and is not recognised.

## Abstract variable state (Σ)

`Lower` carries an abstract environment of PowerShell variables and consults
it whenever a word, condition or assignment touches one
([ADR-0014](../decisions/0014-ps-abstract-state.md)):

- **Words** are evaluated partwise: a word is statically known only when every
  part is; its taint is the join of its parts. A `$var` part resolves to the
  variable's value when it is set and known; an unset or set-but-unknown
  variable, a foreign `$env:` reference, a `$(…)` sub-expression, member/index
  access (bare mode only) and splatting make the word unknown (⊤). Single-quoted
  strings are fully literal. A target is the evaluated text when known, ⊤ when
  not — the raw source spelling never becomes a pseudo-literal scope.
  `$true`/`$false`/`$null` interpolate as `True`/`False`/the empty string
  inside strings; `$$` (the last history line) is unknown and untrusted.
- **Assignments** bind in Σ: a pure literal/expression right-hand side is
  evaluated; a command right-hand side binds set-but-unknown with the RHS
  effects' provenance (credential reads → `secret`, filesystem reads →
  `fileSystem`, …) joined with `untrusted`. `+=` computes the numeric sum when both the previous value and the RHS are numeric literals (int or float) and concatenates known strings otherwise.
  `$a,$b = 'p1','p2'` binds element-wise when the element count matches. A
  member/index assignment target (`$o.Prop = v`, `$a[0] = v`) invalidates the
  base variable in Σ instead of binding it, so a later read of the base
  degrades to ⊤.
- **Control flow**: an `if` runs every arm whose condition is not known-false
  in a forked Σ and joins the reachable final states (a known-true arm reached
  without a preceding unresolved arm decides the conditional). A condition is
  decidable only as a literal constant — `$true`/`$false`/`$null`, a numeric
  literal or a whole quoted string; a non-empty quoted string (even `"0"`,
  `"false"`) is truthy, and only `$false`/`$null`/`0`/the empty string are
  false. A `foreach` over a literal list or a literal range (`1..3`, or
  `1..$n` with `$n` known) iterates exactly, bounded by
  `maxRangeIterations = 64` — a wider or dynamic range degrades to one
  iteration with an unknown loop variable; other loops run the body once.
  `while ($false)` skips its body. `try`/`catch`/`finally` all lower (a
  conservative superset). The statements of a control-flow header (an `if`
  condition pipeline, a loop header) are lowered in place:
  `if (Remove-Item -Force C:\x) { }` deletes the file.
- **Session-state cmdlets** mutate Σ: `Set-Location`/`cd` moves `$pwd`,
  `Set-Variable`/`New-Variable`/`Set-Item Variable:` bind, `Clear-Variable`,
  `Remove-Variable` (alias `rv`, named or positional) and `Remove-Item
  Variable:` unset. `Set-Location`/`Push-Location`/`Pop-Location` additionally
  report `FSMeta` cwd effects. `$pid` and the other automatic variables are
  seeded set-but-unknown.
- **Drive mappings** are session state too: `New-PSDrive -Name X -Root <root>`
  records the root (and reports the network effect a UNC root `\\host\share`
  implies — mounting contacts that host; a single-label `//authority` root is
  an unresolved authority → `NetEgress` ⊤, while a `host:/path` root implies
  no network effect), `Remove-PSDrive` forgets it, and a
  path rooted on a mapped letter (`X:\x`) resolves to the root it names before
  the effect is built. A root the script does not determine, a mount reached on
  only one branch, or a removal on any branch marks the drive unknown: a later
  path under it widens to ⊤ instead of being taken for a local path, and no host
  name is fabricated.
- **Remote-session parameters** (`-Session`, `-ToSession`, `-FromSession`,
  `-ConnectionUri`, `-VMName`, `-ContainerId`, `-CimSession`) are network
  channels: a cmdlet carrying one and reporting no `NetEgress` of its own
  contributes `NetEgress` over ⊤, so a credential copied through a PSSession
  pairs with the egress. `-WebSession` is a cookie container, not a session
  object, and keeps the request's own `-Uri` host.
- **Egress**: an unresolved target keeps its egress — scoped to the literal
  host when one prefixes the dynamic tail (`http://evil.example/$lines` →
  `evil.example`) — and the word's provenance flows onto the effect, so an
  exfiltration pair reflects real per-command dataflow. A statically-known
  target that names no network address (it fails `engine.HostShapedLenient`)
  produces no egress at all; `ensureGatedEgressFallback` then emits the
  command's intrinsic `ProcSpawn`, so the report is never empty.
  `markEgressTaint` stays as a program-level backstop.
- **Secret staging** (`engine.ApplySecretStaging`, applied after every
  command): a file written with credential material is remembered, and a later
  read of it is a secret source — so an upload that follows pairs with it like
  an upload of the credential itself.
- **Budget**: `defaultBudget = 50000` deterministic steps (statements, loop
  iterations, word evaluations); exhaustion or an internal panic unwinds to a
  ⊤ conclusion that preserves the effects discovered so far. The budget is a
  counter, not a wall clock — it needs no race-detector special case.

## Flow

```
Parse(name, src) / ParseTimeout(name, src, micros)
      │
      ▼  sourceShapeTooComplex? (>64 KiB total, >4 KiB line, >256 nesting) ──▶ topProgram (Top=true, Reason)
      ▼  grammars.PowershellLanguage(); gotreesitter.NewParser(lang); parser.SetTimeoutMicros(micros)
   parseWithBudget: parser.Parse on a goroutine; on expiry the caller raises the cancellation flag
      │
      ├─ grammar unavailable / error / nil tree / ParseStoppedEarly ──▶ topProgram (Top=true, Reason)
      ▼  ok
   root = tree.RootNode();  Program{Errors: root.HasError()||root.HasErrorOrMissing()}
      │
      ▼  walker.walk(root)          pre-order CST visit
   ┌─────────────────────────────────────────────────────────┐
   │ "function_statement"     → record name ONLY, do NOT descend (opaque body)
   │ "class_statement", "trap_statement", "param_block"
   │                           → Stmt{KindTop}, do NOT descend (a definition or
   │                             deferred handler, kept opaque ⊤ per ADR-0014)
   │ "switch_statement"       → Stmt{KindTop}, do NOT descend (unmodelled: a
   │                             -File read + any clause can run → ⊤)
   │ "pipeline"               → pipeline(): every redirection is collected here
   │                             (a redirection-only pipeline lowers to
   │                             KindRedirect); literalOutput applies at the
   │                             top-level pipeline
   │ "pipeline_chain"         → pipelineNode()/pipeStages: the stages share the
   │                             Pipe group id; fewer than two stages carry no
   │                             flow and walk transparently
   │ "if_statement"           → structured IfStmt (arms/bodies walked into side lists)
   │ "foreach/for/while/do_statement" → structured LoopStmt (Head lowered in place)
   │ "try_statement"          → structured TryStmt
   │ "command"                → Command (params/args/bindings/redirs/ops); a range
   │                             expression in a control-flow header is skipped
   │ "assignment_expression"  → Assign (Drive/Name via classifyVar)
   │ "invokation_expression"  → Stmt{KindTop}  (static .NET [Type]::Method(…) → ⊤)
   │ everything else          → descend transparently
   └─────────────────────────────────────────────────────────┘
      │
      ▼  statement-level ERROR/MISSING: outside every command with a
         command_name, OR inside a command spanning a statement/pipeline
         boundary (`\n`, `;`, `|`) ──▶ topProgram
         ("a command could not be parsed from the source");
         a single-line in-command ERROR is repaired best-effort
      │
      ▼  Program  ──▶  Lower(p) == LowerWith(p, Options{Windows: GOOS=="windows"})
   Result{Style: StylePS}
      │
      ▼  for each Stmt:  command | assignment | if | loop | try | redirect | top
                     │
   command: ArrayComma? ──▶ ⊤ CodeExec(Direct)  (a comma-separated argument list is not modelled)
   resolve(c.Name)                      l.aliases (order-aware script aliases) → LookupAlias(built-in) → cmdletIndex
                     │
        aliasResolutionTop? (alias state unknown — the name may have been
        rebound to any command) ──▶ ⊤ CodeExec(Direct)
        expandSplat (a fully-known, non-empty @{…} splat expands entrywise into
        bindings; an unknown or empty splat keeps its ⊤ trigger in topReason)
        control-flow keyword? (break/continue/return/exit/throw — they are
        not commands and not in Cmdlets) ──▶ note
        "…: control-flow keyword → no external effect"
        topReason? ──▶ ⊤ CodeExec(Direct)  (Invoke-Expression, Add-Type, New-Object,
        ┆                                   Invoke-History, Trace-Command, dot-source ".",
        ┆                                   call operator & with computed name, splatting,
        ┆                                   computed name)
        program Funcs[canonical]? ──▶ ⊤ CodeExec(Transitive) (opaque body)
        launcher? (Start-Process/Invoke-Item) ──▶ ProcSpawn over the launched
        ┆        program (-FilePath/-Path/first operand); PrivEsc for -Verb RunAs;
        ┆        ⊤ for an interpreter payload / script-host file / unknown program
        memberMethodInvocation? (ForEach-Object -MemberName / a positional
        member name such as `% Delete` / -ArgumentList) ──▶ ⊤ CodeExec(Direct);
        the script-block form falls through
        probeCmdlet? ──▶ FSRead(Direct)     (Get-Command <name>; Get-Module -ListAvailable)
        Cmdlets[canonical] absent? ──▶ ⊤ CodeExec(Direct) (unknown command)
        specs == [] ?              ──▶ note "no external effect"
        else                       ──▶ emitSpec for each spec
                     │
   assignment: Env → EnvWrite ; Registry → Persist ; Variable → no external effect
                     │
                     ▼  finish(): engine.NewReport().Normalize(); destructiveness.Join(bump); dedup notes
                  Result
```

`Stmt.Pipe` (stamped by the walker's `pipeStages`) groups the stages of one pipeline, so the lowerer can establish value flow between them: a `NetEgress` in an earlier stage marks a later ⊤ `CodeExec` sink in the same group as the download cradle (`NetFlow = FlowCradle`) — established from the pipeline's value flow, never from the co-occurrence of an egress and a sink.

`Lower`/`LowerWith` are the entry points; the composition facade pairs them with `Parse` (there is no one-call convenience wrapper).

### Providers / drives (`driveOf`)

A target string is classified by the PowerShell provider its prefix selects (an unrecognised prefix is the filesystem, the default provider):

- `FileSystem` (default) → the spec's declared kind.
- `Env:` → `EnvRead`/`EnvWrite` (write for an FS write/meta spec), scoped to the variable name.
- `Variable:` → session-local, **no external effect**.
- `Registry:` (`HKLM:`/`HKCU:`/`HKCR:`/`HKU:`/`HKEY_`/`registry::`) → `Persist` on **every** host: a registry write is reboot-surviving state wherever the analysed command will run, so a control plane dispatching to Windows endpoints is never told "no effect" (`Options.Windows` only selects the host reading, it cannot suppress the effect; security-review F22).
- `Cert:` → the certificate store: a read is `CredAccess`, a write (an `FSWrite`/`FSMeta` spec) is `Persist`.
- `WSMan:` → durable host configuration, like the registry → `Persist`.
- `Function:`/`Alias:` → session-local, **no external effect**.

### Destructive escalation (`bumpFor`)

`Remove-Item` with `-Recurse` or `-Force` joins `engine.DestructCritical` into the result's destructiveness (the abbreviated spellings `-Rec`/`-Forc` count too, via `hasSwitchCanon`), as do the disk-wiping Storage cmdlets `Clear-Disk`, `Format-Volume` and `Remove-Partition` unconditionally.

## Invariants

- `Lower` never panics and never fabricates: an exhausted lowering budget or an internal panic unwinds to a ⊤ conclusion (with the collected effects preserved), and an effect target is either the evaluated value of a statically-known word or ⊤ — the raw spelling of a variable reference is never reported as a concrete target.
- `Parse` never panics and never returns a Go error: an unrecoverable failure is represented as ⊤ (`Program.Top` with a `Reason`); callers distinguish "parsed" from "unparseable" by inspecting `Program.Top`.
- `Parse` is deterministic under the race detector: the wall-clock budget is disabled there (`parseBudgetMicros = 0`), so a benign source never flips to ⊤ because of scheduling or GC; the parser's deterministic iteration/node/depth limits still bound the parse. The lowering budget is a step counter and is race-safe by construction.
- The abstract state Σ never reads the host environment or the filesystem: a variable value is either determined by the script text or unknown; a foreign `$env:` reference reports `EnvRead` and degrades the word.
- A ⊤ program carries a reason and no statements (`Program.Validate`).
- A `function_statement` body is **not** descended, so a function body is never mistaken for executed code.
- A static .NET invocation `[Type]::Method(…)` (including `[ScriptBlock]::Create`) lowers to ⊤ (`KindTop`).
- `Invoke-Expression`, `Add-Type`, `New-Object`, `Invoke-History` (re-executes a previous command) and `Trace-Command` (evaluates an arbitrary expression string) — the latter two registered in `Cmdlets` with empty spec lists yet intercepted before the table is consulted — dot-sourcing (`.`), the call operator `&` with a computed name, splatting (`@name` whose variable is not a fully-known hashtable — an `@{…}` literal bound to the variable expands entrywise, in operand and parameter-value position alike), a computed command name, and a comma-separated argument list (`ArrayComma`) all lower to ⊤.
- The PowerShell frontend resolves against **its own** alias and cmdlet tables, not the bash knowledge base: the same token means different things in the two languages (`rm`, `curl`, `iex` are aliases for `Remove-Item`, `Invoke-WebRequest`, `Invoke-Expression`). Alias lookups are case-insensitive.
- Alias resolution is order-aware: `resolve` consults the lowerer's alias state (`l.aliases`, fed by `applyAliasDecl` after each command and by the `Alias:` provider operations of `front/ps/aliasstate.go`) first, then `LookupAlias(name, nil)` (the built-in table). An alias only rewrites the calls that follow its declaration — a later `Set-Alias` never rewrites an earlier call. The walker's `Program.Aliases` collection is vestigial: it is never read during lowering.
- The Registry provider reports `Persist` on every host; `Options.Windows` selects the host reading (drive-letter and provider resolution), never whether the write has an effect.
- `Result.Style` is `"ps"`, so the composition layer can tell a PowerShell result from a bash one.
- `Lower`/`LowerWith` mirror the binder's `Result` shape including its `Derivations` (but not `Resolution`/`Destructive`, which stay at their zero value on the PowerShell path) so the two compose uniformly and each contributes why-trace atoms.

## Configuration

- `DefaultTimeoutMicros = 250_000` (250 ms) — the per-parse budget in an ordinary build. `Parse` disables it under the race detector (`parseBudgetMicros`, `front/ps/budget_race.go`), because a wall-clock budget is not meaningful when every memory access is instrumented and letting it fire would make the result depend on host load. `ParseTimeout(…, 0)` disables it explicitly in any build (not recommended for untrusted input). A budget below one tick of the host's monotonic clock is likewise unobservable: gotreesitter checks the deadline against `time.Now()` on every parse-loop iteration, and Windows advances `time.Now()` only on the system timer tick (≥ 1 ms), so a source whose whole parse fits inside a tick never observes a sub-tick deadline — which is why `TestParseTimeoutYieldsTop` pins that case only where the clock resolves it. The production 250 ms budget is far above any tick and unaffected. See [ADR-0013](../decisions/0013-windows-clock-tick-parse-budget.md).
- Pre-parse structural bounds (`sourceShapeTooComplex`, `parse.go`) — `maxSourceBytes = 64 KiB`, `maxSourceLine = 4 KiB`, `maxNestingDepth = 256`, checked in one linear scan *before* the parser runs; a source outside them degrades to ⊤ deterministically (a sound refusal, never a narrower report). The wall-clock deadline is enforced externally by `parseWithBudget`: the parse runs on its own goroutine, and on expiry the caller returns a timeout *and* raises the parser's cancellation flag — gotreesitter's `SetTimeoutMicros` is advisory-only (its deadline is polled every 1024 checks, and the recursive tree-materialisation paths can run for seconds between polls). `timeoutMicros == 0` (the race build) runs the parse in-line under the parser's deterministic limits.
- `Options.Windows` — enables the Registry provider; `Lower` defaults it to `runtime.GOOS == "windows"`. The composition facade (`internal/analysis.Options.Windows`, tri-state) and the CLI (`--windows[=bool]`) expose it, so the Registry branches can be forced on or off independently of the host OS.
- `StylePS = "ps"` — the dialect label on every result.
- `credentialMarkers` — the substrings (`.ssh`, `id_rsa`, `password`, `.aws`, …) whose presence in a command's text marks a filesystem read as a `CredAccess` effect.

## Extension Points

- **Add a cmdlet mapping**: add an entry to `Cmdlets` in `front/ps/aliases.go` with its `Spec`(s); use an empty spec list to declare "no external effect".
- **Add an alias**: add to the built-in `Aliases` map. Script-declared aliases are applied in source order by `applyAliasDecl`/`mutateAliasProvider` (`front/ps/aliasstate.go`) as the lowerer walks — the walker's `Program.Aliases` collection plays no part in resolution.
- **Add a drive/provider**: extend `driveOf` and handle the new drive in `emitOne`.
- **Add a ⊤ trigger**: extend `topReason` in `front/ps/lower.go`.
- **Recognise new switch/param names**: extend `switchNames`/`isSwitch` (it must list every no-value flag, or the operand after it is bound as its value), `pathParam`/`patternParam`/`nameParam`/`urlParam`, and the data-file classes (`readDataNames`/`writeDataNames`/`catalogOutputNames`). `urlParam` is the primary `TargetURL` source (`-Uri`/`-Url`/`-ConnectionUri`/`-Proxy`/`-SmtpServer`), with `nameParam` (host-style parameters) and then the operands as fallbacks; `TargetPath` instead combines its named parameters with the operands.

## Related Specs

- [Binding](binding.md) — the frontend-agnostic binder; `ps` deliberately does not use it, but its `Result` mirrors `bind.Result`.
- [Report Contract](../contracts/report-json.md) — the JSON envelope the facade stamps around this frontend's `Result` (`tool` = `flowsh`, `toolVersion` = `flowsh/v3`); because `ps` does not use the binder, `report.resolution` and `report.destructive` stay the zero value and `report.commandCalls` stays absent on the PowerShell path, while `report.canonical` is derived from the effects alone (no staging folds — there are no `mv` calls to read).
- [Bash Frontend](bash-frontend/README.md) — the sibling frontend, whose `Variant`/`Program` differ; PowerShell has its own alias and cmdlet tables and its own abstract variable state.
- [Knowledge Base](knowledge-base.md) — used by bash binding, **not** by the PowerShell frontend.
- [ADR-0014](../decisions/0014-ps-abstract-state.md) — the decision record for the Σ interpreter, the deterministic lowering budget, unset-reads-to-⊤ semantics and the removal of fabricated literal targets.
- engine core (`engine/effect.go`, `engine/lattice.go`) — the `Effect` IR and lattices this frontend lowers into.
