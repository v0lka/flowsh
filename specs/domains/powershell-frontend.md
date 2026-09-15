# PowerShell Frontend

## Purpose

`ps` is the PowerShell frontend of the effect IR. It has exactly two responsibilities: `Parse` turns PowerShell source text into a faithful, position-preserving normalized AST using the pure-Go tree-sitter runtime (`gotreesitter`) and its embedded PowerShell grammar under a wall-clock budget that the race detector disables; `Lower` folds that AST into the frontend-agnostic effect IR, consulting the PowerShell alias and cmdlet tables — never the bash knowledge base. A failing parse (unknown construct, timeout, internal panic) degrades to the top element ⊤ (`CodeExec`) rather than guessing or crashing.

## Key Files

- `front/ps/parse.go` — the parser and the normalized AST: `Pos`, `Word`, `Param`, `Binding`, `Redirect`, `Command`, `Assign`, `Kind`, `Stmt`, `Program`, `DefaultTimeoutMicros`, `Parse`/`ParseTimeout`, and the CST `walker`.
- `front/ps/budget_race.go` / `front/ps/budget_norace.go` — the build-tagged per-parse budget `parseBudgetMicros` (and `raceDetectorEnabled`) `Parse` applies: `DefaultTimeoutMicros` in an ordinary build, `0` (disabled) under the race detector (see [ADR-0012](../decisions/0012-race-advisory-parse-budget.md)).
- `front/ps/lower.go` — lowering to the IR: `Lower`/`LowerWith`, `lowerer`, `topReason`, `emitSpec`/`emitOne`, `redirs`, `assignment`, `bumpFor`, `finish`, and credential-material detection.
- `front/ps/aliases.go` — the built-in `Aliases` table, `LookupAlias`, the `Cmdlets` command→effect table, `TargetKind`/`Spec`, the parameter-recognition predicates (`isSwitch`/`pathParam`/`nameParam`/`urlParam`), and the drive/provider helpers.
- `front/ps/lower_test.go` — lowering tests.

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
}

type Kind string

const (
	KindCommand    Kind = "command"
	KindAssignment Kind = "assignment"
	KindTop        Kind = "top"
)

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
	TargetPath TargetKind = "path" // -Path/-LiteralPath/-Destination/-DestinationPath/…, else operands
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

### Parameter recognition (`aliases.go`)

Because a parameter that is not a *switch* binds the token that follows it, the four predicates decide both what a target is and whether a cmdlet keeps a target at all:

- `isSwitch` — a flag that takes no value. A missing switch swallows the following operand (often the effect target) into a bogus binding and widens an ordinary cmdlet to ⊤ (`Get-Content -Raw app.log`, `Get-ChildItem -File /tmp`).
- `pathParam` — the `TargetPath` source (`-Path`/`-LiteralPath`/`-Destination`/`-DestinationPath`/`-FilePath`/`-OutFile`/`-Filter`/`-Include`/`-Exclude`/…).
- `nameParam` — the `TargetName` source: named peers (`-Name`/`-Id`/`-ComputerName`/`-ServiceName`/…), the WMI/CIM class and method (`-Class`/`-ClassName`/`-MethodName`), and the Storage/NetTCPIP identifiers (`-DriveLetter`/`-Number`/`-DiskNumber`/`-PartitionNumber`/`-LocalPort`/`-IPAddress`/`-InterfaceAlias`), plus `-ResourceURI`/`-Role`/`-LogName`/`-Group`/`-Member`.
- `urlParam` — the `TargetURL` source (`-Uri`/`-Url`/`-ConnectionUri`/`-Proxy`/`-SmtpServer`). When no URL-ish parameter is present the host-style parameters above are consulted (a probe such as `Test-NetConnection -ComputerName …` names its peer there), and only then the operands (`Invoke-WebRequest https://…`). An explicit parameter wins over a stray operand, so the egress is reported at the parameter's endpoint rather than at a decoy operand.

## Flow

```
Parse(name, src) / ParseTimeout(name, src, micros)
      │
      ▼  grammars.PowershellLanguage(); gotreesitter.NewParser(lang); parser.SetTimeoutMicros(micros)
   parser.Parse([]byte(src))
      │
      ├─ grammar unavailable / error / nil tree / ParseStoppedEarly ──▶ topProgram (Top=true, Reason)
      ▼  ok
   root = tree.RootNode();  Program{Errors: root.HasError()||root.HasErrorOrMissing()}
      │
      ▼  walker.walk(root)          pre-order CST visit
   ┌─────────────────────────────────────────────────────────┐
   │ "function_statement"     → record name ONLY, do NOT descend (opaque body)
   │ "command"                → Command (params/args/bindings/redirs/ops)
   │ "assignment_expression"  → Assign (Drive/Name via classifyVar)
   │ "invokation_expression"  → Stmt{KindTop}  (static .NET [Type]::Method(…) → ⊤)
   │ everything else          → descend transparently
   └─────────────────────────────────────────────────────────┘
      │
      ▼  Program  ──▶  Lower(p) == LowerWith(p, Options{Windows: GOOS=="windows"})
   Result{Style: StylePS}
      │
      ▼  for each Stmt:  command | assignment | top
                     │
   command: resolve(c.Name)                      cmdletIndex (canonical) → LookupAlias(declared, built-in)
                     │
        topReason? ──▶ ⊤ CodeExec(Direct)  (Invoke-Expression, Add-Type, New-Object,
        ┆                                   dot-source ".", call operator & with computed
        ┆                                   name, splatting, computed name)
        program Funcs[canonical]? ──▶ ⊤ CodeExec(Transitive) (opaque body)
        Cmdlets[canonical] absent? ──▶ ⊤ CodeExec(Direct) (unknown command)
        specs == [] ?              ──▶ note "no external effect"
        else                       ──▶ emitSpec for each spec
                     │
   assignment: Env → EnvWrite ; Registry → Persist (Windows only) ; Variable → no external effect
                     │
                     ▼  finish(): engine.NewReport().Normalize(); destructiveness.Join(bump); dedup notes
                  Result
```

`Analyze(src)` is the one-call convenience: `Lower(Parse("", src))`.

### Providers / drives (`driveOf`)

A target string is classified by the PowerShell provider its prefix selects (an unrecognised prefix is the filesystem, the default provider):

- `FileSystem` (default) → the spec's declared kind.
- `Env:` → `EnvRead`/`EnvWrite` (write for an FS write/meta spec), scoped to the variable name.
- `Variable:` → session-local, **no external effect**.
- `Registry:` (`HKLM:`/`HKCU:`/`HKCR:`/`HKU:`/`HKEY_`/`registry::`) → `Persist`, but **Windows-only** (skipped on non-Windows hosts).

### Destructive escalation (`bumpFor`)

`Remove-Item` with `-Recurse` or `-Force` joins `engine.DestructCritical` into the result's destructiveness.

## Invariants

- `Parse` never panics and never returns a Go error: an unrecoverable failure is represented as ⊤ (`Program.Top` with a `Reason`); callers distinguish "parsed" from "unparseable" by inspecting `Program.Top`.
- `Parse` is deterministic under the race detector: the wall-clock budget is disabled there (`parseBudgetMicros = 0`), so a benign source never flips to ⊤ because of scheduling or GC; the parser's deterministic iteration/node/depth limits still bound the parse.
- A ⊤ program carries a reason and no statements (`Program.Validate`).
- A `function_statement` body is **not** descended, so a function body is never mistaken for executed code.
- A static .NET invocation `[Type]::Method(…)` (including `[ScriptBlock]::Create`) lowers to ⊤ (`KindTop`).
- `Invoke-Expression`, `Add-Type`, `New-Object`, dot-sourcing (`.`), the call operator `&` with a computed name, splatting (`@name`/`@{name}`), and a computed command name all lower to ⊤.
- The PowerShell frontend resolves against **its own** alias and cmdlet tables, not the bash knowledge base: the same token means different things in the two languages (`rm`, `curl`, `iex` are aliases for `Remove-Item`, `Invoke-WebRequest`, `Invoke-Expression`). Alias lookups are case-insensitive.
- Alias resolution consults aliases the analysed script declared (via `Set-Alias`/`New-Alias`) first, then the built-in table.
- The Registry provider is inert on non-Windows hosts (`Options.Windows` false) unless it is set explicitly; the facade and the CLI's `--windows` flag expose that override so the Registry branches can be enabled independently of the host OS.
- `Result.Style` is `"ps"`, so the composition layer can tell a PowerShell result from a bash one.
- `Lower`/`LowerWith` mirror the binder's `Result` shape including its `Derivations` (but not `Resolution`/`Destructive`, which stay at their zero value on the PowerShell path) so the two compose uniformly and each contributes why-trace atoms.

## Configuration

- `DefaultTimeoutMicros = 250_000` (250 ms) — the per-parse budget in an ordinary build. `Parse` disables it under the race detector (`parseBudgetMicros`, `front/ps/budget_race.go`), because a wall-clock budget is not meaningful when every memory access is instrumented and letting it fire would make the result depend on host load. `ParseTimeout(…, 0)` disables it explicitly in any build (not recommended for untrusted input).
- `Options.Windows` — enables the Registry provider; `Lower` defaults it to `runtime.GOOS == "windows"`. The composition facade (`internal/analysis.Options.Windows`, tri-state) and the CLI (`--windows[=bool]`) expose it, so the Registry branches can be forced on or off independently of the host OS.
- `StylePS = "ps"` — the dialect label on every result.
- `credentialMarkers` — the substrings (`.ssh`, `id_rsa`, `password`, `.aws`, …) whose presence in a command's text marks a filesystem read as a `CredAccess` effect.

## Extension Points

- **Add a cmdlet mapping**: add an entry to `Cmdlets` in `front/ps/aliases.go` with its `Spec`(s); use an empty spec list to declare "no external effect".
- **Add an alias**: add to the built-in `Aliases` map. Script-declared aliases are collected automatically by the walker.
- **Add a drive/provider**: extend `driveOf` and handle the new drive in `emitOne`.
- **Add a ⊤ trigger**: extend `topReason` in `front/ps/lower.go`.
- **Recognise new switch/param names**: extend `isSwitch`/`pathParam`/`nameParam`/`urlParam`. `isSwitch` must list every no-value flag, or the operand after it is bound as its value; `urlParam` is the primary `TargetURL` source (`-Uri`/`-Url`/`-ConnectionUri`/`-Proxy`/`-SmtpServer`), with `nameParam` (host-style parameters) and then the operands as fallbacks.

## Related Specs

- [Binding](binding.md) — the frontend-agnostic binder; `ps` deliberately does not use it, but its `Result` mirrors `bind.Result`.
- [Report Contract](../contracts/report-json.md) — the JSON envelope the facade stamps around this frontend's `Result` (`tool` = `flowsh`, `toolVersion` = `flowsh/v1`); because `ps` does not use the binder, `report.resolution` and `report.destructive` stay the zero value on the PowerShell path.
- [Bash Frontend](bash-frontend/README.md) — the sibling frontend, whose `Variant`/`Program` differ; PowerShell has its own alias and cmdlet tables.
- [Knowledge Base](knowledge-base.md) — used by bash binding, **not** by the PowerShell frontend.
- engine core (`engine/effect.go`, `engine/lattice.go`) — the `Effect` IR and lattices this frontend lowers into.
