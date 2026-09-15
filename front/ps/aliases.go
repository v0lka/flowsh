package ps

import (
	"strings"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// Alias table
// ===========================================================================

// Aliases is the built-in PowerShell alias table: it maps an alias the shell
// exposes by default onto the cmdlet (or command) it resolves to.
//
// This table is the reason the PowerShell frontend cannot share the bash one:
// the same token means different things in the two languages. In bash `rm`,
// `curl` and `iex` are (respectively) the coreutils binary, the curl binary and
// an unknown command; in PowerShell they are aliases for Remove-Item,
// Invoke-WebRequest and Invoke-Expression. Lowering must therefore consult this
// table before any binary-level reasoning.
//
// The three aliases the task pins explicitly — rm → Remove-Item,
// curl → Invoke-WebRequest, iex → Invoke-Expression — are present, together
// with the rest of the default Windows PowerShell / PowerShell 7 alias set that
// matters for effect analysis.
var Aliases = map[string]string{
	// Filesystem.
	"rm":    "Remove-Item",
	"del":   "Remove-Item",
	"erase": "Remove-Item",
	"rd":    "Remove-Item",
	"rmdir": "Remove-Item",
	"ri":    "Remove-Item",
	"cat":   "Get-Content",
	"gc":    "Get-Content",
	"type":  "Get-Content",
	"sc":    "Set-Content",
	"ac":    "Add-Content",
	"clc":   "Clear-Content",
	"ni":    "New-Item",
	"cp":    "Copy-Item",
	"copy":  "Copy-Item",
	"cpi":   "Copy-Item",
	"mv":    "Move-Item",
	"move":  "Move-Item",
	"mi":    "Move-Item",
	"ren":   "Rename-Item",
	"rni":   "Rename-Item",
	"ls":    "Get-ChildItem",
	"dir":   "Get-ChildItem",
	"gci":   "Get-ChildItem",
	"gi":    "Get-Item",
	"si":    "Set-Item",
	"ii":    "Invoke-Item",
	"cli":   "Clear-Item",
	"test":  "Test-Path", // shadows the bash builtin `test`
	// Item properties.
	"gp":  "Get-ItemProperty",
	"gpv": "Get-ItemPropertyValue",
	"sp":  "Set-ItemProperty",
	"rp":  "Remove-ItemProperty",
	"clp": "Clear-ItemProperty",
	"cpp": "Copy-ItemProperty",
	"mp":  "Move-ItemProperty",
	"rnp": "Rename-ItemProperty",
	// Serialization / path helpers.
	"epcsv": "Export-Csv",
	"ipcsv": "Import-Csv",
	"epal":  "Export-Alias",
	"ipal":  "Import-Alias",
	"rvpa":  "Resolve-Path",
	"cvpa":  "Convert-Path",
	"sls":   "Select-String",
	// Clipboard (Windows / PowerShell 7).
	"gcb": "Get-Clipboard",
	"scb": "Set-Clipboard",
	// Processes and jobs.
	"spps":  "Stop-Process",
	"kill":  "Stop-Process",
	"spp":   "Stop-Process",
	"gps":   "Get-Process",
	"ps":    "Get-Process",
	"saps":  "Start-Process",
	"start": "Start-Process",
	"sa":    "Start-Process",
	"gjb":   "Get-Job",
	"sajb":  "Start-Job",
	"spjb":  "Stop-Job",
	"rcjb":  "Receive-Job",
	"rpjb":  "Remove-Job",
	"rjb":   "Remove-Job",
	"wjb":   "Wait-Job",
	"gsv":   "Get-Service",
	"sasv":  "Start-Service",
	"spsv":  "Stop-Service",
	// Network / IPC.
	"gwmi": "Get-WmiObject",
	"gcim": "Get-CimInstance",
	"curl": "Invoke-WebRequest",
	"iwr":  "Invoke-WebRequest",
	"wget": "Invoke-WebRequest",
	"irm":  "Invoke-RestMethod",
	"icm":  "Invoke-Command",
	"iex":  "Invoke-Expression",
	"tni":  "Test-NetConnection",
	"ncss": "New-PSSession",
	"etsn": "Enter-PSSession",
	"nsn":  "New-PSSession",
	"gsn":  "Get-PSSession",
	"rsn":  "Remove-PSSession",
	"cnsn": "Connect-PSSession",
	"dnsn": "Disconnect-PSSession",
	"exsn": "Exit-PSSession",
	"ipsn": "Import-PSSession",
	"epsn": "Export-PSSession",
	"rcsn": "Receive-PSSession",
	// Output / pipelines.
	"echo":    "Write-Output",
	"write":   "Write-Output",
	"sleep":   "Start-Sleep",
	"where":   "Where-Object",
	"%":       "ForEach-Object",
	"foreach": "ForEach-Object",
	"?":       "Where-Object",
	"select":  "Select-Object",
	"sort":    "Sort-Object",
	"measure": "Measure-Object",
	"group":   "Group-Object",
	"compare": "Compare-Object",
	"diff":    "Compare-Object",
	"gu":      "Get-Unique",
	"oh":      "Out-Host",
	"lp":      "Out-Printer",
	"ogv":     "Out-GridView",
	"tee":     "Tee-Object",
	"fl":      "Format-List",
	"ft":      "Format-Table",
	"fw":      "Format-Wide",
	"fc":      "Format-Custom",
	"fhx":     "Format-Hex",
	// Introspection / variables / location.
	"gm":      "Get-Member",
	"gal":     "Get-Alias",
	"sal":     "Set-Alias",
	"nal":     "New-Alias",
	"gcm":     "Get-Command",
	"gv":      "Get-Variable",
	"sv":      "Set-Variable",
	"nv":      "New-Variable",
	"rv":      "Remove-Variable",
	"gl":      "Get-Location",
	"sl":      "Set-Location",
	"cd":      "Set-Location",
	"chdir":   "Set-Location",
	"pwd":     "Get-Location",
	"cls":     "Clear-Host",
	"man":     "Get-Help",
	"history": "Get-History",
	"h":       "Get-History",
	"ghy":     "Get-History",
	"clhy":    "Clear-History",
	"clear":   "Clear-Host",
	"gcs":     "Get-PSCallStack",
	"gmo":     "Get-Module",
	"rmo":     "Remove-Module",
	"nmo":     "New-Module",
	"shcm":    "Show-Command",
	"clv":     "Clear-Variable",
	"set":     "Set-Variable",
	"gerr":    "Get-Error",
	"gin":     "Get-ComputerInfo",
	"gtz":     "Get-TimeZone",
	"trcm":    "Trace-Command",
	"gbp":     "Get-PSBreakpoint",
	"sbp":     "Set-PSBreakpoint",
	"rbp":     "Remove-PSBreakpoint",
	"dbp":     "Disable-PSBreakpoint",
	"ebp":     "Enable-PSBreakpoint",
	"pushd":   "Push-Location",
	"popd":    "Pop-Location",

	// ---------------------------------------------------------------------
	// B12 (part 2): the remainder of the default PowerShell 7 alias set whose
	// target the frontend can bound. The canonical session-state list
	// (InitialSessionState.cs) also carries the PowerShell 5 snap-in aliases
	// (asnp/gsnp/rsnp) and `md` → mkdir; a snap-in cmdlet is not registered and
	// mkdir is a session *function*, so those are deliberately left out and keep
	// lowering to ⊤ rather than being given a guessed effect. `ise` resolves to
	// an executable, not a cmdlet, and is registered as a process spawn.
	// ---------------------------------------------------------------------
	"ise":   "powershell_ise.exe", // launches the ISE host → ProcSpawn
	"ipmo":  "Import-Module",
	"ihy":   "Invoke-History",
	"r":     "Invoke-History",
	"gdr":   "Get-PSDrive",
	"ndr":   "New-PSDrive",
	"rdr":   "Remove-PSDrive",
	"mount": "New-PSDrive",
	"npssc": "New-PSSessionConfigurationFile",
	"iwmi":  "Invoke-WMIMethod",
	"swmi":  "Set-WMIInstance",
	"rwmi":  "Remove-WMIObject",
	"rujb":  "Resume-Job",
	"sujb":  "Suspend-Job",
}

// LookupAlias resolves name against any aliases the analyzed script declared
// itself (Set-Alias/New-Alias, collected in Program.Aliases) first, then the
// built-in table. Lookups are case-insensitive, as they are in PowerShell.
func LookupAlias(name string, declared map[string]string) (string, bool) {
	for k, v := range declared {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	for k, v := range Aliases {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// ===========================================================================
// Command → effect table
// ===========================================================================

// TargetKind selects where a cmdlet effect's target set comes from.
type TargetKind string

const (
	// TargetNone: the effect has no target (⊥).
	TargetNone TargetKind = "none"
	// TargetPath: the -Path/-LiteralPath/-Destination/… values, else operands.
	TargetPath TargetKind = "path"
	// TargetURL: the -Uri/-Url/-ConnectionUri/-Proxy values, else operands.
	TargetURL TargetKind = "url"
	// TargetName: the -Name/-Id/-*Name values, else operands.
	TargetName TargetKind = "name"
	// TargetSelf: the invoked command's own name.
	TargetSelf TargetKind = "self"
	// TargetCwd: the current directory.
	TargetCwd TargetKind = "cwd"
)

// Spec is one effect a cmdlet contributes. Op is a human-readable verb
// ("read", "write", "delete", …) surfaced in the result notes.
type Spec struct {
	Kind       engine.EffectKind
	Mode       engine.EffectMode
	Target     TargetKind
	Reversible bool
	Op         string
}

// Cmdlets maps a canonical cmdlet name to the effects it contributes. A name
// present with an empty spec list is *known to have no external effect* (the
// pure/formatting/control cmdlets); a name absent from the table is unknown and
// lowers to ⊤.
//
// The ⊤ cmdlets (Invoke-Expression, Add-Type, New-Object) are deliberately
// absent: lower.go intercepts them before this table is consulted.
var Cmdlets = map[string][]Spec{
	// ---- Filesystem: reads ----
	"Get-Content":           {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"Get-Item":              {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"Get-ChildItem":         {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "list"}},
	"Get-ItemProperty":      {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"Get-Acl":               {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"Test-Path":             {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "test"}},
	"Get-FileHash":          {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "hash"}},
	"Import-Csv":            {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"Import-Clixml":         {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"Select-String":         {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"Get-ItemPropertyValue": {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"Import-Alias":          {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},

	// ---- Filesystem: writes ----
	"Set-Content":         {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "write"}},
	"Add-Content":         {{engine.KindFSWrite, engine.ModeDirect, TargetPath, true, "append"}},
	"Clear-Content":       {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "truncate"}},
	"Out-File":            {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "write"}},
	"New-Item":            {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "create"}},
	"Set-Item":            {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "write"}},
	"Export-Csv":          {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "write"}},
	"Export-Clixml":       {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "write"}},
	"Set-ItemProperty":    {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "set"}},
	"New-ItemProperty":    {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "set"}},
	"Remove-ItemProperty": {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "unset"}},
	"Clear-ItemProperty":  {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "unset"}},
	"Copy-ItemProperty": {
		{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"},
		{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "copy"},
	},
	"Move-ItemProperty": {
		{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "move"},
		{engine.KindFSMeta, engine.ModeDirect, TargetPath, true, "rename"},
	},
	"Rename-ItemProperty": {{engine.KindFSMeta, engine.ModeDirect, TargetPath, true, "rename"}},
	"Export-Alias":        {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "write"}},
	"Export-PSSession":    {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "write"}},

	// ---- Filesystem: delete / copy / move / rename / metadata ----
	"Remove-Item": {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "delete"}},
	"Clear-Item":  {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "clear"}},
	"Copy-Item": {
		{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"},
		{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "copy"},
	},
	"Move-Item": {
		{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "move"},
		{engine.KindFSMeta, engine.ModeDirect, TargetPath, true, "rename"},
	},
	"Rename-Item": {{engine.KindFSMeta, engine.ModeDirect, TargetPath, true, "rename"}},
	"Set-Acl":     {{engine.KindFSMeta, engine.ModeDirect, TargetPath, false, "acl"}},

	// ---- Network ----
	"Invoke-WebRequest":  {{engine.KindNetEgress, engine.ModeDirect, TargetURL, false, "http"}},
	"Invoke-RestMethod":  {{engine.KindNetEgress, engine.ModeDirect, TargetURL, false, "http"}},
	"Test-NetConnection": {{engine.KindNetEgress, engine.ModeDirect, TargetURL, false, "connect"}},
	"Resolve-DnsName":    {{engine.KindNetEgress, engine.ModeDirect, TargetURL, false, "dns"}},
	"Get-WmiObject":      {{engine.KindIPC, engine.ModeDirect, TargetName, false, "wmi"}},
	"Get-CimInstance":    {{engine.KindIPC, engine.ModeDirect, TargetName, false, "wmi"}},
	"New-PSSession": {
		{engine.KindNetEgress, engine.ModeDirect, TargetName, false, "connect"},
		{engine.KindIPC, engine.ModeDirect, TargetName, false, "session"},
	},
	"Enter-PSSession": {
		{engine.KindNetEgress, engine.ModeDirect, TargetName, false, "connect"},
		{engine.KindIPC, engine.ModeDirect, TargetName, false, "session"},
	},
	"Invoke-Command": {
		{engine.KindNetEgress, engine.ModeDirect, TargetName, false, "connect"},
		{engine.KindIPC, engine.ModeDirect, TargetName, false, "session"},
	},

	// ---- Processes ----
	"Start-Process": {{engine.KindProcSpawn, engine.ModeDirect, TargetSelf, false, "spawn"}},
	"Invoke-Item":   {{engine.KindProcSpawn, engine.ModeDirect, TargetSelf, false, "open"}},
	"Stop-Process":  {{engine.KindProcSignal, engine.ModeDirect, TargetName, false, "signal"}},
	"Start-Job":     {{engine.KindProcSpawn, engine.ModeDirect, TargetSelf, false, "spawn"}},

	// ---- Persistence ----
	"Register-ScheduledTask":   {{engine.KindPersist, engine.ModeDirect, TargetName, false, "schedule"}},
	"New-ScheduledTask":        {{engine.KindPersist, engine.ModeDirect, TargetName, false, "schedule"}},
	"New-ScheduledTaskAction":  {{engine.KindPersist, engine.ModeDirect, TargetNone, false, "schedule"}},
	"Unregister-ScheduledTask": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "unschedule"}},
	"New-Service":              {{engine.KindPersist, engine.ModeDirect, TargetName, false, "service"}},
	"Set-Service":              {{engine.KindPersist, engine.ModeDirect, TargetName, false, "service"}},

	// ---- Standard streams ----
	"Out-Host":    {{engine.KindStdio, engine.ModeDirect, TargetNone, true, "stdio"}},
	"Out-Default": {{engine.KindStdio, engine.ModeDirect, TargetNone, true, "stdio"}},
	"Out-Null":    {{engine.KindStdio, engine.ModeDirect, TargetNone, true, "stdio"}},
	"Out-String":  {{engine.KindStdio, engine.ModeDirect, TargetNone, true, "stdio"}},
	"Write-Host":  {{engine.KindStdio, engine.ModeDirect, TargetNone, true, "stdio"}},

	// ---- Microsoft.PowerShell.Management ----
	// Service lifecycle mutates persisted system state (mirrors New-/Set-Service).
	"Start-Service":   {{engine.KindPersist, engine.ModeDirect, TargetName, false, "service"}},
	"Stop-Service":    {{engine.KindPersist, engine.ModeDirect, TargetName, false, "service"}},
	"Restart-Service": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "service"}},
	"Suspend-Service": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "service"}},
	"Resume-Service":  {{engine.KindPersist, engine.ModeDirect, TargetName, false, "service"}},
	// Process / host control.
	"Debug-Process":    {{engine.KindProcSignal, engine.ModeDirect, TargetName, false, "debug"}},
	"Restart-Computer": {{engine.KindProcSignal, engine.ModeDirect, TargetName, false, "reboot"}},
	"Stop-Computer":    {{engine.KindProcSignal, engine.ModeDirect, TargetName, false, "shutdown"}},
	// PSDrive namespace mappings (mount-like metadata).
	"New-PSDrive":    {{engine.KindFSMeta, engine.ModeDirect, TargetName, false, "mount"}},
	"Remove-PSDrive": {{engine.KindFSMeta, engine.ModeDirect, TargetName, true, "unmount"}},
	// Event log store: persisted system state; the Clear-/Remove- forms destroy
	// log data.
	"New-EventLog":    {{engine.KindPersist, engine.ModeDirect, TargetName, false, "eventlog"}},
	"Remove-EventLog": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "eventlog"}},
	"Clear-EventLog":  {{engine.KindPersist, engine.ModeDirect, TargetName, false, "clear"}},
	"Write-EventLog":  {{engine.KindPersist, engine.ModeDirect, TargetName, false, "eventlog"}},
	// System clock / time zone: persisted host configuration.
	"Set-Date":     {{engine.KindPersist, engine.ModeDirect, TargetNone, false, "clock"}},
	"Set-TimeZone": {{engine.KindPersist, engine.ModeDirect, TargetNone, false, "timezone"}},
	// Connectivity probe (mirrors Test-NetConnection).
	"Test-Connection": {{engine.KindNetEgress, engine.ModeDirect, TargetURL, false, "ping"}},
	// Recycle-bin purge.
	"Clear-RecycleBin": {{engine.KindFSWrite, engine.ModeDirect, TargetNone, false, "delete"}},
	// Location stack (mirrors Set-Location's cwd effect).
	"Push-Location": {{engine.KindFSMeta, engine.ModeDirect, TargetCwd, true, "cwd"}},
	"Pop-Location":  {{engine.KindFSMeta, engine.ModeDirect, TargetCwd, true, "cwd"}},
	// Temporary file creation.
	"New-TemporaryFile": {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "create"}},

	// ---- Microsoft.PowerShell.Utility ----
	"Send-MailMessage": {{engine.KindNetEgress, engine.ModeDirect, TargetURL, false, "smtp"}},
	"Tee-Object":       {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "write"}},
	"Read-Host":        {{engine.KindStdio, engine.ModeDirect, TargetNone, true, "stdin"}},
	"Out-GridView":     {{engine.KindStdio, engine.ModeDirect, TargetNone, true, "stdio"}},
	"Out-Printer":      {{engine.KindStdio, engine.ModeDirect, TargetNone, true, "print"}},

	// ---- Microsoft.PowerShell.Security ----
	// Get-Credential collects credential material.
	"Get-Credential": {{engine.KindCredAccess, engine.ModeDirect, TargetNone, false, "credential"}},
	// Signatures / catalogs / CMS read or write protected files (a ".pfx"
	// operand additionally trips credential detection in lower.go).
	"Get-AuthenticodeSignature": {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"Set-AuthenticodeSignature": {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "sign"}},
	"Get-PfxCertificate":        {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"New-FileCatalog":           {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "create"}},
	"Test-FileCatalog":          {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "verify"}},
	"Protect-CmsMessage":        {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "encrypt"}},
	"Unprotect-CmsMessage":      {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "decrypt"}},
	// Execution policy is persisted security configuration.
	"Set-ExecutionPolicy": {{engine.KindPersist, engine.ModeDirect, TargetNone, false, "policy"}},

	// ---- Microsoft.PowerShell.Archive ----
	// Read the sources, write the archive / the extracted files.
	"Compress-Archive": {
		{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"},
		{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "compress"},
	},
	"Expand-Archive": {
		{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"},
		{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "extract"},
	},

	// ---- Microsoft.PowerShell.Diagnostics ----
	"Import-Counter": {{engine.KindFSRead, engine.ModeDirect, TargetPath, true, "read"}},
	"Export-Counter": {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "write"}},

	// ---- Microsoft.PowerShell.Host ----
	// Start-Transcript opens and writes a transcript file.
	"Start-Transcript": {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "write"}},

	// ---------------------------------------------------------------------
	// B11 (part 2): additional Windows module cmdlets.
	//
	// Durable host/system configuration (scheduled tasks, network config,
	// firewall rules, local accounts, repositories, session configurations)
	// lowers to Persist, mirroring the registry/service/scheduled-task entries
	// above; a pure query of that state is a Persist read. Network *state*
	// queries (the connection table, adapters) are low-severity NetIngress
	// reads. Importing or dynamically building a module executes code, so it is
	// CodeExec. Pure in-memory declarations (Get-Module, Remove-Module,
	// Export-ModuleMember) have no external effect.
	// ---------------------------------------------------------------------

	// ---- ScheduledTasks ----
	"Get-ScheduledTask":            {{engine.KindPersist, engine.ModeDirect, TargetName, true, "read"}},
	"Start-ScheduledTask":          {{engine.KindProcSpawn, engine.ModeDirect, TargetName, false, "start"}},
	"Stop-ScheduledTask":           {{engine.KindProcSignal, engine.ModeDirect, TargetName, false, "stop"}},
	"Enable-ScheduledTask":         {{engine.KindPersist, engine.ModeDirect, TargetName, false, "enable"}},
	"Disable-ScheduledTask":        {{engine.KindPersist, engine.ModeDirect, TargetName, false, "disable"}},
	"Set-ScheduledTask":            {{engine.KindPersist, engine.ModeDirect, TargetName, false, "set"}},
	"New-ScheduledTaskTrigger":     {{engine.KindPersist, engine.ModeDirect, TargetNone, false, "schedule"}},
	"New-ScheduledTaskPrincipal":   {{engine.KindPersist, engine.ModeDirect, TargetNone, false, "schedule"}},
	"New-ScheduledTaskSettingsSet": {{engine.KindPersist, engine.ModeDirect, TargetNone, false, "schedule"}},

	// ---- CimCmdlets ----
	"Invoke-CimMethod":            {{engine.KindIPC, engine.ModeDirect, TargetName, false, "invoke"}},
	"Get-CimClass":                {{engine.KindIPC, engine.ModeDirect, TargetName, true, "read"}},
	"Remove-CimSession":           {{engine.KindIPC, engine.ModeDirect, TargetName, false, "close"}},
	"Register-CimIndicationEvent": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "subscribe"}},
	"New-CimSession": {
		{engine.KindNetEgress, engine.ModeDirect, TargetName, false, "connect"},
		{engine.KindIPC, engine.ModeDirect, TargetName, false, "session"},
	},

	// ---- NetTCPIP ----
	"New-NetIPAddress":       {{engine.KindPersist, engine.ModeDirect, TargetName, false, "add"}},
	"Set-NetIPAddress":       {{engine.KindPersist, engine.ModeDirect, TargetName, false, "set"}},
	"Remove-NetIPAddress":    {{engine.KindPersist, engine.ModeDirect, TargetName, false, "remove"}},
	"Get-NetTCPConnection":   {{engine.KindNetIngress, engine.ModeDirect, TargetName, true, "read"}},
	"Get-NetAdapter":         {{engine.KindNetIngress, engine.ModeDirect, TargetName, true, "read"}},
	"New-NetFirewallRule":    {{engine.KindPersist, engine.ModeDirect, TargetName, false, "firewall"}},
	"Remove-NetFirewallRule": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "firewall"}},
	"Set-NetFirewallProfile": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "firewall"}},

	// ---- Storage ----
	"Get-Volume":       {{engine.KindFSRead, engine.ModeDirect, TargetName, true, "read"}},
	"Get-Disk":         {{engine.KindFSRead, engine.ModeDirect, TargetName, true, "read"}},
	"Get-Partition":    {{engine.KindFSRead, engine.ModeDirect, TargetName, true, "read"}},
	"New-Partition":    {{engine.KindFSWrite, engine.ModeDirect, TargetName, false, "create"}},
	"Remove-Partition": {{engine.KindFSWrite, engine.ModeDirect, TargetName, false, "delete"}},
	"Format-Volume":    {{engine.KindFSWrite, engine.ModeDirect, TargetName, false, "format"}},
	"Clear-Disk":       {{engine.KindFSWrite, engine.ModeDirect, TargetName, false, "wipe"}},

	// ---- PackageManagement / PowerShellGet ----
	"Install-Package":       {{engine.KindPersist, engine.ModeDirect, TargetName, false, "install"}},
	"Find-Package":          {{engine.KindNetEgress, engine.ModeDirect, TargetName, true, "query"}},
	"Save-Package":          {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "download"}},
	"Install-Module":        {{engine.KindPersist, engine.ModeDirect, TargetName, false, "install"}},
	"Update-Module":         {{engine.KindPersist, engine.ModeDirect, TargetName, false, "update"}},
	"Uninstall-Module":      {{engine.KindFSWrite, engine.ModeDirect, TargetName, false, "uninstall"}},
	"Save-Module":           {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "download"}},
	"Find-Module":           {{engine.KindNetEgress, engine.ModeDirect, TargetName, true, "query"}},
	"Publish-Module":        {{engine.KindNetEgress, engine.ModeDirect, TargetName, false, "publish"}},
	"Register-PSRepository": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "register"}},

	// ---- PSSession ----
	"Get-PSSession":                   {{engine.KindIPC, engine.ModeDirect, TargetName, true, "read"}},
	"Exit-PSSession":                  {{engine.KindIPC, engine.ModeDirect, TargetNone, false, "close"}},
	"Remove-PSSession":                {{engine.KindIPC, engine.ModeDirect, TargetName, false, "close"}},
	"Disconnect-PSSession":            {{engine.KindIPC, engine.ModeDirect, TargetName, false, "disconnect"}},
	"Receive-PSSession":               {{engine.KindIPC, engine.ModeDirect, TargetName, true, "receive"}},
	"New-PSSessionOption":             {{engine.KindIPC, engine.ModeDirect, TargetNone, false, "option"}},
	"Register-PSSessionConfiguration": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "register"}},
	"Connect-PSSession": {
		{engine.KindNetEgress, engine.ModeDirect, TargetName, false, "connect"},
		{engine.KindIPC, engine.ModeDirect, TargetName, false, "session"},
	},

	// ---- Modules ----
	"Import-Module":       {{engine.KindCodeExec, engine.ModeDirect, TargetName, false, "import"}},
	"New-Module":          {{engine.KindCodeExec, engine.ModeDirect, TargetName, false, "module"}},
	"Remove-Module":       {},
	"Get-Module":          {},
	"Export-ModuleMember": {},

	// ---- Microsoft.PowerShell.LocalAccounts (Windows) ----
	"New-LocalUser":           {{engine.KindPersist, engine.ModeDirect, TargetName, false, "user"}},
	"Remove-LocalUser":        {{engine.KindPersist, engine.ModeDirect, TargetName, false, "delete"}},
	"Get-LocalUser":           {{engine.KindPersist, engine.ModeDirect, TargetName, true, "read"}},
	"Add-LocalGroupMember":    {{engine.KindPersist, engine.ModeDirect, TargetName, false, "member"}},
	"Remove-LocalGroupMember": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "member"}},
	"Get-LocalGroup":          {{engine.KindPersist, engine.ModeDirect, TargetName, true, "read"}},

	// ---- WSMan ----
	"Test-WSMan":           {{engine.KindNetEgress, engine.ModeDirect, TargetName, false, "connect"}},
	"Disconnect-WSMan":     {{engine.KindIPC, engine.ModeDirect, TargetName, false, "close"}},
	"Get-WSManInstance":    {{engine.KindIPC, engine.ModeDirect, TargetName, true, "read"}},
	"Invoke-WSManInstance": {{engine.KindIPC, engine.ModeDirect, TargetName, false, "invoke"}},
	"Enable-WSManCredSSP":  {{engine.KindPersist, engine.ModeDirect, TargetName, false, "credssp"}},
	"Disable-WSManCredSSP": {{engine.KindPersist, engine.ModeDirect, TargetName, false, "credssp"}},
	"Connect-WSMan": {
		{engine.KindNetEgress, engine.ModeDirect, TargetName, false, "connect"},
		{engine.KindIPC, engine.ModeDirect, TargetName, false, "session"},
	},

	// ---- Known benign / control / formatting: explicitly no external effect ----
	"Write-Output":      {},
	"Write-Verbose":     {},
	"Write-Debug":       {},
	"Write-Warning":     {},
	"Write-Error":       {},
	"Write-Information": {},
	"Get-Date":          {},
	"Get-Random":        {},
	"Get-Member":        {},
	"Get-Help":          {},
	"Get-Command":       {},
	"Get-Alias":         {},
	"Set-Alias":         {},
	"New-Alias":         {},
	"Get-History":       {},
	"Get-Variable":      {},
	"Set-Variable":      {},
	"New-Variable":      {},
	"Remove-Variable":   {},
	"Get-Location":      {},
	"Set-Location":      {{engine.KindFSMeta, engine.ModeDirect, TargetCwd, true, "cwd"}},
	"Clear-Host":        {},
	"Start-Sleep":       {},
	"Select-Object":     {},
	"Where-Object":      {},
	"ForEach-Object":    {},
	"Sort-Object":       {},
	"Measure-Object":    {},
	"Group-Object":      {},
	"Format-Table":      {},
	"Format-List":       {},
	"Format-Wide":       {},
	"ConvertTo-Json":    {},
	"ConvertFrom-Json":  {},
	"ConvertTo-Csv":     {},
	"ConvertFrom-Csv":   {},
	"Join-Path":         {},
	"Split-Path":        {},
	"Resolve-Path":      {},
	"Get-Process":       {},
	"Get-Job":           {},
	"Stop-Job":          {},
	"Receive-Job":       {},
	"Remove-Job":        {},

	// ---- Consolidated "pure" cmdlets (B11): known, no external effect ----
	// A read-only/projection cmdlet is registered with an empty Spec so it
	// lowers to "no external effect" instead of ⊤. Grouped by module.
	//
	// Microsoft.PowerShell.Management (read-only introspection).
	"Get-Service":      {},
	"Wait-Process":     {},
	"Get-ComputerInfo": {},
	"Get-HotFix":       {},
	"Get-PSDrive":      {},
	"Get-EventLog":     {},
	"Get-WinEvent":     {},
	"Get-TimeZone":     {},
	"Get-Clipboard":    {},
	"Set-Clipboard":    {},
	"Get-Culture":      {},
	"Get-Host":         {},
	// Microsoft.PowerShell.Utility (in-memory transforms / host prompts).
	"ConvertTo-Html":           {},
	"ConvertFrom-StringData":   {},
	"ConvertTo-SecureString":   {},
	"ConvertFrom-SecureString": {},
	"Compare-Object":           {},
	"Write-Progress":           {},
	"Get-UICulture":            {},
	// Microsoft.PowerShell.Security / Diagnostics / Host (read-only).
	"Get-ExecutionPolicy": {},
	"Get-Counter":         {},
	"Stop-Transcript":     {},

	// ---------------------------------------------------------------------
	// B12: cmdlets backing the expanded default-alias table. Each is the
	// target of at least one entry in Aliases (above), so every alias resolves
	// to a registered cmdlet. These are session-state / introspection /
	// formatting cmdlets: probing or debugging session state has no external
	// effect; the history and breakpoint cmdlets mutate session state only.
	// Import-PSSession reaches a remote session like the other PSSession
	// cmdlets.
	// ---------------------------------------------------------------------
	"Get-PSCallStack":      {},
	"Clear-History":        {},
	"Show-Command":         {},
	"Get-Unique":           {},
	"Convert-Path":         {},
	"Format-Custom":        {},
	"Format-Hex":           {},
	"Get-Error":            {},
	"Clear-Variable":       {},
	"Trace-Command":        {},
	"Wait-Job":             {},
	"Get-PSBreakpoint":     {},
	"Set-PSBreakpoint":     {},
	"Remove-PSBreakpoint":  {},
	"Disable-PSBreakpoint": {},
	"Enable-PSBreakpoint":  {},
	"Import-PSSession": {
		{engine.KindNetEgress, engine.ModeDirect, TargetName, false, "connect"},
		{engine.KindIPC, engine.ModeDirect, TargetName, false, "session"},
	},

	// ---------------------------------------------------------------------
	// B11 (part 3) / B12 (part 2): the cmdlets backing the additional default
	// aliases, so every alias resolves to a registered cmdlet (the B12
	// invariant) and none degrades to ⊤.
	//
	// Session history and background jobs are session-local state: probing or
	// mutating them has no external effect. A session-configuration file is
	// written to disk. The WMI family reaches the (local or remote) WMI
	// repository over IPC, mirroring Get-WmiObject. `ise` names the ISE
	// executable rather than a cmdlet, so it is registered as a process spawn.
	// ---------------------------------------------------------------------
	"Invoke-History":                 {},
	"Resume-Job":                     {},
	"Suspend-Job":                    {},
	"New-PSSessionConfigurationFile": {{engine.KindFSWrite, engine.ModeDirect, TargetPath, false, "create"}},
	"Invoke-WMIMethod":               {{engine.KindIPC, engine.ModeDirect, TargetName, false, "wmi"}},
	"Set-WMIInstance":                {{engine.KindIPC, engine.ModeDirect, TargetName, false, "wmi"}},
	"Remove-WMIObject":               {{engine.KindIPC, engine.ModeDirect, TargetName, false, "wmi"}},
	"powershell_ise.exe":             {{engine.KindProcSpawn, engine.ModeDirect, TargetSelf, false, "spawn"}},
}

// isSwitch reports whether a bare parameter name is a PowerShell switch (a flag
// that takes no value), so the argument binder does not mistake the next
// positional token for its value.
//
// A switch that is *not* listed here is (incorrectly) treated as value-taking,
// so the token after it is bound to it instead of being seen as an operand —
// and an operand is often the effect target (the URL of `Invoke-WebRequest
// -UseBasicParsing https://…`, say). The table therefore lists the common
// no-value switches across the cmdlets the frontend knows.
func isSwitch(bare string) bool {
	switch strings.ToLower(bare) {
	case "recurse", "recursive", "force", "whatif", "confirm", "verbose",
		"debug", "passthru", "all", "wait", "noexit", "noprofile",
		"noninteractive", "asjob", "hidden", "readonly", "system", "offline",
		"forceifreparse", "escape", "asplaintext",
		// Common cmdlet switches (no value follows them).
		"container", "nonewline", "compress", "append", "asbytestream",
		"usebasicparsing", "usedefaultcredentials", "proxyusedefaultcredentials",
		"skipcertificatecheck", "notypeinformation",
		// B13: further no-value switches. Each would otherwise swallow the
		// following operand — frequently the effect target — into a bogus
		// binding, leaving the cmdlet with no target and widening it to ⊤
		// (`Get-Content -Raw app.log`, `Get-ChildItem -File /tmp`,
		// `New-Partition -UseMaximumSize`).
		"raw", "file", "directory", "noclobber", "usemaximumsize",
		"casesensitive", "simplematch", "notmatch", "allmatches",
		"autosize", "wrap", "nonewwindow", "useculture", "noenumerate":
		return true
	}
	return false
}

// pathParam reports whether a bare parameter name carries a filesystem-ish
// target value: an item, container or path-pattern the effect applies to.
func pathParam(bare string) bool {
	switch strings.ToLower(bare) {
	case "path", "literalpath", "pspath", "destination", "destinationpath",
		"filepath", "outfile", "target", "source", "fullname", "filter",
		"include", "exclude":
		return true
	}
	return false
}

// nameParam reports whether a bare parameter name carries a named target
// (computer, process, service, task, session, …).
func nameParam(bare string) bool {
	switch strings.ToLower(bare) {
	case "name", "id", "taskname", "computername", "processname", "servicename",
		"cn", "query", "computer", "hostname", "servername", "machinename",
		"session", "sessionname",
		// B13: the identifiers the B11 module cmdlets (CimCmdlets, NetTCPIP,
		// Storage, LocalAccounts, WSMan) take as their target. Without them the
		// cmdlet recognises no target and widens to ⊤ — `Get-Volume
		// -DriveLetter C`, `Get-CimInstance -ClassName Win32_Process`,
		// `Get-NetTCPConnection -LocalPort 443`, `Clear-Disk -Number 0`.
		"classname", "methodname", "driveletter", "number", "disknumber",
		"partitionnumber", "localport", "displayname", "ipaddress",
		"interfacealias", "interfaceindex", "resourceuri", "role", "logname",
		"group", "member", "account", "username", "adaptername",
		"remoteaddress", "objectid", "poolname", "class":
		return true
	}
	return false
}

// urlParam reports whether a bare parameter name carries a network target (a
// URL, endpoint or proxy) — the TargetURL source. A cmdlet fed by -Uri/-Url
// therefore takes its egress target from the parameter, not from an operand.
func urlParam(bare string) bool {
	switch strings.ToLower(bare) {
	case "uri", "url", "connectionuri", "proxy",
		// B13: the SMTP endpoint Send-MailMessage dials.
		"smtpserver":
		return true
	}
	return false
}

// ===========================================================================
// Providers / drives
// ===========================================================================

// PowerShell drive (provider) names recognised by the frontend.
const (
	DriveFS       = "FileSystem"
	DriveEnv      = "Env"
	DriveVariable = "Variable"
	DriveRegistry = "Registry"
)

// driveOf classifies a target string by the PowerShell provider its prefix
// selects. An unrecognised prefix is the filesystem (the default provider).
func driveOf(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	switch {
	case strings.HasPrefix(t, "env:"):
		return DriveEnv
	case strings.HasPrefix(t, "variable:"):
		return DriveVariable
	case strings.HasPrefix(t, "hklm:"), strings.HasPrefix(t, "hkcu:"), strings.HasPrefix(t, "hkcr:"),
		strings.HasPrefix(t, "hku:"), strings.HasPrefix(t, "hkey_"), strings.HasPrefix(t, "registry::"):
		return DriveRegistry
	default:
		return DriveFS
	}
}

// envNameOf returns the variable name of an Env: drive path ("Env:FOO" → "FOO").
func envNameOf(target string) string {
	t := strings.TrimSpace(target)
	if len(t) > 4 && strings.EqualFold(t[:4], "env:") {
		return t[4:]
	}
	return t
}

// classifyVar splits a variable reference written on the left of an assignment
// into its drive and its name. "$env:FOO" → (Env, "FOO"); "$x" → (Variable, "x").
func classifyVar(s string) (drive, name string) {
	if n, ok := envRef(s); ok {
		return DriveEnv, n
	}
	b := unbrace(strings.TrimSpace(s))
	if strings.HasPrefix(b, "$") {
		body := b[1:]
		if body == "" {
			return "", ""
		}
		if i := strings.IndexByte(body, ':'); i >= 0 {
			switch {
			case strings.EqualFold(body[:i], "env"):
				return DriveEnv, body[i+1:]
			case strings.EqualFold(body[:i], "variable"):
				return DriveVariable, body[i+1:]
			}
			return "", body
		}
		return DriveVariable, body
	}
	return "", ""
}
