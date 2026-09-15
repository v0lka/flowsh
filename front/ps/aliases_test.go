package ps

import "testing"

// TestCmdletSpecsAreValid pins acceptance criterion 2 of B11 (part 1): every
// Spec in the Cmdlets table names a valid engine.EffectKind and EffectMode, a
// valid TargetKind and a non-empty operation verb.
func TestCmdletSpecsAreValid(t *testing.T) {
	for name, specs := range Cmdlets {
		for i, sp := range specs {
			if !sp.Kind.Valid() {
				t.Errorf("Cmdlets[%q][%d]: invalid EffectKind %q", name, i, sp.Kind)
			}
			if !sp.Mode.Valid() {
				t.Errorf("Cmdlets[%q][%d]: invalid EffectMode %q", name, i, sp.Mode)
			}
			if sp.Op == "" {
				t.Errorf("Cmdlets[%q][%d]: empty Op", name, i)
			}
			switch sp.Target {
			case TargetNone, TargetPath, TargetURL, TargetName, TargetSelf, TargetCwd:
			default:
				t.Errorf("Cmdlets[%q][%d]: invalid TargetKind %q", name, i, sp.Target)
			}
		}
	}
}

// TestPowerShellModulesAreKnown pins acceptance criterion 1 of B11 (part 1): the
// Management / Utility / Security / Archive / Diagnostics / Host cmdlets are all
// registered — the effect-bearing ones with a non-empty Spec, the pure ones with
// an empty Spec (so they lower to "no external effect" instead of ⊤).
func TestPowerShellModulesAreKnown(t *testing.T) {
	effectBearing := []string{
		// Microsoft.PowerShell.Management.
		"Start-Service", "Stop-Service", "Restart-Service", "Suspend-Service",
		"Resume-Service", "Debug-Process", "Restart-Computer", "Stop-Computer",
		"New-PSDrive", "Remove-PSDrive", "New-EventLog", "Remove-EventLog",
		"Clear-EventLog", "Write-EventLog", "Set-Date", "Set-TimeZone",
		"Test-Connection", "Clear-RecycleBin", "Push-Location", "Pop-Location",
		"New-TemporaryFile",
		// Microsoft.PowerShell.Utility.
		"Send-MailMessage", "Tee-Object", "Read-Host", "Out-GridView", "Out-Printer",
		// Microsoft.PowerShell.Security.
		"Get-Credential", "Get-AuthenticodeSignature", "Set-AuthenticodeSignature",
		"Get-PfxCertificate", "New-FileCatalog", "Test-FileCatalog",
		"Protect-CmsMessage", "Unprotect-CmsMessage", "Set-ExecutionPolicy",
		// Microsoft.PowerShell.Archive.
		"Compress-Archive", "Expand-Archive",
		// Microsoft.PowerShell.Diagnostics.
		"Import-Counter", "Export-Counter",
		// Microsoft.PowerShell.Host.
		"Start-Transcript",
	}
	for _, name := range effectBearing {
		specs, ok := Cmdlets[name]
		if !ok {
			t.Errorf("cmdlet %q missing from Cmdlets", name)
			continue
		}
		if len(specs) == 0 {
			t.Errorf("cmdlet %q must be effect-bearing (non-empty Spec)", name)
		}
	}

	pure := []string{
		// Management (read-only introspection).
		"Get-Service", "Wait-Process", "Get-ComputerInfo", "Get-HotFix",
		"Get-PSDrive", "Get-EventLog", "Get-WinEvent", "Get-TimeZone",
		"Get-Clipboard", "Set-Clipboard", "Get-Culture", "Get-Host",
		// Utility (in-memory transforms / host prompts).
		"ConvertTo-Html", "ConvertFrom-StringData", "ConvertTo-SecureString",
		"ConvertFrom-SecureString", "Compare-Object", "Write-Progress",
		"Get-UICulture",
		// Security / Diagnostics / Host (read-only).
		"Get-ExecutionPolicy", "Get-Counter", "Stop-Transcript",
	}
	for _, name := range pure {
		specs, ok := Cmdlets[name]
		if !ok {
			t.Errorf("cmdlet %q missing from Cmdlets", name)
			continue
		}
		if len(specs) != 0 {
			t.Errorf("cmdlet %q must be pure (empty Spec), got %v", name, specs)
		}
	}
}

// TestNewModuleCmdletsLowerBounded is the behavioural counterpart: a registered
// cmdlet must lower to a bounded effect (never ⊤), and a pure one to no effect.
func TestNewModuleCmdletsLowerBounded(t *testing.T) {
	effectBearing := []string{
		`Start-Service -Name spooler`,
		`Stop-Computer -ComputerName web01`,
		`Test-Connection example.com`,
		`Send-MailMessage -SmtpServer mail.example.com`,
		`Get-Credential`,
		`Compress-Archive -Path a -DestinationPath b.zip`,
		`Set-Date -Date 2020-01-01`,
	}
	for _, src := range effectBearing {
		r := lowerOK(t, src)
		if r.Conservative {
			t.Errorf("%q degraded to ⊤: %v", src, r.Notes)
		}
		if len(r.Effects) == 0 {
			t.Errorf("%q produced no effect", src)
		}
	}

	pure := []string{
		`Get-Service`,
		`Get-ComputerInfo`,
		`Compare-Object $a $b`,
		`Get-Culture`,
	}
	for _, src := range pure {
		r := lowerOK(t, src)
		if r.Conservative || len(r.Effects) != 0 {
			t.Errorf("%q must be pure/non-conservative: effects=%+v notes=%v",
				src, r.Effects, r.Notes)
		}
	}
}
