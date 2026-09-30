# Conformance Corpus

Loaded by `internal/corpus` (`LoadCorpus`); every `*.json` document in this
directory is a `{name, description, cases[]}` bundle (see
[Analysis Facade](../../specs/domains/analysis-report.md)). This README is
documentation, not data — the loader reads only `*.json`.

## Bundles

| File | Group(s) | Content |
| ---- | -------- | ------- |
| `guardfall_bash.json`, `guardfall_posix.json`, `guardfall_posh.json` | `guardfall` | guard-evading classes A–E, both dialect families |
| `destructive_bash.json` | `destructive` | canonical destructive/recall cases |
| `benign_bash.json` | `benign` | precision control (no ⊤/conservative) |
| `ps_cases.json` | `ps` | PowerShell-specific recall cases |
| `resolution_bash.json` | `resolution` | A2 name-resolution chain |
| `external_bash.json`, `external_posh.json` | `external_malicious`, `external_benign` | balanced sample (26+26 bash, 54+54 PowerShell) drawn from public labeled datasets |

## The external set (provenance & methodology)

The `external_*` bundles are sampled from a larger balanced dataset (372
records, exactly 50/50 malicious/benign per dialect: 128+128 bash, 58+58
PowerShell) assembled from public,
labeled command datasets, deduplicated and quality-filtered (single line,
≤500 chars, no template placeholders, label conflicts dropped on both sides).
Sampling is deterministic (seed 42), stratified by source. The initial sample
(25+25 per dialect) was later extended with the 30 cases that had been silent
misses (see *Coverage closure* below) and an equal number of balanced benign
analogs, keeping the per-dialect 50/50 balance.

Case fields: `id`, `group`, `lang`, `input`, `note` (attribution:
`source [license]; context`). A posh case may additionally carry
`"windows": true`: the case is then analysed under the Windows-native provider
profile (`corpus.Case.Windows` → the facade `Options.Windows`, the CLI
`--windows` counterpart). This matters because provider effects are
host-gated by design — on a non-Windows host a registry write is skipped with
a note (and is therefore *not* covered), while a Windows-targeted script
persists state. A windows-flagged case asserts the Windows-provider behaviour
of the script; the recall floor and the latency harness apply the same
profile.

Gate semantics: `external_malicious` cases must be **covered** (an effect
present, or a sound degradation to ⊤) — the GuardFall invariant;
`external_benign` cases must also be **covered** (they are a coverable group)
while **not** raising ⊤/conservative — the benign
precision invariant. Cases the analyser cannot satisfy are replaced during
sampling, not weakened: the gates above run unchanged.

### Sources (as included)

| Source | License | Used for |
| ------ | ------- | -------- |
| [rivoluzione-informatica/bash-datasets](https://github.com/rivoluzione-informatica/bash-datasets) (aggregating NL2Bash, TLDR, GTFOBins, Atomic Red Team, PayloadsAllTheThings) | CC BY-SA 4.0 (compilation) | bash malicious (`unsafe`) and bash benign (`safe`) |
| [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) | MIT | bash + PowerShell malicious (ATT&CK technique commands) |
| [tldr-pages/tldr](https://github.com/tldr-pages/tldr) (`pages/windows`) | MIT (per project docs) | PowerShell benign (cmdlet examples) |
| [darkknight25/Linux_Terminal_Commands_Dataset](https://huggingface.co/datasets/darkknight25/Linux_Terminal_Commands_Dataset) | MIT | bash benign |
| [aelhalili/bash-commands-dataset](https://huggingface.co/datasets/aelhalili/bash-commands-dataset) | MIT | bash benign |
| [infinite-dataset-hub/RealPowShellScripts](https://huggingface.co/datasets/infinite-dataset-hub/RealPowShellScripts) | MIT (synthetic) | PowerShell benign + malicious |

License notes: `external_bash.json` contains records derived from
bash-datasets, which is CC BY-SA 4.0 licensed (the remaining records are MIT).
Attribution above covers the upstream projects; the ShareAlike obligation
attaches to the data file, not to the analyser source.

### Considered but excluded

- **GTFOBins / LOLBAS / dessertlab/offensive-PowerShell** — GPL-3.0; direct
  inclusion would impose copyleft on the corpus data.
- **Fa2y/Malicious-PowerShell-Dataset, das-lab/mpsd, wwe123 (HF),
  Nishang, PowerSploit, swisskyrepo/InternalAllTheThings** — no license.
- **danielbohannon/Revoke-Obfuscation** — labels are *obfuscated vs not*, not
  malicious vs benign (upstream explicitly warns against the latter reading);
  the raw 4 GB corpus is not in the repository.
- **PayloadsAllTheThings** — methodology pages moved to the (unlicensed)
  InternalAllTheThings; its bash rows are already included via bash-datasets.
- **Raconteur (NDSS'25)** — no public dataset link/license on the project page.

### Coverage closure (formerly: known coverage gaps)

While assembling the initial sample, 30 malicious records (29 PowerShell +
1 bash) produced **neither** an effect **nor** ⊤ — genuine recall gaps,
documented here and excluded from the corpus because the
`external_malicious` gate (like GuardFall) requires zero silent misses. Four
root causes were identified and fixed; all 30 cases are now in the corpus:

1. **Registry provider host-gating** (19 posh cases: `New-/Set-/Remove-ItemProperty`,
   `Remove-Item HK*:`) — the frontend derives the `Persist` effect but skips it
   on non-Windows hosts by design. The cases carry `"windows": true` and assert
   the Windows-provider profile.
2. **Presence checks modelled as effect-free** (5 posh: `Get-Command <name>`,
   `Get-Module -ListAvailable`) — now `FSRead` probes (the counterparts of
   bash `which`), see `front/ps/lower.go` (`probeCmdlet`).
3. **`echo`/`Write-Output` modelled as effect-free** (4 posh + 1 bare string
   literal statement) — unconsumed top-level pipeline output is stdout, so
   `Write-Output` now carries `Stdio` (the counterpart of bash `echo`), and a
   top-level string literal normalizes to `Write-Output` in the parser.
4. **`jobs`** (1 bash) — removed from the pure shell-state builtin set: it
   prints the job table to stdout, a `Stdio` effect the KB now describes
   (`kb/data/builtins.yaml`); a bare `jobs` stays covered via the binder's
   intrinsic ProcSpawn.

The full 802-record sampling pool re-screens with zero malicious silent
misses. The benign side was rebalanced in step: benign analogs of the same
families where clean-license sources allow (registry policy *reads* under the
windows profile, `Get-Module -ListAvailable` scans, `Write-Output` shapes,
`jobs -s`), topped up with clearly-benign inspection commands
(`Get-ChildItem`, `Test-Path`, `Get-Alias`, …) — destructive-shaped records
upstream labels call "benign" (`Remove-Item` pipelines, `Set-Service
Disabled`, `Set-ExecutionPolicy Unrestricted`) stay excluded from the
precision control. Still excluded, correctly: benign candidates raising ⊤ on
unmodelled binaries (~89/260 bash, ~31/122 posh) and genuinely effect-free
commands — conservative behaviour, not corpus material.
