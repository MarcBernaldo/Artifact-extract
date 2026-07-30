# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Artifact-extract is a native, **dependency-free** DFIR triage collector: one self-contained
script per OS — `artifact-extract.ps1` (Windows, PowerShell 5.1+) and `artifact-extract.sh`
(Linux, POSIX `sh`) — that copies to a target host, runs elevated, and produces a single
sealed archive Artifact Engine ingests unchanged. There is no build system and no package to
install; the scripts are the deliverable. Read `README.md` for the output contract before
changing collection behaviour.

## Commands

```powershell
# NTFS reader regression test — no elevation, no disk, runs anywhere
powershell -File tests\Test-NtfsReader.ps1

# Regenerate the published hashes after ANY change to a collected script (see below)
sha256sum artifact-extract.ps1 artifact-extract.sh > SHA256SUMS

# Syntax-check without running (PS tokenizer; the .sh has no host here — check under WSL)
# wsl -d Ubuntu -u root -- dash -n artifact-extract.sh
```

The privileged paths (shadow copy, raw volume read, hive export) can only run elevated on a
real volume, so they are validated against a disposable VMware guest, not on the dev host:

```powershell
powershell -File tests\Set-VmCredential.ps1 -Vmx 'E:\VM\Lab\Lab.vmx'      # store guest login once (DPAPI)
powershell -File tests\Invoke-VmValidation.ps1 -Vmx 'E:\VM\Lab\Lab.vmx' -Mode probe
powershell -File tests\Invoke-VmValidation.ps1 -Vmx 'E:\VM\Lab\Lab.vmx' -Mode collect -CollectorArgs '-Disk -Volatile' -Revert
```

`-Mode probe` reports the token/elevation/VSS state the guest actually grants before any
collection. `tests/` is committed here (unlike in the Engine repo).

## Architecture

**The two scripts are mirrors.** Any collection concept added to one should have a counterpart
in the other unless the OS makes it meaningless. `Invoke-Step` (ps1) and `run_step` (sh) are the
same idea: run a step, hash its output, and append one NDJSON line to the manifest. Almost every
collection action goes through them — call them rather than copying files directly, so nothing
escapes the chain of custody.

**Never abort; always seal.** A failure inside any collection module must not cost the whole run.
Modules are wrapped so that whatever was gathered still gets a manifest, an inner seal
(`manifest.sha256`), and a packed archive with an outer `<archive>.sha256`. Preserve this: don't
introduce a code path that can throw past the sealing/compression stage.

**Status classification is deliberate, not cosmetic.** `ok | degraded | error | skipped` drive
the run summary an analyst trusts. Rules learned the hard way, all encoded in `Invoke-Step`:
- A privileged step failing *without* elevation is `degraded`, not `error`.
- Windows PowerShell turns native **stderr into a terminating error** under `ErrorActionPreference
  = 'Stop'`; expected non-zero exits are declared via `-BenignExitCodes`, and the catch block
  re-checks `$LASTEXITCODE`. A step that legitimately writes to stderr (e.g. `query user` with no
  session, `reg query` on an absent key) must set `$ErrorActionPreference = 'Continue'` locally.
- A normal host state (no logged-on user, absent autostart key, no firewall tooling) is a
  *finding*, recorded in the capture — never an `error`.

**Locked Windows files are acquired in three layers** (elevated only), in `Collect-Disk`:
1. A single Volume Shadow Copy created now, via **CIM** (`Invoke-CimMethod Win32_ShadowCopy`) —
   `Get-WmiObject` does not exist in PowerShell 7 and silently no-ops there.
2. Per-file fallbacks (`esentutl /y /vss`, loaded-hive `reg save`) when the snapshot fails.
3. Raw NTFS metafiles (`$MFT`, `$LogFile`) read from **that same shadow copy**, so they are
   consistent with the hives and nothing shifts under a multi-GB read.

**The raw NTFS reader** (`Open-NtfsVolume` → `Get-NtfsDataRuns` → `Export-NtfsMetafile`) is the
one component whose output can't be eyeballed, so it has the unit test above. Its landmines are
all PowerShell type coercions: the clusters-per-record byte is a *signed* byte (`0xF6` → −10, and
`[sbyte]246` throws — reinterpret the bits manually); the run-list terminator is compared against
`[uint32]::MaxValue` (the literal `0xFFFFFFFF` parses as Int32 −1); and every bound in the copy
loop must stay `[long]` or `[math]::Min` picks its Int32 overload and overflows on a real `$MFT`.
A run list the base record can't fully describe is reported incomplete, never written short.

**Durations use a monotonic stopwatch, never wall-clock subtraction** — a host (or a VM syncing to
its hypervisor) can move its clock mid-run. A significant move is itself recorded in the manifest
as a chain-of-custody fact, because timestamps written before the jump sit on the earlier clock.

**The VM harness only ever touches one snapshot** it owns (`artifact-extract-baseline`); it creates
it on first use and reverts to it, leaving the operator's own snapshots alone. `runProgramInGuest`
runs **without** `-interactive` (a headless guest has no desktop session; the agent still grants a
full admin token). Guest passwords come from a DPAPI-protected per-VM file and are decrypted only in
memory — vmrun requires a plaintext password argument, which is the one unavoidable exposure.

## Conventions specific to this repo

- **Regenerate `SHA256SUMS` after every edit to a collected script.** A stale hash breaks the EDR
  allowlist the file exists to support, and `metadata.json` embeds the running script's own hash.
- **Professional, brand-neutral prose.** Do not name specific commercial DFIR tools, or reference
  test/real evidence runs, anywhere a reader sees it — comments, `README`, commit messages, help
  text. The `C\` layout is compatible with common tooling by design; describe it that way.
- **English only** in code, comments, and the manifest. Placeholders in docstrings are invented
  (`HOST-01`, `jdoe`, `10.0.0.5`). Never paste a value collected from a real host into source,
  tests, fixtures, or commit text — synthesise instead.
- **Line endings are LF**, enforced by `.gitattributes`, so published hashes are reproducible and
  the shell script keeps a working shebang.
- **Commits are incremental**, each describing the functionality added or improved at a high level
  (not file-by-file detail). Author is the repo owner only — **no `Co-Authored-By` trailer**.
- `.gitignore` blocks all collection output (`result/`, `result-vm/`, archives, `*.evtx`, `*.raw`,
  `*.ndjson`) and guest credentials (`*.cred`). Never commit any of it.
