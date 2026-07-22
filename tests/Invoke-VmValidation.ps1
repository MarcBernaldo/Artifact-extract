<#
    Runs the Windows collector inside a VMware guest and brings the result back.

    The collector's most important paths - shadow copy creation, raw volume reads,
    hive export - only exist when it runs with full privileges, which cannot be
    exercised from an ordinary session. This drives a disposable guest instead: push
    the script in, run it, pull the collection out, roll the guest back.

    Guest credentials come from a per-VM credential file, created once with
    Set-VmCredential.ps1. The password is stored with DPAPI, so the file only
    decrypts under your account on this machine, and it is never typed into a
    command, a script, or a transcript.

    One honest caveat: vmrun only accepts a plaintext password as an argument, so it
    is decrypted in memory and appears in this host's process list while a guest
    command runs. That is a lab tool talking to a local guest, not a secret store.

    Probe the guest first - it reports what privileges the run would actually get:

        .\tests\Invoke-VmValidation.ps1 -Vmx 'E:\VM\Lab\Lab.vmx' -Mode probe

    Then collect:

        .\tests\Invoke-VmValidation.ps1 -Vmx 'E:\VM\Lab\Lab.vmx' -Mode collect -CollectorArgs '-Vss'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Vmx,
    # Defaults to the per-VM file written by Set-VmCredential.ps1; guests rarely
    # share an account, so each one carries its own.
    [string]$CredentialFile,
    [ValidateSet('probe', 'collect')][string]$Mode = 'probe',
    [string]$CollectorArgs = '',
    [string]$ResultDir,
    # Roll the guest back to the baseline snapshot when finished. The baseline is
    # created on first use and is the only snapshot this script ever touches.
    [switch]$Revert,
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Vmx)) { throw "VM not found: $Vmx" }
if (-not $CredentialFile) {
    $CredentialFile = Join-Path $env:USERPROFILE ('.artifact-extract-vm\{0}.cred' -f `
        ([System.IO.Path]::GetFileNameWithoutExtension($Vmx)))
}
if (-not (Test-Path -LiteralPath $CredentialFile)) {
    throw "No credential file at $CredentialFile - create it with: .\tests\Set-VmCredential.ps1 -Vmx '$Vmx'"
}
$credLines = @(Get-Content -LiteralPath $CredentialFile | Where-Object { $_ })
if ($credLines.Count -lt 2) { throw "$CredentialFile should hold the user on line 1 and the protected password on line 2." }
$GuestUser = $credLines[0].Trim()
try { $secure = ConvertTo-SecureString $credLines[1].Trim() }
catch { throw "Could not decrypt $CredentialFile - it is bound to the account that created it." }
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $GuestPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

$vmrun = @(
    'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
    'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
    'C:\Program Files (x86)\VMware\VMware VIX\vmrun.exe'
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $vmrun) { throw 'vmrun.exe not found - is VMware Workstation installed?' }

$repo = Split-Path -Parent $PSScriptRoot
$collector = Join-Path $repo 'artifact-extract.ps1'
$vmName = [System.IO.Path]::GetFileNameWithoutExtension($Vmx)
if (-not $ResultDir) { $ResultDir = Join-Path $repo ('result-vm\' + $vmName) }
$BASELINE = 'artifact-extract-baseline'
$GUEST_DIR = 'C:\artifact-extract'
$GUEST_PS = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
# No -interactive on runProgramInGuest: it requires a logged-in desktop session,
# which a headless guest does not have. Without it the guest agent still starts the
# process with a full administrator token, which is what the collector needs.

function Say { param([string]$m, [string]$c = 'Gray') Write-Host ("  {0}" -f $m) -ForegroundColor $c }

# Guest arguments are appended after the credentials so the password never lands in
# an error message that echoes the command.
function Vm {
    param([Parameter(Mandatory)][string]$Cmd, [string[]]$Rest = @(), [switch]$Guest, [switch]$Tolerate)
    $argv = @('-T', 'ws', $Cmd, $Vmx)
    if ($Guest) { $argv = @('-T', 'ws', '-gu', $GuestUser, '-gp', $GuestPassword, $Cmd, $Vmx) }
    $argv += $Rest
    $out = & $vmrun @argv 2>&1
    if ($LASTEXITCODE -ne 0 -and -not $Tolerate) {
        throw ("vmrun {0} failed: {1}" -f $Cmd, (($out | Out-String).Trim()))
    }
    return ($out | Out-String).Trim()
}

Write-Host "`nVM validation: $vmName" -ForegroundColor Cyan

# --- Baseline snapshot ------------------------------------------------------------
# Created once and never replaced, so a rollback can only ever return the guest to
# the state it was in before this script first ran.
$snaps = Vm 'listSnapshots' -Tolerate
if ($snaps -notmatch [regex]::Escape($BASELINE)) {
    Say "creating baseline snapshot '$BASELINE'" 'Yellow'
    Vm 'snapshot' @($BASELINE) | Out-Null
}
else { Say "baseline snapshot present" }

# --- Power on and wait for the guest tools ----------------------------------------
if ((Vm 'list' -Tolerate) -notmatch [regex]::Escape($Vmx)) {
    Say 'starting guest (headless)'
    Vm 'start' @('nogui') | Out-Null
}
else { Say 'guest already running' }

Say 'waiting for guest tools'
$deadline = (Get-Date).AddMinutes(6)
do {
    Start-Sleep -Seconds 5
    $state = Vm 'checkToolsState' -Tolerate
} until ($state -eq 'running' -or (Get-Date) -gt $deadline)
if ($state -ne 'running') { throw "guest tools never came up (state: $state) - are VMware Tools installed?" }
Say "guest tools: $state" 'Green'

Vm 'createDirectoryInGuest' @($GUEST_DIR) -Guest -Tolerate | Out-Null

# --- Privilege probe --------------------------------------------------------------
# Whether the guest agent hands the process a full or a filtered token decides
# whether any of the privileged collection paths can be tested at all, so it is
# measured rather than assumed. Free space is reported too: a guest that runs out
# midway produces a truncated archive that looks like a collector failure.
$probePs = @'
$o = [ordered]@{
  user       = "$env:USERDOMAIN\$env:USERNAME"
  ps_version = $PSVersionTable.PSVersion.ToString()
  os         = (Get-CimInstance Win32_OperatingSystem).Caption
  elevated   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  integrity  = ((whoami /groups | Select-String 'Mandatory Label') -split '\s{2,}')[0]
  can_read_raw_volume = $false
  vss_service = (Get-Service VSS -ErrorAction SilentlyContinue).Status.ToString()
  free_gb    = [math]::Round((Get-PSDrive C).Free/1GB,1)
}
try { $fs=[IO.File]::Open('\\.\C:',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite); $fs.Dispose(); $o.can_read_raw_volume=$true } catch {}
$o | ConvertTo-Json | Set-Content -Path 'C:\artifact-extract\probe.json' -Encoding UTF8
'@
$probeLocal = Join-Path $env:TEMP 'ae-probe.ps1'
Set-Content -LiteralPath $probeLocal -Value $probePs -Encoding UTF8
Vm 'CopyFileFromHostToGuest' @($probeLocal, "$GUEST_DIR\probe.ps1") -Guest | Out-Null
Vm 'runProgramInGuest' @($GUEST_PS, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "$GUEST_DIR\probe.ps1") -Guest | Out-Null

New-Item -ItemType Directory -Path $ResultDir -Force | Out-Null
$probeOut = Join-Path $ResultDir 'probe.json'
Vm 'CopyFileFromGuestToHost' @("$GUEST_DIR\probe.json", $probeOut) -Guest | Out-Null
$probe = Get-Content -LiteralPath $probeOut -Raw | ConvertFrom-Json

Write-Host "`nGuest capability" -ForegroundColor Cyan
$probe.PSObject.Properties | ForEach-Object { '  {0,-20} {1}' -f $_.Name, $_.Value }
if (-not $probe.elevated) {
    Write-Host "`n  The guest agent returned a filtered token - privileged collection cannot be tested this way." -ForegroundColor Yellow
    Write-Host "  Use a guest account that is a local administrator, or disable remote UAC filtering in the guest." -ForegroundColor Yellow
}

if ($Mode -eq 'probe') {
    if ($Revert) { Say 'reverting to baseline'; Vm 'revertToSnapshot' @($BASELINE) | Out-Null }
    elseif (-not $KeepRunning) { Say 'stopping guest'; Vm 'stop' @('soft') -Tolerate | Out-Null }
    Write-Host "`nProbe written to $probeOut`n" -ForegroundColor Green
    return
}

# --- Collection -------------------------------------------------------------------
Say 'copying collector into the guest'
Vm 'CopyFileFromHostToGuest' @($collector, "$GUEST_DIR\artifact-extract.ps1") -Guest | Out-Null

Say "running collector $CollectorArgs (this takes a while)"
$sw = [Diagnostics.Stopwatch]::StartNew()
$runner = "& '$GUEST_DIR\artifact-extract.ps1' $CollectorArgs *> '$GUEST_DIR\run.log'"
$runnerLocal = Join-Path $env:TEMP 'ae-runner.ps1'
Set-Content -LiteralPath $runnerLocal -Value $runner -Encoding UTF8
Vm 'CopyFileFromHostToGuest' @($runnerLocal, "$GUEST_DIR\run.ps1") -Guest | Out-Null
# Tolerated: a collection that degrades still exits non-zero but has produced an
# archive worth retrieving, and run.log below explains what happened.
Vm 'runProgramInGuest' @($GUEST_PS, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "$GUEST_DIR\run.ps1") -Guest -Tolerate | Out-Null
$sw.Stop()
Say ("collector finished in {0:N0}s" -f $sw.Elapsed.TotalSeconds) 'Green'

# Pull the transcript first: if the collection failed it is the only evidence of why.
Vm 'CopyFileFromGuestToHost' @("$GUEST_DIR\run.log", (Join-Path $ResultDir 'run.log')) -Guest -Tolerate | Out-Null

# The collector names its archive after the guest and the UTC start time, so the
# guest is asked what it produced rather than the name being guessed here.
$listLocal = Join-Path $env:TEMP 'ae-list.ps1'
Set-Content -LiteralPath $listLocal -Encoding UTF8 -Value @'
Get-ChildItem 'C:\artifact-extract\result' -File |
  Select-Object -ExpandProperty Name |
  Set-Content 'C:\artifact-extract\produced.txt' -Encoding UTF8
'@
Vm 'CopyFileFromHostToGuest' @($listLocal, "$GUEST_DIR\list.ps1") -Guest | Out-Null
Vm 'runProgramInGuest' @($GUEST_PS, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "$GUEST_DIR\list.ps1") -Guest -Tolerate | Out-Null
$producedList = Join-Path $ResultDir 'produced.txt'
Vm 'CopyFileFromGuestToHost' @("$GUEST_DIR\produced.txt", $producedList) -Guest -Tolerate | Out-Null

if (Test-Path -LiteralPath $producedList) {
    foreach ($name in (Get-Content -LiteralPath $producedList | Where-Object { $_ })) {
        Say "retrieving $name"
        Vm 'CopyFileFromGuestToHost' @("$GUEST_DIR\result\$name", (Join-Path $ResultDir $name)) -Guest -Tolerate | Out-Null
    }
}

if ($Revert) { Say 'reverting to baseline'; Vm 'revertToSnapshot' @($BASELINE) | Out-Null }
elseif (-not $KeepRunning) { Say 'stopping guest'; Vm 'stop' @('soft') -Tolerate | Out-Null }

Write-Host "`nCollection retrieved to $ResultDir" -ForegroundColor Green
Get-ChildItem $ResultDir | Select-Object Name, @{n = 'MB'; e = { [math]::Round($_.Length / 1MB, 2) } } | Format-Table -AutoSize
