<#
.SYNOPSIS
    Artifact-extract - native, dependency-free DFIR artifact collector (Windows).
.DESCRIPTION
    Collects triage artifacts using only built-in Windows tooling and writes a
    self-describing collection (C\ volume layout + NDJSON manifest with a full
    chain of custody), then packs it into a single .zip. See README.md for the contract.
.NOTES
    Requires PowerShell 5.1+. Run elevated for full coverage; degrades gracefully otherwise.
#>
[CmdletBinding()]
param(
    [switch]$Disk,
    [switch]$Volatile,
    [switch]$Memory,
    [switch]$All,
    [ValidateSet('quick', 'full')]
    [string]$Profile = 'quick',
    [string]$Output = '',
    [switch]$Vss,
    [switch]$KeepFolder,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$script:CollectorVersion = '0.1.0'

if ($Help) {
    @"
Artifact-extract $script:CollectorVersion - native DFIR collector (Windows)

Usage: .\artifact-extract.ps1 [-Disk] [-Volatile] [-Memory] [-All]
                              [-Profile quick|full] [-Output <path>] [-Vss] [-KeepFolder]

  (no flags)   disk only (C\ volume layout)   -Volatile   live captures
  -Disk        disk artifacts, explicit        -Memory     memory image (stub in v1)
  -All         disk + volatile + memory        -Profile    collection depth
  -Output      destination root               -KeepFolder keep the uncompressed folder
               (default: <script dir>\result)
  -Vss         also collect the key forensic set from every EXISTING shadow copy
               (historical versions) into VSS1\, VSS2\... - can be large
  -Help        this message

Output is packed into <host>_windows_<UTC>.zip (+ .sha256) in the destination root,
which defaults to a 'result' folder next to this script.
"@ | Write-Host
    return
}

# --- Category resolution (default = disk only; categories are additive) -------------
if ($All) { $Disk = $true; $Volatile = $true; $Memory = $true }
if (-not ($Disk -or $Volatile -or $Memory)) { $Disk = $true }

# --- Environment / clock ------------------------------------------------------------
$script:StartUtc   = (Get-Date).ToUniversalTime()
$stamp             = $script:StartUtc.ToString('yyyyMMddTHHmmssZ')
$hostName          = $env:COMPUTERNAME
$utcOffset         = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).ToString()
$identity          = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal         = New-Object Security.Principal.WindowsPrincipal($identity)
$script:IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Most of the collection shells out to built-in tools (reg, wevtutil, esentutl, tar).
# A packaged/sandboxed host (e.g. the Microsoft Store build of PowerShell) blocks that,
# which would silently reduce the collection to file copies only - so probe it up front.
$script:CanRunNative = $false
try {
    & cmd.exe /c exit 0 2>&1 | Out-Null
    $script:CanRunNative = ($LASTEXITCODE -eq 0)
}
catch { $script:CanRunNative = $false }
$script:IsPackagedHost = ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName -like '*\WindowsApps\*')

# --- Output layout ------------------------------------------------------------------
# Default destination: a 'result' folder next to this script (not the current directory),
# so the collection lands with the tool wherever it was copied to.
if (-not $Output) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $Output = Join-Path $base 'result'
}
$outRoot = [System.IO.Path]::GetFullPath((Join-Path $Output ("{0}_windows_{1}" -f $hostName, $stamp)))
New-Item -ItemType Directory -Path $outRoot -Force | Out-Null

$script:ManifestPath = Join-Path $outRoot 'collection_manifest.ndjson'
$script:LogPath      = Join-Path $outRoot 'collection.log'
$script:Utf8NoBom    = New-Object System.Text.UTF8Encoding($false)
$script:Counters     = [ordered]@{ ok = 0; error = 0; skipped = 0; degraded = 0; bytes = 0 }
$script:FinalArtifact = $outRoot

# --- Logging helpers ----------------------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Level, $Message
    # Tolerate a missing log dir (e.g. after the working folder is packed and removed).
    try { [System.IO.File]::AppendAllText($script:LogPath, $line + "`n", $script:Utf8NoBom) } catch { }
    Write-Host $line
}

function Write-Manifest {
    param(
        [string]$Action, [string]$Command, [string]$Target, [string]$Category,
        $ExitCode, [long]$Bytes, [string]$Sha256, [int]$DurationMs, [string]$Status,
        [string]$Message
    )
    $rel = if ($Target) { ($Target.Substring($outRoot.Length)).TrimStart('\', '/').Replace('\', '/') } else { $null }
    $obj = [ordered]@{
        ts_utc      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        action      = $Action
        command     = $Command
        target      = $rel
        category    = $Category
        exit_code   = $ExitCode
        bytes       = $Bytes
        sha256      = $Sha256
        duration_ms = $DurationMs
        status      = $Status
    }
    if ($Message) { $obj.message = $Message }
    $json = ($obj | ConvertTo-Json -Compress -Depth 4)
    [System.IO.File]::AppendAllText($script:ManifestPath, $json + "`n", $script:Utf8NoBom)
    if ($script:Counters.Contains($Status)) { $script:Counters[$Status]++ }
    $script:Counters.bytes += $Bytes
}

# Run a step that is expected to produce $Target, hash it, and record the manifest line.
function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][scriptblock]$Script,
        # Exit codes that are an expected condition rather than a failure (a fallback
        # handles them), so they never inflate the error count.
        [int[]]$BenignExitCodes = @()
    )
    $parent = Split-Path -Parent $Target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'ok'; $message = $null; $exit = $null
    try {
        $global:LASTEXITCODE = 0
        & $Script | Out-Null
        if ($LASTEXITCODE -is [int]) { $exit = $LASTEXITCODE }
        if ($exit -and $exit -ne 0) {
            if ($BenignExitCodes -contains $exit) {
                $status = 'degraded'; $message = "exit code $exit (expected; handled by fallback)"
            }
            else {
                # Without elevation, a privileged step failing is expected degradation, not an error.
                $status = if ($script:IsElevated) { 'error' } else { 'degraded' }
                $message = "exit code $exit"
            }
        }
    }
    catch {
        $status = if ($script:IsElevated) { 'error' } else { 'degraded' }
        $message = $_.Exception.Message
    }
    $sw.Stop()

    $bytes = 0L; $sha = $null
    if (Test-Path -LiteralPath $Target -PathType Leaf) {
        # -Force/-LiteralPath so hidden/system files (desktop.ini, NTUSER.*) and paths with
        # wildcard chars are handled; hashing failures degrade the step, never abort the run.
        try {
            $bytes = (Get-Item -LiteralPath $Target -Force -ErrorAction Stop).Length
            if ($bytes -gt 0) { $sha = (Get-FileHash -LiteralPath $Target -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }
        }
        catch {
            if ($status -eq 'ok') { $status = 'degraded'; $message = "hash failed: $($_.Exception.Message)" }
        }
    }
    elseif ($status -eq 'ok') {
        $status = 'degraded'; $message = 'no output produced'
    }

    Write-Manifest -Action $Action -Command $Command -Target $Target -Category $Category `
        -ExitCode $exit -Bytes $bytes -Sha256 $sha -DurationMs ([int]$sw.ElapsedMilliseconds) `
        -Status $status -Message $message
    if ($status -ne 'ok') { Write-Log "  $Action -> $status$(if($message){": $message"})" 'WARN' }
}

# ==================================================================================
#  Collection modules
# ==================================================================================

# Copy one source file into the C\ tree, preserving its path (C:\x -> <root>\C\x).
function Add-DiskFile {
    param([Parameter(Mandatory)][string]$Source, [string]$Action = 'file_copy')
    if ($Source -notmatch '^[A-Za-z]:\\') { return }
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return }
    $drive = $Source.Substring(0, 1).ToUpper()
    $target = Join-Path $outRoot ($drive + $Source.Substring(2))
    Invoke-Step -Action $Action -Category 'disk' -Command ("copy `"$Source`"") -Target $target `
        -Script { Copy-Item -LiteralPath $Source -Destination $target -Force }
}

# Copy every file under a directory tree into the C\ tree.
function Add-DiskTree {
    param([Parameter(Mandatory)][string]$Root)
    if (-not (Test-Path -LiteralPath $Root)) { return }
    Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Add-DiskFile -Source $_.FullName
    }
}

# --- Locked-file acquisition (elevated only) ----------------------------------------
# Primary: one Volume Shadow Copy of C:, read every locked file out of it.
# Fallbacks: per-file 'esentutl /y /vss', then 'reg save HKU\<SID>' for loaded user hives.
$script:VssDiag = ''

# Create a ClientAccessible shadow copy of C: and expose it as a usable path.
# CIM is used deliberately: Get-WmiObject does not exist in PowerShell 7, so the WMI
# variant silently failed there. Returns @{ Root; Link; Cim } or $null, reason in $script:VssDiag.
function New-ShadowSnapshot {
    $script:VssDiag = ''
    try {
        $svc = Get-Service VSS -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') { try { Start-Service VSS -ErrorAction Stop } catch { } }

        $r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create `
            -Arguments @{ Volume = 'C:\'; Context = 'ClientAccessible' } -ErrorAction Stop
        if ($null -eq $r) { $script:VssDiag = 'Create returned nothing'; return $null }
        if ($r.ReturnValue -ne 0) {
            $script:VssDiag = "Win32_ShadowCopy.Create ReturnValue=$($r.ReturnValue)"
            return $null
        }
        $sc = Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Where-Object { $_.ID -eq $r.ShadowID }
        if (-not $sc -or -not $sc.DeviceObject) {
            $script:VssDiag = 'shadow copy created but DeviceObject missing'
            return $null
        }
        $device = $sc.DeviceObject
        # Preferred: symlink the device so ordinary path APIs work.
        $link = Mount-ShadowDevice $device
        if ($link) { return @{ Root = $link; Link = $link; Cim = $sc } }
        # Fallback: address the device path directly (.NET handles \\?\GLOBALROOT paths).
        $script:VssDiag = 'mklink failed; using raw device path'
        return @{ Root = $device; Link = $null; Cim = $sc }
    }
    catch {
        $script:VssDiag = $_.Exception.Message
        return $null
    }
}

function Remove-ShadowSnapshot {
    param($Snap)
    if (-not $Snap) { return }
    Dismount-ShadowDevice $Snap.Link
    try { if ($Snap.Cim) { Remove-CimInstance -InputObject $Snap.Cim -ErrorAction SilentlyContinue } } catch { }
}

# .NET file APIs throughout, so both the symlink and the raw device path work.
function Copy-ShadowPath {
    param([string]$Src, [string]$Rel)
    $target = Join-Path $outRoot (Join-Path 'C' $Rel)
    Invoke-Step -Action 'vss_copy' -Category 'disk' -Command "vss copy C:\$Rel" -Target $target `
        -Script { [System.IO.File]::Copy($Src, $target, $true) }
}

function Add-ShadowFile {
    param($Snap, [string]$Rel)
    $src = $Snap.Root.TrimEnd('\') + '\' + $Rel
    if (-not [System.IO.File]::Exists($src)) { return }
    Copy-ShadowPath -Src $src -Rel $Rel
}

function Get-ShadowFiles {
    param([string]$Dir, [string]$Pattern = '*')
    try { return @([System.IO.Directory]::EnumerateFiles($Dir, $Pattern, [System.IO.SearchOption]::AllDirectories)) }
    catch { return @() }
}

function Add-ShadowTree {
    param($Snap, [string]$RelRoot, [string]$Pattern = '*')
    $base = $Snap.Root.TrimEnd('\')
    foreach ($src in (Get-ShadowFiles -Dir ($base + '\' + $RelRoot) -Pattern $Pattern)) {
        Copy-ShadowPath -Src $src -Rel $src.Substring($base.Length + 1)
    }
}

# Per-file native VSS copy - independent of the snapshot/symlink path above.
function Copy-LockedEsentutl {
    param([string]$Rel)
    $src = 'C:\' + $Rel
    if (-not [System.IO.File]::Exists($src)) { return }
    $target = Join-Path $outRoot (Join-Path 'C' $Rel)
    Invoke-Step -Action 'esentutl_copy' -Category 'disk' -Command "esentutl /y /vss `"$src`" /d `"$target`"" `
        -Target $target -Script { esentutl /y /vss $src /d $target 2>&1 | Out-Null }
}

# --- Historical collection from EXISTING shadow copies (-Vss) -----------------------
# Distinct from the snapshot above: that one is created now, purely to defeat file locks.
# These are the restore points already on the volume, and they hold *previous* versions of
# the same artifacts - often the only way to recover what an attacker altered or deleted.

function Get-ExistingShadowCopies {
    try {
        $vol = Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'" -ErrorAction Stop
        if (-not $vol) { return @() }
        return @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop |
            Where-Object { $_.VolumeName -eq $vol.DeviceID } | Sort-Object InstallDate)
    }
    catch { return @() }
}

function Mount-ShadowDevice {
    param([string]$Device)
    $link = Join-Path $env:TEMP ('aeng_vss_' + [guid]::NewGuid().ToString('N'))
    # New-Item first: pure PowerShell, no child process. mklink is the fallback for hosts
    # where it does not accept a device target. Never let a failure here abort the run.
    try {
        New-Item -ItemType SymbolicLink -Path $link -Target ($Device + '\') -ErrorAction Stop | Out-Null
        if (Test-Path -LiteralPath $link) { return $link }
    }
    catch { }
    try {
        cmd /c mklink /d "$link" $Device\ 2>&1 | Out-Null
        if (Test-Path -LiteralPath $link) { return $link }
    }
    catch { }
    return $null
}

function Dismount-ShadowDevice {
    param([string]$Link)
    if (-not $Link) { return }
    # Remove only the link, never follow it into the snapshot.
    try { [System.IO.Directory]::Delete($Link); return } catch { }
    try { if (Test-Path -LiteralPath $Link) { cmd /c rmdir "$Link" 2>&1 | Out-Null } } catch { }
}

function Get-ShadowDirs {
    param([string]$Dir)
    try { return @([System.IO.Directory]::EnumerateDirectories($Dir)) } catch { return @() }
}

# Copy out of a shadow copy into a VSS<N>\ folder (mirrors the volume root, KAPE-style).
function Add-VssFile {
    param([string]$Root, [string]$Prefix, [string]$Rel)
    $src = $Root.TrimEnd('\') + '\' + $Rel
    if (-not [System.IO.File]::Exists($src)) { return }
    $target = Join-Path $outRoot (Join-Path $Prefix $Rel)
    Invoke-Step -Action 'vss_historical' -Category 'disk' -Command "$Prefix copy $Rel" -Target $target `
        -Script { [System.IO.File]::Copy($src, $target, $true) }
}

function Add-VssTree {
    param([string]$Root, [string]$Prefix, [string]$RelRoot, [string]$Pattern = '*')
    $base = $Root.TrimEnd('\')
    foreach ($s in (Get-ShadowFiles -Dir ($base + '\' + $RelRoot) -Pattern $Pattern)) {
        $src = $s
        $target = Join-Path $outRoot (Join-Path $Prefix $src.Substring($base.Length + 1))
        Invoke-Step -Action 'vss_historical' -Category 'disk' `
            -Command "$Prefix copy $($src.Substring($base.Length + 1))" -Target $target `
            -Script { [System.IO.File]::Copy($src, $target, $true) }
    }
}

function Collect-ShadowHistory {
    $shadows = Get-ExistingShadowCopies
    if ($shadows.Count -eq 0) {
        Write-Manifest -Action 'vss_history' -Command 'enumerate Win32_ShadowCopy' -Target $null -Category 'disk' `
            -ExitCode $null -Bytes 0 -Sha256 $null -DurationMs 0 -Status 'skipped' `
            -Message 'no existing shadow copies on this volume (System Protection may be off)'
        Write-Log '  no existing shadow copies found on C:' 'WARN'
        return
    }
    Write-Log "  $($shadows.Count) existing shadow copy(ies) found - collecting historical artifacts"
    Write-Log "  (this repeats the key artifact set per snapshot; expect the collection to grow accordingly)"
    $i = 0
    foreach ($sc in $shadows) {
        $i++
        $prefix = "VSS$i"
        $link = Mount-ShadowDevice $sc.DeviceObject
        $root = if ($link) { $link } else { $sc.DeviceObject }
        Write-Log ("  {0} <- {1} (created {2})" -f $prefix, $sc.ID, $sc.InstallDate)
        Write-Manifest -Action 'vss_history' -Command "mount $($sc.ID)" -Target $null -Category 'disk' `
            -ExitCode 0 -Bytes 0 -Sha256 $null -DurationMs 0 -Status 'ok' `
            -Message "$prefix = shadow copy $($sc.ID) created $($sc.InstallDate)"
        try {
            # Registry hives + their transaction logs
            foreach ($h in 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT') {
                foreach ($ext in '', '.LOG1', '.LOG2') { Add-VssFile $root $prefix "Windows\System32\config\$h$ext" }
            }
            # Execution artifacts
            foreach ($ext in '', '.LOG1', '.LOG2') { Add-VssFile $root $prefix "Windows\AppCompat\Programs\Amcache.hve$ext" }
            Add-VssFile $root $prefix 'Windows\System32\sru\SRUDB.dat'
            # Event logs (historical - recovers entries cleared from the live logs)
            Add-VssTree $root $prefix 'Windows\System32\winevt\Logs' '*.evtx'
            # Per-user hives
            foreach ($ud in (Get-ShadowDirs ($root.TrimEnd('\') + '\Users'))) {
                $uname = Split-Path -Leaf $ud
                foreach ($ext in '', '.LOG1', '.LOG2') {
                    Add-VssFile $root $prefix "Users\$uname\NTUSER.DAT$ext"
                    Add-VssFile $root $prefix "Users\$uname\AppData\Local\Microsoft\Windows\UsrClass.dat$ext"
                }
            }
        }
        finally { Dismount-ShadowDevice $link }
    }
}

# Loaded user hives can be saved with no VSS at all.
function Save-LoadedUserHives {
    Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { -not $_.Special -and $_.LocalPath -like 'C:\Users\*' } | ForEach-Object {
            $sid = $_.SID
            $name = Split-Path -Leaf $_.LocalPath
            $t1 = Join-Path $outRoot "C\Users\$name\NTUSER.DAT"
            Invoke-Step -Action 'registry_save' -Category 'disk' -Command "reg save HKU\$sid" -Target $t1 `
                -Script { reg save "HKU\$sid" $t1 /y 2>&1 | Out-Null }
            $t2 = Join-Path $outRoot "C\Users\$name\AppData\Local\Microsoft\Windows\UsrClass.dat"
            Invoke-Step -Action 'registry_save' -Category 'disk' -Command "reg save HKU\${sid}_Classes" -Target $t2 `
                -Script { reg save "HKU\${sid}_Classes" $t2 /y 2>&1 | Out-Null }
        }
}

function Collect-Disk {
    Write-Log "Collecting disk artifacts (C\ volume layout) [profile=$Profile]"
    $sys32 = Join-Path $outRoot 'C\Windows\System32'

    # Registry hives (locked -> reg save reads them live)
    $hives = @{ 'SYSTEM' = 'HKLM\SYSTEM'; 'SOFTWARE' = 'HKLM\SOFTWARE'; 'SAM' = 'HKLM\SAM'; 'SECURITY' = 'HKLM\SECURITY' }
    foreach ($h in $hives.GetEnumerator()) {
        $target = Join-Path $sys32 ('config\{0}' -f $h.Key)
        Invoke-Step -Action 'registry_save' -Category 'disk' `
            -Command ("reg save {0} `"{1}`" /y" -f $h.Value, $target) -Target $target `
            -Script { reg save $h.Value $target /y 2>&1 | Out-Null }
    }

    # Event logs - EVERY channel present on the system, not a curated subset.
    # Enumerating the .evtx files on disk (rather than 'wevtutil el') keeps us to the
    # channels that actually have a log, and the filename maps back to the channel name
    # ('%4' is the escaped '/'). wevtutil handles the live lock; archived or unregistered
    # logs cannot be exported by channel name, so those fall back to a direct file copy.
    $logDir = 'C:\Windows\System32\winevt\Logs'
    if (Test-Path -LiteralPath $logDir) {
        Get-ChildItem -LiteralPath $logDir -Filter '*.evtx' -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $file = $_
            $channel = $file.BaseName -replace '%4', '/'
            $target = Join-Path $sys32 ('winevt\Logs\{0}' -f $file.Name)
            # 15007 = channel not registered (archived log); the copy below picks those up.
            Invoke-Step -Action 'eventlog_export' -Category 'disk' -BenignExitCodes 15007 `
                -Command ("wevtutil epl `"{0}`" `"{1}`"" -f $channel, $target) -Target $target `
                -Script { wevtutil epl $channel $target 2>&1 | Out-Null }
            if (-not (Test-Path -LiteralPath $target)) {
                # Only worth copying if the file is actually readable (archived/unregistered
                # channels). If the export failed on permissions, a copy fails the same way.
                $readable = $false
                try {
                    $fs = [System.IO.File]::Open($file.FullName, 'Open', 'Read', 'ReadWrite')
                    $fs.Close(); $readable = $true
                }
                catch { }
                if ($readable) { Add-DiskFile -Source $file.FullName -Action 'eventlog_copy' }
            }
        }
    }

    # Prefetch (readable copies; requires admin to enumerate)
    $pfDir = 'C:\Windows\Prefetch'
    if (Test-Path $pfDir) {
        Get-ChildItem -Path $pfDir -Filter '*.pf' -ErrorAction SilentlyContinue | ForEach-Object {
            $target = Join-Path $outRoot ('C\Windows\Prefetch\{0}' -f $_.Name)
            Invoke-Step -Action 'file_copy' -Category 'disk' `
                -Command ("copy `"{0}`"" -f $_.FullName) -Target $target `
                -Script { Copy-Item -LiteralPath $_.FullName -Destination $target -Force }
        }
    }
    # Scheduled task definitions (persistence T1053)
    Add-DiskTree -Root 'C:\Windows\System32\Tasks'
    Add-DiskTree -Root 'C:\Windows\SysWOW64\Tasks'

    # Standalone config / execution artifacts
    Add-DiskFile -Source 'C:\Windows\System32\drivers\etc\hosts'
    Add-DiskFile -Source 'C:\Windows\AppCompat\pca\PcaAppLaunchDic.txt'   # Win11 plaintext execution log
    Add-DiskFile -Source 'C:\Windows\AppCompat\pca\PcaGeneralDb0.txt'

    # All-users startup
    Add-DiskTree -Root 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'

    # Per-user artifacts (non-locked): Recent (LNK + Jump Lists), Startup, PowerShell console history
    Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $u = $_.FullName
        Add-DiskTree -Root (Join-Path $u 'AppData\Roaming\Microsoft\Windows\Recent')
        Add-DiskTree -Root (Join-Path $u 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
        Add-DiskFile -Source (Join-Path $u 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
    }

    # Windows Error Reporting (faulting-app paths; survives binary deletion) - larger, full only
    if ($Profile -eq 'full') {
        Add-DiskTree -Root 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'
        Add-DiskTree -Root 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'
    }
    # --- Locked files via a single Volume Shadow Copy (Wave 2; elevated only) ---
    if (-not $script:IsElevated) {
        Write-Manifest -Action 'vss_snapshot' -Command 'n/a' -Target $null -Category 'disk' `
            -ExitCode $null -Bytes 0 -Sha256 $null -DurationMs 0 -Status 'skipped' `
            -Message 'locked-file acquisition (Amcache/SRUM/NTUSER/UsrClass/transaction logs/browser) requires elevation'
        Write-Log '  locked files skipped - run elevated to acquire them' 'WARN'
    }
    else {
        Write-Log 'Acquiring locked files via Volume Shadow Copy...'
        $snap = New-ShadowSnapshot
        if (-not $snap) {
            Write-Manifest -Action 'vss_snapshot' -Command 'Win32_ShadowCopy.Create' -Target $null -Category 'disk' `
                -ExitCode $null -Bytes 0 -Sha256 $null -DurationMs 0 -Status 'degraded' `
                -Message "shadow copy unavailable: $script:VssDiag"
            Write-Log "  VSS unavailable ($script:VssDiag) - falling back to esentutl / reg save" 'WARN'
            # Fallback 1: per-file native VSS copy (manages its own snapshot internally).
            foreach ($rel in @(
                    'Windows\AppCompat\Programs\Amcache.hve',
                    'Windows\System32\sru\SRUDB.dat',
                    'Windows\System32\config\SYSTEM.LOG1', 'Windows\System32\config\SYSTEM.LOG2',
                    'Windows\System32\config\SOFTWARE.LOG1', 'Windows\System32\config\SOFTWARE.LOG2',
                    'Windows\System32\config\SAM.LOG1', 'Windows\System32\config\SECURITY.LOG1')) {
                Copy-LockedEsentutl $rel
            }
            # Fallback 2: loaded user hives (NTUSER/UsrClass) need no VSS at all.
            Save-LoadedUserHives
        }
        else {
            Write-Manifest -Action 'vss_snapshot' -Command 'Win32_ShadowCopy.Create' -Target $null -Category 'disk' `
                -ExitCode 0 -Bytes 0 -Sha256 $null -DurationMs 0 -Status 'ok' -Message $script:VssDiag
            try {
                # Registry transaction logs (the hives themselves come from reg save above)
                foreach ($h in 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT') {
                    Add-ShadowFile $snap "Windows\System32\config\$h.LOG1"
                    Add-ShadowFile $snap "Windows\System32\config\$h.LOG2"
                }
                Add-ShadowFile $snap 'Windows\System32\config\DEFAULT'
                # Execution artifacts (ESE / hive)
                Add-ShadowFile $snap 'Windows\AppCompat\Programs\Amcache.hve'
                Add-ShadowFile $snap 'Windows\AppCompat\Programs\Amcache.hve.LOG1'
                Add-ShadowFile $snap 'Windows\AppCompat\Programs\Amcache.hve.LOG2'
                Add-ShadowFile $snap 'Windows\System32\sru\SRUDB.dat'
                # Per-user hives (UserAssist / MRU / Shellbags) + browser history
                Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    $rel = "Users\$($_.Name)"
                    Add-ShadowFile $snap "$rel\NTUSER.DAT"
                    Add-ShadowFile $snap "$rel\NTUSER.DAT.LOG1"
                    Add-ShadowFile $snap "$rel\NTUSER.DAT.LOG2"
                    Add-ShadowFile $snap "$rel\AppData\Local\Microsoft\Windows\UsrClass.dat"
                    Add-ShadowFile $snap "$rel\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1"
                    Add-ShadowFile $snap "$rel\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2"
                    Add-ShadowFile $snap "$rel\AppData\Local\Google\Chrome\User Data\Default\History"
                    Add-ShadowFile $snap "$rel\AppData\Local\Microsoft\Edge\User Data\Default\History"
                    Add-ShadowTree $snap "$rel\AppData\Roaming\Mozilla\Firefox\Profiles" 'places.sqlite'
                }
                # WMI repository (fileless persistence) - larger, full profile only
                if ($Profile -eq 'full') { Add-ShadowTree $snap 'Windows\System32\wbem\Repository' }
            }
            finally { Remove-ShadowSnapshot $snap }
        }
    }
    # --- Historical versions from existing shadow copies (-Vss) ---
    if ($Vss) {
        if (-not $script:IsElevated) {
            Write-Manifest -Action 'vss_history' -Command 'n/a' -Target $null -Category 'disk' `
                -ExitCode $null -Bytes 0 -Sha256 $null -DurationMs 0 -Status 'skipped' `
                -Message 'historical shadow-copy collection requires elevation'
            Write-Log '  -Vss requested but not elevated - skipped' 'WARN'
        }
        else {
            Write-Log 'Collecting historical artifacts from existing shadow copies...'
            Collect-ShadowHistory
        }
    }
    # NOTE: raw NTFS ($MFT / $UsnJrnl:$J / $LogFile) -> Wave 3 (raw-NTFS reader).
}

function Collect-Volatile {
    Write-Log 'Collecting volatile artifacts (live captures)'
    $v = Join-Path $outRoot 'volatile'

    Invoke-Step -Action 'systeminfo' -Category 'volatile' -Command 'systeminfo' `
        -Target (Join-Path $v 'systeminfo.txt') `
        -Script { systeminfo 2>&1 | Out-File -FilePath (Join-Path $v 'systeminfo.txt') -Encoding UTF8 }

    Invoke-Step -Action 'timezone' -Category 'volatile' -Command 'Get-TimeZone; w32tm /query' `
        -Target (Join-Path $v 'timezone.txt') `
        -Script {
            $o = Join-Path $v 'timezone.txt'
            Get-TimeZone | Format-List | Out-File -FilePath $o -Encoding UTF8
            "`nUTC offset: $utcOffset`nLocal: $(Get-Date -Format o)`nUTC:   $((Get-Date).ToUniversalTime().ToString('o'))" |
                Out-File -FilePath $o -Append -Encoding UTF8
        }

    Invoke-Step -Action 'processes' -Category 'volatile' -Command 'Get-CimInstance Win32_Process' `
        -Target (Join-Path $v 'processes.csv') `
        -Script {
            Get-CimInstance Win32_Process |
                Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate |
                Export-Csv -Path (Join-Path $v 'processes.csv') -NoTypeInformation -Encoding UTF8
        }

    Invoke-Step -Action 'network' -Category 'volatile' -Command 'Get-NetTCPConnection' `
        -Target (Join-Path $v 'net_connections.csv') `
        -Script {
            Get-NetTCPConnection -ErrorAction SilentlyContinue |
                Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
                Export-Csv -Path (Join-Path $v 'net_connections.csv') -NoTypeInformation -Encoding UTF8
        }

    Invoke-Step -Action 'services' -Category 'volatile' -Command 'Get-CimInstance Win32_Service' `
        -Target (Join-Path $v 'services.csv') `
        -Script {
            Get-CimInstance Win32_Service |
                Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
                Export-Csv -Path (Join-Path $v 'services.csv') -NoTypeInformation -Encoding UTF8
        }

    Invoke-Step -Action 'scheduled_tasks' -Category 'volatile' -Command 'schtasks /query /fo CSV /v' `
        -Target (Join-Path $v 'scheduled_tasks.csv') `
        -Script { schtasks /query /fo CSV /v 2>&1 | Out-File -FilePath (Join-Path $v 'scheduled_tasks.csv') -Encoding UTF8 }

    Invoke-Step -Action 'local_users' -Category 'volatile' -Command 'Get-CimInstance Win32_UserAccount' `
        -Target (Join-Path $v 'local_users.csv') `
        -Script {
            Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
                Select-Object Name, SID, Disabled, Lockout, PasswordRequired |
                Export-Csv -Path (Join-Path $v 'local_users.csv') -NoTypeInformation -Encoding UTF8
        }

    Invoke-Step -Action 'sessions' -Category 'volatile' -Command 'query user' `
        -Target (Join-Path $v 'sessions.txt') `
        -Script {
            # 'query user' exits 1 when no interactive sessions exist - not a failure.
            (query user 2>&1) | Out-File -FilePath (Join-Path $v 'sessions.txt') -Encoding UTF8
            $global:LASTEXITCODE = 0
        }

    # Autoruns-style registry triage (fast; complements the offline hives)
    Invoke-Step -Action 'autoruns_registry' -Category 'volatile' -Command 'reg query Run/RunOnce/Winlogon/IFEO' `
        -Target (Join-Path $v 'autoruns_registry.txt') `
        -Script {
            $o = Join-Path $v 'autoruns_registry.txt'
            $keys = @(
                'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
                'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
                'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
            Set-Content -Path $o -Value '' -Encoding UTF8
            foreach ($k in $keys) {
                Add-Content -Path $o -Value "==== $k ====" -Encoding UTF8
                (reg query $k /s 2>&1) | Out-File -FilePath $o -Append -Encoding UTF8
            }
            $global:LASTEXITCODE = 0
        }

    Invoke-Step -Action 'network_config' -Category 'volatile' -Command 'ipconfig /all; route print' `
        -Target (Join-Path $v 'network_config.txt') `
        -Script {
            $o = Join-Path $v 'network_config.txt'
            (ipconfig /all 2>&1) | Out-File -FilePath $o -Encoding UTF8
            "`n==== route print ====" | Out-File -FilePath $o -Append -Encoding UTF8
            (route print 2>&1) | Out-File -FilePath $o -Append -Encoding UTF8
            $global:LASTEXITCODE = 0
        }

    Invoke-Step -Action 'smb' -Category 'volatile' -Command 'Get-SmbShare/Session; net use' `
        -Target (Join-Path $v 'smb.txt') `
        -Script {
            $o = Join-Path $v 'smb.txt'
            '==== SmbShare ===='   | Out-File -FilePath $o -Encoding UTF8
            (Get-SmbShare -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String) | Out-File -FilePath $o -Append -Encoding UTF8
            '==== SmbSession ===='  | Out-File -FilePath $o -Append -Encoding UTF8
            (Get-SmbSession -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String) | Out-File -FilePath $o -Append -Encoding UTF8
            '==== net use ===='    | Out-File -FilePath $o -Append -Encoding UTF8
            (net use 2>&1) | Out-File -FilePath $o -Append -Encoding UTF8
            $global:LASTEXITCODE = 0
        }

    if ($Profile -eq 'full') {
        Invoke-Step -Action 'arp' -Category 'volatile' -Command 'arp -a' `
            -Target (Join-Path $v 'arp.txt') `
            -Script { arp -a 2>&1 | Out-File -FilePath (Join-Path $v 'arp.txt') -Encoding UTF8 }
        Invoke-Step -Action 'dns_cache' -Category 'volatile' -Command 'Get-DnsClientCache' `
            -Target (Join-Path $v 'dns_cache.csv') `
            -Script { Get-DnsClientCache -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $v 'dns_cache.csv') -NoTypeInformation -Encoding UTF8 }
        Invoke-Step -Action 'drivers' -Category 'volatile' -Command 'driverquery /v /fo csv' `
            -Target (Join-Path $v 'drivers.csv') `
            -Script { driverquery /v /fo csv 2>&1 | Out-File -FilePath (Join-Path $v 'drivers.csv') -Encoding UTF8; $global:LASTEXITCODE = 0 }
        Invoke-Step -Action 'hotfixes' -Category 'volatile' -Command 'Get-HotFix' `
            -Target (Join-Path $v 'hotfixes.csv') `
            -Script { Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID, Description, InstalledOn, InstalledBy | Export-Csv -Path (Join-Path $v 'hotfixes.csv') -NoTypeInformation -Encoding UTF8 }
        Invoke-Step -Action 'installed_software' -Category 'volatile' -Command 'reg Uninstall keys' `
            -Target (Join-Path $v 'installed_software.csv') `
            -Script {
                $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
                Get-ItemProperty $paths -ErrorAction SilentlyContinue |
                    Where-Object DisplayName |
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                    Export-Csv -Path (Join-Path $v 'installed_software.csv') -NoTypeInformation -Encoding UTF8
            }
    }
}

function Collect-Memory {
    Write-Log 'Memory acquisition requested'
    $m = Join-Path $outRoot 'memory'
    New-Item -ItemType Directory -Path $m -Force | Out-Null
    $msg = 'memory acquisition not implemented in v1 (no reliable native-only path; requires a kernel driver - out of scope)'
    Write-Manifest -Action 'memory_acquire' -Command 'n/a' -Target $null -Category 'memory' `
        -ExitCode $null -Bytes 0 -Sha256 $null -DurationMs 0 -Status 'skipped' -Message $msg
    Write-Log "  memory -> skipped: $msg" 'WARN'
}

# Pack the collection into a single .zip and hash it (outer chain-of-custody seal).
function Compress-Collection {
    $parent  = Split-Path -Parent $outRoot
    $leaf    = Split-Path -Leaf $outRoot
    $archive = "$outRoot.zip"
    if (Test-Path $archive) { Remove-Item $archive -Force }
    Write-Log "Compressing collection -> $leaf.zip"

    $ok = $false
    try {
        if (Get-Command tar.exe -ErrorAction SilentlyContinue) {
            $global:LASTEXITCODE = 0
            tar.exe -a -cf $archive -C $parent $leaf 2>&1 | Out-Null
            $ok = ($LASTEXITCODE -eq 0 -and (Test-Path $archive))
        }
        if (-not $ok) {   # fallback: native PowerShell zip
            Compress-Archive -Path $outRoot -DestinationPath $archive -Force
            $ok = Test-Path $archive
        }
    }
    catch { Write-Log "  compression error: $($_.Exception.Message)" 'WARN'; $ok = $false }

    if ($ok) {
        $hash = (Get-FileHash -Path $archive -Algorithm SHA256).Hash.ToLower()
        [System.IO.File]::WriteAllText("$archive.sha256", "$hash  $leaf.zip`n", $script:Utf8NoBom)
        $size = (Get-Item $archive).Length
        Write-Log ("  archive: {0} ({1:N1} MB) sha256={2}" -f "$leaf.zip", ($size / 1MB), $hash)
        if (-not $KeepFolder) {
            Write-Log '  removing working folder (use -KeepFolder to retain it)'
            Remove-Item $outRoot -Recurse -Force
        }
        $script:FinalArtifact = $archive
    }
    else {
        Write-Log '  compression failed - keeping uncompressed folder' 'WARN'
        $script:FinalArtifact = $outRoot
    }
}

# ==================================================================================
#  Main
# ==================================================================================
$selected = @()
if ($Disk) { $selected += 'disk' }
if ($Volatile) { $selected += 'volatile' }
if ($Memory) { $selected += 'memory' }

Write-Log "Artifact-extract $script:CollectorVersion starting on $hostName"
Write-Log "Elevated: $script:IsElevated | Profile: $Profile | Categories: $($selected -join ', ')"
Write-Log "Output: $outRoot"
if (-not $script:IsElevated) { Write-Log 'Not elevated - disk collection will be partial (steps marked degraded).' 'WARN' }
if (-not $script:CanRunNative) {
    Write-Log '****************************************************************' 'WARN'
    Write-Log 'This PowerShell host cannot launch native executables.' 'WARN'
    Write-Log 'reg / wevtutil / esentutl / tar will all fail, so registry hives,' 'WARN'
    Write-Log 'event log exports and locked files CANNOT be collected.' 'WARN'
    if ($script:IsPackagedHost) { Write-Log 'Cause: running from a packaged (Microsoft Store) PowerShell.' 'WARN' }
    Write-Log 'Re-run from Windows PowerShell:  powershell.exe -File .\artifact-extract.ps1' 'WARN'
    Write-Log '****************************************************************' 'WARN'
    Write-Manifest -Action 'host_capability' -Command 'probe native execution' -Target $null -Category 'meta' `
        -ExitCode $null -Bytes 0 -Sha256 $null -DurationMs 0 -Status 'degraded' `
        -Message 'host cannot launch native executables; hives/event logs/locked files unavailable'
}

# metadata.json
$os = Get-CimInstance Win32_OperatingSystem
$scriptHash = if ($PSCommandPath -and (Test-Path $PSCommandPath)) { (Get-FileHash -Path $PSCommandPath -Algorithm SHA256).Hash.ToLower() } else { $null }
$metadata = [ordered]@{
    collector          = 'artifact-extract'
    collector_version  = $script:CollectorVersion
    collector_sha256   = $scriptHash
    host               = $hostName
    os_caption         = $os.Caption
    os_version         = $os.Version
    os_build           = $os.BuildNumber
    architecture       = $env:PROCESSOR_ARCHITECTURE
    user               = $identity.Name
    elevated           = $script:IsElevated
    timezone           = (Get-TimeZone).Id
    utc_offset         = $utcOffset
    started_utc        = $script:StartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    started_local      = (Get-Date).ToString('o')
    profile            = $Profile
    categories         = $selected
    # Record the options actually used, so a collection is self-describing after the fact.
    vss_historical     = [bool]$Vss
    keep_folder        = [bool]$KeepFolder
    output_root        = $Output
    ps_version         = $PSVersionTable.PSVersion.ToString()
    native_execution   = $script:CanRunNative
    packaged_host      = $script:IsPackagedHost
}
[System.IO.File]::WriteAllText((Join-Path $outRoot 'metadata.json'),
    ($metadata | ConvertTo-Json -Depth 4), $script:Utf8NoBom)

# A failure inside a module must never cost us the whole collection: whatever was gathered
# still gets sealed and packed below.
try {
    if ($Disk) { Collect-Disk }
    if ($Volatile) { Collect-Volatile }
    if ($Memory) { Collect-Memory }
}
catch {
    Write-Log "Collection stopped early: $($_.Exception.Message)" 'WARN'
    Write-Manifest -Action 'collection_error' -Command 'n/a' -Target $null -Category 'meta' `
        -ExitCode $null -Bytes 0 -Sha256 $null -DurationMs 0 -Status 'error' `
        -Message $_.Exception.Message
}

# Seal the manifest, then pack everything into a single archive.
if (Test-Path $script:ManifestPath) {
    $manifestHash = (Get-FileHash -Path $script:ManifestPath -Algorithm SHA256).Hash.ToLower()
    [System.IO.File]::WriteAllText((Join-Path $outRoot 'manifest.sha256'),
        "$manifestHash  collection_manifest.ndjson`n", $script:Utf8NoBom)
}

$elapsed = ((Get-Date).ToUniversalTime() - $script:StartUtc).TotalSeconds
Write-Log ("Done in {0:N1}s | ok={1} degraded={2} error={3} skipped={4} | {5:N1} MB" -f `
    $elapsed, $script:Counters.ok, $script:Counters.degraded, $script:Counters.error, `
    $script:Counters.skipped, ($script:Counters.bytes / 1MB))

Compress-Collection

Write-Host ''
Write-Host "Collection written to: $script:FinalArtifact"
# The collector ran to completion; per-step status lives in the manifest, so exit clean.
exit 0
