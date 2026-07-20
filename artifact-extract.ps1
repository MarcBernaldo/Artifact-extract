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
    [string]$Output = '.',
    [switch]$KeepFolder,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$script:CollectorVersion = '0.1.0'

if ($Help) {
    @"
Artifact-extract $script:CollectorVersion - native DFIR collector (Windows)

Usage: .\artifact-extract.ps1 [-Disk] [-Volatile] [-Memory] [-All]
                              [-Profile quick|full] [-Output <path>] [-KeepFolder]

  (no flags)   disk only (C\ volume layout)   -Volatile   live captures
  -Disk        disk artifacts, explicit        -Memory     memory image (stub in v1)
  -All         disk + volatile + memory        -Profile    collection depth
  -Output      destination root (default: .)   -KeepFolder keep the uncompressed folder
  -Help        this message

Output is packed into <host>_windows_<UTC>.zip (+ .sha256) in the destination root.
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

# --- Output layout ------------------------------------------------------------------
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
        [Parameter(Mandatory)][scriptblock]$Script
    )
    $parent = Split-Path -Parent $Target
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'ok'; $message = $null; $exit = $null
    try {
        $global:LASTEXITCODE = 0
        & $Script | Out-Null
        if ($LASTEXITCODE -is [int]) { $exit = $LASTEXITCODE }
        if ($exit -and $exit -ne 0) {
            # Without elevation, a privileged step failing is expected degradation, not an error.
            $status = if ($script:IsElevated) { 'error' } else { 'degraded' }
            $message = "exit code $exit"
        }
    }
    catch {
        $status = if ($script:IsElevated) { 'error' } else { 'degraded' }
        $message = $_.Exception.Message
    }
    $sw.Stop()

    $bytes = 0L; $sha = $null
    if (Test-Path $Target -PathType Leaf) {
        $bytes = (Get-Item $Target).Length
        if ($bytes -gt 0) { $sha = (Get-FileHash -Path $Target -Algorithm SHA256).Hash.ToLower() }
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

    # Event logs (curated; full profile adds more channels)
    $channels = @('Security', 'System', 'Application',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational')
    if ($Profile -eq 'full') {
        $channels += @('Microsoft-Windows-WMI-Activity/Operational',
            'Microsoft-Windows-TaskScheduler/Operational',
            'Microsoft-Windows-Windows Defender/Operational',
            'Microsoft-Windows-Bits-Client/Operational',
            'Microsoft-Windows-Sysmon/Operational')
    }
    foreach ($ch in $channels) {
        $fname = ($ch -replace '[\\/]', '%4') + '.evtx'
        $target = Join-Path $sys32 ('winevt\Logs\{0}' -f $fname)
        Invoke-Step -Action 'eventlog_export' -Category 'disk' `
            -Command ("wevtutil epl `"{0}`" `"{1}`"" -f $ch, $target) -Target $target `
            -Script { wevtutil epl $ch $target 2>&1 | Out-Null }
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
    # NOTE: $MFT / USN / NTUSER.DAT (locked) deferred to Phase 4 (VSS/esentutl/raw-NTFS).
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

    if ($Profile -eq 'full') {
        Invoke-Step -Action 'arp' -Category 'volatile' -Command 'arp -a' `
            -Target (Join-Path $v 'arp.txt') `
            -Script { arp -a 2>&1 | Out-File -FilePath (Join-Path $v 'arp.txt') -Encoding UTF8 }
        Invoke-Step -Action 'dns_cache' -Category 'volatile' -Command 'Get-DnsClientCache' `
            -Target (Join-Path $v 'dns_cache.csv') `
            -Script { Get-DnsClientCache -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $v 'dns_cache.csv') -NoTypeInformation -Encoding UTF8 }
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
}
[System.IO.File]::WriteAllText((Join-Path $outRoot 'metadata.json'),
    ($metadata | ConvertTo-Json -Depth 4), $script:Utf8NoBom)

if ($Disk) { Collect-Disk }
if ($Volatile) { Collect-Volatile }
if ($Memory) { Collect-Memory }

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
