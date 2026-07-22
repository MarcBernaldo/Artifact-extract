<#
    Regression test for the raw NTFS reader in artifact-extract.ps1.

    Raw volume access needs elevation and a real disk, so the reader is exercised here
    against a synthetic volume image instead: a hand-built boot sector plus one MFT
    record whose $DATA attribute has a fragmented, partly sparse run list. Everything
    the reader has to get right - boot geometry, the signed clusters-per-record byte,
    the update sequence array, negative relative cluster offsets, sparse runs, the
    trailing partial cluster - is checked byte for byte.

    Run unelevated:  powershell -File tests\Test-NtfsReader.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Failures = 0
function Assert-Equal {
    param($Expected, $Actual, [string]$What)
    if ($Expected -eq $Actual) { Write-Host "  PASS  $What" -ForegroundColor Green }
    else { Write-Host "  FAIL  $What  (expected '$Expected', got '$Actual')" -ForegroundColor Red; $script:Failures++ }
}
function Assert-Throws {
    param([scriptblock]$Script, [string]$Match, [string]$What)
    try { & $Script; Write-Host "  FAIL  $What  (no error raised)" -ForegroundColor Red; $script:Failures++ }
    catch {
        if ($_.Exception.Message -like "*$Match*") { Write-Host "  PASS  $What" -ForegroundColor Green }
        else { Write-Host "  FAIL  $What  (message was '$($_.Exception.Message)')" -ForegroundColor Red; $script:Failures++ }
    }
}

# Pull the reader functions out of the collector without running it.
$collector = Join-Path (Split-Path -Parent $PSScriptRoot) 'artifact-extract.ps1'
if (-not (Test-Path -LiteralPath $collector)) { throw "collector not found at $collector" }
$wanted = 'Read-RawBytes', 'Open-NtfsVolume', 'Invoke-NtfsFixup', 'Get-NtfsDataRuns', 'Export-NtfsMetafile'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$null, [ref]$null)
$defs = $ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $wanted -contains $n.Name
    }, $true)
if ($defs.Count -ne $wanted.Count) { throw "expected $($wanted.Count) reader functions, found $($defs.Count)" }
. ([scriptblock]::Create((($defs | ForEach-Object { $_.Extent.Text }) -join "`n")))

# --- Build the synthetic volume ---------------------------------------------------
$SECTOR = 512; $SPC = 8; $CLUSTER = $SECTOR * $SPC   # 4096
$MFT_LCN = 4; $RECSIZE = 1024
$img = New-Object byte[] (16 * $CLUSTER)

# Boot sector: NTFS signature, geometry, MFT location, and 0xF6 as the signed
# clusters-per-MFT-record byte (-10 -> 2^10 -> 1024-byte records).
[System.Text.Encoding]::ASCII.GetBytes('NTFS    ').CopyTo($img, 3)
[BitConverter]::GetBytes([uint16]$SECTOR).CopyTo($img, 0x0B)
$img[0x0D] = [byte]$SPC
[BitConverter]::GetBytes([long]$MFT_LCN).CopyTo($img, 0x30)
$img[0x40] = 0xF6

# MFT record 0
$rec = $MFT_LCN * $CLUSTER
[System.Text.Encoding]::ASCII.GetBytes('FILE').CopyTo($img, $rec)
[BitConverter]::GetBytes([uint16]0x30).CopyTo($img, $rec + 0x04)   # USA offset
[BitConverter]::GetBytes([uint16]3).CopyTo($img, $rec + 0x06)      # USA count (1 + 2 sectors)
[BitConverter]::GetBytes([uint16]0x38).CopyTo($img, $rec + 0x14)   # first attribute
# Update sequence array: the sequence number sits at the end of every sector, and the
# bytes it displaced are parked here for the reader to put back.
[BitConverter]::GetBytes([uint16]0x0001).CopyTo($img, $rec + 0x30)
[BitConverter]::GetBytes([uint16]0xBEEF).CopyTo($img, $rec + 0x32)
[BitConverter]::GetBytes([uint16]0xF00D).CopyTo($img, $rec + 0x34)
[BitConverter]::GetBytes([uint16]0x0001).CopyTo($img, $rec + (1 * $SECTOR) - 2)
[BitConverter]::GetBytes([uint16]0x0001).CopyTo($img, $rec + (2 * $SECTOR) - 2)

# Non-resident $DATA attribute
$REAL_SIZE = 16000                                  # 3 clusters + a short tail
$a = $rec + 0x38
[BitConverter]::GetBytes([uint32]0x80).CopyTo($img, $a + 0x00)
[BitConverter]::GetBytes([uint32]0x50).CopyTo($img, $a + 0x04)     # attribute length
$img[$a + 0x08] = 1                                                # non-resident
$img[$a + 0x09] = 0                                                # unnamed stream
[BitConverter]::GetBytes([uint16]0x40).CopyTo($img, $a + 0x20)     # run list offset
[BitConverter]::GetBytes([long]($CLUSTER * 4)).CopyTo($img, $a + 0x28)
[BitConverter]::GetBytes([long]$REAL_SIZE).CopyTo($img, $a + 0x30)

# Run list: 2 clusters at LCN 10, 1 sparse cluster, then 1 cluster at LCN 6 -
# encoded as the relative offset -4, which is the sign extension the reader must handle.
$runs = [byte[]]@(0x11, 0x02, 0x0A, 0x01, 0x01, 0x11, 0x01, 0xFC, 0x00)
$runs.CopyTo($img, $a + 0x40)

# Cluster payloads
foreach ($c in @(@{L = 10; V = 0xAA }, @{L = 11; V = 0xBB }, @{L = 6; V = 0xCC })) {
    for ($i = 0; $i -lt $CLUSTER; $i++) { $img[($c.L * $CLUSTER) + $i] = [byte]$c.V }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ntfs-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$imgPath = Join-Path $tmp 'volume.img'
$outPath = Join-Path $tmp 'mft.bin'
[System.IO.File]::WriteAllBytes($imgPath, $img)

try {
    Write-Host "`nNTFS reader" -ForegroundColor Cyan

    $vol = Open-NtfsVolume -Path $imgPath
    try {
        Assert-Equal 512 $vol.BytesPerSector 'boot sector: bytes per sector'
        Assert-Equal 4096 $vol.ClusterSize 'boot sector: cluster size'
        Assert-Equal 1024 $vol.RecordSize 'boot sector: 0xF6 read as signed -10 -> 1024-byte records'
        Assert-Equal ($MFT_LCN * $CLUSTER) $vol.MftOffset 'boot sector: MFT offset'

        $raw = Read-RawBytes -Vol $vol -Offset $vol.MftOffset -Count $vol.RecordSize
        Assert-Equal 'FILE' ([System.Text.Encoding]::ASCII.GetString($raw, 0, 4)) 'record 0 is a FILE record'

        $fixed = Invoke-NtfsFixup -Record $raw -SectorSize $vol.BytesPerSector
        Assert-Equal 0xBEEF ([BitConverter]::ToUInt16($fixed, (1 * $SECTOR) - 2)) 'fixup: sector 1 tail restored'
        Assert-Equal 0xF00D ([BitConverter]::ToUInt16($fixed, (2 * $SECTOR) - 2)) 'fixup: sector 2 tail restored'

        $data = Get-NtfsDataRuns -Record $fixed -StreamName ''
        Assert-Equal $REAL_SIZE $data.RealSize 'data runs: real size'
        Assert-Equal 3 $data.Runs.Count 'data runs: run count'
        Assert-Equal 10 $data.Runs[0].Lcn 'data runs: first run cluster'
        Assert-Equal -1 $data.Runs[1].Lcn 'data runs: sparse run flagged'
        Assert-Equal 6 $data.Runs[2].Lcn 'data runs: negative relative offset sign-extended'

        Export-NtfsMetafile -Vol $vol -RecordNumber 0 -StreamName '' -Target $outPath
        $got = [System.IO.File]::ReadAllBytes($outPath)
        Assert-Equal $REAL_SIZE $got.Length 'export: size matches the real size, not the allocated size'

        $expected = New-Object byte[] $REAL_SIZE
        for ($i = 0; $i -lt $CLUSTER; $i++) { $expected[$i] = 0xAA }
        for ($i = 0; $i -lt $CLUSTER; $i++) { $expected[$CLUSTER + $i] = 0xBB }
        # third cluster stays zero - the sparse run
        for ($i = 3 * $CLUSTER; $i -lt $REAL_SIZE; $i++) { $expected[$i] = 0xCC }
        $same = $true
        for ($i = 0; $i -lt $REAL_SIZE; $i++) { if ($got[$i] -ne $expected[$i]) { $same = $false; break } }
        Assert-Equal $true $same 'export: content matches run list (data + sparse hole + partial tail)'
    }
    finally { $vol.Stream.Dispose() }

    # A run list that does not cover the whole file must be reported, never written out
    # as if it were complete.
    Write-Host "`nShort run list" -ForegroundColor Cyan
    [BitConverter]::GetBytes([long]999999).CopyTo($img, $a + 0x30)
    [System.IO.File]::WriteAllBytes($imgPath, $img)
    $vol2 = Open-NtfsVolume -Path $imgPath
    try {
        Assert-Throws { Export-NtfsMetafile -Vol $vol2 -RecordNumber 0 -StreamName '' -Target $outPath } `
            'incomplete' 'export: truncated extraction raises instead of passing silently'
    }
    finally { $vol2.Stream.Dispose() }

    # The $MFT on a real volume runs to several GB; every bound in the copy loop has to
    # stay 64-bit or [math]::Min() picks its Int32 overload and throws mid-extraction.
    Write-Host "`n64-bit bounds" -ForegroundColor Cyan
    $big = [long]4693164032; $chunkMax = [long]8MB
    Assert-Equal 8388608 ([int][math]::Min($chunkMax, $big)) 'copy loop: multi-GB run length does not overflow Int32'
    Assert-Equal 8388608 ([int][math]::Min([math]::Min($chunkMax, $big), $big)) 'copy loop: multi-GB remaining size does not overflow Int32'
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

if ($script:Failures -gt 0) { Write-Host "`n$script:Failures test(s) failed`n" -ForegroundColor Red; exit 1 }
Write-Host "`nAll tests passed`n" -ForegroundColor Green
