<#
    Stores the guest account for one VM so Invoke-VmValidation.ps1 can log into it.

    The password is protected with DPAPI: the file it writes can only be decrypted by
    the account that ran this script, on this machine. Run it interactively - the
    password is read without echo and is never passed as an argument, so it does not
    reach a command line, a history file, or a transcript.

        .\tests\Set-VmCredential.ps1 -Vmx 'E:\VM\Lab\Lab.vmx'

    Use an account that is a local administrator inside the guest; without that the
    privileged collection paths cannot be tested. Never store a real production or
    domain credential here - these are lab guests.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Vmx,
    [string]$StoreDir = (Join-Path $env:USERPROFILE '.artifact-extract-vm')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Vmx)) { throw "VM not found: $Vmx" }
$vmName = [System.IO.Path]::GetFileNameWithoutExtension($Vmx)

if (-not (Test-Path -LiteralPath $StoreDir)) {
    New-Item -ItemType Directory -Path $StoreDir -Force | Out-Null
}

Write-Host "`nGuest account for '$vmName'" -ForegroundColor Cyan
$user = Read-Host '  guest user (e.g. Administrator, or DOMAIN\user)'
if (-not $user) { throw 'no user given' }
$pass = Read-Host '  guest password' -AsSecureString
if ($pass.Length -eq 0) { throw 'no password given' }

$target = Join-Path $StoreDir "$vmName.cred"
Set-Content -LiteralPath $target -Encoding UTF8 -Value @($user, (ConvertFrom-SecureString $pass))

Write-Host "`nStored $target" -ForegroundColor Green
Write-Host "  user      $user"
Write-Host "  password  protected with DPAPI (only your account on this machine can read it)"
Write-Host "`nNext:  .\tests\Invoke-VmValidation.ps1 -Vmx '$Vmx' -Mode probe`n"
