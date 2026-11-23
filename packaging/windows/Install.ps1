#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\MIPAM",
    [string]$DataDir = "$env:ProgramData\MIPAM"
)
$ErrorActionPreference = 'Stop'
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$DataDir = [IO.Path]::GetFullPath($DataDir)
$Binary = Join-Path $InstallDir 'mipam.exe'
$Config = Join-Path $DataDir 'mipam.json'
if ((Get-Service MIPAM -ErrorAction SilentlyContinue) -or (Test-Path $Binary) -or (Test-Path $Config)) {
    throw 'Existing installation detected. Follow the backup/upgrade procedure; the installer does not overwrite data.'
}
if (-not (Test-Path (Join-Path $PSScriptRoot 'mipam.exe'))) { throw 'Extract the complete release archive first.' }
New-Item -ItemType Directory -Force $InstallDir, $DataDir | Out-Null
# SIDs avoid locale-dependent account names. No ordinary-user access to state.
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot secure configuration directory.' }
$State = Join-Path $DataDir 'data'
New-Item -ItemType Directory -Force $State | Out-Null
& icacls.exe $State /grant:r '*S-1-5-19:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot grant service access to state.' }
Copy-Item (Join-Path $PSScriptRoot 'mipam.exe') $Binary
@{
    listen = '127.0.0.1:8080'; public_url = 'http://127.0.0.1:8080'
    database = (Join-Path $State 'mipam.db')
    log_file = (Join-Path $State 'mipam.log')
    backup_dir = (Join-Path $State 'backups')
    backup_key_file = (Join-Path $State 'backup.key')
    backup_hours = 24; backup_keep = 14
} | ConvertTo-Json | ForEach-Object { [IO.File]::WriteAllText($Config, $_, (New-Object Text.UTF8Encoding $false)) }
& $Binary -config $Config bootstrap
if ($LASTEXITCODE -ne 0) { throw 'Bootstrap failed. Service was not installed.' }
& $Binary -config $Config service-install
if ($LASTEXITCODE -ne 0) { throw 'Service registration failed.' }
# Register stopped; never run the web service as LocalSystem.
& sc.exe config MIPAM obj= 'NT AUTHORITY\LocalService' start= demand | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service identity configuration failed. Do not start it.' }
Write-Host "Installed but not started. Review $Config and preserve the backup key separately."
Write-Host 'After review: Set-Service MIPAM -StartupType Automatic; Start-Service MIPAM'
Write-Host 'Loopback URL: http://127.0.0.1:8080. Configure TLS before remote access.'
