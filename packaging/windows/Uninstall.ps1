#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$Service = Get-Service MIPAM -ErrorAction SilentlyContinue
if ($Service) {
    if ($Service.Status -ne 'Stopped') { Stop-Service MIPAM }
    & sc.exe delete MIPAM | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove MIPAM service.' }
}
Write-Host 'Service removed. Binaries, configuration, backup key and all data were retained.'
