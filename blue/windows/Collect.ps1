# Save JSON reports in a private directory; no security-setting modifications.
[CmdletBinding()]
param()
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell 5.1.' }
$directory = Join-Path $env:ProgramData ('PvPReports-' + [Guid]::NewGuid().ToString('N'))
New-Item -Path $directory -ItemType Directory | Out-Null
& icacls.exe $directory /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Private report ACL failed.' }
$names = @('Recon','Review','Persistence','SMB-Review','Firewall-Audit')
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { $names += 'AD-Review' }
$summary = @()
foreach ($name in $names) {
    try {
        $text = & "$PSScriptRoot\$name.ps1" | Out-String
        $null = $text | ConvertFrom-Json
        $text | Set-Content -LiteralPath (Join-Path $directory ($name + '.json')) -Encoding UTF8
        $summary += [pscustomobject]@{ Report=$name; Collected=$true }
    } catch { $summary += [pscustomobject]@{ Report=$name; Collected=$false; Error=$_.Exception.Message } }
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $directory 'collection.json') -Encoding UTF8
Write-Host "Reports: $directory"
Write-Host 'Inspect section errors and findings; collected does not mean clean.'
if (@($summary | Where-Object Collected -EQ $false).Count -gt 0) { throw 'Some reports failed. Review collection.json.' }
