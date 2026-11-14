# Copy selected regular configuration files into a private directory; no live database copies.
[CmdletBinding()]
param([Parameter(Mandatory)][string[]]$Path)
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$selected = @($Path | ForEach-Object {
    $item = Get-Item -LiteralPath $_ -Force
    if ($item.PSIsContainer -or $item.Extension -notin @('.config','.conf','.ini','.json','.xml') -or $item.Length -gt 10MB) { throw 'Select regular config files (.config/.conf/.ini/.json/.xml), at most 10 MiB each.' }
    $cursor = $item
    while ($null -ne $cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are excluded.' }
        if ($cursor -is [IO.FileInfo]) { $cursor = $cursor.Directory } else { $cursor = $cursor.Parent }
    }
    $item
})
$directory = Join-Path $env:ProgramData ('PvPBackup-' + [Guid]::NewGuid().ToString('N'))
New-Item -Path $directory -ItemType Directory | Out-Null
& icacls.exe $directory /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Backup directory ACL failed; no files copied.' }
$records = @()
$index = 0
foreach ($item in $selected) {
    $blob = ('{0:D5}.bin' -f $index)
    Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $directory $blob)
    $records += [pscustomobject]@{ Path=$item.FullName; Blob=$blob; SHA256=(Get-FileHash -LiteralPath (Join-Path $directory $blob)).Hash; Sddl=(Get-Acl -LiteralPath $item.FullName).Sddl }
    $index++
}
[pscustomobject]@{ HostName=$env:COMPUTERNAME; UTC=[DateTime]::UtcNow.ToString('o'); Files=$records; Note='Manual per-file recovery only. Preserve the current file before replacement, restore ACLs from SDDL if required, and validate the service before reload. This is not AD system-state or database backup.' } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $directory 'manifest.json') -Encoding UTF8
Write-Host "Backup: $directory"
