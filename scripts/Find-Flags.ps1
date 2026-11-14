<#
.SYNOPSIS
    scripts/Find-Flags.ps1

    Read-only filesystem sweep for likely flag files on a Windows host you
    already have a session on (thehouse, sunflower, or during the grace
    period, your own box). Mirrors scripts/flag_finder.sh for Linux hosts.

    Does not modify, move, or delete anything it finds. Per the briefing
    packet, never alter a flag or its location once found.

    Submission value: if the file already contains a bare 64-hex value,
    submit that value as-is. Only when it contains something else is a hash
    of the file shown as a fallback.

.PARAMETER Quick
    Skip the slower full-C:-drive sweep and only check documented +
    common locations.

.EXAMPLE
    .\Find-Flags.ps1
    .\Find-Flags.ps1 -Quick
#>

param(
    [switch]$Quick
)

function Get-FlagValue {
    param([string]$Path)
    $raw = $null
    try { $raw = [string](Get-Content -LiteralPath $Path -Raw -ErrorAction Stop) } catch { return }
    $raw = ($raw -replace '\s', '')
    if ($raw -match '^[0-9a-fA-F]{64}$') {
        Write-Host ("        submit: {0}" -f $raw)
    } elseif ($raw.Length -gt 0 -and $raw.Length -le 512) {
        Write-Host ("        content: {0}" -f $raw)
    }
}

Write-Host "=== Documented flag locations ===" -ForegroundColor Cyan
$documented = @("C:\Windows\flag.txt")
foreach ($path in $documented) {
    if (Test-Path $path) {
        Write-Host "[FOUND] $path"
        Get-FlagValue -Path $path
        $hash = Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($hash) { Write-Host ("        sha256(file): {0}" -f $hash.Hash) }
    }
}

Write-Host "`n=== Common 'hidden' locations worth checking manually ===" -ForegroundColor Cyan
$candidateDirs = @(
    "C:\Users",
    "C:\inetpub",
    "C:\ProgramData",
    "C:\Temp",
    "C:\Windows\Temp",
    "C:\Shares",
    "C:\Backups"
)
foreach ($dir in $candidateDirs) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Recurse -Depth 4 -Filter "*flag*" -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Host "[CANDIDATE] $($_.FullName)"
                if ($_.Length -le 65536) { Get-FlagValue -Path $_.FullName }
            }
    }
}

if (-not $Quick) {
    Write-Host "`n=== Full C:\ sweep for anything flag-named (slower) ===" -ForegroundColor Cyan
    Get-ChildItem -Path "C:\" -Recurse -Filter "*flag*" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\Windows\\(WinSxS|System32\\DriverStore)\\' } |
        ForEach-Object {
            Write-Host "[CANDIDATE] $($_.FullName)"
            if ($_.Length -le 65536) { Get-FlagValue -Path $_.FullName }
        }
} else {
    Write-Host "`n(Full sweep skipped - rerun without -Quick for a complete pass)" -ForegroundColor Yellow
}

Write-Host "`n=== Recently modified files outside normal install locations ===" -ForegroundColor Cyan
$recentCutoff = (Get-Date).AddDays(-30)
foreach ($dir in @("C:\Users", "C:\inetpub", "C:\ProgramData", "C:\Shares")) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $recentCutoff } |
            Select-Object FullName, LastWriteTime |
            Select-Object -First 50
    }
}

Write-Host "`nDone. This list is read-only - confirm each hit manually before submitting." -ForegroundColor Green
Write-Host "Remember: do not move, rename, or edit any flag file you find." -ForegroundColor Green
