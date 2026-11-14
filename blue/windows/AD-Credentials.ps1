# Rotate one explicitly selected domain user. Default is preview; never changes membership.
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory)][string]$Identity,
    [string]$Server,
    [switch]$Apply,
    [switch]$DependenciesReviewed,
    [ValidateSet('unknown','not-scored','coordinated')][string]$ScoringStatus = 'unknown'
)
. "$PSScriptRoot\Common.ps1"
Assert-Windows
Import-Module ActiveDirectory -ErrorAction Stop
if ($Identity -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Use an exact sAMAccountName.' }
$params = @{}
if ($Server) { $params.Server = $Server }
$account = Get-ADUser -Identity $Identity -Properties ServicePrincipalName, PasswordLastSet, Enabled @params
if ($account.SamAccountName -ine $Identity) { throw 'Identity must match the selected sAMAccountName.' }
if ($account.SID.Value -match '-(500|502)$') { throw 'Built-in Administrator/krbtgt are excluded from this utility. Resolve account policy separately.' }
if (@($account.ServicePrincipalName | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) { throw 'Account has SPNs; use a service-specific credential maintenance procedure.' }
$account | Select-Object SamAccountName, SID, Enabled, PasswordLastSet | Format-List | Out-Host
if (-not $Apply) { Write-Host 'PREVIEW: no credential change.'; return }
if (-not $DependenciesReviewed -or $ScoringStatus -eq 'unknown') { throw 'Review service/task dependencies and declare scoring status before applying.' }
if (-not $PSCmdlet.ShouldProcess($account.DistinguishedName, 'Reset one domain password')) { return }
if ((Read-Host 'Type the exact account name') -cne $account.SamAccountName) { throw 'Confirmation mismatch.' }
$password = $null
try {
    $password = Read-Host 'New password' -AsSecureString
    if ($password.Length -eq 0) { throw 'Empty password.' }
    Set-ADAccountPassword -Identity $account.DistinguishedName -Reset -NewPassword $password @params
    Write-Host 'Password changed. Complete the coordinated scoring PCR and test a NEW login/bind. Existing sessions may remain valid.'
} finally { if ($null -ne $password) { $password.Dispose() } }
