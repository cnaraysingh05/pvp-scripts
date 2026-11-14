# Native authenticated Windows checks. No network access without -Run.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('LDAP','SMB')][string]$Kind,
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$Scope,
    [string]$BaseDN,
    [string]$Share,
    [string]$ExpectedEntry,
    [ValidateRange(1,65535)][int]$Port = 389,
    [switch]$Run
)
. "$PSScriptRoot\..\blue\windows\Common.ps1"
Assert-Windows
$config = Get-Content -LiteralPath $Scope -Raw | ConvertFrom-Json
$address = $null
if ($Server -match 'XX' -or -not [Net.IPAddress]::TryParse($Server, [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'Supply a confirmed IPv4 address.' }
if ($config.confirmed -ne $true -or $Server -notin $config.own_targets -or $Server -in $config.opponent_targets) { throw 'Server is not in confirmed own scope.' }
if ($Kind -eq 'LDAP' -and (-not $BaseDN -or $BaseDN -match 'XX')) { throw 'Supply the confirmed BaseDN.' }
if ($Kind -eq 'SMB' -and ($Share -notmatch '^[A-Za-z0-9_$ .-]+$' -or -not $ExpectedEntry -or $Share -match 'XX' -or $ExpectedEntry -match 'XX')) { throw 'Supply the share and an exact expected entry name.' }
if (-not $Run) { Write-Host "PREVIEW: authenticated $Kind check against $Server"; return }
$credential = Get-Credential -Message "Scored $Kind account (password is not logged)"
if ($null -eq $credential) { throw 'Credentials canceled.' }
if ($Kind -eq 'LDAP') {
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($Server, $Port)
    $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier, $credential.GetNetworkCredential(), [System.DirectoryServices.Protocols.AuthType]::Negotiate)
    try {
        $connection.Timeout = [TimeSpan]::FromSeconds(10)
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.SessionOptions.Signing = $true
        $connection.SessionOptions.Sealing = $true
        $connection.Bind()
        $request = [System.DirectoryServices.Protocols.SearchRequest]::new($BaseDN, '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, [string[]]@('distinguishedName'))
        $response = $connection.SendRequest($request)
        if ($response.Entries.Count -ne 1) { throw 'Expected one directory base entry.' }
        Write-Host 'PASS: authenticated LDAP bind and base query.'
    } finally { $connection.Dispose() }
} else {
    $drive = 'PVP' + [Guid]::NewGuid().ToString('N').Substring(0,8)
    $mounted = $false
    try {
        New-PSDrive -Name $drive -PSProvider FileSystem -Root "\\$Server\$Share" -Credential $credential -ErrorAction Stop | Out-Null
        $mounted = $true
        $entries = @(Get-ChildItem -LiteralPath ($drive + ':\') -ErrorAction Stop)
        if (@($entries | Where-Object Name -CEQ $ExpectedEntry).Count -eq 0) { throw 'Expected share entry not found.' }
        Write-Host 'PASS: authenticated SMB share listing and expected entry.'
    } finally { if ($mounted) { Remove-PSDrive -Name $drive -Force } }
}
Write-Host 'Compare this result with the scoring engine. A native-client pass does not reproduce every scoring check.'
