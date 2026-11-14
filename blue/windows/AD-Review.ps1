# Domain inventory; read-only. Requires the ActiveDirectory module and directory access.
[CmdletBinding()]
param([string]$Server)
. "$PSScriptRoot\Common.ps1"
Assert-Windows
Import-Module ActiveDirectory -ErrorAction Stop
$params = @{}
if ($Server) { $params.Server = $Server }
$domain = Get-ADDomain @params
$privilegedSids = @('S-1-5-32-544', "$($domain.DomainSID)-512", "$($domain.DomainSID)-520")
$forest = Get-ADForest @params
$forestRoot = Get-ADDomain -Identity $forest.RootDomain @params
$privilegedSids += "$($forestRoot.DomainSID)-518", "$($forestRoot.DomainSID)-519"
$report = [ordered]@{
    HostName = $env:COMPUTERNAME
    UTC = [DateTime]::UtcNow.ToString('o')
    Domain = $domain | Select-Object DNSRoot, NetBIOSName, DomainSID, PDCEmulator
    PasswordPolicy = Read-Section { Get-ADDefaultDomainPasswordPolicy @params | Select-Object MinPasswordLength, ComplexityEnabled, LockoutThreshold, MaxPasswordAge }
    Users = Read-Section {
        Get-ADUser -Filter * -Properties Enabled, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, ServicePrincipalName, AdminCount, TrustedForDelegation @params |
            Select-Object SamAccountName, SID, Enabled, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, ServicePrincipalName, AdminCount, TrustedForDelegation
    }
    PrivilegedGroups = @($privilegedSids | ForEach-Object {
        $sid = $_
        [pscustomobject]@{ SID = $sid; DirectMembers = Read-Section { Get-ADGroupMember -Identity $sid @params | Select-Object Name, SamAccountName, SID, ObjectClass }; EffectiveMembers = Read-Section { Get-ADGroupMember -Identity $sid -Recursive @params | Select-Object Name, SamAccountName, SID, ObjectClass } }
    })
    Computers = Read-Section { Get-ADComputer -Filter * -Properties Enabled, OperatingSystem, TrustedForDelegation @params | Select-Object Name, Enabled, OperatingSystem, TrustedForDelegation }
    Services = Read-Section { Get-Service NTDS,DNS,Netlogon,Kdc,ADWS,DFSR | Select-Object Name, Status, StartType }
    ServiceIdentities = Read-Section { Get-CimInstance Win32_Service | Select-Object Name, StartName, State }
    TaskIdentities = Read-Section { Get-ScheduledTask | Select-Object TaskName, TaskPath, Principal }
    Note = 'Packet account lists describe human access; do not bulk remove built-in, computer, or service identities. AdminCount alone does not establish current membership. Resolve Administrator/crazydave ambiguity with Green Team.'
}
$report | ConvertTo-Json -Depth 10
