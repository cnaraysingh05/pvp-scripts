# Join effective rule filters so broad allows and conflicting blocks can be reviewed.
[CmdletBinding()]
param()
. "$PSScriptRoot\Common.ps1"
Assert-Windows
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound | ForEach-Object {
    $rule = $_
    [pscustomobject]@{
        Name = $rule.Name; DisplayName = $rule.DisplayName; Action = [string]$rule.Action
        Profile = [string]$rule.Profile; PolicySource = $rule.PolicyStoreSource
        Ports = Read-Section { $rule | Get-NetFirewallPortFilter | Select-Object Protocol, LocalPort, RemotePort }
        Addresses = Read-Section { $rule | Get-NetFirewallAddressFilter | Select-Object LocalAddress, RemoteAddress }
        Application = Read-Section { $rule | Get-NetFirewallApplicationFilter | Select-Object Program, Package }
        Service = Read-Section { $rule | Get-NetFirewallServiceFilter | Select-Object Service }
    }
})
[ordered]@{
    HostName = $env:COMPUTERNAME; UTC = [DateTime]::UtcNow.ToString('o')
    Profiles = Read-Section { Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules }
    InboundRules = $rules
    Note = 'Review filters together. An Any-address allow is not necessarily unrestricted if its application/service filters constrain it. Existing block rules can override allows.'
} | ConvertTo-Json -Depth 10
