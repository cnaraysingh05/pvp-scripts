# Read-only share permissions and filesystem ACL inventory.
[CmdletBinding()]
param()
. "$PSScriptRoot\Common.ps1"
Assert-Windows
$report = [ordered]@{
    HostName = $env:COMPUTERNAME
    UTC = [DateTime]::UtcNow.ToString('o')
    Configuration = Read-Section { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EncryptData, RejectUnencryptedAccess }
    Shares = @(Get-SmbShare | ForEach-Object {
        $share = $_
        [pscustomobject]@{
            Name = $share.Name; Path = $share.Path; Special = $share.Special
            ShareAccess = Read-Section { Get-SmbShareAccess -Name $share.Name | Select-Object AccountName, AccessControlType, AccessRight }
            FileSystemAccess = Read-Section {
                if ($share.Path) { Get-Acl -LiteralPath $share.Path | Select-Object Owner, Sddl, AccessToString }
            }
        }
    })
    Sessions = Read-Section { Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, Dialect }
    ServiceAccounts = Read-Section { Get-CimInstance Win32_Service | Select-Object Name, StartName, State }
    TaskAccounts = Read-Section { Get-ScheduledTask | Select-Object TaskName, TaskPath, Principal }
    Note = 'Effective access combines share and NTFS permissions. Preserve the scored share and authorized users. Do not delete flags during sensitive-file cleanup.'
}
$report | ConvertTo-Json -Depth 10
