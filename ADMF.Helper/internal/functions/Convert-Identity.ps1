function Convert-Identity {
    <#
    .SYNOPSIS
        Converts a given identity name to its corresponding Security Identifier (SID).

    .DESCRIPTION
        The Convert-Identity function takes a name of a built-in user or group and converts it to its corresponding SID.
        If the name is not a built-in name, it attempts to convert it to a SID using .NET classes.
        If the conversion fails, it returns the original name.

    .PARAMETER Name
        The name of the built-in user or group to convert to a SID.

    .PARAMETER BuiltInNamesOnly
        A switch that, when present, causes the function to only convert names that correspond to built-in users or groups.

    .EXAMPLE
        Convert-Identity -Name "BUILTIN\Administrators"
        Returns the SID for the built-in Administrators group: S-1-5-32-544

    .INPUTS
        System.String

    .OUTPUTS
        System.String

    .NOTES
        The function uses a hashtable to map built-in names to their corresponding SIDs.
        For non-built-in names, it uses the System.Security.Principal.NTAccount and System.Security.Principal.SecurityIdentifier .NET classes to perform the conversion.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]
        $Name,

        [switch]
        $BuiltInNamesOnly
    )

    begin {
        $builtIn = @{
            'BUILTIN\Administrators'                      = 'S-1-5-32-544'
            'BUILTIN\Users'                               = 'S-1-5-32-545'
            'BUILTIN\Guests'                              = 'S-1-5-32-546'
            'BUILTIN\Account Operators'                   = 'S-1-5-32-548'
            'BUILTIN\Server Operators'                    = 'S-1-5-32-549'
            'BUILTIN\Print Operators'                     = 'S-1-5-32-550'
            'BUILTIN\Backup Operators'                    = 'S-1-5-32-551'
            'BUILTIN\Replicator'                          = 'S-1-5-32-552'
            'BUILTIN\Pre-Windows 2000 Compatible Access'  = 'S-1-5-32-554'
            'BUILTIN\Remote Desktop Users'                = 'S-1-5-32-555'
            'BUILTIN\Network Configuration Operators'     = 'S-1-5-32-556'
            'BUILTIN\Incoming Forest Trust Builders'      = 'S-1-5-32-557'
            'BUILTIN\Performance Monitor Users'           = 'S-1-5-32-558'
            'BUILTIN\Performance Log Users'               = 'S-1-5-32-559'
            'BUILTIN\Windows Authorization Access Group'  = 'S-1-5-32-560'
            'BUILTIN\Terminal Server License Servers'     = 'S-1-5-32-561'
            'BUILTIN\Distributed COM Users'               = 'S-1-5-32-562'
            'BUILTIN\IIS_IUSRS'                           = 'S-1-5-32-568'
            'BUILTIN\Cryptographic Operators'             = 'S-1-5-32-569'
            'BUILTIN\Event Log Readers'                   = 'S-1-5-32-573'
            'BUILTIN\Certificate Service DCOM Access'     = 'S-1-5-32-574'
            'BUILTIN\RDS Remote Access Servers'           = 'S-1-5-32-575'
            'BUILTIN\RDS Endpoint Servers'                = 'S-1-5-32-576'
            'BUILTIN\RDS Management Servers'              = 'S-1-5-32-577'
            'BUILTIN\Hyper-V Administrators'              = 'S-1-5-32-578'
            'BUILTIN\Access Control Assistance Operators' = 'S-1-5-32-579'
            'BUILTIN\Remote Management Users'             = 'S-1-5-32-580'
            'BUILTIN\Storage Replica Administrators'      = 'S-1-5-32-582'
        }
    }

    process {
        Write-PSFMessage -Level System -Message "Converting identity '$($Name)'"
        if ($builtIn[$Name]) { return $builtIn[$Name] }

        $sid = $Name -as [System.Security.Principal.SecurityIdentifier]
        if (-not $sid) {
            try {
                $sid = ([System.Security.Principal.NTAccount]$Name).Translate([System.Security.Principal.SecurityIdentifier])
            } catch {
                return $Name
            }
        }

        # Case: Builtin SID
        if (-not $sid.AccountDomainSid) { return $sid -as [string] }

        [int]$rid = ($sid.Value -split '-')[-1]
        if (($rid -le 1000) -and $BuiltInNamesOnly) { return "%DomainSID%-$rid" }
        if ($rid -gt 1000 -and (-not $BuiltInNamesOnly)) { return "%DomainSID%-$rid" }

        $Name
    }
}