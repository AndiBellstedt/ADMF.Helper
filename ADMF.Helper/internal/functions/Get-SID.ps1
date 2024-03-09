function Get-SID {
    <#
    .SYNOPSIS
        Retrieves the Security Identifier (SID) from a given rule object.

    .DESCRIPTION
        The Get-SID function checks if the rule object has a SID property and returns it if present.
        If the SID property is not present, it checks if the IdentityReference property is a SID and returns it if true.
        If neither of these conditions are met, it assumes the IdentityReference is a NTAccount and attempts to translate it to a SID.

    .PARAMETER Rule
        The rule object from which to retrieve the SID.

    .EXAMPLE
        $rule = New-Object PSObject -Property @{
            SID = "S-1-5-32-544"
            IdentityReference = "BUILTIN\Administrators"
        }
        Get-SID -Rule $rule
        Returns the SID: S-1-5-32-544

    .INPUTS
        System.Object

    .OUTPUTS
        System.String

    .NOTES
        The function uses the System.Security.Principal.SecurityIdentifier .NET class to check if the IdentityReference is a SID and to translate the IdentityReference to a SID if it's a NTAccount.
    #>
    [CmdletBinding()]
    param (
        $Rule
    )

    # SID is in the object
    if ($Rule.SID) { return $Rule.SID }

    # IdentityReference is a SID
    if ($Rule.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) { return $Rule.IdentityReference }

    # IdentityReference is a NTAccount
    $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
}