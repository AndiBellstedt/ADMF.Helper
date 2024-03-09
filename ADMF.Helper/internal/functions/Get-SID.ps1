function Get-SID {
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