function Test-AceEquality {
    <#
    .SYNOPSIS
        Compares two access rules with each other.

    .DESCRIPTION
        Compares two access rules with each other.

    .PARAMETER Rule1
        The first rule to compare

    .PARAMETER Rule2
        The second rule to compare

    .EXAMPLE
        PS C:\> Test-AccessRuleEquality -Rule1 $rule -Rule2 $rule2

        Compares $rule with $rule2
    #>
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param (
        $Rule1,

        $Rule2
    )

    $propertyNames = "ActiveDirectoryRights", "InheritanceType", "ObjectType", "InheritedObjectType", "ObjectFlags", "AccessControlType", "IsInherited", "InheritanceFlags", "PropagationFlags"
    foreach ($propName in $propertyNames) {
        if ($Rule1.$propName -ne $Rule2.$propName) { return $false }
    }

    if ("$(Get-SID -Rule $Rule1)" -ne "$(Get-SID -Rule $Rule2)") { return $false }

    return $true
}