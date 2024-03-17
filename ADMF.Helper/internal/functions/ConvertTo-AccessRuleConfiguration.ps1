function ConvertTo-AccessRuleConfiguration {
    <#
    .SYNOPSIS
        Tool to convert Access Rule test results into configuration sets.

    .DESCRIPTION
        Tool to convert Access Rule test results into configuration sets.

    .PARAMETER Path
        Replace the path the results should apply to.
        By default, paths should be auto-detected.

    .PARAMETER ObjectCategory
        Name of the object category that the result should be applied to.
        By default, rules are applied to paths of the origin.

    .PARAMETER InputObject
        The test result to convert.

    .PARAMETER Clip
        Converts results to json and pastes them to clipboard.

    .EXAMPLE
        PS C:\> $res | ConvertTo-AccessRuleConfiguration

        Converts the input test result to configuration rules

    .EXAMPLE
        PS C:\> $res | carc -ObjectCategory trustuser -Clip

        Converts the input test result to configuration rules that apply to the object category "trustuser".
        Then it converts the results to json and pastes it to the clipboard
    #>
    [Alias('carc')]
    [CmdletBinding()]
    param (
        [string]
        $Path,

        [string]
        $ObjectCategory,

        [Parameter(ValueFromPipeline = $true)]
        $InputObject,

        [switch]
        $Clip
    )

    begin {
        $list = [System.Collections.ArrayList]@()
    }

    process {
        $data = $InputObject
        if ($InputObject.Changed) { $data = $InputObject.Changed }

        foreach ($datum in $data) {
            $source = $datum.ADObject

            if ($datum.Configuration) { $source = $datum.Configuration }

            $hash = @{
                Identity              = $source.IdentityReference | Convert-Identity
                ActiveDirectoryRights = $source.ActiveDirectoryRights -as [string]
                InheritanceType       = $source.InheritanceType -as [string]
                AccessControlType     = $source.AccessControlType -as [string]
                ObjectType            = $source.ObjectType -as [string]
                InheritedObjectType   = $source.InheritedObjectType -as [string]
            }

            if ($Path) {
                $hash.Path = $Path
            } elseif ($ObjectCategory) {
                $hash.ObjectCategory = $ObjectCategory
            } else {
                if ($InputObject.Identity) {
                    $hash.Path = $InputObject.Identity | Set-String -OldValue 'DC=.+' -NewValue '%DomainDN%'
                } elseif ($datum.DistinguishedName) {
                    $hash.Path = $datum.DistinguishedName | Set-String -OldValue 'DC=.+' -NewValue '%DomainDN%'
                } else {
                    $hash.Path = "INSERT_HERE"
                }
            }

            switch ($datum.Type) {
                'Restore' { $hash.Present = $false }
            }

            if ($Clip) {
                $null = $list.Add([PSCustomObject]$hash)
            } else {
                [PSCustomObject]$hash
            }
        }
    }

    end {
        if ($Clip) {
            $list | ConvertTo-Json | Set-Clipboard
        }
    }
}