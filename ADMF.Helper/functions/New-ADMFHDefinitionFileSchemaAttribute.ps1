function New-ADMFHDefinitionFileSchemaAttribute {
    <#
    .SYNOPSIS
        Generates a definition file for schema attributes to process with Active Directory Management Framework (ADMF).

    .DESCRIPTION
        The function generates a definition file for schema attributes to process with Active Directory Management Framework (ADMF).
        It queries the Active Directory schema for attribute definitions and transforms the query result into an object format required by the ADMF command "Register-FMSchema".

        The function supports filtering of the attributes to include and exclude.
        The data format for the defintion file can be  PSD1 or JSON.

    .PARAMETER FileName
        The name of the output file.

        Defaults to "SchemaAttributes".

    .PARAMETER Path
        The path where the output file will be created.

        Defaults to the current directory.

    .PARAMETER Include
        An array of attribute names to include in the output file.
        Wildcards are supported.

        Defaults to all attributes.

    .PARAMETER Exclude
        An array of attribute names to exclude from the output file.
        Wildcards are supported.

        Defaults is nothing.

    .PARAMETER FileType
        The format of the output file. Can be "PSD1" or "JSON".

        Defaults to "PSD1".

    .PARAMETER Server
        The AD server to run the query against.

    .PARAMETER Credential
        The credentials to use for the query.

    .PARAMETER Encoding
        The encoding of the output file.

        Defaults to "UTF8".

    .PARAMETER Force
        If specified, the function will overwrite an existing output file.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .EXAMPLE
        PS C:\> New-ADMFHDefinitionFileSchemaAttribute

        This will create a file "SchemaAttributes.psd1" within the current directory with all schema attributes from the forest schema.

    .EXAMPLE
        PS C:\> New-ADMFHDefinitionFileSchemaAttribute -OutputPath "C:\myDefinition" -FileName "myFile" -Include "manager", "ipsec*" -Exclude "Ipsec-Base"

        This will create a file "C:\myDefinition\myFile.psd1" containing probably 18 attributes ("manager", "ipsec*") while excluding the property "Ipsec-Base".

    .NOTES
        AUTHOR:     Andi Bellstedt
        VERSION:    1.0.0
        DATE:       2023-12-28
        KEYWORDS:   ADMF, ActiveDirectory, AD, Schema, Attribute, SchemaAttributes

    #>
    #requires -module ActiveDirectory
    [cmdletbinding(
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = "Medium"
    )]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FileName = "SchemaAttributes",

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path = $pwd.Path,

        [ValidateNotNullOrEmpty()]
        [string[]]
        $Include = "*",

        [string[]]
        $Exclude,

        [ValidateSet("PSD1", "JSON")]
        [string]
        $FileType = "PSD1",

        [string]
        $Server,

        [pscredential]
        $Credential,

        [ValidateSet( "Unknown", "String", "Unicode", "BigEndianUnicode", "UTF8", "UTF7", "UTF32", "Ascii", "default", "oem" )]
        [string]
        $Encoding = "UTF8",

        [switch]
        $Force
    )


    # Ensure that file name ends with file type
    $lowerFileType = ".$($FileType.ToLower())"
    if (-not $FileName.EndsWith($lowerFileType)) {
        [string]$FileName = $FileName + $lowerFileType
    }


    # Query schema attributes
    [string]$schemaNamingContext = (Get-ADRootDSE).schemaNamingContext
    $paramGetAdObject = @{ SearchBase = $schemaNamingContext }
    if ($Server) { $paramGetAdObject.Server = $Server }
    if ($Credential) { $paramGetAdObject.Credential = $Credential }

    $classes = Get-ADObject @paramGetAdObject -LDAPFilter "(objectCategory=CN=Class-Schema,$($schemaNamingContext))" -Properties mayContain, mustContain | ConvertTo-PSFClixml | ConvertFrom-PSFClixml | Sort-Object canonicalname
    [array]$attributes = Get-ADObject @paramGetAdObject -LDAPFilter "(objectCategory=CN=Attribute-Schema,$($schemaNamingContext))" -Properties "*"

    # Filter attributes for include
    [array]$attributes = foreach ($includeItem in $Include) {
        $attributes | Where-Object admindisplayname -Like $includeItem
    }

    # Get attributes to exclude
    $toExlude = ""
    $toExlude = foreach ($excludeItem in $Exclude) {
        ($attributes | Where-Object admindisplayname -Like $excludeItem).CanonicalName
    }

    # Final filtering and sorting
    [array]$attributes = $attributes | Where-Object CanonicalName -NotIn $toExlude | Sort-Object canonicalname -Unique

    # Stop if no attributes found
    if (-not $attributes) {
        Stop-PSFFunction -Message "No attributes found. Nothing to do."
        return
    }


    # Convert query result to object with required properties for ADMF command "Register-FMSchema"
    $i = 0
    $counter = 0
    $progressMinCount = [math]::Round(($attributes.count / 30), 0)
    $objectsLists = foreach ($attribute in $attributes) {
        Write-PSFMessage -Level Verbose -Message "Working on $($attribute.adminDisplayName)"

        $objectClassesWithAttribute = New-Object System.Collections.ArrayList
        #$classes | Where-Object { ($attribute.LdapDisplayName -in $_.mayContain) -or ($attribute.LdapDisplayName -in $_.mustContain) } | ForEach-Object { $null = $objectClassesWithAttribute.Add($_.Name) }
        $classes | Where-Object { ($attribute.LdapDisplayName -in $_.mayContain) } | ForEach-Object { $null = $objectClassesWithAttribute.Add($_.Name) }

        $definitionObject = $attribute | Select-PSFObject @(
            'canonicalname to string',
            'attributeID as OID',
            'Name',
            'AdminDisplayName',
            'LdapDisplayName',
            'OMSyntax to int32',
            'AttributeSyntax',
            'isSingleValued as SingleValued',
            'AdminDescription',
            'SearchFlags to int32',
            @{
                Name       = 'ObjectClass'
                Expression = { $objectClassesWithAttribute.ForEach({ $_ }) }
            },
            'IsDefunct to boolean',
            @{
                Name       = 'Optional'
                Expression = { $false }
            },
            @{
                Name       = 'ContextName'
                Expression = { "" }
            }
        )
        if ($null -ne $attribute.isMemberOfpartialAttributeSet) {
            $definitionObject | Add-Member -MemberType NoteProperty -Name 'PartialAttributeSet' -Value $attribute.isMemberOfpartialAttributeSet -Force
        }
        if ($null -ne $attribute.showInAdvancedViewOnly) {
            $definitionObject | Add-Member -MemberType NoteProperty -Name 'AdvancedView' -Value $attribute.showInAdvancedViewOnly -Force
        }

        $definitionObject

        if ($counter -ge $progressMinCount) {
            Write-Progress -Activity "Working on schema attribute(s)" -Status "Process: $($i) of $($attributes.count)" -PercentComplete (($i / $attributes.Count) * 100)
            $counter = 0
        }
        $i = $i + 1
        $counter = $counter + 1
    }
    Write-Progress -Activity "Finished $($attributes.count) schema attribute(s)" -Status "Process: $($attributes.count) of $($attributes.count)" -PercentComplete 100 -Completed


    # Convert transformed objects into desired output format
    switch ($FileType) {
        "JSON" {
            Write-PSFMessage -Level Verbose -Message "Formatting output as JSON"
            $outputString = $objectsLists | Select-Object * -ExcludeProperty canonicalname | ConvertTo-Json
        }

        "PSD1" {
            Write-PSFMessage -Level Verbose -Message "Formatting output to PSD1"
            $outputString = $objectsLists | ConvertTo-PSD1 -CommentProperty 'canonicalname'
        }

        Default { Stop-PSFFunction -Message "FileType '$FileType' is not supported. Developers mistake!" -EnableException $true }
    }


    # Write output to file
    $filePath = Join-Path -Path $Path -ChildPath $FileName
    $paramOutFile = @{
        FilePath = $filePath
        Encoding = $Encoding
    }
    if ($Force) {
        $paramOutFile.Add("Force", $true)
    } else {
        if (Test-Path -Path $filePath -PathType Leaf) {
            Write-PSFMessage -Level Warning -Message "File '$($filePath)' already exists and parameter -Force not specified. Skipping..."
            continue
        }
    }

    # Write file
    if ($PSCmdlet.ShouldProcess($filePath, "Write $($FileType) configuration data for $($attributes.count) attribute(s)")) {
        Write-PSFMessage -Level Verbose -Message "Write $($FileType) configuration data for $($attributes.count) attribute(s) to $($filePath)"
        $outputString | Out-File @paramOutFile
    }
}
