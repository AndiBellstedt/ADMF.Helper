function New-ADMFHDefinitionFileGroup {
    <#
    .SYNOPSIS
        Creates definition file(s) for organizational units to process with Active Directory Management Framework (ADMF).

    .DESCRIPTION
        The function is used to create definition files for organizational units (OUs) in a format that can be processed by the Active Directory Management Framework (ADMF).
        The function queries Active Directory for OUs starting from the specified `SearchBase`.
        It excludes any OUs specified in `Exclude`.
        The resulting OUs are then transformed into an object format required by the ADMF command "Register-DMOrganizationalUnit".

        The transformed objects are then converted into the specified `FileType` (either "PSD1" or "JSON") and written to a file. The `FileName` parameter specifies the name of the file, and `OutputPath` specifies the directory where the file will be created.

        If the `SingleFile` switch is specified, the function will create a single file for all OUs.
        Otherwise, it will create a separate file for each OU.

        The `Server` parameter can be used to specify an AD server to run the query against.
        If not specified, the query will be run against the default AD server.

    .PARAMETER FileName
        The name of the file to be created.
        file extension will be added automatically if not specified or not matching the specified `FileType`.

        Default filename is "root" -> will result in "root.psd1" or "root.json" depending on the specified `FileType`.

    .PARAMETER Path
        The path where the output file will be created.

        Defaults to the current directory.

    .PARAMETER SearchBase
        The distinguished name of the domain or organizational unit to start the search from.

        Defaults to the distinguished name of the current domain.

    .PARAMETER Exclude
        The distinguished name of an organizational unit to exclude from the search.
        Defaults to the distinguished name of the domain controllers container of the current domain.

    .PARAMETER Include
        The name of the organizational unit to include in the search.
        Defaults to all.

    .PARAMETER Filter
        The filter to use for the query.

        Defaults to "*".

    .PARAMETER FileType
        The type of the file to be created. Can be "PSD1" or "JSON".

        Defaults to "PSD1".

    .PARAMETER Server
        The AD server to run the query against.

        Not specified by default. Will be run against the default AD server.

    .PARAMETER Credential
        The credentials to use for the query.

    .PARAMETER SingleFile
        If specified, the function will create a single file for all organizational units.
        Otherwise, it will create a separate file for each organizational unit.

    .PARAMETER Encoding
        The encoding to use for the output file.

        Defaults to "UTF8".

    .PARAMETER Force
        If specified, the function will overwrite existing files.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .EXAMPLE
        PS C:\> New-ADMFHDefinitionFileGroup

        This will create a file "root.psd1" within the domain and separate psd1 files for all sub OUs found under domain root.

    .EXAMPLE
        PS C:\> New-ADMFHDefinitionFileGroup -SingleFile

        This will create only a sinlge file "root.psd1" containing all OUs found in the domain.

    .NOTES
        AUTHOR:     Andi Bellstedt
        VERSION:    1.0.0
        DATE:       2023-12-27
        KEYWORDS:   ADMF, ActiveDirectory, AD, OrganizationalUnit, OU

    #>
    #requires -module ActiveDirectory
    [cmdletbinding(
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = "Medium"
    )]
    param(
        [Parameter(Position = 0)]
        [string]
        $FileName,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path = $pwd.Path,

        [ValidateNotNullOrEmpty()]
        [string]
        $Filter = "*",

        [parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $SearchBase = (Get-ADDomain).DistinguishedName,

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

        [switch]
        $SingleFile,

        [ValidateSet( "Unknown", "String", "Unicode", "BigEndianUnicode", "UTF8", "UTF7", "UTF32", "Ascii", "default", "oem" )]
        [string]
        $Encoding = "UTF8",

        [switch]
        $Force
    )

    begin {
        [array]$Searchbases = @()
        $FunctionName = $MyInvocation.MyCommand.Name

        function New-ADMFHDefinitionFileGroupRecursive {
            [cmdletbinding(
                SupportsShouldProcess = $true,
                ConfirmImpact = "Medium"
            )]
            param(
                [string]
                $FileName,

                [ValidateNotNullOrEmpty()]
                [string]
                $Path,

                [ValidateNotNullOrEmpty()]
                [string]
                $Filter,

                [ValidateNotNullOrEmpty()]
                [string]
                $SearchBase,

                [ValidateNotNullOrEmpty()]
                [string[]]
                $Include,

                [string[]]
                $Exclude,

                [string]
                $FileType,

                [string]
                $Server,

                [pscredential]
                $Credential,

                [switch]
                $SingleFile,

                [string]
                $Encoding,

                [switch]
                $Force,

                [string]
                $FunctionName
            )

            # Query groups
            $paramGetAdGroup = @{
                Filter     = $Filter
                Properties = @("Description", "canonicalName", "GroupCategory", "GroupScope", "SamAccountName", "DistinguishedName")
                SearchBase = $SearchBase
            }
            if ($Server) { $paramGetAdGroup.Server = $Server }
            if ($Credential) { $paramGetAdGroup.Credential = $Credential }
            if ($SingleFile) {
                $paramGetAdGroup.SearchScope = "Subtree"
            } else {
                $paramGetAdGroup.SearchScope = "OneLevel"
            }
            [array]$objects = Get-ADGroup @paramGetAdGroup
            if (-not $objects) { return }

            # Filter groups for include
            $objects = foreach ($includeItem in $Include) {
                $objects | Where-Object Name -Like $includeItem
            }

            # Get attributes to exclude
            $toExlude = ""
            $toExlude = foreach ($excludeItem in $Exclude) {
                ($objects | Where-Object Name -Like $excludeItem).CanonicalName
            }

            # Final filtering and sorting
            $objects = $objects | Where-Object CanonicalName -NotIn $toExlude | Sort-Object canonicalname -Unique

            # Convert query result to object with required properties for ADMF command "Register-DMGroup"
            $definitionObjects = $objects | Select-PSFObject @(
                "canonicalName",
                "Name",
                "SamAccountName"
                @{
                    Name       = 'Path'
                    Expression = { $_.DistinguishedName -replace ',DC=.+$', ',%DomainDN%' -replace '^.+?,' }
                },
                "Description to string",
                'GroupScope as Scope to String',
                'GroupCategory as Category to String',
                @{
                    Name       = 'Present'
                    Expression = { $true }
                },
                @{
                    Name       = 'Optional'
                    Expression = { $false }
                },
                @{
                    Name       = 'ContextName'
                    Expression = { $null }
                }
            )


            # Convert transformed objects into desired output format
            switch ($FileType) {
                "JSON" {
                    $outputString = $definitionObjects | Select-Object * -ExcludeProperty canonicalname | ConvertTo-Json
                }

                "PSD1" {
                    $outputString = $definitionObjects | ConvertTo-PSD1 -CommentProperty 'canonicalname'
                }

                Default { Stop-PSFFunction -Message "FileType '$FileType' is not supported. Developers mistake!" -EnableException $true }
            }


            # Ensure there is a filename, otherwise derive from canonicalname of the first object
            if (-not $FileName) {
                $FileName = $objects[0].CanonicalName.Replace($objects[0].name, "").TrimStart($objects[0].CanonicalName.Split("/", 2)[0]).trim("/").Replace(" ", "").Replace("_", "").replace("/", "_")
            }
            # Ensure that file name ends with file type
            $lowerFileType = ".$($FileType.ToLower())"
            if (-not $FileName.EndsWith($lowerFileType)) {
                [string]$FileName = $FileName + $lowerFileType
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

            if ($PSCmdlet.ShouldProcess($filePath, "Write $($FileType) configuration data for $($objects.count) group(s)")) {
                $outputString | Out-File @paramOutFile
            }

            # Stop if no recursion is required
            if ($SingleFile) { return }


            # Recursively call function for each sub-OU in searchbase
            $paramGetAdOU = @{
                Filter      = "*"
                Properties  = @("canonicalName")
                SearchBase  = $SearchBase
                SearchScope = "onelevel"
            }
            if ($Server) { $paramGetAdOU.Server = $Server }
            if ($Credential) { $paramGetAdOU.Credential = $Credential }
            [array]$ouList = Get-ADOrganizationalUnit @paramGetAdOU | Where-Object distinguishedname -notlike $SearchBase | Sort-Object canonicalname

            <#
            $ouList | ft
            $ou = $ouList[1]
            #>
            foreach ($ou in $ouList) {
                $ouCanonicalName = $ou.canonicalname.TrimStart($ou.canonicalname.Split("/")[0]).trimstart("/")
                $nextFileName = $ouCanonicalName.replace("_", "").replace(" ", "").replace("/", "_")
                <#
                $FileName = $nextFileName
                $SearchBase = $ou.DistinguishedName
                #>
                $paramExecuteRecursive = @{
                    FileName     = $nextFileName
                    Path         = $Path
                    Filter       = $Filter
                    SearchBase   = $ou.DistinguishedName
                    Include      = $Include
                    Exclude      = $Exclude
                    FileType     = $FileType
                    Server       = $Server
                    Credential   = $Credential
                    SingleFile   = $SingleFile
                    Encoding     = $Encoding
                    Force        = $Force
                    FunctionName = $FunctionName # mask function name for logging
                }

                # Start recursion
                New-ADMFHDefinitionFileGroupRecursive @paramExecuteRecursive
            }
        }
    }

    process {
        # Loop through searchbase(s) and query OUs/container
        foreach ($searchBaseItem in $SearchBase) {

            # Query container and OUs from searchbase
            $paramGetAdSearchbases = @{
                LDAPFilter  = "(|(objectClass=container)(objectClass=organizationalUnit))"
                Properties  = @("canonicalName")
                SearchBase  = $searchBaseItem
                SearchScope = "OneLevel"
            }
            if ($Server) { $paramGetAdSearchbases.Server = $Server }
            if ($Credential) { $paramGetAdSearchbases.Credential = $Credential }

            $searchBases += Get-ADObject @paramGetAdSearchbases | Where-Object distinguishedname -notlike "CN=System,*" | Sort-Object canonicalName | Select-Object -ExpandProperty distinguishedname
        }

        # if nothing found, searchbase might be a OU or a specific container without sub OUs/containers -> add itself to searchbases
        if ((-not $searchBases) -and ($SearchBase -notlike "DC=*")) {
            $searchBases += $SearchBase
        }
    }

    end {
        # Loop through searchbases and start filecreation
        foreach ($searchBasesItem in $searchBases) {
            $paramExecuteRecursive = @{
                FileName     = $FileName
                Path         = $Path
                Filter       = $Filter
                SearchBase   = $searchBasesItem
                Include      = $Include
                Exclude      = $Exclude
                FileType     = $FileType
                Server       = $Server
                Credential   = $Credential
                SingleFile   = $SingleFile
                Encoding     = $Encoding
                Force        = $Force
                FunctionName = $FunctionName # mask function name for logging
            }
            New-ADMFHDefinitionFileGroupRecursive @paramExecuteRecursive
        }
    }
}
