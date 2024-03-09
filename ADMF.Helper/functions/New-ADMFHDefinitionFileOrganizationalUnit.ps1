# build ADMF ou definition files from AD OU structure
function New-ADMFHDefinitionFileOrganizationalUnit {
    <#
    .SYNOPSIS
        Creates definition file(s) for organizational units to process with Active Directory Management Framework (ADMF).

    .DESCRIPTION
        The function is used to create definition files for organizational units (OUs) in a format that can be processed by the Active Directory Management Framework (ADMF).
        The function queries Active Directory for OUs starting from the specified `SearchBase`.
        It excludes any OUs specified in `ExcludeDN`.
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

    .PARAMETER ExcludeDN
        The distinguished name of an organizational unit to exclude from the search.
        Defaults to the distinguished name of the domain controllers container of the current domain.

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

    .EXAMPLE
        PS C:\> New-ADMFHDefinitionFileOrganizationalUnit

        This will create a file "root.psd1" within the domain and separate psd1 files for all sub OUs found under domain root.

    .EXAMPLE
        PS C:\> New-ADMFHDefinitionFileOrganizationalUnit -SingleFile

        This will create only a sinlge file "root.psd1" containing all OUs found in the domain.

    .NOTES
        AUTHOR:     Andi Bellstedt
        VERSION:    1.0.0
        DATE:       2023-12-27
        KEYWORDS:   ADMF, ActiveDirectory, AD, OrganizationalUnit, OU

    #>
    #requires -module ActiveDirectory
    [cmdletbinding(
        PositionalBinding     = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact         = "Medium"
    )]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FileName = "root",

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path = $pwd.Path,

        [ValidateNotNullOrEmpty()]
        [string]
        $SearchBase = (Get-ADDomain).DistinguishedName,

        [string]
        $ExcludeDN = (Get-ADDomain).DomainControllersContainer,

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


    # Ensure that file name ends with file type
    $lowerFileType = ".$($FileType.ToLower())"
    if (-not $FileName.EndsWith($lowerFileType)) {
        [string]$FileName = $FileName + $lowerFileType
    }


    # Query organizational units
    $paramGetAdOrgUnit = @{
        Filter     = "*"
        Properties = @("Description", "canonicalname")
        SearchBase = $SearchBase
    }
    if ($Server) { $paramGetAdOrgUnit.Server = $Server }
    if ($Credential) { $paramGetAdOrgUnit.Credential = $Credential }
    if ($SingleFile) {
        $paramGetAdOrgUnit.SearchScope = "Subtree"
    } else {
        $paramGetAdOrgUnit.SearchScope = "OneLevel"
    }
    $ouList = Get-ADOrganizationalUnit @paramGetAdOrgUnit | Sort-Object canonicalname | Where-Object DistinguishedName -NotIn $ExcludeDN

    # Stop if no OUs found
    if (-not $ouList) { return }


    # Convert query result to object with required properties for ADMF command "Register-DMOrganizationalUnit"
    $ouListObjects = $ouList | Select-PSFObject @(
        'canonicalname to string',
        'Name',
        'Description to string',
        @{
            Name       = 'Path'
            Expression = { $_.DistinguishedName.Split(",", 2)[1] -replace 'DC=.+$', '%DomainDN%' }
        },
        @{
            Name       = 'Optional'
            Expression = { $false }
        },
        @{
            Name       = 'Present'
            Expression = { $true }
        }
    )

    # Convert transformed objects into desired output format
    switch ($FileType) {
        "JSON" {
            $outputString = $ouListObjects | Select-Object * -ExcludeProperty canonicalname | ConvertTo-Json
        }

        "PSD1" {
            $outputString = $ouListObjects | ConvertTo-PSD1 -CommentProperty 'canonicalname'
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
        $outputString | Out-File @paramOutFile
    }


    # Stop if no recursion is required
    if ($SingleFile) { return }


    # Recursively call function for each OU
    foreach ($ou in $ouList) {
        $ouCanonicalName = $ou.canonicalname.TrimStart($ou.canonicalname.Split("/")[0]).trimstart("/")
        $nextFileName = $ouCanonicalName.replace("_", "").replace(" ", "").replace("/", "_")

        $paramExecuteRecursive = @{
            FileName   = $nextFileName
            OutputPath = $Path
            SearchBase = $ou.DistinguishedName
            ExcludeDN  = $ExcludeDN
        }
        if ($Server) { $paramExecuteRecursive.Server = $Server }

        # Start recursion
        New-ADMFHDefinitionFileOrganizationalUnit @paramExecuteRecursive
    }
}
