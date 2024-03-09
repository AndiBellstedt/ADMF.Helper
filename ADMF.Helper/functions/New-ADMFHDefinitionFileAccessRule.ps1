function New-ADMFHDefinitionFileAccessRule {
    <#
    .SYNOPSIS
        Generates a definition file for Access Rules in the Active Directory Management Framework (ADMF).

    .DESCRIPTION
        The function generates a definition file for Access Rules in the Active Directory Management Framework (ADMF).
        It queries the Active Directory for Access Rules based on the provided like Filter, SearchBase and SearchScope.
        The result are transformed into an object format required by the ADMF command "Register-DMAccessRule".

        The function supports filtering of the attributes to include and exclude.
        The data format for the defintion file can be  PSD1 or JSON.

        This function requires PowerShell 5.1 and the PSFramework and ActiveDirectory modules.

    .PARAMETER FileName
        The name of the output file.

        If not specified, the function will derive the filename from the canonical name of the first object.

    .PARAMETER Path
        The path where the output file will be created.

        Defaults to the current directory.

    .PARAMETER Filter
        A filter to apply to the Access Rules query.

        Defaults to all Access Rules.

    .PARAMETER SearchBase
        An array of distinguished names to use as the base of the Access Rules query.

        Defaults to the distinguished name of the current domain.

    .PARAMETER SearchScope
        The scope of the Access Rules query.
        Can be one of the following:
            "Base" = only the ACL of the object itself
            "OneLevel" = only the ACLs of the direct children
            "Subtree" = the ACLs of the object and all children

        Defaults to "Base".

    .PARAMETER FileType
        The format of the output file. Can be "PSD1" or "JSON".

        Defaults to "PSD1".

    .PARAMETER Server
        The AD server to run the query against.

    .PARAMETER Credential
        The credentials to use for the query.
        Optional

    .PARAMETER Encoding
        The encoding of the output file.

        Defaults to "UTF8".

    .EXAMPLE
        PS C:\> New-ADMFHDefinitionFileAccessRule

        Generates a definition file "root.psd1" in for Access Rules on the root object of the current domain.
        The file "root.psd1" will be created in the current directory and with UTF8 encoding.

    .EXAMPLE
        PS C:\> New-ADMFHDefinitionFileAccessRule -Path C:\ADMF -SearchScope Subtree

        Generates access rules definition files for all objects beneath the current domain and save a PSD1 file per container/organizationalUnit.
        Be aware, the domain root explicitly will NOT be generated with Subtree option.

        The output will be generated in the directory "C:\ADMF" and with UTF8 encoding.

    .EXAMPLE
        PS C:\> New-ADMFHDefinitionFileAccessRule -Path C:\ADMF -SearchBase "CN=Builtin,$((Get-ADDomain).DistinguishedName)" -FileType "JSON" -Force

        Generates a access rules definition file for the Builtin container and save a JSON file.
        The file will be created in the directory "C:\ADMF" and with UTF8 encoding.
        If the file already exists, it will be overwritten.

    .EXAMPLE
        PS C:\> "CN=Builtin,$((Get-ADDomain).DistinguishedName)" | New-ADMFHDefinitionFileAccessRule -Path C:\ADMF -FileName "MyFile" -SearchScope Subtree

        Generates a access rules definition file for the Builtin container with all subcontainers and save a PSD1 file.
        The file will be created in the directory "C:\ADMF", names with the -fixed- filename "MyFile.psd1" and with UTF8 encoding.
        If the file already exists, it will NOT be overwritten.

    .NOTES
        AUTHOR:     Andi Bellstedt
        VERSION:    1.0.0
        DATE:       2024-03-09
        KEYWORDS:   ADMF, ActiveDirectory, AccessRules, ACL, ACE

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
        [Alias("DistinguishedName", "DN")]
        [string[]]
        $SearchBase = (Get-ADDomain).DistinguishedName,

        [ValidateSet("Base", "OneLevel", "Subtree")]
        [ValidateNotNullOrEmpty()]
        $SearchScope = "Base",

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

    begin {
        $paramAD = $PSBoundParameters | ConvertTo-PSFHashtable -Include Server, Credential
        [array]$Searchbases = @()
        if (-not $FileName) { $resetFileName = $true } else { $resetFileName = $false }

        $domainTable = (Get-ADForest @paramAD).Domains | ForEach-Object { @{ $_ = (Get-ADDomain @paramAD).NetBIOSName } }
    }

    process {

        # Loop through searchbase(s) and query OUs/container
        foreach ($searchBaseItem in $SearchBase) {
            # Query container and OUs from searchbase
            $paramGetAdSearchbases = @{
                LDAPFilter  = "(|(objectClass=container)(objectClass=organizationalUnit))"
                #Filter      = $Filter
                Properties  = @("canonicalName")
                SearchBase  = $searchBaseItem
                SearchScope = $SearchScope
            }
            if ($Server) { $paramGetAdSearchbases.Server = $Server }
            if ($Credential) { $paramGetAdSearchbases.Credential = $Credential }

            # Searach each and every object in SearchBase, but exclude the Policies container if it is the system container within a domain
            if ($searchBaseItem -match '(?<DomainName>DC=.*)(\/|$)') { $seachDomainName = $Matches.DomainName } else { $seachDomainName = "*" }
            $searchBases += Get-ADObject @paramGetAdSearchbases | Where-Object distinguishedname -notlike "*,CN=Policies,CN=System,$($seachDomainName)" | Sort-Object canonicalName | Select-Object -ExpandProperty distinguishedname
        }

        # if nothing found, searchbase might be a OU or a specific container without sub OUs/containers -> add itself to searchbases
        if (-not $searchBases) {
            $searchBases += $SearchBase
        }
    }

    end {
        $searchBasesDone = [System.Collections.ArrayList]::new()
        $fileOutputData = [System.Collections.ArrayList]::new()
        foreach ($SearchBaseItem in $searchBases) {
            # Query the searchbase it self, to determine the domain and get the adminSDHolder ACL
            $baseObject = Get-ADObject @paramAD -Identity $SearchBaseItem -Properties CanonicalName, nTSecurityDescriptor, adminCount

            if (-not $baseObject) {
                Stop-PSFFunction -Message "Object '$SearchBaseItem' not found"
                return
            }

            $null = $searchBasesDone.Add($SearchBaseItem)

            $domain = Get-ADDomain @paramAD -Identity ($baseObject.CanonicalName.split('/')[0])

            # Query all objects from the searchbase
            [array]$objects = Get-ADObject @paramAD -Filter $Filter -SearchBase $SearchBaseItem -SearchScope $SearchScope -Properties CanonicalName, nTSecurityDescriptor, adminCount | Where-Object distinguishedname -notlike "*,CN=Policies,CN=System,$($domain.DistinguishedName)" | Sort-Object CanonicalName
            [array]$objects = $objects | Where-Object { $_.DistinguishedName -notin $searchBases }
            [array]$objects += $baseObject
            [array]$objects = $objects | Sort-Object CanonicalName -Unique

            <#
            $objects | Measure-Object
            $objects | Format-Table
            $searchBases
            $searchBasesDone
            $object = $objects  | ogv -OutputMode Single
            #>
            $objects = foreach ($object in $objects) {
                $found = $false
                :inner foreach ($dn in ($searchBases | Where-Object { $_ -notin $searchBasesDone })) {
                    if ( $object.DistinguishedName -like "*$($dn)" ) {
                        $found = $true
                        break inner
                    }
                }
                if (-not $found) { $object }
            }

            # Loop through all
            $definitionObjects = [System.Collections.ArrayList]::new()
            #$object = $objects[0]
            foreach ($object in $objects) {
                $aceList = [System.Collections.ArrayList]::new()
                $objectAceList = $object.nTSecurityDescriptor.Access | Where-Object IsInherited -eq $false
                if (-not $objectAceList) {
                    Write-PSFMessage -Level Verbose -Message "No ACEs found for '$($object.CanonicalName)'. Skipping object..."
                    continue
                }

                $aceSpecialPermission = @()
                # All ACEs that are in the default-ACL definition of the objectClass
                $paramGetDefPerm = @{ ObjectClass = $object.ObjectClass }
                if ($server) {
                    $paramGetDefPerm.Add("Server", $server)
                } else {
                    $paramGetDefPerm.Add("Server", (Get-ADDomainController -DomainName $domain.DNSRoot -ForceDiscover -Discover).Name)
                }
                $aceSpecialPermission = Get-DMObjectDefaultPermission @paramGetDefPerm | ForEach-Object { Add-Member -InputObject $_ -MemberType NoteProperty -Name "IsDefault" -Value $true -PassThru -Force }


                # Loop through all ACEs of the object and check if they are in the toCompare list, only add them if they are not
                $defaultAceInObject = [System.Collections.ArrayList]::new()
                :aceLoop foreach ($ace in $objectAceList) {
                    $ace | Add-Member -MemberType NoteProperty -Name "Present" -Value $true -Force
                    $ace | Add-Member -MemberType NoteProperty -Name "NoFixConfig" -Value $false -Force
                    $ace | Add-Member -MemberType NoteProperty -Name "IsDefault" -Value $false -Force

                    :toCompareAceLoop foreach ($aceSpecial in $aceSpecialPermission) {
                        if (Test-AceEquality -Rule1 $ace -Rule2 $aceSpecial) {
                            $ace.NoFixConfig = $true
                            $ace.isDefault = $true
                            $null = $defaultAceInObject.Add($aceSpecial)
                            #break toCompareAceLoop
                        }
                    }

                    $null = $aceList.Add($ace)
                }

                # Check on default permissions that are explicitly NOT present in the object
                foreach ($aceSpecial in $aceSpecialPermission) {
                    if ($aceSpecial -notin $defaultAceInObject) {
                        $ace = $aceSpecial | Select-Object * -ExcludeProperty SID
                        $ace | Add-Member -MemberType NoteProperty -Name "Present" -Value $false -Force
                        $ace | Add-Member -MemberType NoteProperty -Name "NoFixConfig" -Value $false -Force
                        $null = $aceList.Add($ace)
                    }
                }

                # Convert to object with ADMF compatible format
                foreach ($ace in $aceList) {
                    # Resolve identity to SID
                    $identity = $ace.IdentityReference.tostring() | Convert-Identity -BuiltInNamesOnly

                    # "keep"/resolve identity to display name
                    $identityDisplayName = ($ace.IdentityReference -as [System.Security.Principal.NTAccount]).Value
                    if (-not $identityDisplayName) {
                        try {
                            # Resolve SID to display name
                            $identityDisplayName = ([System.Security.Principal.SecurityIdentifier]$ace.IdentityReference).Translate([System.Security.Principal.NTAccount]).Value
                        } catch {
                            # search SID in domain via LDAP
                            $identityDisplayName = ([ADSI]"LDAP://<SID=$(($ace.IdentityReference).Value)>").name

                            # Fallback to global catalog
                            if (-not $identityDisplayName) {
                                $root = [ADSI]"GC://$((Get-ADRootDSE @paramAD).defaultNamingContext)"
                                $search = New-Object System.DirectoryServices.DirectorySearcher($root, "(objectSID=$(($ace.IdentityReference).Value))")
                                $resultGC = $search.FindOne()
                                $identityDisplayName = $resultGC.Properties.name
                            }

                            # Mark as unknown identity
                            if (-not $identityDisplayName) { $identityDisplayName = "<<< Unknown identity>>>" }
                        }
                    }

                    # Parse domains in the forest and translate domain/forest SID to placeholders
                    foreach ($item in $domainTable.Values) {
                        if ($identity.StartsWith($item)) {
                            # Check on "root domain only" groups
                            if ($identity.split("-")[-1] -in ("518", "519", "527", "498")) {
                                $placeholder = Get-DMNameMapping | Where-Object { $_.value -eq $item -and $_.name -eq '%RootDomainName%' } | Select-Object -ExpandProperty Name
                            } else {
                                $placeholder = Get-DMNameMapping | Where-Object { $_.value -eq $item -and $_.name -eq '%DomainName%' } | Select-Object -ExpandProperty Name
                            }

                            if ($placeholder) {
                                $identity = $identity -replace $item, $domainTable[$item]
                                $identity = $placeholder + $identity
                            }
                        }
                    }

                    # Output admf defintion object
                    $output = [PSCustomObject]@{
                        CanonicalName         = $object.CanonicalName
                        Path                  = ($object.DistinguishedName -replace 'DC=.+$', '%DomainDN%')
                        Identity              = $identity
                        identityDisplayName   = $identityDisplayName
                        ActiveDirectoryRights = $ace.ActiveDirectoryRights.tostring()
                        AccessControlType     = $ace.AccessControlType.tostring()
                        InheritanceType       = $ace.InheritanceType.tostring()
                        ObjectType            = (Convert-DMSchemaGuid -Name $ace.ObjectType -OutType Name)
                        InheritedObjectType   = (Convert-DMSchemaGuid -Name $ace.InheritedObjectType -OutType Name)
                        Optional              = $false
                        Present               = $ace.Present
                        NoFixConfig           = $ace.NoFixConfig
                    }

                    $null = $definitionObjects.Add($output)
                }
            }
            if (-not $definitionObjects) { continue }

            # Convert to output format
            switch ($FileType) {
                "JSON" {
                    $outputString = $definitionObjects | Select-Object * -ExcludeProperty canonicalname | ConvertTo-Json
                }

                "PSD1" {
                    [array]$outputString = foreach ($definitionObject in $definitionObjects) {
                        # Convert PSD1 string
                        $output = $definitionObject | Select-Object * -ExcludeProperty identityDisplayName | ConvertTo-PSD1 -CommentProperty 'canonicalname' -NoArrayWhenSingleObject -ForceIndentation

                        # insert identityDisplayName as comment in the Identity property
                        if ($output -match "Identity\s*=\s.*") {
                            $output = $output -replace $Matches[0], "$(($Matches[0].trim()))  # $($definitionObject.identityDisplayName)"
                        }

                        # Output the result
                        $output
                    }

                    # Workarround the array formatting and bring back the array
                    $outputString = "(`n" + ($outputString -join ",`n`n") + "`n)"
                }

                Default { Stop-PSFFunction -Message "FileType '$FileType' is not supported. Developers mistake!" -EnableException $true }
            }

            # Ensure there is a filename, otherwise derive from canonicalname of the first object
            #if ((-not $FileName) -or $resetFileName) {
            if ($resetFileName) {
                $FileName = $baseObject.CanonicalName.TrimStart($baseObject.CanonicalName.Split("/", 2)[0]).trim("/").Replace(" ", "").Replace("_", "").replace("/", "_")
                if (-not $FileName) { $FileName = "root" }
            }
            # Ensure that file name ends with file type
            $lowerFileType = ".$($FileType.ToLower())"
            if (-not $FileName.EndsWith($lowerFileType)) {
                [string]$FileName = $FileName + $lowerFileType
            }


            # Create file output data
            $null = $fileOutputData.Add(
                [PSCustomObject]@{
                    FilePath               = (Join-Path -Path $Path -ChildPath $FileName)
                    OutputString           = [string]$outputString
                    DefinitionObjectsCount = $definitionObjects.count
                    ObjectsCount           = $objects.count
                }
            )
        }

        # Work through file output data (grouping by filepath)
        foreach ($fileGroup in ($fileOutputData | Group-Object FilePath)) {
            # Combine data for one file together
            $stingGroupParts = $fileGroup.Group.OutputString | ForEach-Object { $_.TrimStart("(`n").TrimEnd("`n)") }
            $outputString = "(`n" + ($stingGroupParts -join ",`n") + "`n)"

            # Get amount of objects in the group
            $definitionObjectsCount = $fileGroup.Group.DefinitionObjectsCount | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            $objectsCount = $fileGroup.Group.ObjectsCount | Measure-Object -Sum | Select-Object -ExpandProperty Sum

            # Get file name
            $filePath = $fileGroup.Name

            # Prepare output parameters
            $paramOutFile = @{
                FilePath = $filePath
                Encoding = $Encoding
            }
            # Check on existense and force option
            if ($Force -and (Test-Path -Path $filePath -PathType Leaf)) {
                $paramOutFile.Add("Force", $true)
            } else {
                if (Test-Path -Path $filePath -PathType Leaf) {
                    Write-PSFMessage -Level Warning -Message "File '$($filePath)' already exists and parameter -Force not specified. Skipping..."
                    continue
                }
            }

            # Perform output
            if ($PSCmdlet.ShouldProcess($filePath, "Write $($definitionObjectsCount) access rule defintion(s) in $($FileType) configuration data for $($objectsCount) objects")) {
                Write-PSFMessage -Level Verbose -Message "Write $($definitionObjectsCount) access rule defintion(s) in $($FileType) configuration data for $($objectsCount) objects to '$($filePath)'."
                $outputString | Out-File @paramOutFile
            }
        }
    }
}
