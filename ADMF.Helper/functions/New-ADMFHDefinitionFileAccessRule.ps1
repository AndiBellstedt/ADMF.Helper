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

    .PARAMETER Force
        If this switch is enabled, the function will overwrite existing files.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .EXAMPLE
        PS C:\> New-ADMFHDefinitionFileAccessRule

        Generates a definition file "DomainRoot_%domainFQDN%.psd1" in for Access Rules on the root object of the current domain.
        The file "DomainRoot.psd1" will be created in the current directory and with UTF8 encoding.

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
            Write-PSFMessage -Level Verbose -Message "Collecting items from '$($searchBaseItem)'..."

            # Query container and OUs from searchbase
            $paramGetAdSearchbases = @{
                LDAPFilter  = "(|(objectClass=container)(objectClass=organizationalUnit))"
                Properties  = @("canonicalName")
                SearchBase  = $searchBaseItem
                SearchScope = $SearchScope
            }
            if ($Server) { $paramGetAdSearchbases.Server = $Server }
            if ($Credential) { $paramGetAdSearchbases.Credential = $Credential }

            # Search each and every object in SearchBase, but exclude the (group) policies container if it is the system container within a domain
            # this is done due to GPOs are in a different component of ADMF
            if ($searchBaseItem -match '(,DC=([^,]+))+$') { $seachDomainName = $Matches[0].trim(",") } else { $seachDomainName = "*" }
            $foundADObject = Get-ADObject @paramGetAdSearchbases | Where-Object distinguishedname -notlike "*,CN=Policies,CN=System,$($seachDomainName)" | Sort-Object canonicalName | Select-Object -ExpandProperty distinguishedname
            Write-PSFMessage -Level System -Message "Found $($foundADObject.Count) items in '$($searchBaseItem)'. Adding to collection..."
            $searchBases += $foundADObject
        }

        # if nothing found, searchbase might be a OU or a specific container without sub OUs/containers -> add itself to searchbases
        if (-not $searchBases) {
            Write-PSFMessage -Level System -Message "No sub OUs/containers found. Adding searchbase itself to collection..."
            $searchBases += $SearchBase
        }
    }

    end {
        $searchBasesDone = [System.Collections.ArrayList]::new()
        $fileOutputData = [System.Collections.ArrayList]::new()
        Write-PSFMessage -Level Verbose -Message "There are $($searchBases.Count) in collection. Going to process collection now"
        foreach ($SearchBaseItem in $searchBases) {
            Write-PSFMessage -Level Verbose -Message "Processing '$($SearchBaseItem)'"
            # Query the searchbase it self, to determine the domain and get the adminSDHolder ACL
            $baseObject = Get-ADObject @paramAD -Identity $SearchBaseItem -Properties CanonicalName, nTSecurityDescriptor, adminCount

            if (-not $baseObject) {
                Stop-PSFFunction -Message "Object '$SearchBaseItem' not found"
                return
            }

            $null = $searchBasesDone.Add($SearchBaseItem)

            Write-PSFMessage -Level Debug -Message "Getting base domain of item '$($SearchBaseItem)'"
            $domain = Get-ADDomain @paramAD -Identity ($baseObject.CanonicalName.split('/')[0])

            # Query all objects from the searchbase
            Write-PSFMessage -Level System -Message "Querying all objects from '$($baseObject.CanonicalName)'"
            [array]$objects = Get-ADObject @paramAD -Filter $Filter -SearchBase $SearchBaseItem -SearchScope $SearchScope -Properties CanonicalName, nTSecurityDescriptor, adminCount | Where-Object distinguishedname -notlike "*,CN=Policies,CN=System,$($domain.DistinguishedName)" | Sort-Object CanonicalName
            [array]$objects = $objects | Where-Object { $_.DistinguishedName -notin $searchBases }
            [array]$objects += $baseObject
            [array]$objects = $objects | Sort-Object CanonicalName -Unique
            Write-PSFMessage -Level Verbose -Message "Found $($objects.Count) objects to process"

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
            Write-PSFMessage -Level Debug -Message "$($objects.Count) objects remain to process after filtering"

            # Loop through all
            $definitionObjects = [System.Collections.ArrayList]::new()
            foreach ($object in $objects) {
                Write-PSFMessage -Level Verbose -Message "Start processing of object '$($object.CanonicalName)'"
                $aceList = [System.Collections.ArrayList]::new()

                [array]$objectAceList = $object.nTSecurityDescriptor.Access | Where-Object IsInherited -eq $false
                Write-PSFMessage -Level Verbose -Message "Found $($objectAceList.Count) ACEs for '$($object.CanonicalName)'"
                if (-not $objectAceList) {
                    Write-PSFMessage -Level Verbose -Message "No ACEs found for '$($object.CanonicalName)'. Skipping object..."
                    continue
                }

                # Get all ACEs that are in the default-ACL definition of the objectClass
                $aceSpecialPermission = @()
                $paramGetDefPerm = @{ ObjectClass = $object.ObjectClass }
                if ($server) {
                    $paramGetDefPerm.Add("Server", $server)
                } else {
                    $paramGetDefPerm.Add("Server", (Get-ADDomainController @paramAD -DomainName $domain.DNSRoot -ForceDiscover -Discover).Name)
                }
                if ($Credential) { $paramGetDefPerm.Credential = $Credential }
                Write-PSFMessage -Level System -Message "Getting default ACL definition from schema for objectClass '$($object.CanonicalName)'"
                $aceSpecialPermission = Get-DMObjectDefaultPermission @paramGetDefPerm | ForEach-Object { Add-Member -InputObject $_ -MemberType NoteProperty -Name "IsDefault" -Value $true -PassThru -Force }
                Write-PSFMessage -Level System -Message "Reveived $($aceSpecialPermission.Count) default ACEs for objectClass '$($object.CanonicalName)' from schema"

                # Loop through all ACEs of the object and check if they are in the toCompare list, only add them if they are not
                Write-PSFMessage -Level Debug -Message "Compare ACEs of object '$($object.CanonicalName)' with default ACEs to determine the 'default once' and mark them as 'no fix config' and 'is default'"
                $defaultAceInObject = [System.Collections.ArrayList]::new()
                :aceLoop foreach ($ace in $objectAceList) {
                    $ace | Add-Member -MemberType NoteProperty -Name "Present" -Value $true -Force
                    $ace | Add-Member -MemberType NoteProperty -Name "NoFixConfig" -Value $false -Force
                    $ace | Add-Member -MemberType NoteProperty -Name "IsDefault" -Value $false -Force

                    :toCompareAceLoop foreach ($aceSpecial in $aceSpecialPermission) {
                        if (Test-AceEquality -Rule1 $ace -Rule2 $aceSpecial) {
                            Write-PSFMessage -Level Debug -Message "Mark ACE as schemaDefault: $($ace.AccessControlType) - '$($ace.ActiveDirectoryRights)' on Ä$($ace.IdentityReference)'"
                            $ace.NoFixConfig = $true
                            $ace.isDefault = $true
                            $null = $defaultAceInObject.Add($aceSpecial)
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
                        Write-PSFMessage -Level Verbose -Message "ACE is in schemaDefault, but not on the object '$($object.CanonicalName)': $($ace.AccessControlType) - '$($ace.ActiveDirectoryRights)' on '$($ace.IdentityReference)'"
                        $null = $aceList.Add($ace)
                    }
                }

                # Convert to object with ADMF compatible format
                Write-PSFMessage -Level Verbose -Message "Start converting $($aceList.count) ACEs to ADMF compatible format"
                foreach ($ace in $aceList) {
                    # Resolve identity to SID
                    $identity = $ace.IdentityReference.tostring() | Convert-Identity -BuiltInNamesOnly

                    # "keep"/resolve identity to display name
                    $identityDisplayName = ($ace.IdentityReference -as [System.Security.Principal.NTAccount]).Value
                    if (-not $identityDisplayName) {
                        try {
                            # Resolve SID to display name
                            Write-PSFMessage -Level System -Message "Try resolving identity '$($ace.IdentityReference)' from SID to NTAccount"
                            $identityDisplayName = ([System.Security.Principal.SecurityIdentifier]$ace.IdentityReference).Translate([System.Security.Principal.NTAccount]).Value
                        } catch {
                            # search SID in domain via LDAP
                            Write-PSFMessage -Level System -Message "Resolving identity '$($ace.IdentityReference)' from SID to NTAccount failed. Falling back to LDAP search."
                            $identityDisplayName = ([ADSI]"LDAP://<SID=$(($ace.IdentityReference).Value)>").name

                            # Fallback to global catalog
                            if (-not $identityDisplayName) {
                                $root = [ADSI]"GC://$((Get-ADRootDSE @paramAD).defaultNamingContext)"
                                $search = New-Object System.DirectoryServices.DirectorySearcher($root, "(objectSID=$(($ace.IdentityReference).Value))")
                                $resultGC = $search.FindOne()
                                $identityDisplayName = $resultGC.Properties.name
                                Write-PSFMessage -Level System -Message "Identity '$($ace.IdentityReference)' found via LDAP: $($identityDisplayName)"
                            }

                            # Mark as unknown identity
                            if (-not $identityDisplayName) {
                                Write-PSFMessage -Level Warning -Message "Unable to resolve identity '$($ace.IdentityReference)'. Marking as unknown identity."
                                $identityDisplayName = "<<< Unknown identity>>>"
                            }
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
                    Write-PSFMessage -Level System -Message "Compose ADMF definition object for '$($ace.IdentityReference)' on '$($object.CanonicalName)'"
                    $objectDistinguishedName = $object.DistinguishedName
                    # ensure it is no DN with a DC part beneath a container or OU (like RootDNS records in the system)
                    if ($objectDistinguishedName.Split(",").Where({ $_ -notlike "DC=*" }) -and ($objectDistinguishedName -match "(,DC=([^,]+))+$")) {
                        $objectDistinguishedName = $objectDistinguishedName -replace ($Matches[0].Trim(",")), '%DomainDN%'
                    } else {
                        $objectDistinguishedName = $objectDistinguishedName -replace 'DC=.+$', '%DomainDN%'
                    }
                    $output = [PSCustomObject]@{
                        CanonicalName         = $object.CanonicalName
                        Path                  = $objectDistinguishedName
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
                    Write-PSFMessage -Level Verbose -Message "Converting $($definitionObjects.count) objects to JSON format"
                    $outputString = $definitionObjects | Select-Object * -ExcludeProperty canonicalname | ConvertTo-Json
                }

                "PSD1" {
                    Write-PSFMessage -Level Verbose -Message "Converting $($definitionObjects.count) objects to PSD1 format"
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
                if (-not $FileName) { $FileName = "DomainRoot_$($domain.DNSRoot)" }
            }
            # Ensure that file name ends with file type
            $lowerFileType = ".$($FileType.ToLower())"
            if (-not $FileName.EndsWith($lowerFileType)) {
                [string]$FileName = $FileName + $lowerFileType
            }
            $filePath = Join-Path -Path $Path -ChildPath $FileName
            Write-PSFMessage -Level Verbose -Message "The $($definitionObjects.count) definitions will be written to file '$($filePath)'."


            # Create file output data
            $null = $fileOutputData.Add(
                [PSCustomObject]@{
                    FilePath               = $filePath
                    OutputString           = [string]$outputString
                    DefinitionObjectsCount = $definitionObjects.count
                    ObjectsCount           = $objects.count
                }
            )
        }

        # Work through file output data (grouping by filepath)
        foreach ($fileGroup in ($fileOutputData | Group-Object FilePath)) {
            Write-PSFMessage -Level Verbose -Message "Start processing of content for file '$($fileGroup.Name)'"

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
