function Invoke-ADMFHExampleGenerator {
    <#
    .SYNOPSIS
        Generates example configuration files for the Active Directory Management Framework (ADMF).

    .DESCRIPTION
        The function generates example configuration files for the Active Directory Management Framework (ADMF).
        It supports three ADMF components: DCManagement, DomainManagement, and ForestManagement.

        The function iterates over the specified ADMF components, loads the corresponding module, and retrieves all available register commands.
        It then generates an example configuration file for each command, excluding any commands specified in the `ExcludedCommands` parameter.

        The example configuration files are created in the directory specified by the `Path` parameter, with one subdirectory for each ADMF component.
        The files are named "example_<command>.psd1" and contain a hashtable for each parameter set of the command, with comments describing each parameter.

    .PARAMETER Path
        The directory where the output files will be created.

        Defaults to the current directory.

    .PARAMETER AdmfComponent
        The ADMF components for which to generate example configuration files.
        Can be "DCManagement", "DomainManagement", and/or "ForestManagement".

        Defaults to all three.

    .PARAMETER DoNotIncludeParameterHelpInformation
        If specified, the function will not include help comments for the parameters in the output files.

        Will result in shorter and more readable files, but you have to know what the parameters are for.

    .PARAMETER ExcludedCommands
        An array of commands to exclude from the output files.

    .PARAMETER Indentation
        The number of characters to use for indentation in the output files.

        Defaults to 4.

    .PARAMETER IndentChar
        The character to use for indentation in the output files.

        Defaults to a space.

    .PARAMETER Encoding
        The encoding of the output files.

        Defaults to "UTF8".

    .PARAMETER Force
        If specified, the function will overwrite existing output files.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .EXAMPLE
        PS C:\> Invoke-ADMFHExampleGenerator

        This will create example configuration files for all  component in subfolders of the current directory.

    .EXAMPLE
        PS C:\> Invoke-ADMFHExampleGenerator -DoNotIncludeParameterHelpInformation

        This will create example configuration files for all  component in subfolders of the current directory.
        The files will not include help comments for the parameters.

    .EXAMPLE
        PS C:\> Invoke-ADMFHExampleGenerator -Path "C:\myPath" -AdmfComponent "DCManagement" -Force

        This will create example configuration files for all commands of the DCManagement component in the directory "C:\myPath\DCManagement".
        If files already exist, they will be overwritten.

    .NOTES
        AUTHOR:     Andi Bellstedt
        VERSION:    1.0.0
        DATE:       2023-12-27
        KEYWORDS:   ADMF, ADMFHelper, Example Configuration, Configuration File creator

    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    param(
        [Parameter(Position = 0)]
        [string]
        $Path = $PWD.Path,

        [Parameter(Position = 1)]
        [ValidateSet("DCManagement", "DomainManagement", "ForestManagement")]
        [string[]]
        $AdmfComponent = @("DCManagement", "DomainManagement", "ForestManagement"),

        [switch]
        $DoNotIncludeParameterHelpInformation,

        [string[]]
        $ExcludedCommands,

        [int]
        $Indentation = 4,

        [string]
        $IndentChar = ' ',

        [ValidateSet( "Unknown", "String", "Unicode", "BigEndianUnicode", "UTF8", "UTF7", "UTF32", "Ascii", "default", "oem" )]
        [string]
        $Encoding = "UTF8",

        [switch]
        $Force
    )


    $indentString = [string]::Join(
        "",
            (0 .. ($Indentation - 1) | ForEach-Object { $IndentChar })
    )



    foreach ($moduleName in $AdmfComponent) {
        Write-PSFMessage -Level Verbose -Message "Processing module '$moduleName'"

        switch ($moduleName) {
            "DCManagement" {
                $prefix = "DC"
            }

            "DomainManagement" {
                $prefix = "DM"
            }

            "ForestManagement" {
                $prefix = "FM"
            }

            Default {}
        }

        if ("Register-$($prefix)Callback" -notin $ExcludedCommands) {
            $ExcludedCommands += "Register-$($prefix)Callback"
        }

        # ensure module is loaded
        if (-not (Get-Module -Name $moduleName -ErrorAction Ignore -Verbose:$false)) { Import-Module -Name $moduleName -Force  -Verbose:$false }

        # get the module for version information
        $module = Get-Module -Name $moduleName

        # get all available register commands
        $commands = Get-Command "Register-$($prefix)*"

        # sort out excluded commands
        if ($ExcludedCommands) {
            $toExclude = foreach ($ExcludedCommand in $ExcludedCommands) {
                $commands | Where-Object name -like $ExcludedCommand
            }
        }
        if ($toExclude) {
            Write-PSFMessage -Level Verbose -Message "Exclude from parsing: $([string]::Join(", ",$toExclude))"
            $commands = $commands | Where-Object name -notin $toExclude.name
        }

        $filePath = (Join-Path -Path $Path -ChildPath ($module.Name + "_" + $module.Version))
        Write-PSFMessage -Level Verbose -Message "Compose output file '$($fileaName)' with in path '$($filePath)'"
        if (-not (Test-Path -Path $filePath -PathType Container)) {
            Write-PSFMessage -Level Verbose -Message "Folder '$($filePath)' does not exist, creating it..."
            $null = New-Item -Path $filePath -ItemType Directory -Force
        }

        Write-PSFMessage -Level SomewhatVerbose -Message "Processing $($commands.Count) commands"
        foreach ($command in $commands) {
            Write-PSFMessage -Level Verbose -Message "Processing command '$($command.Name)'"
            # extract parameter sets
            $parameterSets = $command.ParameterSets
            $commonParameterNames = "Verbose", "Debug", "ErrorAction", "WarningAction", "InformationAction", "ErrorVariable", "WarningVariable", "InformationVariable", "OutVariable", "OutBuffer", "PipelineVariable"

            Write-PSFMessage -Level SomewhatVerbose -Message "Found $($parameterSets.Count) parameter set(s) on command '$($command.Name)'"
            $output = foreach ($parameterSet in $parameterSets) {
                Write-PSFMessage -Level SomewhatVerbose -Message "Processing parameter set '$($parameterSet.Name)'"

                # extract parameters and filter out common parameters
                $parameters = $parameterSet.Parameters | Where-Object name -notin $commonParameterNames

                # When multiple parameter sets are available, add a comment with the parameter set name
                if ($parameterSets.count -gt 1) {
                    "# Parameter Set: $($parameterSet.Name)"
                    "# ---------------" + ([string]::join("", (0..($parameterSet.Name.Length - 1) | ForEach-Object { "-" } )))
                }

                # Begin the hashtable
                "@{"

                # loop through the parameters and add a comment with the parameter description
                Write-PSFMessage -Level SomewhatVerbose -Message "Processing $($parameters.Count) parameter(s) on parameter set '$($parameterSet.Name)' in command '$($command.Name)'"
                foreach ($parameter in $parameters) {
                    Write-PSFMessage -Level System -Message "Processing parameter '$($parameter.Name)'"

                    # Build help comment if not suppressed
                    if (-not $DoNotIncludeParameterHelpInformation) {
                        Write-PSFMessage -Level System -Message "Build help comment for parameter '$($parameter.Name)'"
                        $help = (Get-Help $command.Name -Parameter $parameter.name)

                        "$($indentString)<#"

                        $help.description.text.Split("`n") | ForEach-Object { "$($indentString)$($indentString)$($_)" }

                        "$($indentString)#>"
                    }

                    "$($indentString)$($parameter.name) = '<$($parameter.ParameterType.Name)>'    # IsMandatory: $($parameter.IsMandatory)"

                    if (-not $DoNotIncludeParameterHelpInformation) { "" }
                }

                # End the hashtable
                "}`n`n"
            }

            # Prepare writing file
            $fileaName = "example_$($command.Noun.replace($prefix, $null)).psd1"

            $FileFullname = (Join-Path -Path $filePath -ChildPath $fileaName)
            $paramOutFile = @{
                FilePath = $FileFullname
                Encoding = $Encoding
            }
            if ($Force) {
                $paramOutFile.Add("Force", $true)
            } else {
                if(Test-Path -Path $FileFullname -PathType Leaf) {
                    Write-PSFMessage -Level Warning -Message "File '$($FileFullname)' already exists and parameter -Force not specified. Skipping..."
                    continue
                }
            }

            # Write file
            if($PSCmdlet.ShouldProcess($outPath, "Write example file for command '$($command.Name)'")) {
                $output | Out-File @paramOutFile
            }
        }
    }
}
