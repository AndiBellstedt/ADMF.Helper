@{
    # Script module or binary module file associated with this manifest
    RootModule           = 'ADMF.Helper.psm1'

    # Version number of this module.
    ModuleVersion        = '0.4.0'

    # ID used to uniquely identify this module
    GUID                 = '18182081-6c45-496e-9445-3df4083fa123'

    # Author of this module
    Author               = 'Andreas Bellstedt'

    # Company or vendor of this module
    CompanyName          = ''

    # Copyright statement for this module
    Copyright            = 'Copyright (c) 2024 Andreas Bellstedt'

    # Description of the functionality provided by this module
    Description          = 'Helper files to handle Active Directory Management Framework (ADMF). For example: Generating config file from ADMF commands, dumping current infrastructure into config files'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    # Supported PSEditions
    CompatiblePSEditions = 'Desktop'

    # Modules that must be imported into the global environment prior to importing
    # this module
    RequiredModules      = @(
        @{
            ModuleName    = 'PSFramework'
            ModuleVersion = '1.10.318'
        },
        @{
            ModuleName    = 'ADMF'
            ModuleVersion = '1.13.100'
        }
    )

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @('bin\ADMF.Helper.dll')

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @('xml\ADMF.Helper.Types.ps1xml')

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @('xml\ADMF.Helper.Format.ps1xml')

    # Functions to export from this module
    FunctionsToExport    = @(
        'Invoke-ADMFHExampleGenerator',
        'New-ADMFHDefinitionFileAccessRule',
        'New-ADMFHDefinitionFileGroup',
        'New-ADMFHDefinitionFileOrganizationalUnit',
        'New-ADMFHDefinitionFileSchemaAttribute'
    )

    # Cmdlets to export from this module
    CmdletsToExport      = ''

    # Variables to export from this module
    VariablesToExport    = ''

    # Aliases to export from this module
    AliasesToExport      = ''

    # List of all modules packaged with this module
    ModuleList           = @()

    # List of all files packaged with this module
    FileList             = @()

    # Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData          = @{

        #Support for PowerShellGet galleries.
        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @(
                'ADMF',
                'Helper',
                'ADMF.Helper',
                'ActiveDirectoryManagementFramework'
            )

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/AndiBellstedt/ADMF.Helper/blob/main/license'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/AndiBellstedt/ADMF.Helper'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'https://github.com/AndiBellstedt/ADMF.Helper/blob/main/ADMF.Helper/changelog.md'

        } # End of PSData hashtable

    } # End of PrivateData hashtable
}