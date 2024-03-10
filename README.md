![logo][]
# ADMF.Helper
| Plattform | Information |
| --------- | ----------- |
| PowerShell gallery | [![PowerShell Gallery](https://img.shields.io/powershellgallery/v/ADMF.Helper?label=psgallery)](https://www.powershellgallery.com/packages/ADMF.Helper) [![PowerShell Gallery](https://img.shields.io/powershellgallery/p/ADMF.Helper)](https://www.powershellgallery.com/packages/ADMF.Helper) [![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/ADMF.Helper?style=plastic)](https://www.powershellgallery.com/packages/ADMF.Helper) |
| GitHub  | [![GitHub release](https://img.shields.io/github/release/AndiBellstedt/ADMF.Helper.svg)](https://github.com/AndiBellstedt/ADMF.Helper/releases/latest) ![GitHub](https://img.shields.io/github/license/AndiBellstedt/ADMF.Helper?style=plastic) <br> ![GitHub issues](https://img.shields.io/github/issues-raw/AndiBellstedt/ADMF.Helper?style=plastic) <br> ![GitHub last commit (branch)](https://img.shields.io/github/last-commit/AndiBellstedt/ADMF.Helper/master?label=last%20commit%3A%20master&style=plastic) <br> ![GitHub last commit (branch)](https://img.shields.io/github/last-commit/AndiBellstedt/ADMF.Helper/Development?label=last%20commit%3A%20development&style=plastic) |
<br>

A PowerShell module with helper functions to support Active Directory Management Framework (ADMF).


# Purpose
The functions in the module should be a helper on building configuration files for ADMF, gettings the format of config files and some more things.\
Even while ADMF is giving a lot of help and even examples on generating config from given infrastructure, the functions in the module might provide more convenience on larger scale.\
\
Functions provide examples and explanations on each parameter.\
Functions in the module are *prefixed* with "`ADMFH`".

The module has dependencies on *-for the obvious-* on ADMF module.

# Changelog
Changes will be tracked in the [changelog.md](ADMF.Helper/changelog.md)
This file is also the reference information within the module.

# Installation
In order to get started with the module, simply run this in an elevated console:
```powershell
Install-Module ADMF.Helper
Import-Module ADMF.Helper
Get-Command -Module ADMF.Helper
```
This will install the module on your system, ready for use.

# Usage examples
## Generating sample config files
There is a capability in ADMF.Helper that generates example configuration files from the functions out of Active Directory Management Framework:
```powershell
    Invoke-ADMFHExampleGenerator
```
The function iterates through ADMF components, retrieves all available register commands and write sample config files. That might help to get familier with the given options in ADMF for new users.

## Create config from given structures
There is a capability in ADMF.Helper to create configuration files in PSD1 (default) or JSON format from the given Active Directory structure:
```powershell
    New-ADMFHDefinitionFileOrganizationalUnit
```
This will create a file "root.psd1" within the domain and separate psd1 files for all sub OUs found under domain root.

[logo]: assets/ADMF.Helper_128x128.png