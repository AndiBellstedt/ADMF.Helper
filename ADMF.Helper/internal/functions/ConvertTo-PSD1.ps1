function ConvertTo-PSD1 {
    <#
    .SYNOPSIS
        Converts an array of input objects into a PSD1 formatted string, with optional comments and formatting.

    .DESCRIPTION
        The ConvertTo-PSD1 function takes an array of input objects and converts them into a PSD1 formatted string.
        The function can be used to generate PSD1 formatted strings for use in configuration files.

    .PARAMETER InputObject
        The array of objects to be converted to a PSD1 formatted string.
        This parameter is mandatory and can be piped into the function.

    .PARAMETER CommentProperty
        The property of the input object to be used for generating comments in the output string.
        Defaults to 'canonicalname'.

    .PARAMETER CommentTransformation
        A script block that defines how to transform the CommentProperty into a comment string.
        By default, it removes the first part of the CommentProperty (up to the first '/') and trims the result.

    .PARAMETER Indentation
        The number of characters to use for indentation in the output string.
        Defaults to 4.

    .PARAMETER IndentChar
        The character to use for indentation in the output string.
        Defaults to a space.

    .PARAMETER FormatPretty
        If specified, the function will attempt to format the output string to be more readable.
        This includes padding keys to the same length and aligning the values.
        Defaults to $true.

    .PARAMETER NoArrayWhenSingleObject
        If specified, the function will not use array notation in the output string when all objects send to the function results in only a single object.

    .PARAMETER ForceIndentation
        If specified, the function will always use indentation, even if only a single object is sent to the function.

    .EXAMPLE
        PS> $myObject | ConvertTo-PSD1

        Converts the pscustomobject in $myObject into a PSD1 formatted string

    #>
    param(
        [Parameter(
            position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [psobject[]]
        $InputObject,

        [string]
        $CommentProperty = 'canonicalname',

        [scriptblock]$CommentTransformation = { $args[0].$CommentProperty.Replace($args[0].$CommentProperty.Split("/", 2)[0], "") },

        [int]
        $Indentation = 4,

        [string]
        $IndentChar = ' ',

        [bool]
        $FormatPretty = $true,

        [switch]
        $NoArrayWhenSingleObject,

        [switch]
        $ForceIndentation
    )

    begin {
        # build Indentation string
        $indentString = [string]::Join(
            "",
            (0 .. ($Indentation - 1) | ForEach-Object { $IndentChar })
        )

        # initialize output array
        $admfOuDefinitionList = New-Object System.Collections.ArrayList
    }


    process {
        # loop through input objects
        foreach ($objectItem in $InputObject) {

            # convert object to hashtable and then to PSD1 string
            #[array]$admfOuDefinition = $objectItem | ConvertTo-PSFHashtable -Exclude $CommentProperty | ConvertTo-Expression
            [array]$admfOuDefinition = $objectItem | ConvertTo-Hashtable -Exclude $CommentProperty | ConvertTo-Expression
            $admfOuDefinition = $admfOuDefinition.trimstart("[ordered]")


            # Padright to make to output pretty
            if ($FormatPretty) {
                $lines = ($admfOuDefinition -split "`n")
                $maxLength = $lines | Where-Object { $_ -like "*=*" } | ForEach-Object { $_.split("=")[0].trim().length } | Sort-Object | Select-Object -Last 1
                $admfOuDefinition = foreach ($line in $lines) {
                    if ($line -like "*=*") {
                        $keyChars = $line.split("=")[0].trim()
                        if ($keyChars.length -lt $maxLength) {
                            $line -replace $keyChars, $keyChars.PadRight(($maxLength), " ")
                        } else {
                            $line
                        }
                    } else {
                        $line
                    }
                }
            }

            # add indentation to each line of psd1 string, unless it is a single object and NoArrayWhenSingleObject is specified
            if ((-not ($NoArrayWhenSingleObject -and $admfOuDefinitionList.count -le 1)) -or $ForceIndentation) {
                $lines = ($admfOuDefinition -split "`n")
                [array]$admfOuDefinition = foreach ($line in $lines) {
                    "$($indentString)$($line)"
                }
            }

            # calculate comment text if applicable
            if ($CommentTransformation) {
                $commentText = $CommentTransformation.Invoke($objectItem)
            } elseif ($CommentProperty) {
                $commentText = $objectItem.$CommentProperty
            } else {
                $commentText = ""
            }

            # combine comment text and psd1 string
            if (($NoArrayWhenSingleObject -and $admfOuDefinitionList.count -le 1) -and (-not $ForceIndentation)) {
                # no indentation for single object
                [string]$outputString = ""
            } else {
                # indentation for multiple objects
                [string]$outputString = $indentString
            }
            $outputString = $outputString + "# " + $commentText + "`n" + [string]::Join("`n", $admfOuDefinition)

            # add to output array for final composition
            $null = $admfOuDefinitionList.add($outputString)
        }
    }

    end {
        # compose final output
        if ($NoArrayWhenSingleObject -and $admfOuDefinitionList.count -eq 1) {
            [string]$output = $admfOuDefinitionList
        } else {
            [string]$output = "(`n" + [string]::Join(",`n`n", $admfOuDefinitionList.ToArray()) + "`n)`n"
        }

        # return output
        $output
    }
}
