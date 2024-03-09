function ConvertTo-Hashtable {
    <#
    .SYNOPSIS
        Converts an input object to a hashtable.

    .DESCRIPTION
        The ConvertTo-Hashtable function takes an input object and converts it to a hashtable.
        It iterates over each property of the input object and adds it to the hashtable.
        Properties specified in the Exclude parameter are not added to the hashtable.

    .PARAMETER InputObject
        The input object to convert to a hashtable. This parameter is mandatory.

    .PARAMETER Exclude
        An array of property names to exclude from the hashtable.

    .EXAMPLE
        $obj = New-Object PSObject -Property @{
            Name = "John Doe"
            Age = 30
            Country = "USA"
        }
        ConvertTo-Hashtable -InputObject $obj -Exclude "Country"
        Returns a hashtable with the properties Name and Age.

    .INPUTS
        System.Object[]

    .OUTPUTS
        System.Collections.Hashtable

    .NOTES
        The function uses the PSObject.Properties property to get the properties of the input object.
        It uses the Where-Object cmdlet to filter out the properties specified in the Exclude parameter.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]
        $InputObject,

        [string[]]
        $Exclude
    )

    begin {}

    process {
        $ht = [ordered]@{}
        foreach ($item in $InputObject) {

            foreach($prop in ($item.PSObject.Properties | Where-Object name -notin $Exclude)) {
                $ht[$prop.Name] = $prop.Value
            }
        }
        $ht
    }

    end {}
}