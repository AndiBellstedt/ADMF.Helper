function ConvertTo-Hashtable {
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