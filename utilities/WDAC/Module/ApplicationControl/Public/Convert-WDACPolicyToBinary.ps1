function Convert-WDACPolicyToBinary {

    <#
        .SYNOPSIS
        This function compiles a WDAC policy to make it ready for deployment
    
        .DESCRIPTION
    
        This function compiles a WDAC policy to make it ready for deployment
         
        .INPUTS
    
            $InputPolicyFile - input policy file
    
                    ex: "C:\temp\xyz.10.0.0.7.Base_Policy.xml"
    
            $OutputBinaryFile - applied to a base policy to enable Supplemental policy support
               
    
        .OUTPUTS
        
            Only the Supplemental Policy is modified: 
    
                    ex: "C:\temp\xyz.10.0.0.7.Policy.xml" (modified)
    
    
        .EXAMPLE
    
            ex: ".\Convert-WDACPolicyToBinary -InputPolicyFile $InputPolicyFile $OutputBinary $OutputBinary"
    
        .NOTES
    #>
    
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [string]$InputPolicyFile,
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [string]$OutputBinaryFile
    
        )
    
        $command = "ConvertFrom-CIPolicy -XmlFilePath $InputPolicyFile -BinaryFilePath $OutputBinaryFile"
        powershell.exe -command $command
       
    
    }
    