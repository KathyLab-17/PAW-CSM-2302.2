function New-WDACPolicy {

    <#
        .SYNOPSIS
        This function creates a blank WDAC policy
    
        .DESCRIPTION
    
        This function creates a blank WDAC policy
         
        .INPUTS
    
            $policyversion - the desired policy version 
                           - acceptable values 0.0.0.0 - 999.999.999.999
                           - recommended values to match Windows 10 build numbers 10.0.0.0 - 10.999.999.999
    
                    ex: "10.0.0.5"
    
            $policytype - sets policy type
    
                    ex: "Base"
                    ex: "Supplemental"                       
    
            $OutputPolicyFile - output policy file
    
                    ex: "C:\Users\user5\AppData\Local\Temp\f9c74795-b8c3-4703-9d8a-45816ba89967\WDAC_Policy.10.0.0.9\policy_xml\policy.xml"         
    
        .OUTPUTS
        
            WDAC policy file: 
    
                    ex: "C:\Users\user5\AppData\Local\Temp\f9c74795-b8c3-4703-9d8a-45816ba89967\WDAC_Policy.10.0.0.9\policy_xml\policy.xml" 
    
        .EXAMPLE
    "
                    ex: "New-WDACPolicy -policyversion 10.0.0.9 -org abc -policytype Base -OutputPolicyFile C:\Users\user5\AppData\Local\Temp\f9c74795-b8c3-4703-9d8a-45816ba89967\WDAC_Policy.10.0.0.9\policy_xml\policy.xml"
    
        .NOTES
    #>
    
    
        [CmdletBinding()] 
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [ValidatePattern("(^\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3})$")]
            [string]$policyversion,
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [ValidateSet('Base', 'Supplemental')]
            [string]$policytype,
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [string]$OutputPolicyFile
        )
    
        #empty scan path
        $script:TempScanDirectory = $env:temp + "\" + [System.Guid]::NewGuid().ToString()
        New-Item -ItemType Directory -Path $TempScanDirectory
    
        #Create blank base policy
        New-CIPolicy -FilePath $OutputPolicyFile -UserPEs -ScanPath $TempScanDirectory\ -Level PcaCertificate -MultiplePolicyFormat
        Set-CIPolicyVersion -FilePath $OutputPolicyFile -Version $policyversion
    
        remove-item -Path $TempScanDirectory -Recurse -force
    }