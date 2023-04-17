function Add-WDACSupplementalPolicyToBasePolicy {

    <#
        .SYNOPSIS
        This function registers a Supplemental Policy with Base Policy.
    
        .DESCRIPTION
    
        This function registers a Supplemental Policy with Base Policy.
    
                         The policy type is changed: <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Supplemental Policy">
    
        A reference to the base policy is added to the Supplemental Policy file. 
        The Supplemental PolicyID is regenerated.
    
                        <BasePolicyID>{EAC65B98-0402-4D60-B120-5ACBFD5577E0}</BasePolicyID>
                        <PolicyID>{2FA0B38B-A724-4F04-9B7D-BC28A5F26C91}</PolicyID>
    
         
        .INPUTS
    
            $BasePolicyFile - input base policy
    
                    ex: "C:\temp\xyz.10.0.0.7.Base_Policy.xml"
    
            $SupplementalPolicyFile - input $SupplementalPolicy policy
    
                    ex: "C:\temp\xyz.10.0.0.7.Supplemental_Policy.xml"
    
        .OUTPUTS
        
            Only the Supplemental Policy is modified: 
    
                    ex: "C:\temp\xyz.10.0.0.7.Supplemental_Policy.xml (modified)"
        .EXAMPLE
    
            ex: .\Add-WDACSupplementalPolicyToBasePolicy -SupplementalPolicyFile $SupplementalPolicy_File -BasePolicyFile $BasePolicy_File
    
        .NOTES
    #>
    
    
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [string]$BasePolicyFile,
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [string]$SupplementalPolicyFile
    
        )
    
    
        #configure supplementary policy - configure base and supplemental policy relationship
        Set-CIPolicyIdInfo -FilePath $SupplementalPolicyFile -BasePolicyToSupplementPath $BasePolicyFile
    
    }