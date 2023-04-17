function New-WDACSolution {

    <#
        .SYNOPSIS
        This function automates the creation of a WDAC solution for scenarios such as PAW-CSM with the help of the other functions in this module.
    
        .DESCRIPTION
    
        This function automates the creation of a WDAC solution for scenarios such as PAW-CSM with the help of the other functions in this module.
        The currently supported solutions are:
    
        -PAW-CSM
    
        Future targeted solutions are:
    
        -CR (compromised recovery)
        -ZTworkstation (Lightly-Managed Zero Trust Workstation)
    
        Solutions are exported as a ZIP file containing the following directories:
    
         - policy_binaries
         - policy_templates
         - policy_xml
         
        .INPUTS
    
            $Solution - the chosen solution
    
                ex: "PAWCSM"      
    
            $policyversion - the desired policy version 
                           - acceptable values 0.0.0.0 - 999.999.999.999
                           - recommended values to match Windows 10 build numbers 10.0.0.0 - 10.999.999.999
    
                    ex: "10.0.0.5"
    
            $org - short acronym representing your organization
    
                    ex: "abc"
            
            $PolicyMode - policy enforcement mode
    
                    ex: "Audit"
                    ex: "Enforced"                
    
                    
            $PolicyContentFolder - your policy files directory. For this solution it should contain the following content:
    
                    ├───Custom
                    │       Block_Unwanted_MS.xml
                    │       Microsoft_Recommended_Block_Rules.xml
                    │
                    └───Microsoft
                            AllowMicrosoft.xml
                            DefaultWindows_Enforced.xml                 
    
            $OutputDirectory - directory where the WDAC solution
    
                    ex: "c:\temp"         
    
        .OUTPUTS
        
            WDAC Solution Zip File: 
    
                    ex: "C:\temp\WDAC_Policy.10.0.0.7_2021.06.18_19.52.zip"
    
        .EXAMPLE
    
            ex: .\New-WDACSolution -Solution PAWCSM -policyversion 10.0.0.5 -org abc -PolicyContentFolder "C:\code\msft\trejo.code\dev_wdac\Policy_Templates" -OutputDirectory "c:\temp"
    
        .NOTES
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateSet('PAWCSM', 'PAWCR', 'ZTworkstation')]
        [string]$Solution,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$policyversion,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$org,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateSet('Audit', 'Enforced')]
        [string]$PolicyMode,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$PolicyTemplatesFolder, 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$OutputDirectory
    )
    
        #create workspace
        New-WDACPolicyWorkspace -policyversion $policyversion -org $org
    
        #policy name format
        $policyName = $org + "." + $policyversion
    
    
        if ($Solution -eq "PAWCSM")
        {
    
            #create base policy    
            $policytype = "Base"
            $script:BasePolicy_Blank_Name = $policyName + "." + $policytype + "_Policy_Blank"
            $script:BasePolicy_Blank_File = $policyWorkspacePath + "\policy_xml\" + $BasePolicy_Blank_Name + ".xml"
    
            New-WDACPolicy -policyversion $policyversion -policytype Base -OutputPolicyFile $BasePolicy_Blank_File
    
             #templates - define file name
             $script:BasePolicy_WithTemplates_Name = $policyName + "." + $policytype + "_Policy_WithTemplates"
             $script:BasePolicy_WithTemplates_File = $policyWorkspacePath + "\policy_xml\" + $BasePolicy_WithTemplates_Name + ".xml"

             #templates - add OS template
             copy-item $PolicyTemplatesFolder\Microsoft\DefaultWindows_Enforced.xml $policyWorkspacePath\policy_templates\DefaultWindows_Enforced.xml -Force
             Add-WDACPolicyFiles -InputPolicyFile $BasePolicy_Blank_File -PolicyFiles "$policyWorkspacePath\policy_templates\DefaultWindows_Enforced.xml" -OutputPolicyFile $BasePolicy_WithTemplates_File      
           
            #templates - add recommended templates
            copy-item -Recurse $PolicyTemplatesFolder\Custom\ $policyWorkspacePath\policy_templates -Force
            Add-WDACPolicyFiles -InputPolicyFile $BasePolicy_WithTemplates_File -PolicyFiles "$policyWorkspacePath\policy_templates\Custom\" -OutputPolicyFile $BasePolicy_WithTemplates_File -Overwrite
    
            #create supplemental policy
            $policytype = "Supplemental"
            $script:SupplementalPolicy_Blank_Name = $policyName + "." + $policytype + "_Policy_Blank"
            $script:SupplementalPolicy_Blank_File = $policyWorkspacePath + "\policy_xml\" + $SupplementalPolicy_Blank_Name + ".xml"
    
            New-WDACPolicy -policyversion $policyversion -policytype Supplemental -OutputPolicyFile $SupplementalPolicy_Blank_File
    
            #add default path rules to supplemental policy
            $script:SupplementalPolicy_WithDefaultPaths_Name = $policyName + "." + $policytype + "_Policy_WithDefaultPaths"
            $script:SupplementalPolicy_WithDefaultPaths_File = $policyWorkspacePath + "\policy_xml\" + $SupplementalPolicy_WithDefaultPaths_Name + ".xml"
    
            Add-WDACPolicyDefaultFilePathRules -InputPolicyFile $SupplementalPolicy_Blank_File -OutputPolicyFile $SupplementalPolicy_WithDefaultPaths_File
            
            
            #configure base policy base policy
            $policytype = "Base"
            $script:BasePolicy_Name = $policyName + "." + $policytype + "_Policy"
            $script:BasePolicy_File = $policyWorkspacePath + "\policy_xml\" + $BasePolicy_Name + ".xml"
    
            $policytype = "Supplemental"
            $script:SupplementalPolicy_Name = $policyName + "." + $policytype + "_Policy"
            $script:SupplementalPolicy_File = $policyWorkspacePath + "\policy_xml\" + $SupplementalPolicy_Name + ".xml"
    
            Copy-Item $BasePolicy_WithTemplates_File $BasePolicy_File
            Copy-Item $SupplementalPolicy_WithDefaultPaths_File $SupplementalPolicy_File
    
            #register supplemental policy with base policy
            Add-WDACSupplementalPolicyToBasePolicy -SupplementalPolicyFile $SupplementalPolicy_File -BasePolicyFile $BasePolicy_File
    
            
            If ($PolicyMode -eq 'Audit') {
            
                Set-WDACPolicy -PolicyFile $BasePolicy_File -PolicyMode Audit -SupportsSupplementalPolicy
                Set-WDACPolicy -PolicyFile $SupplementalPolicy_File -PolicyMode Audit
    
            }
    
    
            If ($PolicyMode -eq 'Enforced') {
                
                Set-WDACPolicy -PolicyFile $BasePolicy_File -PolicyMode Enforced -SupportsSupplementalPolicy
                Set-WDACPolicy -PolicyFile $SupplementalPolicy_File -PolicyMode Enforced
    
            }
    
            # Enable HVCI          
            Set-HVCIOptions -Enabled -FilePath $BasePolicy_File
    
    
            #generate binaries
            $policytype = "Base"
            $script:BasePolicy_Binary_Name = $policyName + "." + $policytype + "_Policy"
            $script:BasePolicy_Binary_File = $policyWorkspacePath + "\policy_binaries\" + $BasePolicy_Binary_Name + ".bin"
    
            $policytype = "Supplemental"
            $script:SupplementalPolicy_Binary_Name = $policyName + "." + $policytype + "_Policy"
            $script:SupplementalPolicy_Binary_File = $policyWorkspacePath + "\policy_binaries\" + $SupplementalPolicy_Binary_Name + ".bin"
        
            Convert-WDACPolicyToBinary -InputPolicyFile $BasePolicy_File -OutputBinaryFile $BasePolicy_Binary_File
            Convert-WDACPolicyToBinary -InputPolicyFile $SupplementalPolicy_File -OutputBinaryFile $SupplementalPolicy_Binary_File
    
            ####################
            #Generate OMI-URIs
            ####################
    
            #Enumerate Policy IDs
            [xml]$BasePolicyXML = get-content $BasePolicy_File
            $BasePolicyGUID = $BasePolicyXML.SiPolicy.PolicyID -replace '[{}]', ""
      
            [xml]$SupplementalPolicyXML = get-content $SupplementalPolicy_File
            $SupplementalPolicyGUID = $SupplementalPolicyXML.SiPolicy.PolicyID -replace '[{}]', ""
    
    
            $OMAURIs = @()
            $OMAURIs += "To deploy these policies via Intune, use these custom OMA-URI values `n"
            $OMAURIs += "`n"
            $OMAURIs += "OMA-URIs for Policies: `n"
            $OMAURIs += "`n"
            $OMAURIs += "        Base Policy:" + "   ./Vendor/MSFT/ApplicationControl/Policies/" + $BasePolicyGUID + "/Policy `n"
            $OMAURIs += "Supplemental Policy:" + "   ./Vendor/MSFT/ApplicationControl/Policies/" + $SupplementalPolicyGUID + "/Policy `n"
            $OMAURIs += "`n" 
    
            Write-Host $OMAuris -ForegroundColor White -BackgroundColor Blue 
            $OMAURIsExport = $policyWorkspacePath + "\policy_binaries\" + "OMA-URIs.txt" 
            $OMAuris | Out-File -FilePath $OMAURIsExport
            
            #output and cleanup
            Export-WDACPolicyWorkspace -policyWorkspacePath $policyWorkspacePath -OutputDirectory $OutputDirectory
            Remove-WDACPolicyWorkspace -policyWorkspacePath $policyWorkspacePath
    
        }
        
    
        if ($Solution -eq "PAWCR" -or $Solution -eq "ZTworkstation")
        {
    
            Write-Host "This solution is no supported yet."
    
        }
    
    }