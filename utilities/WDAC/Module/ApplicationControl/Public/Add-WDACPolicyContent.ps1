function Add-WDACPolicyContent {

    <#
    .SYNOPSIS
    This function scans a target directory for file content, indexes it, specify how applications are identified and trusted, and adds that content to WDAC policy file (.xml).

    .DESCRIPTION
    This function scans a target directory for file content, indexes it, specify how applications are identified and trusted, and adds that content to WDAC policy file (.xml).

    This policy default to using the following recommended file rule levels:

                     Primary: FilePublisher (this is a signed value)
                     Fallback: Hash (used in the event that the file is not signed)

    If needed, this function accepts all supported file rule levels:

                    None, Hash, FileName, FilePath, SignedVersion, PFN, Publisher, FilePublisher, LeafCertificate, PcaCertificate, RootCertificate, WHQL, WHQLPublisher, WHQLFilePublisher

    This function supports both ALLOW and BLOCK rules. The default is ALLOW.

    TIP: For others to better understand the WDAC policies that has been deployed, we recommend maintaining separate ALLOW and DENY policies on Windows 10.

         Consider adding ALLOW rules to a separate policy, such as Supplemental policy

     
    .INPUTS

        $InputPolicyFile - folder path to a policy file

                ex: "C:\temp\xyz.10.0.0.7.Base_Policy.xml"

        $ContentPath - folder path to content that will be scanned for identified

                ex: "C:\temp\xyz.10.0.0.7.Base_Policy.xml"

        $RuleLevel - primary file rule criteria used to specify the level at which binaries should be trusted (Default: FilePublisher) 

        $FallbackRuleLevel - Used when the discovered binaries cannot be trusted based on the primary file rule criteria

        $RuleAction - Marks whether identified binaries should trusted ('ALLOW') or blocked ('BLOCK') (Default: ALLOW)

        $OutputPolicyFile - Output file path
        
                      - Required if the $Overwrite switch is not used

        $Overwrite - Optional switch that enables overwriting of the input file


    .OUTPUTS
    
        ALLOW or BLOCK rules will be added to the policy

        ex:

          <FileRules>
            <Allow ID="ID_ALLOW_A_10_1" FriendlyName="C:\WINDOWS\* FileRule" MinimumFileVersion="0.0.0.0" FilePath="C:\WINDOWS\*" />
            <Allow ID="ID_ALLOW_A_11_1" FriendlyName="C:\Program Files\* FileRule" MinimumFileVersion="0.0.0.0" FilePath="C:\Program Files\*" />
            <Allow ID="ID_ALLOW_A_12_1" FriendlyName="C:\Program Files (x86)\* FileRule" MinimumFileVersion="0.0.0.0" FilePath="C:\Program Files (x86)\*" />
          </FileRules>

                
    .EXAMPLE

        ex: .\Add-WDACPolicyContent -InputPolicyFile "C:\Temp\45816ba89967\policy.xml" -ContentPath "C:\Program Files (x86)\Git\bin\" -OutputPolicyFile "C:\Temp\45816ba89967\policy.xml" -Action Allow -Overwrite   

    .NOTES
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$InputPolicyFile,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$ContentPath,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string[]]$RuleLevel = "FilePublisher",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string[]]$FallbackRuleLevel = "Hash",
        [Parameter(ValueFromPipeline = $true)]
        [ValidateSet('Allow', 'Block')]
        [string]$RuleAction = 'Allow',
        [Parameter(ValueFromPipeline = $true)]
        [string]$OutputPolicyFile,
        [Parameter(ValueFromPipeline = $true)]
        [switch]$Overwrite

    )



    if ($true -eq $overwrite) {

        $script:TempDirectory = $env:temp + "\" + [System.Guid]::NewGuid().ToString()
        New-Item -ItemType Directory -Path $TempDirectory

        $NewContent = $TempDirectory + "NewContent.xml"
        $MergedPolicy = $TempDirectory +  "MergedPolicy.xml"

        #expands the variable before running due to cmdlet limitations
        #generate file with new content

        if ($RuleAction -eq "Allow")

        {
        $command = "New-CIPolicy -Level $RuleLevel -Fallback $FallbackRuleLevel -UserPEs -ScanPath '$ContentPath' -FilePath $NewContent"
        powershell.exe -command $command

        }

        if ($RuleAction -eq "Block")

        {
        $command = "New-CIPolicy -Level $RuleLevel -Fallback $FallbackRuleLevel -UserPEs -ScanPath '$ContentPath' -FilePath $NewContent -Deny"
        powershell.exe -command $command
        }
      
        #merges input policy and new content. Removes $NewContent file
        #expands the variable before running due to cmdlet limitations
        powershell.exe -command "Merge-CIPolicy -PolicyPaths "$InputPolicyFile, $NewContent" -OutputFilePath $MergedPolicy"
        remove-item $NewContent

        $InputPolicyPath = (get-item $InputPolicyFile).FullName
        move-item -Path $MergedPolicy $InputPolicyPath -Force   


    }

    if ($true -ne $overwrite) {

        #WDAC File Rule Levels 
        #None, Hash, FileName, FilePath, SignedVersion, PFN, Publisher, FilePublisher, LeafCertificate, PcaCertificate, RootCertificate, WHQL, WHQLPublisher, WHQLFilePublisher

        if ($RuleAction -eq "Allow")

        {
        #expands the variable before running due to cmdlet limitations
        $command = "New-CIPolicy -Level $RuleLevel -Fallback $FallbackRuleLevel -UserPEs -ScanPath '$ContentPath' -FilePath $OutputPolicyFile"
        powershell.exe -command $command

        }

        if ($RuleAction -eq "Block")

        {
        #expands the variable before running due to cmdlet limitations
        $command = "New-CIPolicy -Level $RuleLevel -Fallback $FallbackRuleLevel -UserPEs -ScanPath '$ContentPath' -FilePath $OutputPolicyFile -Deny"
        powershell.exe -command $command
        }
   
    }

    
}