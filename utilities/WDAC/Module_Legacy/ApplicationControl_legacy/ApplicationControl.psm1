<#
    .SYNOPSIS
        This module contains cmdlets that streamline application control policy creation for common scenarios
    
    .DESCRIPTION
    The included functions enable creation of unsigned base and supplemental WDAC Policies and Policy solutions for testing and production use.

    .LINK
        Links to further documentation.

    .NOTES

-----------------------------------------------------------------------------------------------------------------------------------
Module Name : ApplicationControl.psm1
Authors : David Trejo (datrejo@microsoft.com)
Version : 2021.06
-----------------------------------------------------------------------------------------------------------------------------------
Copyright :           Copyright (c) 2020 Microsoft     @  https://www.microsoft.com/

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the “Software”), to deal in the Software without
restriction, including without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies 
or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING 
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-----------------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------
MICROSOFT DISCLAIMER
THIS CODE IS SAMPLE CODE. THESE SAMPLES ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
MICROSOFT FURTHER DISCLAIMS ALL IMPLIED WARRANTIES INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES
OF MERCHANTABILITY OR OF FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK ARISING OUT OF THE USE OR
PERFORMANCE OF THE SAMPLES REMAINS WITH YOU. IN NO EVENT SHALL MICROSOFT OR ITS SUPPLIERS BE LIABLE FOR
ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS
INTERRUPTION, LOSS OF BUSINESS INFORMATION, OR OTHER PECUNIARY LOSS) ARISING OUT OF THE USE OF OR
INABILITY TO USE THE SAMPLES, EVEN IF MICROSOFT HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
BECAUSE SOME STATES DO NOT ALLOW THE EXCLUSION OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR
INCIDENTAL DAMAGES, THE ABOVE LIMITATION MAY NOT APPLY TO YOU.
-----------------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------

#>

function New-WDACPolicyWorkspace {

<#
.SYNOPSIS
This function creates a temporary working directory

.DESCRIPTION
The function creates a temporary working directly in c:\temp

.INPUTS

    $policyversion - 4-digit policy version (ex: 10.0.2.5)

    $org - acronym for your org (ex: abc)                
   
.OUTPUTS
    Temporary Directory

    ex: "C:\Users\User\AppData\Local\Temp\826e34d4-c461-4402-ae14-86482d6b875d\WDAC_Policy.10.0.2.5"

.EXAMPLE
    
    ex: ".\New-WDACPolicyWorkspace -policyversion 10.0.2.5 -org abc"

.NOTES
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidatePattern("(^\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3})$")]
        [string]$policyversion,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$org
    )

    $script:WorkingDirectory = $env:temp + "\" + [System.Guid]::NewGuid().ToString()
    New-Item -ItemType Directory -Path $WorkingDirectory

    $date = (Get-Date).ToString("yyyy.MM.dd_HH.mm")    
    
    $script:policyWorkspacePath = $WorkingDirectory + "\WDAC_Policy.$policyversion"
    $script:policyTemplatesPath = $policyWorkspacePath + "\policy_files\"
    $script:policyXmlPath = $policyWorkspacePath + "\policy_xml\"
    $script:policyBinariesPath = $policyWorkspacePath + "\policy_binaries\" 

    $script:LogPath = $policyWorkspacePath + "\Logs"
    $script:LogFile = $LogPath + "\" + "ApplicationControlPolicyOperations" + "_" + $date + ".log"

    new-item -ItemType Directory $policyWorkspacePath -Force
    new-item -ItemType Directory $policyTemplatesPath -Force
    new-item -ItemType Directory $policyXmlPath -Force
    new-item -ItemType Directory $policyBinariesPath -Force

    New-item -ItemType Directory $LogPath -Force
            
}
function Export-WDACPolicyWorkspace {

    <#
    .SYNOPSIS
    This function exports temporary working directory as a zip file

    .DESCRIPTION
    This function exports temporary working directory as a zip file to a user-defined location

    .INPUTS

        $policyWorkspacePath - folder path 

        $OutputDirectory - directory for the output file

    
    .OUTPUTS
        <filename.zip>

        ex: "C:\temp\WDAC_Policy.10.0.0.7_2021.06.18_19.52.zip"

    .EXAMPLE
        Example use of function that exports contents and removes the source directory

        .\Export-WDACPolicyWorkspace -policyWorkspacePath "C:\Temp\86482d6b875d\WDAC_Policy.10.0.2.5" -OutputDirectory C:\temp\

    .NOTES
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$policyWorkspacePath,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$OutputDirectory
    )
    

    $date = (Get-Date).ToString("yyyy.MM.dd_HH.mm")

    If (Test-path $policyWorkspacePath) {

            
        $script:OutputFile = $OutputDirectory + "\" + (get-item $policyWorkspacePath).name + "_" + $date + ".zip"
    
        Set-Location $policyWorkspacePath
        #Set-Location ..
        Compress-Archive -Path $policyWorkspacePath -DestinationPath $OutputFile

            
    }   
    else {
        Write-Host "An Application Control Policy Workspace Path is not in memory. Set $policyWorkspacePath to the path that you want to export and try again"
    }
}

function Remove-WDACPolicyWorkspace {

    <#
    .SYNOPSIS
    This function removes temporary working directory

    .DESCRIPTION
    This function removes a temporary working directory

    .INPUTS

        $policyWorkspacePath -folder path to remove

    .OUTPUTS
        
        ex: Deletion of "C:\temp\WDAC_Policy.10.0.0.7_2021.06.18_19.52.zip"

    .EXAMPLE        
    
        ex: .\Remove-WDACPolicyWorkspace -policyWorkspacePath "C:\Temp\86482d6b875d\WDAC_Policy.10.0.2.5"

    .NOTES
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$policyWorkspacePath
    )


    If (Test-path $policyWorkspacePath) {

        Set-Location $policyWorkspacePath
        Set-Location ..
        Remove-Item -Path $policyWorkspacePath -Force -Recurse
    }   
    else {
        Write-Host "An Application Control Policy Workspace Path is not in memory. Set $policyWorkspacePath to the path that you want to remove and try again"
    }
}

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

function Add-WDACPolicyFiles {

    <#
    .SYNOPSIS
    This function merges WDAC policy files (.xml), such as a templates, with a input policy.

    .DESCRIPTION
    This function merges WDAC policy files (.xml), such as a templates, with a input policy.     
     
    .INPUTS

        $InputPolicyFile - folder path to a policy file

                ex: "C:\temp\xyz.10.0.0.7.Base_Policy.xml"

        $PolicyFiles - path to policy file or directory that contains one or more policy files

                "c:\temp\DefaultWindows_Enforced.xml"

                "c:\temp"

        $OutputPolicyFile - Output file path
        
                      - Required if the $Overwrite switch is not used

        $Overwrite - Optional switch that enables overwriting of the input file


    .OUTPUTS
    
        This policy supports creation of new files as outputs or overwriting the input.

                ex: "C:\temp\policy.xml"

                ex: "C:\temp\policy_updated.xml"

    .EXAMPLE

                ex: .\Add-WDACPolicyFiles -InputPolicyFile $InputPolicyFile -PolicyFiles "c:\temp\DefaultWindows_Enforced.xml" -OutputPolicyFile $OutputPolicy

                ex: .\Add-WDACPolicyFiles -InputPolicyFile $InputPolicyFile -PolicyFiles "c:\temp" -OutputPolicyFile $OutputPolicy

    .NOTES
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$InputPolicyFile,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$PolicyFiles,
        [Parameter(ValueFromPipeline = $true)]
        [string]$OutputPolicyFile,
        [Parameter(ValueFromPipeline = $true)]
        [switch]$Overwrite

    )

    $PolicyPaths = @()
    $PolicyPaths += "`"$InputPolicyFile`"" + ","
    
    $IsDirectory = Test-Path $PolicyFiles -PathType Container

    if ($true -eq $IsDirectory)
    {

        $i = 0

        $items = (Get-ChildItem $PolicyFiles).fullname

        ForEach ( $item in $items ) {

            If ($i -lt ($items.count - 1)) {

                $PolicyPaths += "`"$item`"" + ","
                $i++

            }
            else {

                $PolicyPaths += "`"$item`"" 
        
            }
    

        }

    }

    if ($false -eq $IsDirectory)
    {

        $i = 0

        ForEach ( $PolicyFile  in $PolicyFiles ) {

            If ($i -lt ($PolicyFile.count - 1)) {

                $PolicyPaths += "`"$PolicyFile`"" + ","
                $i++

            }
            else {

                $PolicyPaths += "`"$PolicyFile`"" 
    
            }


        }


    }


    if ($true -eq $overwrite) {

        $script:TempDirectory = $env:temp + "\" + [System.Guid]::NewGuid().ToString()
        New-Item -ItemType Directory -Path $TempDirectory

        $MergedPolicy = $TempDirectory + "\" + "MergedPolicy.xml"

        $command = "Merge-CIPolicy -PolicyPaths $PolicyPaths -OutputFilePath $MergedPolicy"
        powershell.exe -command $command
        
        $InputPolicyPath = (get-item $InputPolicyFile).FullName
        move-item -Path $MergedPolicy $InputPolicyPath -Force   

    }


    if ($true -ne $overwrite) {
        
        #expands the variable before running due to MERGE-CIPOLICY cmdlet limitations
        $command = "Merge-CIPolicy -PolicyPaths $PolicyPaths -OutputFilePath $OutputPolicyFile"
        powershell.exe -command $command
        
    }

}


function Add-WDACPolicyDefaultFilePathRules {
   
    <#
    .SYNOPSIS
    This function adds common path rules to an WDAC policy file (.xml).

    .DESCRIPTION
    This function adds commonly trusted paths as path rules to a WDAC policy file (.xml). A switch allows support for an ARM-specific folder.
   
    The Default Paths path rules are:
   
        C:\WINDOWS\*
        C:\ProgramData\*
        C:\Program Files\*
        C:\Program Files (x86)\*    (Present on ARM devices - ex: Surface Pro X)
     
    .INPUTS

        $InputPolicyFile - folder path to a policy file

                ex: "C:\temp\xyz.10.0.0.7.Base_Policy.xml"

        $ArmSupport - adds an ARM-specific path for x86-emulated content

        $OutputPolicyFile - Output file path
        
                      - Required if the $Overwrite switch is not used

        $Overwrite  - Optional switch that enables overwriting of the input file


    .OUTPUTS
    
        This policy supports creation of new files as outputs or overwriting the input.

                ex: "C:\temp\policy.xml"

                ex: "C:\temp\policy_updated.xml"

    .EXAMPLE

                ex: .\Add-WDACPolicyDefaultFilePathRules -InputPolicyFile $InputPolicyFile -OutputPolicyFile $OutputPolicyFile

                ex: .\Add-WDACPolicyDefaultFilePathRules -InputPolicyFile $InputPolicyFile -OutputPolicyFile $OutputPolicyFile -ArmSupport

    .NOTES
#>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$InputPolicyFile,
        [Parameter(ValueFromPipeline = $true)]
        [switch]$ArmSupport,
        [Parameter(ValueFromPipeline = $true)]
        [string]$OutputPolicyFile,
        [Parameter(ValueFromPipeline = $true)]
        [switch]$Overwrite


    )

    #prepare environmental variables and wildcards
    $windir = ${Env:windir} + "\*"
    $ProgramW6432 = ${Env:ProgramW6432} + "\*"
    $ProgramFiles_x86 = ${Env:ProgramFiles(x86)} + "\*"
    $ProgramFiles_arm = ${Env:ProgramFiles(Arm)} + "\*"

    #generate file path rules
    $CIPolicyRules = @() 
    $CIPolicyRules += New-CIPolicyRule -FilePathRule $windir
    $CIPolicyRules += New-CIPolicyRule -FilePathRule $ProgramW6432
    $CIPolicyRules += New-CIPolicyRule -FilePathRule $ProgramFiles_x86

    #generate path rules - optional arm64 support
    if ($ArmSupport -eq $true) {

        $CIPolicyRules += New-CIPolicyRule -FilePathRule $ProgramFiles_Arm
    
    }

    #Create temp policy with file paths
    $script:TempDirectory = $env:temp + "\" + [System.Guid]::NewGuid().ToString()
    New-Item -ItemType Directory -Path $TempDirectory

    $DefaultFilePathRulesFile = $TempDirectory + "\" + "DefaultFilePathRules.xml"

    New-CIPolicy -FilePath $DefaultFilePathRulesFile -UserPEs -Rules $CIPolicyRules -MultiplePolicyFormat
    
    if ($true -eq $overwrite) {

        $tempPolicyFile = $TempDirectory + "\" + "tempPolicyFile.xml"

        $command = "Merge-CIPolicy -PolicyPaths $InputPolicyFile, $DefaultFilePathRulesFile -OutputFilePath $tempPolicyFile"
        powershell.exe -command $command
    
        $InputPolicyPath = (get-item $InputPolicyFile).FullName
        move-item -Path $tempPolicyFile $InputPolicyPath -Force

    }

    if ($true -ne $overwrite) {

        #expands the variable before running due to MERGE-CIPOLICY cmdlet limitations
        $command = "Merge-CIPolicy -PolicyPaths $InputPolicyFile, $DefaultFilePathRulesFile -OutputFilePath $OutputPolicyFile"
        powershell.exe -command $command
   
    }

    remove-item $DefaultFilePathRulesFile


}

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

function Set-WDACPolicy {

<#
    .SYNOPSIS
    This function configures a WDAC Policy according to recommended settings.

    .DESCRIPTION

   This function configures recommended WDAC Policy settings including whether the policy is in audit mode or whether the policy is enforced.
     
    .INPUTS

        $PolicyFile - input policy file

                ex: "C:\temp\xyz.10.0.0.7.Base_Policy.xml"


        $PolicyMode - policy enforcement mode

                ex: "Audit"
                ex: "Enforced"                

        $SupportsSupplementalPolicy - applied to a base policy to enable Supplemental policy support
           

    .OUTPUTS
    
        Only the Supplemental Policy is modified: 

                ex: "C:\temp\xyz.10.0.0.7.Policy.xml (modified)"


                Default Policy Rules:

                <Rules>
                    <Rule>
                    <Option>Enabled:UMCI</Option>
                    </Rule>
                    <Rule>
                    <Option>Required:WHQL</Option>
                    </Rule>
                    <Rule>
                    <Option>Disabled:Flight Signing</Option>
                    </Rule>
                    <Rule>
                    <Option>Enabled:Unsigned System Integrity Policy</Option>
                    </Rule>
                    <Rule>
                    <Option>Required:EV Signers</Option>
                    </Rule>
                    <Rule>
                    <Option>Disabled:Script Enforcement</Option>
                    </Rule>
                    <Rule>
                    <Option>Required:Enforce Store Applications</Option>
                    </Rule>
                    <Rule>
                    <Option>Enabled:Update Policy No Reboot</Option>
                    </Rule>
                    <Rule>
                    <Option>Enabled:Dynamic Code Security</Option>
                    </Rule>
                    <Rule>
                    <Option>Enabled:Allow Supplemental Policies</Option>
                    </Rule>
                </Rules>
    .EXAMPLE

        ex: .\Set-WDACPolicy -$PolicyFile $PolicyFile -PolicyMode Enforced -PolicyMode Enforced

    .NOTES
#>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$PolicyFile,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateSet('Audit', 'Enforced')]
        [string]$PolicyMode,
        [Parameter(ValueFromPipeline = $true)]
        [switch]$SupportsSupplementalPolicy
    

    )

    #Set default rules

    #removes all possible rules in place (if found) so we can start from scratch
    Set-RuleOption -option 0 -delete  $PolicyFile
    Set-RuleOption -option 1 -delete  $PolicyFile
    Set-RuleOption -option 2 -delete  $PolicyFile
    Set-RuleOption -option 3 -delete  $PolicyFile
    Set-RuleOption -option 4 -delete  $PolicyFile
    Set-RuleOption -option 5 -delete  $PolicyFile
    Set-RuleOption -option 6 -delete  $PolicyFile
    Set-RuleOption -option 7 -delete  $PolicyFile
    Set-RuleOption -option 8 -delete  $PolicyFile
    Set-RuleOption -option 9 -delete  $PolicyFile
    Set-RuleOption -option 10 -delete $PolicyFile
    Set-RuleOption -option 11 -delete $PolicyFile
    Set-RuleOption -option 12 -delete $PolicyFile
    Set-RuleOption -option 13 -delete $PolicyFile
    Set-RuleOption -option 14 -delete $PolicyFile
    Set-RuleOption -option 15 -delete $PolicyFile
    Set-RuleOption -option 16 -delete $PolicyFile
    Set-RuleOption -option 17 -delete $PolicyFile
    Set-RuleOption -option 18 -delete $PolicyFile
    Set-RuleOption -option 19 -delete $PolicyFile

    # Rule 0 - Enabled:UMCI
    # WDAC policies restrict both kernel-mode and user-mode binaries
    Set-RuleOption -Option 0 $PolicyFile

    # Rule 1 - Enabled:Boot Menu Protection
    # Not supported

    # Rule 2 - Required:WHQL
    # Requires that every executed driver is WHQL signed
    Set-RuleOption -Option 2 $PolicyFile

    # Rule 3 - Enable Audit Mode
    # Enables the execution of binaries outside of the WDAC policy but logs each occurrence in the CodeIntegrity event log
    # Set-RuleOption -Option 3 $PolicyFile

    # Rule 4 - Disabled:Flight Signing
    # WDAC policies will not trust flightroot-signed binaries  (Insider Builds)
    Set-RuleOption -Option 4 $PolicyFile

    # Rule 5 - Enabled:Inherit Default Policy
    # Not supported

    # Rule 6 -  Enabled:Unsigned System Integrity Policy (Default)
    # Allows the policy to remain unsigned
    Set-RuleOption -Option 6 $PolicyFile

    # Rule 7 - Allowed:Debug Policy Augmented
    # Not supported

    # Rule 8 - Required:EV Signers
    # Requires that drivers must have been submitted by a partner that has an Extended Verification (EV) certificate
    Set-RuleOption -Option 8 $PolicyFile

    # Rule 9 - Enabled:Advanced Boot Options Menu
    # Allows the F8 menu to appear to physically present users
    # Set-RuleOption -Option 9 $PolicyFile

    # Rule 10 -  Enabled:Boot Audit on Failure
    # When a driver fails during startup, the WDAC policy will be placed in audit mode so that Windows will load
    # Set-RuleOption -Option 10 $PolicyFile

    # Rule 11 - Disabled:Script Enforcement
    # Disables script enforcement options. Unsigned PowerShell scripts and interactive PowerShell are no longer restricted to Constrained Language Mode
    Set-RuleOption -Option 11 $PolicyFile

    # Rule 12 - Required:Enforce Store Applications
    # WDAC policies will also apply to Universal Windows applications
    Set-RuleOption -Option 12 $PolicyFile

    # Rule 13 - Enabled:Managed Installer
    # Automatically allow applications installed by a software distribution solution, such as Microsoft Endpoint Configuration Manager
    # Set-RuleOption -Option 13 $PolicyFile

    # Rule 14 - Enabled:Intelligent Security Graph Authorization
    # Automatically allow applications with "known good" reputation as defined by Microsoft’s Intelligent Security Graph (ISG)
    # Set-RuleOption -Option 14 $PolicyFile

    # Rule 15 - Enabled:Invalidate EAs on Reboot
    # This option will cause WDAC to periodically re-validate the reputation for files that were authorized by the ISG
    # Set-RuleOption -Option 15 $PolicyFile

    # Rule 16 - Enabled:Update Policy No Reboot
    # Allow future WDAC policy updates to apply without requiring a system reboot
    Set-RuleOption -Option 16 $PolicyFile

    # Rule 17 - Enabled:Allow Supplemental Policies
    # Use this option on a base policy to allow supplemental policies to expand it
    # Set-RuleOption -Option 18 $PolicyFile

    # Rule 18 - Disabled:Runtime FilePath Rule Protection
    # Disable default FilePath rule protection for any FileRule that allows a file based on FilePath
    # apps and executables allowed based on file path rules must come from a file path that’s only writable by an administrator
    # Set-RuleOption -Option 18 $PolicyFile

    #Rule 19 - Applies WDAC Policies to .NET Applications and DLLs  (Not ready to test this now)
    Set-RuleOption -Option 19 $PolicyFile


    If ($PolicyMode -eq 'Audit') {
            

        # Rule 3 - Enable Audit Mode
        # Enables the execution of binaries outside of the WDAC policy but logs each occurrence in the CodeIntegrity event log
        Set-RuleOption -Option 3 $PolicyFile

        # Rule 9 - Enabled:Advanced Boot Options Menu
        # Allows the F8 menu to appear to physically present users
        Set-RuleOption -Option 9 $PolicyFile

        #Rule 10 -  Enabled:Boot Audit on Failure
        # When a driver fails during startup, the WDAC policy will be placed in audit mode so that Windows will load
        Set-RuleOption -Option 10 $PolicyFile
         
    }

    If ($PolicyMode -eq 'Enforced') {

        # Rule 9 - Enabled:Advanced Boot Options Menu - optional
        # Allows the F8 menu to appear to physically present users
        # Set-RuleOption -Option 9 $PolicyFile
                     
    }
                   
    If ($SupportsSupplementalPolicy -eq $true) {

        # Rule 17 - Enabled:Allow Supplemental Policies
        # Use this option on a base policy to allow supplemental policies to expand it
        Set-RuleOption -Option 17 $PolicyFile
              
        
                        
    }
        
    
}

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
     - policy_files
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
    [string]$PolicyContentFolder, 
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

        #add templates - OS
        $script:BasePolicy_WithTemplates_Name = $policyName + "." + $policytype + "_Policy_WithTemplates"
        $script:BasePolicy_WithTemplates_File = $policyWorkspacePath + "\policy_xml\" + $BasePolicy_WithTemplates_Name + ".xml"

        #add OS template
        copy-item $PolicyContentFolder\Microsoft\DefaultWindows_Enforced.xml $policyWorkspacePath\policy_files\DefaultWindows_Enforced.xml -Force
        Add-WDACPolicyFiles -InputPolicyFile $BasePolicy_Blank_File -PolicyFiles "$policyWorkspacePath\policy_files\DefaultWindows_Enforced.xml" -OutputPolicyFile $BasePolicy_WithTemplates_File
    
        #add recommended templates
        copy-item -Recurse $PolicyContentFolder\Custom\ $policyWorkspacePath\policy_files\ -Force
        Add-WDACPolicyFiles -InputPolicyFile $BasePolicy_WithTemplates_File -PolicyFiles "$policyWorkspacePath\policy_files\Custom\" -OutputPolicyFile $BasePolicy_WithTemplates_File -Overwrite

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