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
