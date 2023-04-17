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