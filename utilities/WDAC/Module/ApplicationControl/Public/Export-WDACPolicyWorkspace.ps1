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