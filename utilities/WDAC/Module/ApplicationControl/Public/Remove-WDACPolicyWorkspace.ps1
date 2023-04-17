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