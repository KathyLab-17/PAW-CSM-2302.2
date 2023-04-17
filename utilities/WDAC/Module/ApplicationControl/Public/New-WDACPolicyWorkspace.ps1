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
        $script:policyTemplatesPath = $policyWorkspacePath + "\policy_templates\"
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