#region Initialisation...
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
####################################################
####################################################
#Instantiate Vars
####################################################
[CmdLetBinding()]
param(
    [Parameter()]
    [switch] $install,
    [switch] $unInstall,
    [switch] $userInstall,
    [string] $tagFile,
    [switch] $regTag
)
#Restart as 64-bit
if (![System.Environment]::Is64BitProcess) {
    $additionalArgs = ''
    foreach ($Param in $PSBoundParameters.GetEnumerator()) {
        if (-not $MyInvocation.MyCommand.Parameters[$Param.key].SwitchParameter) {
            $additionalArgs += "-$($Param.Key) $($Param.Value) "
        }
        else {
            $additionalArgs += "-$($Param.Key) "
        }
    }

    # start new PowerShell as x64 bit process, wait for it and gather exit code and standard error output
    $sysNativePowerShell = "$($PSHOME.ToLower().Replace("syswow64", "sysnative"))\powershell.exe"

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $sysNativePowerShell
    $pinfo.Arguments = "-ex bypass -file `"$PSCommandPath`" $additionalArgs"
    $pinfo.RedirectStandardError = $true
    #$pinfo.RedirectStandardOutput = $true
    $pinfo.CreateNoWindow = $true
    
    #$pinfo.RedirectStandardError = $false
    #$pinfo.RedirectStandardOutput = $false
    #$pinfo.CreateNoWindow = $false
    
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null

    $exitCode = $p.ExitCode

    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($stderr) { Write-Error -Message $stderr }
}
Else {

    $script:BuildVer = "1.1"
    $script:ProgramFiles = $env:ProgramFiles
    $script:ParentFolder = $PSScriptRoot | Split-Path -Parent
    $script:ScriptFullName = $myInvocation.MyCommand.Name
    $script:ScriptName = $scriptFullName.Substring(0, $scriptFullName.Length - 4)
    $script:LogName = $scriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
    If ( $userInstall ) {
        $script:logPath = "$($env:LOCALAPPDATA)\Microsoft\IntuneApps\$scriptName"
    }
    Else { 
        $script:logPath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName" 
    }
    $script:logFile = "$logPath\$LogName.log"
    Add-Type -AssemblyName Microsoft.VisualBasic
    $script:EventLogName = "Application"
    $script:EventLogSource = "EventSystem"
    If ($VerbosePreference -eq 'Continue') { Start-Transcript -Path "$logPath\Transcript.log" -Append }
    ####################################################
    ####################################################
    #Build Functions
    ####################################################

    Function Start-Log {
        param (
            [string]$FilePath,

            [Parameter(HelpMessage = 'Deletes existing file if used with the -DeleteExistingFile switch')]
            [switch]$DeleteExistingFile
        )
		
        #Create Event Log source if it's not already found...
        if ([System.Diagnostics.EventLog]::Exists($script:EventLogName) -eq $false) {
            New-EventLog -LogName $EventLogName -Source $EventLogSource
        }
        if ([System.Diagnostics.EventLog]::SourceExists($script:EventLogSource ) -eq $false) {
            [System.Diagnostics.EventLog]::CreateEventSource($script:EventLogSource , $EventLogName)
        }
        #If (!([system.diagnostics.eventlog]::SourceExists($EventLogSource))) { New-EventLog -LogName $EventLogName -Source $EventLogSource }

        Try {
            If (!(Test-Path $FilePath)) {
                ## Create the log file
                New-Item $FilePath -Type File -Force | Out-Null
            }
            
            If ($DeleteExistingFile) {
                Remove-Item $FilePath -Force
            }
			
            ## Set the global variable to be used as the FilePath for all subsequent Write-Log
            ## calls in this session
            $script:ScriptLogFilePath = $FilePath
        }
        Catch {
            Write-Error $_.Exception.Message
        }
    }

    ####################################################

    Function Write-Log {
        #Write-Log -Message 'warning' -LogLevel 2
        #Write-Log -Message 'Error' -LogLevel 3
        param (
            [Parameter(Mandatory = $true)]
            [string]$Message,
			
            [Parameter()]
            [ValidateSet(1, 2, 3)]
            [int]$LogLevel = 1,

            [Parameter(HelpMessage = 'Outputs message to Event Log,when used with -WriteEventLog')]
            [switch]$WriteEventLog
        )
        Write-Host
        Write-Host $Message
        Write-Host
        $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
        $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
        $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
        $Line = $Line -f $LineFormat
        Add-Content -Value $Line -Path $ScriptLogFilePath
        If ($WriteEventLog) { Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message $Message  -Id 100 -Category 0 -EntryType Information }
    }

    ####################################################

    Function New-IntuneTag {
        <#
    .SYNOPSIS
    .DESCRIPTION
    .EXAMPLE
    .PARAMETER
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
#>
        Param (
            [string]$TagFilePath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName\",
            [string]$tagName
        )
              
        Begin {
            Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
        }

        Process {
            # Create a tag file just so Intune knows this was installed
            Write-Log "Creating Intune Tag file path: [$TagFilePath]"

            If (-not (Test-Path $TagFilePath) ) {

                New-Item -Path $TagFilePath -ItemType "directory" -Force | out-null
            }

            # Check if tagName already has .tag at the end
            If ($tagName.Substring(($tagName.Length - 4), 4) -eq ".tag") {
                Write-Log -Message "Using passed in tagName: $tagName"
                $tagFileName = "$TagFilePath\$tagName"
            }
            Else {
                Write-Log -Message "Using default of scriptname: $tagName and appending .tag"
                $tagFileName = "$TagFilePath\$tagName.tag"
            }
        
            Write-Log "Creating Intune Tag file: [$tagFileName]"
                       
            Set-Content -Path $tagFileName -Value "Installed"

            Write-Log -Message "Created Intune Tag file: [$tagFileName]"
                
        }
    }

    ####################################################

    Function Remove-IntuneTag {
        <#
    .SYNOPSIS
    .DESCRIPTION
    .EXAMPLE
    .PARAMETER
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
#>
        Param (
            [string]$TagFilePath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName\",
            [string]$tagName
        )
              
        Begin {
            Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
        }

        Process {
            # Remove the tag file so Intune knows this was uninstalled
            # Check if tagName already has .tag at the end
            If ($tagName.Substring(($tagName.Length - 4), 4) -eq ".tag") {
                Write-Log -Message "Using passed in tagName: $tagName"
                $tagFileName = "$TagFilePath\$tagName"
            }
            Else {
                Write-Log -Message "Using default of scriptname: $tagName and appending .tag"
                $tagFileName = "$TagFilePath\$tagName.tag"
            }
        
            Write-Log "Removing Intune Tag file: [$tagFileName]"
        
            If (Test-Path $tagFileName) {
                Remove-Item -Path $tagFileName -Force
            }

        }
    }

    ####################################################

    Function New-IntuneRegTag {
        <#
    .SYNOPSIS
    .DESCRIPTION
    .EXAMPLE
    .PARAMETER
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
#>
        Param (
            [string]$TagRegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\",
            [string]$tagName
        )
              
        Begin {
            Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
        }

        Process {
            # Create a registry tag just so Intune knows this was installed
            Write-Log "Creating Intune Tag file path: [$TagRegPath\$tagName]"

            #Get-ItemProperty -Path "HKLM:\SOFTWARE\$TagRegPath" -Name $tagName

            New-Item -Path "Registry::$TagRegPath" -Force

            $returnCode = New-ItemProperty -Path "Registry::$TagRegPath" -Name $tagName -PropertyType String -Value "Installed" -Force
            Write-Log -Message "Return code: $returnCode" 
        }
    }

    ####################################################

    Function Remove-IntuneRegTag {
        <#
    .SYNOPSIS
    .DESCRIPTION
    .EXAMPLE
    .PARAMETER
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
#>
        Param (
            [string]$TagRegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\",
            [string]$tagName
        )
              
        Begin {
            Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
        }

        Process {
            # Remove registry tag just so Intune knows this was uninstalled
            Write-Log "Removing Intune Tag file path: [$TagRegPath\$tagName]"
        
            $returnCode = Remove-ItemProperty -Path "Registry::$TagRegPath" -Name $tagName -Force
            Write-Log -Message "Return code: $returnCode"
        }
    }

    ####################################################

    function Test-Null($objectToCheck) {
        if ($objectToCheck -eq $null) {
            return $true
        }

        if ($objectToCheck -is [String] -and $objectToCheck -eq [String]::Empty) {
            return $true
        }

        if ($objectToCheck -is [DBNull] -or $objectToCheck -is [System.Management.Automation.Language.NullString]) {
            return $true
        }

        return $false
    }

    ####################################################

    Function Import-PSModule {
        <#
                .SYNOPSIS
            Cmdlet for loading modules single or multiple modules

 

                .DESCRIPTION
                        This function will import modules, load and or install modules from a PowerShell Repository

 

                .PARAMETER ModuleToLoad
                        Modules to load

 

        .EXAMPLE
            PS C:\> Import-PSModules -ModuleToLoad Foo

 

                        Imports the Foo module

 

        .NOTES
            NOTE: You can not pull up the help information until the object has been imported
        #>

        [cmdletbinding()]
        param(
            [object]$moduleToLoad
        )

        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        process {
            Write-Log -Message "Check to see if module: $ModuleToLoad is already imported"
            if (Get-Module -Name $moduleToLoad) {
                $mod = Get-Module -Name $moduleToLoad | Select-Object Name, Version
                Write-Log -Message "Module already installed: $mod"
            }
            else {
                Write-Log -Message "If module is not imported, but available on disk then import it"
                Write-Log -Message "This will check all of the available modules in the module paths"
                if (Get-Module -ListAvailable -Name $moduleToLoad) {
                    $mod = Get-Module -ListAvailable -Name $moduleToLoad | Select-Object Name, Version
                    Write-Log -Message "Module details: $mod"
                }
                else {
                    try {
                        Write-Log -Message "If module is not imported, not available on disk, but is in online gallery then install and import"
                        if (Find-Module -Name $moduleToLoad) {
                            Write-Log -Message "If the module is found, try to install it"
                            Write-Log -Message "Using command: Install-Module -Name $moduleToLoad -AcceptLicense -AllowClobber -Force"
                            Install-Module -Name $moduleToLoad -AcceptLicense -AllowClobber -Force

                            $mod = Get-Module -ListAvailable -Name $moduleToLoad | Select-Object Name, Version
                            Write-Log -Message "Licensed module now installed: $mod"
                        }
                        else {
                            Write-Log -Message "Module is not imported, not available and not in online gallery, aborting"
                            Throw 'Import-PSModule Error'
                        }
                    }
                    Catch [System.Management.Automation.ParameterBindingException] {
                        Write-Log -Message "Module did not install with -AcceptLicense parameter, trying without"
                        Write-Log -Message "Using command: Install-Module -Name $moduleToLoad -AllowClobber -Force"
                        Install-Module -Name $moduleToLoad -AllowClobber -Force

                        $mod = Get-Module -ListAvailable -Name $moduleToLoad | Select-Object Name, Version
                        Write-Log -Message "Module now installed: $mod"
                    }
                    catch {
                        Write-Log -Message "Error importing/installing module: $moduleToLoad"
                        Write-Log -Message "Error exception: $($_.Exception)"
                        Write-Log -Message "Error message: $($_.Exception.message)"
                        Write-Warning "Error: $($_.Exception.message)" 
                        Throw 'Import-PSModule Error'
                    }
                }
            }
        }

        End {
            Write-Log -Message "Ending: $($MyInvocation.Mycommand)"
        }
    }

    ####################################################

    Function Uninstall-PSModule {
        <#
                .SYNOPSIS
            Cmdlet for unloading modules single or multiple modules

                .DESCRIPTION
                        This function will uninstall modules

                .PARAMETER ModuleToUninstall
                        Modules to load

        .EXAMPLE
            PS C:\> Import-PSModules -ModuleToUninstall Foo

                        Removes the Foo module

        .NOTES
            NOTE: You can not pull up the help information until the object has been imported
        #>

        [cmdletbinding()]
        param(
            [object]$moduleToUninstall
        )

        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        process {
            Write-Log -Message "Check to see if module: $ModuleToUninstall is installed."
            if (Get-Module -ListAvailable -Name $ModuleToUninstall) {
                Write-Log -Message "Module found, removing"
                Try {
                    Get-Module $ModuleToUninstall | Uninstall-Module -AllVersions -Force
                }
                catch {
                    Write-Log -Message "Error removing/uninstalling module: $moduleToLoad"
                    Write-Log -Message "Error exception: $($_.Exception)"
                    Write-Log -Message "Error message: $($_.Exception.message)"
                    Write-Warning "Error: $($_.Exception.message)" 
                    #Throw 'Uninstall-PSModule Error'
                }
            }
        }

        End {
            Write-Log -Message "Ending: $($MyInvocation.Mycommand)"
        }
    }

    ####################################################

    Start-Log -FilePath $logFile -DeleteExistingFile
    Write-Host
    Write-Host "Script log file path is [$logFile]" -ForegroundColor Cyan
    Write-Host
    Write-Log -Message "Starting $ScriptName version $BuildVer" -WriteEventLog
    Write-Log -Message "Running from location: $PSScriptRoot" -WriteEventLog
    Write-Log -Message "Script log file path is [$logFile]" -WriteEventLog
    Write-Log -Message "Running in 64-bit mode: $([System.Environment]::Is64BitProcess)"

    #endregion Initialisation...
    ##########################################################################################################
    ##########################################################################################################

    #region Main Script work section
    ##########################################################################################################
    ##########################################################################################################
    #Main Script work section
    ##########################################################################################################
    ##########################################################################################################

    $listOfModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups', `
            'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Identity.Governance')

    If ($Install) {
        Write-Log -Message "Performing Install steps..."

        #region Install modules
        # Configure TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        #Check for NuGet Package Provider installed on machine
        if ((Get-PackageProvider -ListAvailable).name -eq "NuGet") {
            #check if Nuget is installed on the machine
            $nuget = Get-PackageProvider -Name Nuget

            if ($nuget.version -eq ((find-PackageProvider -name nuget).version)) {
                #check for latest version    
                Write-Log -Message "NuGet is up to date"
            }
            else {
                try {
                    Install-PackageProvider -name nuget -Force -confirm:$False -ErrorAction Stop
                    Write-Log -Message "NuGet Package Provider is installed"    
                }
                catch {
                    Write-Log -Message("NuGet Package Provider failed to install with error: $($_.Exception.message)")
                    Write-Warning "Error: $($_.Exception.message)"
                    If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
                    Throw
                }    
            }
        }
        else {
            try {
                Write-Log -Message  "Running command 'Install-PackageProvider -name nuget -Force -confirm:`$false'"
                Install-PackageProvider -name nuget -Force -confirm:$false -ErrorAction Stop
                Write-Log -Message "NuGet Package Provider is installed"
            }
            catch {
                #Write-Log -Message "NuGet Package Provider failed to install"
                Write-Log -Message("NuGet Package Provider failed to install with error: $($_.Exception.message)")
                Write-Warning "Error: $($_.Exception.message)"
                If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
                Throw        
            }
        }

        #Register the PSGallery repository and set the installation policy to trusted
        Write-Log -Message  "Running '(Get-PSRepository).name -eq PSGallery'"

        If ((Get-PSRepository).name -eq "PSGallery") {
            Set-PSRepository -name "PSGallery" -InstallationPolicy Trusted
            Write-Log -Message "PS Repository installation policy set to trusted"
        }
        else {
            Register-PSRepository -Default -InstallationPolicy Trusted
            Write-Log -Message "default PS Repository registered and installation policy set to trusted"
        }

        
        #Update PackageManagement module
        Install-Module -Name PackageManagement -Force -MinimumVersion 1.4.6 -Repository PSGallery -ErrorAction SilentlyContinue

        # Call function to install the list of modules
        Write-Log -Message "Installing modules"
        foreach ($module in $listOfModules) {
            Write-Log -Message "Importing module: $module"
            Import-PSModule -moduleToLoad $module
        }

        # Create Scheduled Task To Update Modules
        $ExistingScheduledTask = Get-ScheduledTask -TaskName "UPDATE-PSMODULES" -ErrorAction SilentlyContinue
        #endregion Install modules

        #region Create PAWCSM module folder
        $modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules"

        $targetPath = "$modulePath\PAWCSM"
        Write-Log -Message "Creating folder: $targetPath" -WriteEventLog
        Try {
            New-Item -Path $targetPath -ItemType "directory" -Force -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw 
        }
        #endregion Create PAWCSM module folder

        #region Copy PAWCSM module files
        Write-Log -Message "Copying package content to: $targetPath" -WriteEventLog
        Try {
            Copy-Item -Path "$PSScriptRoot\*" -Exclude "$ScriptFullName", "IntuneApps", "JSON" -Destination $targetPath -Recurse -Force -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw 
        }
        #endregion Copy PAWCSM module files

        #region Create C:\REPO\PAWCSM folder
        $targetPath = "$env:SystemDrive\REPO\PAWCSM"
        Write-Log -Message "Creating folder: $targetPath" -WriteEventLog
        Try {
            New-Item -Path $targetPath -ItemType "directory" -Force -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw 
        }
        #endregion Create C:\REPO\PAWCSM folder

        #Handle Intune detection method
        If (! ($userInstall) ) {
            Write-Log -Message "Creating detection rule for System install"

            If ( $regTag ) {
                Write-Log -Message "Using RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                New-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            Else {
                Write-Log -Message "Using FileTag"
                
                If ( ! ( Test-Null ( $tagFile ) ) ) {
                    Write-Log -Message "Using tagFile name: $tagFile"
                    New-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
                }
                Else { 
                    Write-Log -Message "Using default tagFile name: $scriptName"
                    New-IntuneTag -TagFilePath "$logPath" -tagName $scriptName 
                }
            }
        }
        ElseIf ( $userInstall ) {
            Write-Log -Message "Creating detection rule for User install"

            If ( $regTag ) {
                Write-Log -Message "Using RegTag: HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                New-IntuneRegTag -TagRegPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            Else {
                Write-Log -Message "Using FileTag: "
                
                If ( ! ( Test-Null ( $tagFile ) ) ) {
                    Write-Log -Message "Using tagFile name: $tagFile"
                    New-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
                }
                Else { 
                    Write-Log -Message "Using default tagFile name: $scriptName"
                    New-IntuneTag -TagFilePath "$logPath" -tagName $scriptName 
                }
            } 
        }
    }
    ElseIf ( $UnInstall ) {
        Write-Log -Message "Performing Uninstall steps..."

        #region remove modules
        # Call function to uninstall the list of functions
        Write-Log -Message "Uninstalling modules"
        foreach ($module in $listOfModules) {
            Write-Log -Message "Removing module: $module"
            Uninstall-PSModule -moduleToUninstall $module
        }
        #endregion remove modules

        #region Remove Scheduled Task
        Unregister-ScheduledTask -TaskName "UPDATE-PSMODULES"
 
        If ( Get-ScheduledTask -TaskName "UPDATE-PSMODULES" ) { 
            Write-Log -Message "Error - Scheduled Task: UPDATE-PSMODULES failed to uninstall"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Exit
        }
        #endregion Remove Scheduled Task

        #region Remove PAWCSM module folder
        $modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules"
        $targetPath = "$modulePath\PAWCSM"
        
        Write-Log -Message "Removing: $targetPath" -WriteEventLog
        Try {
            Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw 
        }
        #endregion Remove PAWCSM module folder

        #Handle Intune detection method
        If (! ($userInstall) ) {
            Write-Log -Message "Removing detection for System install"

            If ( $regTag ) {
                Write-Log -Message "Removing RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                Remove-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            Else {
                Write-Log -Message "Removing FileTag"
                
                If ( ! ( Test-Null ( $tagFile ) ) ) {
                    Write-Log -Message "Removing tagFile name: $tagFile"
                    Remove-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
                }
                Else { 
                    Write-Log -Message "Removing default tagFile name: $scriptName"
                    Remove-IntuneTag -TagFilePath "$logPath" -tagName $scriptName 
                }
            }
        }
        ElseIf ( $userInstall ) {
            Write-Log -Message "Removing detection for User install"

            If ( $regTag ) {
                Write-Log -Message "Removing RegTag: HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                Remove-IntuneRegTag -TagRegPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            Else {
                Write-Log -Message "Removing FileTag: "
                
                If ( ! ( Test-Null ( $tagFile ) ) ) {
                    Write-Log -Message "Removing tagFile name: $tagFile"
                    Remove-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
                }
                Else { 
                    Write-Log -Message "Removing default tagFile name: $scriptName"
                    Remove-IntuneTag -TagFilePath "$logPath" -tagName $scriptName 
                }
            } 
        }
    }

    Write-Log "$ScriptName completed." -WriteEventLog
    If ($VerbosePreference -eq 'Continue') { Stop-Transcript }

    ##########################################################################################################
    ##########################################################################################################
    #endregion Main Script work section
}
# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDUszH8iD3HCXiP
# CVlM41RQwT8AL7Ti2K3sAefW0pst2aCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINeZc6d6+VKoDCPtiJ0YrQpo
# R/MwKp7Yh8i7jtR4wbAxMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAObx56TV8PLqQZz6y9fBP0E3oroZ6lHWcLTmzmiO1XtxTgPZ/hLzBCEAZ
# REkz2UJXNMYsUvSKhDxRGXlfo+PtuVFTvktzwNVgTke/crYuNDS6NqPQQpgHqJrs
# DXm3RZZqNHBrkgsU0i2mcHG2DHykxiNPeP+xhal/bXH9hUEdY4lUheDFOOxfpYHR
# npzhEVMxEoTEDCLBwkkaDkVjNIfiYtRh6mJnE9c97edW4ErnpakZR7i9ime+9Sh1
# FypBH6+uaFQGJYpanO0lIGhRD12xQm5Eem4d4g7ivMA2twLV+5Bhe33cZoupPS1h
# OYdounEVooc3rePzGc+SPJ3iP8e47KGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDn1MsfAiayPubknuaHvrW88Z0UNk0GY+ofBIG5o6Nw1gIGZBMWIsTh
# GBMyMDIzMDQxMjIxMTAxOS4zODdaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpENkJELUUz
# RTctMTY4NTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABx/sAoEpb8ifcAAEAAAHHMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEz
# NVoXDTI0MDIwMjE5MDEzNVowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ2QkQtRTNFNy0xNjg1MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAr0LcVtnatNFMBrQTtG9P8ISAPyyGmxNfhEzaOVlt088p
# BUFAIasmN/eOijE6Ucaf3c2bVnN/02ih0smSqYkm5P3ZwU7ZW202b6cPDJjXcrjJ
# j0qfnuccBtE3WU0vZ8CiQD7qrKxeF8YBNcS+PVtvsqhd5YW6AwhWqhjw1mYuLetF
# 5b6aPif/3RzlyqG3SV7QPiSJends7gG435Rsy1HJ4XnqztOJR41I0j3EQ05JMF5Q
# NRi7kT6vXTT+MHVj27FVQ7bef/U+2EAbFj2X2AOWbvglYaYnM3m/I/OWDHUgGw8K
# IdsDh3W1eusnF2D7oenGgtahs+S1G5Uolf5ESg/9Z+38rhQwLgokY5k6p8k5arYW
# tszdJK6JiIRl843H74k7+QqlT2LbAQPq8ivQv0gdclW2aJun1KrW+v52R3vAHCOt
# bUmxvD1eNGHqGqLagtlq9UFXKXuXnqXJqruCYmfwdFMD0UP6ii1lFdeKL87PdjdA
# wyCiVcCEoLnvDzyvjNjxtkTdz6R4yF1N/X4PSQH4FlgslyBIXggaSlPtvPuxAtua
# c/ITj4k0IRShGiYLBM2Dw6oesLOoxe07OUPO+qXXOcJMVHhE0MlhhnxfN2B1JWFP
# WwQ6ooWiqAOQDqzcDx+79shxA1Cx0K70eOBplMog27gYoLpBv7nRz4tHqoTyvA0C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBQFUNLdHD7BAF/VU/X/eEHLiUSSIDAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQDQy5c8ogP0y8xAsLVca07wWy1mT+nqYgAFnz2972kNO+KJ7AE4f+SVbvOnkeeu
# OPq3xc+6TS8g3FuKKYEwYqvnRHxX58tjlscZsZeKnu7fGNUlpNT9bOQFHWALURuo
# Xp8TLHhxj3PEq9jzFYBP2YNMLol70ojY1qpze3nMMJfpdurdBBpaOLlJmRNTLhxd
# +RJGJQbY1XAcx6p/FigwqBasSDUxp+0yFPEBB9uBE3KILAtq6fczGp4EMeon6Ymk
# yCGAtXMKDFQQgdP/ITe7VghAVbPTVlP3hY1dFgc+t8YK2obFSFVKslkASATDHulC
# Mht+WrIsukclEUP9DaMmpq7S0RLODMicI6PtqqGOhdnaRltA0d+Wf+0tPt9SUVtr
# PJyO7WMPKbykCRXzmHK06zr0kn1YiUYNXCsOgaHF5ImO2ZwQ54UE1I55jjUdldyj
# y/UPJgxRm9NyXeO7adYr8K8f6Q2nPF0vWqFG7ewwaAl5ClKerzshfhB8zujVR0d1
# Ra7Z01lnXYhWuPqVZayFl7JHr6i6huhpU6BQ6/VgY0cBiksX4mNM+ISY81T1RYt7
# fWATNu/zkjINczipzbfg5S+3fCAo8gVB6+6A5L0vBg39dsFITv6MWJuQ8ZZy7fwl
# FBZE4d5IFbRudakNwKGdyLGM2otaNq7wm3ku7x41UGAmkDCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDZCRC1FM0U3LTE2ODUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAOIASP0JSbv5R23wxciQivHyckYooIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDn4SsGMCIYDzIwMjMwNDEyMjEwNTEwWhgPMjAyMzA0MTMyMTA1MTBaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOfhKwYCAQAwBwIBAAICB68wBwIBAAICEagw
# CgIFAOfifIYCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBTS1Sr1L8h9w12
# P9iWpc02BccnZC7oG8I/saYhauoZWk3nhMMaPHyylVKAVCxRRpNLfcpEfxI6hmPH
# 48wNByDX2c1nylc9Qk7tuyjdqOdZl2jOij/PF628C0g8hGcqOe/1Aj0CwiIHBWQK
# 3Y6VADyHjypPzyUIBTQ1o8NyXkjhDTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABx/sAoEpb8ifcAAEAAAHHMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIIYRI1tJqlfHAWkGGGi66GksaNzqFXz8/0i/D5bk5NxEMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgR+fl2+JSskULOeVYLbeMgk7HdIbREmAsjwtc
# y6MJkskwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Acf7AKBKW/In3AABAAABxzAiBCAF1M/i2DCp2qrCIYQXlBrNXUoMmQ349FGlDXyC
# 81lrjjANBgkqhkiG9w0BAQsFAASCAgBv3ZaVliad19toM3tdLyWfF1Hv5INj6Mrf
# j8X3Niabb942IGsXdQhSn//Oh/C3AepHyX+aWh5mCp3aPd8/nieSG4BnREMYaIPk
# 3NE7FL14xaL8tYXnwHAuPibShBlz2FmRat2HR24ABUl5bZLP60LAdX+5OyQgawa/
# j3LrWuKjdWY5RkgcT9b/8o1mK2VZDSTSGvJurfh2pWjzSSvksgRUvbXB3mni+LyS
# pI0GmEgxg9i+fw5ovmdNVBZMy9VnbaPt6cxU6HX0dmBa7XHyOFxU0YDeXsczYD27
# DyeDUmPeLJ31TSyf6iiyApHwziGNxsbB7sk4sfjl10qRWNC9LoxNwwh4yvj67/5Z
# OR8nCGBLNfABH3A7d/rFK/TfpE7/7HKicB9voz/RoyR1n5NMQBSzTwFyCl8Mt1ok
# 8Uul3bz+0ohGqnnqWk75ap/54d37U5IcbyfZrL2o9vg1xLAKxGTO3fPkYawZRtP1
# MzyjTW5bnPorcxeNaEZTED3HkODpbltrzE1gvN6Q8jVRZk07S24Ak8WXzpiWAE1Q
# enxinqsn/Keh60GXeOYD97QA4gO7xyJ8A7SKF5ApCTmtOBdVmxm0uEucZMHxCDTN
# 02hZn4DGjOKB736qydzFGoP2aWofsT7jbSZ4X18BSfB4VjGhBtH2zK80osshhUMa
# Tw/1tpqC8A==
# SIG # End signature block
