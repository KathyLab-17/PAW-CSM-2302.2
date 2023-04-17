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
#$VerbosePreference = "Continue" #Enables Verbose Logging, can be enabled with -verbose on the cmdline too
$script:exitCode = 0

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
    $script:ScriptName = $myInvocation.MyCommand.Name
    $script:ScriptName = $scriptName.Substring(0, $scriptName.Length - 4)
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

    Function New-RegKey {
        param($key)
  
        $key = $key -replace ':', ''
        $parts = $key -split '\\'
  
        $tempkey = ''
        $parts | ForEach-Object {
            $tempkey += ($_ + "\")
            if ( (Test-Path "Registry::$tempkey") -eq $false) {
                New-Item "Registry::$tempkey" | Out-Null
            }
        }
    }

    ####################################################

    function IsNull($objectToCheck) {
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

    Function Get-XMLConfig {
        <#
.SYNOPSIS
This function reads the supplied XML Config file
.DESCRIPTION
This function reads the supplied XML Config file
.EXAMPLE
Get-XMLConfig -XMLFile PathToXMLFile
This function reads the supplied XML Config file
.NOTES
NAME: Get-XMLConfig
#>

        [cmdletbinding()]

        param
        (
            [Parameter(Mandatory = $true)]
            [string]$XMLFile,

            [bool]$Skip = $false
        )

        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {
            
            If (-Not(Test-Path $XMLFile)) {
                Write-Log -Message "Error - XML file not found: $XMLFile" -LogLevel 3
                Return $Skip = $true
            }
            Write-Log -Message "Reading XML file: $XMLFile"
            [xml]$script:XML_Content = Get-Content $XMLFile

            ForEach ($XMLEntity in $XML_Content.GetElementsByTagName("Azure_Settings")) {
                $script:baseUrl = [string]$XMLEntity.baseUrl
                $script:logRequestUris = [string]$XMLEntity.logRequestUris
                $script:logHeaders = [string]$XMLEntity.logHeaders
                $script:logContent = [string]$XMLEntity.logContent
                $script:azureStorageUploadChunkSizeInMb = [int32]$XMLEntity.azureStorageUploadChunkSizeInMb
                $script:sleep = [int32]$XMLEntity.sleep
            }

            ForEach ($XMLEntity in $XML_Content.GetElementsByTagName("IntuneWin_Settings")) {
                $script:PackageName = [string]$XMLEntity.PackageName
                $script:displayName = [string]$XMLEntity.displayName
                $script:Description = [string]$XMLEntity.Description
                $script:Publisher = [string]$XMLEntity.Publisher
            }

        }

        End {
            If ($Skip) { Return }# Just return without doing anything else
            Write-Log -Message "Returning..."
            Return
        }

    }

    ####################################################

    Function Show-PWPromptForm {
        <#
.SYNOPSIS
This function shows a password prompt form
.DESCRIPTION
This function shows a password prompt form
.EXAMPLE
Show-PWPromptForm -promptMsg "Enter your network password"
This function shows a password prompt form
.NOTES
NAME: Show-PWPromptForm
#>

        [cmdletbinding()]

        param
        (
            [Parameter(Mandatory = $true)]
            [string]$promptTitle,

            [Parameter(Mandatory = $true)]
            [string]$promptMsg
        )

        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {
            
            <# Build Form #>
            Write-Log -Message "Preparing form."

            # Bring in the Windows Forms Library 
            Add-Type -assembly System.Windows.Forms

            # Generate the form 
            $Form = New-Object System.Windows.Forms.Form

            # Window Font 
            $Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)

            # Font styles are: Regular, Bold, Italic, Underline, Strikeout
            $Form.Font = $Font

            # Window Basics
            $Form.Text = $promptTitle
            $Form.Width = 350
            $Form.Height = 300
            $Form.AutoSize = $true
            $Form.MinimizeBox = $False
            $Form.MaximizeBox = $False
            $Form.ControlBox = $True
            $Form.WindowState = "Normal"
            # Maximized, Minimized, Normal
            $Form.SizeGripStyle = "Hide"
            # Auto, Hide, Show
            $Form.ShowInTaskbar = $False
            $Form.Opacity = 1.0
            # 1.0 is fully opaque; 0.0 is invisible
            $Form.StartPosition = "CenterScreen"
            $Form.TopMost = $True
            # CenterScreen, Manual, WindowsDefaultLocation, WindowsDefaultBounds, CenterParent

            <# Header Text #>

            # Create the label
            $lbl_HeaderText = New-Object System.Windows.Forms.Label

            # Create Instruction String 
            $lbl_InstructionString = $promptMsg

            # Label Basics 
            $lbl_HeaderText.Text = $lbl_InstructionString
            $lbl_HeaderText.Location = New-Object System.Drawing.Point(10, 10)
            $lbl_HeaderText.AutoSize = $true

            # Add to form 
            $Form.Controls.Add($lbl_HeaderText)

            # Create the label
            $lbl_TxbHeader1 = New-Object System.Windows.Forms.Label

            # Label Basics 
            $lbl_TxbHeader1.Text = "Enter Password"
            $lbl_TxbHeader1.Location = New-Object System.Drawing.Point(20, 70)
            $lbl_TxbHeader1.AutoSize = $true

            # Add to form 
            $Form.Controls.Add($lbl_TxbHeader1)

            # Create the label
            $lbl_TxbHeader2 = New-Object System.Windows.Forms.Label

            # Label Basics 
            $lbl_TxbHeader2.Text = "Repeat Password"
            $lbl_TxbHeader2.Location = New-Object System.Drawing.Point(20, 130)
            $lbl_TxbHeader2.AutoSize = $true

            # Add to form 
            $Form.Controls.Add($lbl_TxbHeader2)

            # Create the label
            $lbl_FeedbackMsg = New-Object System.Windows.Forms.Label

            # Label Basics 
            $lbl_FeedbackMsg.Text = "Passwords Do Not Match"
            $lbl_FeedbackMsg.ForeColor = "Red"
            $lbl_FeedbackMsg.Location = New-Object System.Drawing.Point(20, 230)
            $lbl_FeedbackMsg.AutoSize = $true
            $lbl_FeedbackMsg.Visible = $false

            # Add to form 
            $Form.Controls.Add($lbl_FeedbackMsg)

            <# Text Boxes #>

            # Create Pw Box 1
            $txb_PwEnter1 = New-Object System.Windows.Forms.MaskedTextBox

            # Set Params
            $txb_PwEnter1.Width = 200
            $txb_PwEnter1.Height = 50 
            $txb_PwEnter1.Location = New-Object System.Drawing.Point(20, 95)
            $txb_PwEnter1.PasswordChar = '*'

            # Add to Form 
            $Form.Controls.Add($txb_PwEnter1)

            # Create Pw Box 2
            $txb_PwEnter2 = New-Object System.Windows.Forms.MaskedTextBox

            # Set Params
            $txb_PwEnter2.Width = 200
            $txb_PwEnter2.Height = 50 
            $txb_PwEnter2.Location = New-Object System.Drawing.Point(20, 155)
            $txb_PwEnter2.PasswordChar = '*'

            # Add to Form 
            $Form.Controls.Add($txb_PwEnter2)

            <# Buttons #>

            # Create a button
            $btn_InstallPrinters = New-Object System.Windows.Forms.Button

            # Button basics
            $btn_InstallPrinters.Location = New-Object System.Drawing.Size(20, 200)
            $btn_InstallPrinters.Size = New-Object System.Drawing.Size(150, 25)
            $btn_InstallPrinters.Text = "Install Printers"
            #$btn_InstallPrinters.DialogResult = [System.Windows.Forms.DialogResult]::OK
        
            $Form.AcceptButton = $btn_InstallPrinters

            # Set Function Handler
            $btn_InstallPrinters.Add_Click( {

                    # Set Error Conditions 
                    $InputErrorPresent = $false 
                    $InputErrorMessage = "Unspecified Input Error"
    
                    # Check if the PWs Match 
                    if ($txb_PwEnter1.Text -ne $txb_PwEnter2.Text) {
                        # Set Error Conditions 
                        $InputErrorPresent = $true
                        $InputErrorMessage = "Entered Passwords do not match"

                        Write-Log -Message "User entered mismatched Passwords"
                    }

                    # Check if 1st PW box empty
                    if ( IsNull ( $txb_PwEnter1.Text ) ) {
                        # Set Error Conditions 
                        $InputErrorPresent = $true
                        $InputErrorMessage = "Enter your password"

                        Write-Log -Message "1st PW box empty"
                    }
    
                    # Check if the error flag has been set 
                    if ($InputErrorPresent) {
                        # Set and show error 
                        $lbl_FeedbackMsg.Text = $InputErrorMessage
                        $lbl_FeedbackMsg.Visible = $true

                        Write-Log -Message "Button clicked, but error message shown"

                        Return

                    }
                    else { 
                        # Clear Error Message 
                        $lbl_FeedbackMsg.Visible = $false 

                        Write-Log -Message "Passwords entered correctly"

                    }

                    Write-Log -Message "Returning with password string"
                    $Script:pw = $txb_PwEnter1.Text

                    # Now Close the form 
                    $Form.Close()

                    Return
                
                })

            # Add to Form 
            $Form.Controls.Add($btn_InstallPrinters)

            <# Show the Form #>
            Write-Log -Message "Form onscreen"
            #Set-Content -Path "C:\Windows\Temp\PPForm.tag" -Value "Running..."
            $Form.ShowDialog()

        }
    }

    ####################################################

    Function Is-VM {
        <#
.SYNOPSIS
This function checks WMI to determine if the device is a VM
.DESCRIPTION
This function checks WMI to determine if the device is a VM
.EXAMPLE
Is-VM
This function checks WMI to determine if the device is a VM
.NOTES
NAME: Is-VM
#>

        [CmdletBinding()]
        Param ()
    
        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {
            Write-Log -Message "Checking WMI class: Win32_ComputerSystem for string: *virtual*"
            Try {
                $ComputerSystemInfo = Get-CIMInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                #$ComputerSystemInfo
                if ($ComputerSystemInfo.Model -like "*virtual*") {
                    Write-Log -Message "Virtual string detected"
                    $True
                }
                else {
                    Write-Log -Message "Virtual string not found"          
                    $False
                }
            }
            Catch [Exception] {
                Write-Log -Message "Error occurred: $($_.Exception.message)"
                Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            }
        }

        End {
            Write-Log -Message "Ending: $($MyInvocation.Mycommand)"
        }
    }

    ####################################################

    Function Install-Hotfix {
        <#
.SYNOPSIS
This function installs the specified Hotfix
.DESCRIPTION
This function installs the specified Hotfix
.EXAMPLE
Install-Hotfix -HotFixID KBxxxxxx.msu
This function installs the specified Hotfix
.NOTES
NAME: Install-Hotfix
#>

        [CmdletBinding()]
        Param (

            [Parameter(Mandatory = $true)]
            [string]$HotFixID

        )
    
        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {
            If (get-hotfix | Where-Object { $_.HotFixID -match $HotFixID }) {
                Write-Log -Message "Hotfix: $HotFixID already installed, returning."
                Return "Installed"
            }
            Write-Log -Message "Running Hotfix install for: wusa.exe ""$PSScriptRoot\$HotFixID"" /quiet /norestart /log:""$logPath\wusa.evtx"""
            Try {
                Start-Process -FilePath "wusa.exe" -ArgumentList """$PSScriptRoot\$HotFixID"" /quiet /norestart /log:""$logPath\wusa.evtx""" -WorkingDirectory "$PSScriptRoot" -Wait -WindowStyle Hidden -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred deploying Hotfix: $($_.Exception.message)"
                Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                Return "Failed"
            }

            <#
        If (get-hotfix | Where-Object {$_.HotFixID -match $HotFixID}) {
            Write-Log -Message "Hotfix: $HotFixID successfully installed."
            Return "Installed"
        }
        Else {
            Write-Log -Message "Error - something went wrong installing Hotfix: $HotFixID"
            Return "Failed"
        }
        #>
        }

        End {
            Write-Log -Message "Ending: $($MyInvocation.Mycommand)"
        }
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
    #region IntuneCodeSample
    # === variant 1: use try/catch with ErrorAction stop -> use write-error to signal Intune failed execution
    # example:
    # try
    # {
    #     Set-ItemProperty ... -ErrorAction Stop
    # }
    # catch
    # {   
    #     Write-Error -Message "Could not write regsitry value" -Category OperationStopped
    #     $exitCode = -1
    # }

    # === variant 2: ErrorVariable and check error variable -> use write-error to signal Intune failed execution
    # example:
    # Start-Process ... -ErrorVariable err -ErrorAction SilentlyContinue
    # if ($err)
    # {
    #     Write-Error -Message "Could not write regsitry value" -Category OperationStopped
    #     $exitCode = -1
    # }
    #endregion IntuneCodeSample

    #endregion Initialisation...
    ##########################################################################################################
    ##########################################################################################################

    #region Main Script work section
    ##########################################################################################################
    ##########################################################################################################
    #Main Script work section
    ##########################################################################################################
    ##########################################################################################################

    $listOfModules = @("AzureADPreview", "AzureAD", "MSOnline", "Microsoft.Graph.Intune", "WindowsAutoPilotIntune", "Microsoft.Azure.ActiveDirectory.PIM.PSModule")

    If ($Install) {
        Write-Log -Message "Performing Install steps..."

        #powershell.exe -NoLogo -NoProfile -Command '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Install-Module -Name PackageManagement -Force -MinimumVersion 1.4.6 -Scope CurrentUser -AllowClobber -Repository PSGallery'

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

        if (!$ExistingScheduledTask) {   
            Write-Log -Message  "Scheduled task not created, creating now"
            $SchTaskLogonAction = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument ('-NoProfile -WindowStyle Hidden -command "Update-Module -Force"')
            $SchTaskPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
            $SchTaskTrig = New-ScheduledTaskTrigger -Daily -DaysInterval 7 -At 1pm
            $SchTaskSett = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 30) 
            Register-ScheduledTask -Action $SchTaskLogonAction -Trigger $SchTaskTrig -Settings $SchTaskSett -Principal $SchTaskPrin -TaskName "UPDATE-PSMODULES" -Description "Updates PowerShell Modules" | Out-Null 
        }

        #Handle Intune detection method
        If (! ($userInstall) ) {
            Write-Log -Message "Creating detection rule for System install"

            If ( $regTag ) {
                Write-Log -Message "Using RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                New-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            Else {
                Write-Log -Message "Using FileTag"
                
                If ( ! ( IsNull ( $tagFile ) ) ) {
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
                
                If ( ! ( IsNull ( $tagFile ) ) ) {
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

        # Call function to uninstall the list of functions
        Write-Log -Message "Uninstalling modules"
        foreach ($module in $listOfModules) {
            Write-Log -Message "Removing module: $module"
            Uninstall-PSModule -moduleToUninstall $module
        }

        # Remove Scheduled Task
        Unregister-ScheduledTask -TaskName "UPDATE-PSMODULES"

        If ( Get-ScheduledTask -TaskName "UPDATE-PSMODULES" ) { 
            Write-Log -Message "Error - Scheduled Task: UPDATE-PSMODULES failed to uninstall"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Exit
        }
    
        #Handle Intune detection method
        If (! ($userInstall) ) {
            Write-Log -Message "Removing detection for System install"

            If ( $regTag ) {
                Write-Log -Message "Removing RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                Remove-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            Else {
                Write-Log -Message "Removing FileTag"
                
                If ( ! ( IsNull ( $tagFile ) ) ) {
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
                
                If ( ! ( IsNull ( $tagFile ) ) ) {
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
    exit $exitCode

    ##########################################################################################################
    ##########################################################################################################
    #endregion Main Script work section
}
# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDVaxrM03w4FDXh
# Md5vD8VLZPCsV20uiyxx+/l0ulHvxKCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
# v/jUTF1RAAAAAALNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAyWhcNMjMwNTExMjA0NjAyWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDrIzsY62MmKrzergm7Ucnu+DuSHdgzRZVCIGi9CalFrhwtiK+3FIDzlOYbs/zz
# HwuLC3hir55wVgHoaC4liQwQ60wVyR17EZPa4BQ28C5ARlxqftdp3H8RrXWbVyvQ
# aUnBQVZM73XDyGV1oUPZGHGWtgdqtBUd60VjnFPICSf8pnFiit6hvSxH5IVWI0iO
# nfqdXYoPWUtVUMmVqW1yBX0NtbQlSHIU6hlPvo9/uqKvkjFUFA2LbC9AWQbJmH+1
# uM0l4nDSKfCqccvdI5l3zjEk9yUSUmh1IQhDFn+5SL2JmnCF0jZEZ4f5HE7ykDP+
# oiA3Q+fhKCseg+0aEHi+DRPZAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU0WymH4CP7s1+yQktEwbcLQuR9Zww
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ3MDUzMDAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AE7LSuuNObCBWYuttxJAgilXJ92GpyV/fTiyXHZ/9LbzXs/MfKnPwRydlmA2ak0r
# GWLDFh89zAWHFI8t9JLwpd/VRoVE3+WyzTIskdbBnHbf1yjo/+0tpHlnroFJdcDS
# MIsH+T7z3ClY+6WnjSTetpg1Y/pLOLXZpZjYeXQiFwo9G5lzUcSd8YVQNPQAGICl
# 2JRSaCNlzAdIFCF5PNKoXbJtEqDcPZ8oDrM9KdO7TqUE5VqeBe6DggY1sZYnQD+/
# LWlz5D0wCriNgGQ/TWWexMwwnEqlIwfkIcNFxo0QND/6Ya9DTAUykk2SKGSPt0kL
# tHxNEn2GJvcNtfohVY/b0tuyF05eXE3cdtYZbeGoU1xQixPZAlTdtLmeFNly82uB
# VbybAZ4Ut18F//UrugVQ9UUdK1uYmc+2SdRQQCccKwXGOuYgZ1ULW2u5PyfWxzo4
# BR++53OB/tZXQpz4OkgBZeqs9YaYLFfKRlQHVtmQghFHzB5v/WFonxDVlvPxy2go
# a0u9Z+ZlIpvooZRvm6OtXxdAjMBcWBAsnBRr/Oj5s356EDdf2l/sLwLFYE61t+ME
# iNYdy0pXL6gN3DxTVf2qjJxXFkFfjjTisndudHsguEMk8mEtnvwo9fOSKT6oRHhM
# 9sZ4HTg/TTMjUljmN3mBYWAWI5ExdC1inuog0xrKmOWVMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAALN82S/+NRMXVEAAAAA
# As0wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGIM
# AER+cmP8Oy9ftDiCao3CfbBKN7LHUSAq9P5TQ4rLMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEArLlkg79eMkWzBB84eRi9PMrMzJZnNivdzi6D
# 6hUjWC2uCgJSiLnCAxnDaX8DSftRuVJVbl4ed9LPXyuCVu4D3/AbXno3Wutcleqc
# 1IarjTkRgOPRlH2/kQOBx5IHYhf5jPlh5tINkxDDhTmlLzd4RXm0cKu3UD7KY1v1
# MK3qngWbW2By6mfuPQDEqv7xE3hIZ6Mqu92BvU1W47UJGs60D3F7EjcyrSDv/oet
# /MmHQYcMi2esM4LjIsfc3x30RwPvaCooh105iMDSdyraECXDCEImgNcCPgBu+BsT
# UiJAFaB+EuhD2MxwwswaZy6Bi5B+3GEZLxPrrxP5dhd2ITO4RqGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCBhYhju5JwyrsDvU27uzmdCSH8H0vjeDH6K
# JPUHhZeQTwIGZBNQb4iwGBMyMDIzMDQxMjIxMTAxOS44NTlaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpBRTJDLUUzMkItMUFGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAABv99uuQQVUihYAAEA
# AAG/MA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEyNFoXDTI0MDIwMjE5MDEyNFowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkFFMkMtRTMy
# Qi0xQUZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuExh0n1UxKMzBvkPHer47nry
# D4UK2GVy1X6bOVC+hLVhDlsIWQ1uX/9a8IRI3zXo/y1oTDuj+rJHyX4OZQn42E0i
# u7x6swPvM34zIOSPn8lgnWzGEAsRtz9zBrLW9+4w/YhWlXI8hvc7ovqupuL3TXte
# 8BbmNOUDSL+Ou2bBfObGzsH3yY/BELvqwO13KZ9Z1OxKacnqq1u9E9Rhai90STog
# 22lR2MVRSx55FHi/emnZA/IKvsAtEH2K6JmgOyQ7/mDQrWNEA5roUjhQqLQw1/3w
# z/CIvc9+FPxX2dxR0nvvYe5VLqv8Q99cOkO6z6V4stGDyFDuO8CwtiSvCC3QrOOu
# gAl33aPD9YZswywWRk+YGyLI+Fw+kCCUY6h1qOjTj5glz0esmds3ue45WaI2hI9u
# sForM8gy//5tDZXj0KKU1BxA04xpfEy91RZUbc6pdAvEkpYrN2jlpXhMvTD7pgdY
# yxkVSaWZv7kWp5y9NjWP/CTDGXTC6DWiGcXwPQO66QdVNWxuiGdpfPaEUnWXcKnD
# Vua1khBAxO4m9wg/1qM6f7HwXf/pHifMej+qB7SUZOiJScX+1HmffmZRAFiJXS0q
# UDk0ZAZW3oX2xLyl0044eHI7Y95GPaw8OlSTeNiNAKl+MyH5OaifsUuyVHOf4rsr
# E+ZyAuS9e9ERqu5H/10CAwEAAaOCATYwggEyMB0GA1UdDgQWBBRVAolUT3eV3wK/
# +Luf/wawCPMYpzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQAjCREvjT6yXwJYdvkFUqTGGh6RizAY+ciuB6UOBUm0
# yqq5QC+5pCEa9WSMvbUGzxDCEFBgD93gWGnkiyYcHCazlgZK+E7WxtI3bP++Fb4R
# JZiWLo/IC9hX12hCZZwYXIGVzC9BVAcNx/zsFqI/9u8u/bhGjDHPad47C4OQNCHr
# kNqzGYxb4GQq6Psw6o7cEty3MU3Jd4uzBazaFhPRvmBfSn+Ufd6pTNZLgIX9BjrL
# mZblc/d2LIAurEr5W29WfW5RMRIEZzO9TaMr/zzdmW/cV6VdaDTygy5g4O3UXadt
# 1DraUpn5jcD10TVWNnyz/paeleHojrGCCksqexpelMkUsiYP0HX9pFUgNglWU10r
# 1wEzFwZM9aX2Rqq3fFRrN3gu8tCX+H1nKK2AobW1vmsKLTH6PyX1LkyvRwTj45a1
# paeHIR8TGzm3+iY7wpC1MHuzqAqAdDeaIVdVlch807VJJ4hDive6AiOQCV9MwiUy
# hf5v4P8jTGof8CqjDb3PnLlNSnFm2BFhMZ35oNTEosc37GZHScM83hTN1E481sLY
# JrrhhcdtcyNB60juMjqGUD6uQ/7DbMvtv93tFj5WjxVhMCkkY66EEYgpfFLOCb2n
# gJJWFuJCIGsCiDfDxGwE4RVYAnoFzoa2OfSqijYg2drdZfpptRRvKxMsAzu3oxkS
# /TCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046QUUyQy1FMzJCLTFBRkMxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVADgEd+JNrp4d
# pvFKMZi91txbfic3oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDn4WWiMCIYDzIwMjMwNDEzMDExNTE0WhgPMjAy
# MzA0MTQwMTE1MTRaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOfhZaICAQAwBwIB
# AAICDAcwBwIBAAICEc0wCgIFAOfityICAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQBlSfU2L/8WSulUAXV978NpY1Jr7k0hc2PXH/hxFvBtLJzaf/iI0Da3z0Dx
# Q6PUmoN2y5HJePvMYHz0tq5oSpe23w2LaC/s4iXTkEKC1zs2tkOWVd2jw19oM8X4
# 1zXIUpUU0/1txZgyAJH4yh1Ahdr9EbhM+pg8zJ4Y7tAlSc0cOjGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABv99uuQQVUihY
# AAEAAAG/MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEIImlGi91GYlwIqQqc3lvCGhMBc0jvFKla+dg
# leHQdfdfMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg/Q4tRz63EiRj4K+1
# 9yNUwogBIOsp44CIuBfnZHCvBa4wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAb/fbrkEFVIoWAABAAABvzAiBCCNzwJaAZEc/Yf0/w74
# cmzprmq4oT5/HJRv+dViI7pOJTANBgkqhkiG9w0BAQsFAASCAgAd7tmwwGjOuaaM
# BEiAoOCB6XxCzSM7QuJtVXA3GlOBM7w1MnNyPaFeZ8sPp0gk/AutuHSJjmwaWEWQ
# 1SG+7C0t6AQSx+nYWLvaPeaAUKkblH6s1QAaB17xxeLPJZ/ymWFijF6EXvqDr1EL
# oP1Dz5L1wc0znIkInZXHafQAo1emVQMR9WNDm8A1PPTCF0YPwqO9Vxe8lOW1ej0j
# t9pzno3fbRgdR+MmffND8BMRcIx/4hgmPqW8Ac614vx6s1MGf6laN4i8hh7L4d60
# 3fzTIRbCUCfTID2d6WEBMaQwfDAK9tY+dKz00Vo3Ko0vCpyby4h4Bi2450IkVzPA
# XK7uEc4Wg4TInshh62LxXEUZk4WBo7jZFlI/dC2Cm9lok50rW1gvW3ShdHhOkRLZ
# 6lfTwwqVLMxYrQq6pzDA7XPynvRdXXdmsofH0dlrNLb1C8qepd2cHW3MHwEwLYgv
# Eqi+Ndr4HmetLsN0cbxgpeEBuTp9PrJ7+s80b1CJ6gMSlUDeFGcGbVQS13FeAotc
# cj2iV8jHcFhjbxfbFdexNr9FcaJ0XTwnkUEhSYx0dewHNVp2f/5MdSIl7+gKBp+F
# OaytpAphrf3Y12icJpQolRikdv5B3KKSy5Ga9Mll3m3l2iAff5daEFpl/9jmufmB
# A4VnyoAQnRpicMooU26cOPTKZ1uCgQ==
# SIG # End signature block
