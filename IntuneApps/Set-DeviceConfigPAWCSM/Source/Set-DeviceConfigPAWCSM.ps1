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
    [string] $defenderTag,
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
else {

    $script:BuildVer = "1.1"
    $script:ProgramFiles = $env:ProgramFiles
    $script:ParentFolder = $PSScriptRoot | Split-Path -Parent
    $script:ScriptName = $myInvocation.MyCommand.Name
    $script:ScriptName = $scriptName.Substring(0, $scriptName.Length - 4)
    $script:LogName = $scriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
    if ( $userInstall ) {
        $script:logPath = "$($env:LOCALAPPDATA)\Microsoft\IntuneApps\$scriptName"
    }
    else {
        $script:logPath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName"
    }
    $script:logFile = "$logPath\$LogName.log"
    Add-Type -AssemblyName Microsoft.VisualBasic
    Add-Type -AssemblyName "System.Device"
    $script:EventLogName = "Application"
    $script:EventLogSource = "EventSystem"
    if ($VerbosePreference -eq 'Continue') { Start-Transcript -Path "$logPath\Transcript.log" -Append }
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
        #if (!([system.diagnostics.eventlog]::SourceExists($EventLogSource))) { New-EventLog -LogName $EventLogName -Source $EventLogSource }

        Try {
            if (!(Test-Path $FilePath)) {
                ## Create the log file
                New-Item $FilePath -Type File -Force | Out-Null
            }

            if ($DeleteExistingFile) {
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
        if ($WriteEventLog) { Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message $Message  -Id 100 -Category 0 -EntryType Information }
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

            if (-not (Test-Path $TagFilePath) ) {

                New-Item -Path $TagFilePath -ItemType "directory" -Force | out-null
            }

            # Check if tagName already has .tag at the end
            if ($tagName.Substring(($tagName.Length - 4), 4) -eq ".tag") {
                Write-Log -Message "Using passed in tagName: $tagName"
                $tagFileName = "$TagFilePath\$tagName"
            }
            else {
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
            if ($tagName.Substring(($tagName.Length - 4), 4) -eq ".tag") {
                Write-Log -Message "Using passed in tagName: $tagName"
                $tagFileName = "$TagFilePath\$tagName"
            }
            else {
                Write-Log -Message "Using default of scriptname: $tagName and appending .tag"
                $tagFileName = "$TagFilePath\$tagName.tag"
            }

            Write-Log "Removing Intune Tag file: [$tagFileName]"

            if (Test-Path $tagFileName) {
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

            if (-Not(Test-Path $XMLFile)) {
                Write-Log -Message "Error - XML file not found: $XMLFile" -LogLevel 3
                Return $Skip = $true
            }
            Write-Log -Message "Reading XML file: $XMLFile"
            [xml]$script:XML_Content = Get-Content $XMLFile

            foreach ($XMLEntity in $XML_Content.GetElementsByTagName("Azure_Settings")) {
                $script:baseUrl = [string]$XMLEntity.baseUrl
                $script:logRequestUris = [string]$XMLEntity.logRequestUris
                $script:logHeaders = [string]$XMLEntity.logHeaders
                $script:logContent = [string]$XMLEntity.logContent
                $script:azureStorageUploadChunkSizeInMb = [int32]$XMLEntity.azureStorageUploadChunkSizeInMb
                $script:sleep = [int32]$XMLEntity.sleep
            }

            foreach ($XMLEntity in $XML_Content.GetElementsByTagName("IntuneWin_Settings")) {
                $script:PackageName = [string]$XMLEntity.PackageName
                $script:displayName = [string]$XMLEntity.displayName
                $script:Description = [string]$XMLEntity.Description
                $script:Publisher = [string]$XMLEntity.Publisher
            }

        }

        End {
            if ($Skip) { Return }# Just return without doing anything else
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
            if (get-hotfix | Where-Object { $_.HotFixID -match $HotFixID }) {
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
        if (get-hotfix | Where-Object {$_.HotFixID -match $HotFixID}) {
            Write-Log -Message "Hotfix: $HotFixID successfully installed."
            Return "Installed"
        }
        else {
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

    Function Enable-LocationServices {

        <#
        .SYNOPSIS
        This function enables the Windows 10 GeoLocation service
        .DESCRIPTION
        This function enables the Windows 10 GeoLocation service
        .EXAMPLE
        Enable-LocationServices
        This function enables the Windows 10 GeoLocation service
        .NOTES
        NAME: Enable-LocationServices
    #>

        [CmdletBinding()]
        Param ()

        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {

            #HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location
            $LocationConsentKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
            Write-Log -Message "Checking registry key presence: $($LocationConsentKey)"
            if (-not(Test-Path -Path $LocationConsentKey)) {
                Write-Log -Message "Presence of '$($LocationConsentKey)' key was not detected, attempting to create it"
                New-Item -Path $LocationConsentKey -Force | Out-Null
            }

            $LocationConsentValue = Get-ItemPropertyValue -Path $LocationConsentKey -Name "Value" -ErrorAction SilentlyContinue
            Write-Log -Message "Checking registry value 'Value' configuration in key: $($LocationConsentKey)"
            if ($LocationConsentValue -notlike "Allow") {
                Write-Log -Message "Registry value 'Value' configuration mismatch detected, setting value to: Allow"
                Set-ItemProperty -Path $LocationConsentKey -Name "Value" -Type "String" -Value "Allow" -Force
            }

            $CULocationConsentKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
            Write-Log -Message "Checking registry key presence: $($CULocationConsentKey) for username: $env:Username , profilepath: $env:USERPROFILE"
            if (-not(Test-Path -Path $CULocationConsentKey)) {
                Write-Log -Message "Presence of '$($CULocationConsentKey)' key was not detected, attempting to create it"
                #New-Item -Path $CULocationConsentKey -Force | Out-Null
                New-Item -Path $CULocationConsentKey -Force
                Set-ItemProperty -Path $CULocationConsentKey -Name "Value" -Type "String" -Value "Allow" -Force
            }

            <#
        $CULocationConsentValue = Get-ItemPropertyValue -Path $CULocationConsentKey -Name "Value" -ErrorAction SilentlyContinue
        Write-Log -Message "Checking registry value 'Value' configuration in key: $($CULocationConsentKey)"
        if ($CULocationConsentValue -notlike "Allow") {
            Write-Log -Message "Registry value 'Value' configuration mismatch detected, setting value to: Allow"
            Set-ItemProperty -Path $CULocationConsentKey -Name "Value" -Type "String" -Value "Allow" -Force
        }
        #>

            $SensorPermissionStateRegValue = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
            $SensorPermissionStateValue = Get-ItemPropertyValue -Path $SensorPermissionStateRegValue -Name "SensorPermissionState" -ErrorAction SilentlyContinue
            Write-Log -Message "Checking registry value 'SensorPermissionState' configuration in key: $($SensorPermissionStateRegValue)"
            if ($SensorPermissionStateValue -ne 1) {
                Write-Log -Message "Registry value 'SensorPermissionState' configuration mismatch detected, setting value to: 1"
                Set-ItemProperty -Path $SensorPermissionStateRegValue -Name "SensorPermissionState" -Type "DWord" -Value 1 -Force
            }

            $LocationServiceStatusRegValue = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
            Write-Log -Message "Checking registry key presence: $($LocationServiceStatusRegValue)"
            if (-not(Test-Path -Path $LocationServiceStatusRegValue)) {
                Write-Log -Message "Presence of '$($LocationServiceStatusRegValue)' key was not detected, attempting to create it"
                New-Item -Path $LocationServiceStatusRegValue -Force | Out-Null
            }

            New-ItemProperty -Path $LocationServiceStatusRegValue -Name "Status" -Type "DWord" -Value 1 -Force
            $LocationServiceStatusValue = Get-ItemPropertyValue -Path $LocationServiceStatusRegValue -Name "Status" -ErrorAction SilentlyContinue
            Write-Log -Message "Checking registry value 'Status' configuration in key: $($LocationServiceStatusRegValue)"
            if ($LocationServiceStatusValue -ne 1) {
                Write-Log -Message "Registry value 'Status' configuration mismatch detected, setting value to: 1"
                Set-ItemProperty -Path $LocationServiceStatusRegValue -Name "Status" -Type "DWord" -Value 1 -Force
            }

            $LocationService = Get-Service -Name "lfsvc"
            Write-Log -Message "Checking location service 'lfsvc' for status: Running"
            if ($LocationService.Status -notlike "Running") {
                Write-Log -Message "Location service is not running, attempting to start service"
                Start-Service -Name "lfsvc"
            }

        }
    }

    ####################################################

    Function Get-GeoCoordinate {

        <#
        .SYNOPSIS
        This function determines current device physical location co-ordinates
        .DESCRIPTION
        This function determines current device physical location co-ordinates
        .EXAMPLE
        Get-GeoCoordinate
        This function determines current device physical location co-ordinates
        .NOTES
        NAME: Get-GeoCoordinate
    #>

        [CmdletBinding()]
        Param ()

        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {

            # Construct return value object
            $Coordinates = [PSCustomObject]@{
                Latitude  = $null
                Longitude = $null
            }

            Write-Log -Message "Attempting to start resolving the current device coordinates"
            $GeoCoordinateWatcher = New-Object -TypeName "System.Device.Location.GeoCoordinateWatcher"
            $GeoCoordinateWatcher.Start()

            # Wait until watcher resolves current location coordinates
            $GeoCounter = 0
            while (($GeoCoordinateWatcher.Status -notlike "Ready") -and ($GeoCoordinateWatcher.Permission -notlike "Denied") -and ($GeoCounter -le 60)) {
                Start-Sleep -Seconds 1
                $GeoCounter++
            }

            # Break operation and return empty object since permission was denied
            if ($GeoCoordinateWatcher.Permission -like "Denied") {
                Write-Log -Message "Permission was denied accessing coordinates from location services"

                # Stop and dispose of the GeCoordinateWatcher object
                $GeoCoordinateWatcher.Stop()
                $GeoCoordinateWatcher.Dispose()

                # Handle return error
                return $Coordinates
            }

            # Set coordinates for return value
            $Coordinates.Latitude = ($GeoCoordinateWatcher.Position.Location.Latitude).ToString().Replace(",", ".")
            $Coordinates.Longitude = ($GeoCoordinateWatcher.Position.Location.Longitude).ToString().Replace(",", ".")

            # Stop and dispose of the GeCoordinateWatcher object
            $GeoCoordinateWatcher.Stop()
            $GeoCoordinateWatcher.Dispose()

            # Handle return value
            return $Coordinates

        }
    }

    ####################################################


    Function Set-OSTimeZone {

        <#
    .SYNOPSIS
        Automatically detect the current location using Location Services in Windows 10 and call the Azure Maps API to determine and set the Windows time zone based on current location data.

    .DESCRIPTION
        This script will automatically set the Windows time zone based on current location data. It does so by detecting the current position (latitude and longitude) from Location services
        in Windows 10 and then calls the Azure Maps API to determine correct Windows time zone based of the current position. If Location Services is not enabled in Windows 10, it will automatically
        be enabled and ensuring the service is running.

    .PARAMETER AzureMapsSharedKey
        Specify the Azure Maps API shared key available under the Authentication blade of the resource in Azure.

    .NOTES
    NAME: Set-OSTimeZone
    #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [parameter(Mandatory = $false, HelpMessage = "Specify the Azure Maps API shared key available under the Authentication blade of the resource in Azure.")]
            [ValidateNotNullOrEmpty()]
            [string]$AzureMapsSharedKey

        )

        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {

            try {
                # Load required assembly and construct a GeCoordinateWatcher object
                Write-Log -Message "Attempting to load required 'System.Device' assembly"
                #Add-Type -AssemblyName "System.Device" -ErrorAction Stop

                try {
                    # Ensure Location Services in Windows is enabled and service is running
                    Enable-LocationServices

                    # Retrieve the latitude and longitude values
                    $GeoCoordinates = Get-GeoCoordinate
                    if (($GeoCoordinates.Latitude -ne $null) -and ($GeoCoordinates.Longitude -ne $null)) {
                        Write-Log -Message "Successfully resolved current device coordinates"
                        Write-Log -Message "Detected latitude: $($GeoCoordinates.Latitude)"
                        Write-Log -Message "Detected longitude: $($GeoCoordinates.Longitude)"

                        # Construct query string for Azure Maps API request
                        $AzureMapsQuery = -join @($GeoCoordinates.Latitude, ",", $GeoCoordinates.Longitude)

                        try {
                            # Call Azure Maps timezone/byCoordinates API to retrieve IANA time zone id
                            Write-Log -Message "Attempting to determine IANA time zone id from Azure MAPS API using query: $($AzureMapsQuery)"
                            $AzureMapsTimeZoneURI = "https://atlas.microsoft.com/timezone/byCoordinates/json?subscription-key=$($AzureMapsSharedKey)&api-version=1.0&options=all&query=$($AzureMapsQuery)"
                            $AzureMapsTimeZoneResponse = Invoke-RestMethod -Uri $AzureMapsTimeZoneURI -Method "Get" -ErrorAction Stop
                            if ($AzureMapsTimeZoneResponse -ne $null) {
                                $IANATimeZoneValue = $AzureMapsTimeZoneResponse.TimeZones.Id
                                Write-Log -Message "Successfully retrieved IANA time zone id from current position data: $($IANATimeZoneValue)"

                                try {
                                    # Call Azure Maps timezone/enumWindows API to retrieve the Windows time zone id
                                    Write-Log -Message "Attempting to Azure Maps API to enumerate Windows time zone ids"
                                    $AzureMapsWindowsEnumURI = "https://atlas.microsoft.com/timezone/enumWindows/json?subscription-key=$($AzureMapsSharedKey)&api-version=1.0"
                                    $AzureMapsWindowsEnumResponse = Invoke-RestMethod -Uri $AzureMapsWindowsEnumURI -Method "Get" -ErrorAction Stop
                                    if ($AzureMapsWindowsEnumResponse -ne $null) {
                                        $TimeZoneID = $AzureMapsWindowsEnumResponse | Where-Object { ($PSItem.IanaIds -like $IANATimeZoneValue) -and ($PSItem.Territory.Length -eq 2) } | Select-Object -ExpandProperty WindowsId
                                        Write-Log -Message "Successfully determined the Windows time zone id: $($TimeZoneID)"

                                        try {
                                            # Set the time zone
                                            Write-Log -Message "Attempting to configure the Windows time zone id with value: $($TimeZoneID)"
                                            Set-TimeZone -Id $TimeZoneID -ErrorAction Stop
                                            Write-Log -Message "Successfully configured the Windows time zone"
                                        }
                                        catch [System.Exception] {
                                            Write-Log -Message "Failed to set Windows time zone. Error message: $($PSItem.Exception.Message)"
                                        }
                                    }
                                    else {
                                        Write-Log -Message "Invalid response from Azure Maps call enumerating Windows time zone ids"
                                    }
                                }
                                catch [System.Exception] {
                                    Write-Log -Message "Failed to call Azure Maps API to enumerate Windows time zone ids. Error message: $($PSItem.Exception.Message)"
                                }
                            }
                            else {
                                Write-Log -Message "Invalid response from Azure Maps query when attempting to retrieve the IANA time zone id"
                            }
                        }
                        catch [System.Exception] {
                            Write-Log -Message "Failed to retrieve the IANA time zone id based on current position data from Azure Maps. Error message: $($PSItem.Exception.Message)"
                        }
                    }
                    else {
                        Write-Log -Message "Unable to determine current device coordinates from location services, breaking operation"
                    }
                }
                catch [System.Exception] {
                    Write-Log -Message "Failed to determine Windows time zone. Error message: $($PSItem.Exception.Message)"
                }
            }
            catch [System.Exception] {
                Write-Log -Message "Failed to load required 'System.Device' assembly, breaking operation"
            }

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

    if ($Install) {
        Write-Log -Message "Performing Install steps..."

        #region CMTrace
        if (Test-Path -Path $PSScriptRoot\cmtrace.exe) {
            # cmtrace.exe exists in script folder
            Write-Log -Message "Copy CMTrace for logging"

            Write-Log -Message "Create path: $env:ProgramFiles\Tools"
            Try {
                New-Item -Path "$env:ProgramFiles\Tools" -ItemType "Directory" -Force -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to create path: $($_.Exception.message)"
                Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                Exit
            }

            Write-Log -Message "Copy item: $PSScriptRoot\cmtrace.exe"
            Try {
                Copy-Item -Path "$PSScriptRoot\cmtrace.exe" -Destination "$env:ProgramFiles\Tools" -Force -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to create path: $($_.Exception.message)"
                Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                Exit
            }

            # Create Resgistry Keys
            Write-Log -Message "Creating CMTrace log-file shell extension registry entries..."
            New-Item -Path 'HKLM:\Software\Classes\.lo_' -type Directory -Force -ErrorAction SilentlyContinue
            New-Item -Path 'HKLM:\Software\Classes\.log' -type Directory -Force -ErrorAction SilentlyContinue
            New-Item -Path 'HKLM:\Software\Classes\.log.File' -type Directory -Force -ErrorAction SilentlyContinue
            New-Item -Path 'HKLM:\Software\Classes\.Log.File\shell' -type Directory -Force -ErrorAction SilentlyContinue
            New-Item -Path 'HKLM:\Software\Classes\Log.File\shell\Open' -type Directory -Force -ErrorAction SilentlyContinue
            New-Item -Path 'HKLM:\Software\Classes\Log.File\shell\Open\Command' -type Directory -Force -ErrorAction SilentlyContinue
            New-Item -Path 'HKLM:\Software\Microsoft\Trace32' -type Directory -Force -ErrorAction SilentlyContinue

            # Create the properties to make CMtrace the default log viewer
            New-ItemProperty -LiteralPath 'HKLM:\Software\Classes\.lo_' -Name '(default)' -Value "Log.File" -PropertyType String -Force -ea SilentlyContinue;
            New-ItemProperty -LiteralPath 'HKLM:\Software\Classes\.log' -Name '(default)' -Value "Log.File" -PropertyType String -Force -ea SilentlyContinue;
            New-ItemProperty -LiteralPath 'HKLM:\Software\Classes\Log.File\shell\open\command' -Name '(default)' -Value "`"$env:ProgramFiles\Tools\CMTrace.exe`" `"%1`"" -PropertyType String -Force -ea SilentlyContinue;

            # Create an ActiveSetup that will remove the initial question in CMtrace if it should be the default reader
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\CMtrace" -type Directory -Force
            new-itemproperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\CMtrace" -Name "Version" -Value 1 -PropertyType String -Force
            new-itemproperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\CMtrace" -Name "StubPath" -Value "reg.exe add HKCU\Software\Microsoft\Trace32 /v ""Register File Types"" /d 0 /f" -PropertyType ExpandString -Force
        }
        #endregion CMTrace

        #region Enable Max Performance Power Overlay
        Write-Log -Message "Enabling Max Performance Power Overlay"
        $command = "powercfg.exe"
        $args = "/overlaysetactive overlay_scheme_max"
        $workDir = "$env:SystemRoot\System32"
        Try {
            Start-Process -FilePath $command -WorkingDirectory $workDir -ArgumentList $args -Wait -WindowStyle Hidden -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred trying to enable Max Performance Power Overlay: $($_.Exception.message)"
        }
        #endregion Enable Max Performance Power Overlay

        #region Scheduled Tasks All History option
        $logName = 'Microsoft-Windows-TaskScheduler/Operational'
        $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
        $log.IsEnabled = $true
        $log.SaveChanges()
        #endregion Scheduled Tasks All History option

        #Correct AAD Time Sync
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient -Name SpecialPollInterval -Value 900 -ErrorAction Stop
        try {
            Start-Process -FilePath "C:\Windows\System32\sc.exe" -ArgumentList "triggerinfo w32time start/networkon stop/networkoff" -Wait -WindowStyle Hidden -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred trying to configure Time Sync: $($_.Exception.message)"
        }
        #region IsVM
        if (Is-VM) {
            Write-Log -Message "Machine is a VM"
        }
        else {
            Write-Host "Machine is a physical device"

            #Enable Hibernate
            Write-Log -Message "Enabling Hibernation"
            $command = "C:\Windows\System32\PowerCfg.exe"
            $args = "/HIBERNATE"
            $workDir = "C:\Windows\System32"
            Try {
                Start-Process -FilePath $command -WorkingDirectory $workDir -ArgumentList $args -Wait -WindowStyle Hidden -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to enable hibernate: $($_.Exception.message)"
                #Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                #Exit
            }

            Try {
                New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\Explorer -Name ShowHibernateOption -Value 1 -PropertyType DWORD -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to apply ShowHibernate regkey: $($_.Exception.message)"
                #Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                #Exit
            }

            $command = "C:\Windows\System32\PowerCfg.exe"
            $args = "/Change hibernate-timeout-ac 300"
            $workDir = "C:\Windows\System32"
            Try {
                Start-Process -FilePath $command -WorkingDirectory $workDir -ArgumentList $args -Wait -WindowStyle Hidden -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to enable hibernate ac timeout: $($_.Exception.message)"
                #Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                #Exit
            }

            $command = "C:\Windows\System32\PowerCfg.exe"
            $args = "/Change hibernate-timeout-dc 30"
            $workDir = "C:\Windows\System32"
            Try {
                Start-Process -FilePath $command -WorkingDirectory $workDir -ArgumentList $args -Wait -WindowStyle Hidden -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to enable hibernate dc timeout: $($_.Exception.message)"
                #Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                #Exit
            }

            $command = "C:\Windows\System32\PowerCfg.exe"
            $args = "/Change standby-timeout-ac 60"
            $workDir = "C:\Windows\System32"
            Try {
                Start-Process -FilePath $command -WorkingDirectory $workDir -ArgumentList $args -Wait -WindowStyle Hidden -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred trying to enable standby ac timeout: $($_.Exception.message)"
                #Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                #Exit
            }

            Write-Log -Message 'Show Hibernate option in Shutdown Menu'
            $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
            $regProperties = @{
                Name         = 'ShowHibernateOption'
                Value        = '1'
                PropertyType = 'DWORD'
                ErrorAction  = 'Stop'
            }

            Try {
                $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            }
            Catch [System.Management.Automation.ItemNotFoundException] {
                Write-Log -Message "Error: $registryPath path not found, attempting to create..."
                $Null = New-Item -Path $registryPath -Force
                $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            }
            Catch {
                Write-Log -Message "Error changing registry: $($_.Exception.message)"
                Write-Warning "Error: $($_.Exception.message)"
                #Exit
            }
            Finally {
                Write-Log -Message "Finished changing registry"
            }
        }
        #endregion IsVM

        #region RemoveLTIBootStrap
        Write-Log -Message "Removing MDT LTIBootStrap.vbs files..."
        Get-PSDrive -PSProvider FileSystem | ForEach-Object Root | Get-ChildItem -File -Force -ErrorAction Ignore | Where-Object Name -eq 'LTIBootstrap.vbs' | Tee-Object -Variable deleted | Remove-Item -Force
        Write-Log -Message: "Removed files: $($deleted.pspath.replace("Microsoft.PowerShell.Core\FileSystem::", """))"
        #endregion RemoveLTIBootStrap

        #region Disable Network Location Wizard
        #Handle registry changes
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"
        $regProperties = @{
            Name        = "NewNetworkWindowOff"
            ErrorAction = "Stop"
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Log -Message "Finished changing registry: Network - NewNetworkWindowOff"
        }
        #endregion Disable Network Location Wizard

        #region Add Microsoft Print to PDF
        try {
            Enable-WindowsOptionalFeature -online -NoRestart -FeatureName Printing-PrintToPDFServices-Features -All -ErrorAction Stop
            Write-Log -Message "Added Microsoft Print to PDF"
        }
        catch {
            Write-Log -Message "Error occurred trying to add Microsoft Print to PDF: $($_.Exception.message)"
        }
        #endregion Add Microsoft Print to PDF

        #region Remove PowerShell 2.0
        try {
            Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
            Write-Log -Message "Removed Powershell v2.0"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove Powershell v2.0: $($_.Exception.message)"
        }
        #endregion Remove PowerShell 2.0

        #region Remove WorkFolders-Client
        try {
            Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName WorkFolders-Client -ErrorAction Stop
            Write-Log -Message "Removed WorkFolders"
        }
        catch {
            Write-Log -Message "Failed to remove WorkFolders"
            Write-Log -Message "Error occurred trying to remove Powershell v2.0: $($_.Exception.message)"
        }
        #endregion Remove WorkFolders-Client

        #region Remove XPS Printing
        try {
            Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName Printing-XPSServices-Features -ErrorAction Stop
            Write-Log -Message "Removed XPS Printing"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove XPS Printing: $($_.Exception.message)"
        }
        #endregion Remove XPS Printing

        #region Remove WindowsMediaPlayer
        try {
            Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName WindowsMediaPlayer -ErrorAction Stop
            Write-Log -Message "Removed Windows Media Player"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove Windows Media Player: $($_.Exception.message)"
        }
        #endregion Remove WindowsMediaPlayer

        #region Remove AzureRM PowerShell module
        try {
            Write-Log -Message "Removing AzureRM PowerShell module"
            $OldAzureModules = Get-InstalledModule -Name "AzureRM*" -ErrorAction Stop
            foreach ($module in $OldAzureModules) {
                Uninstall-Module -Name $module.name -Force -ErrorAction Stop
            }
            Write-Log -Message "Removed AzureRM PowerShell module"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove AzureRM PowerShell module: $($_.Exception.message)"
        }
        #endregion Remove AzureRM PowerShell module

        #region Remove AzureAD PowerShell module
        try {
            Write-Log -Message "Removing AzureAD PowerShell module"
            $OldAzureModules = Get-InstalledModule -Name "AzureAD*" -ErrorAction Stop
            foreach ($module in $OldAzureModules) {
                Uninstall-Module -Name $module.name -Force -ErrorAction Stop
            }
            Write-Log -Message "Removed AzureAD PowerShell module"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove AzureAD PowerShell module: $($_.Exception.message)"
        }
        #endregion Remove AzureAD PowerShell module

        #region Remove WindowsAutoPilotIntune PowerShell module
        try {
            Write-Log -Message "Removing WindowsAutoPilotIntune PowerShell module"
            Uninstall-Module -Name WindowsAutoPilotIntune -Force -ErrorAction Stop
            Write-Log -Message "Removed WindowsAutoPilotIntune PowerShell module"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove WindowsAutoPilotIntune PowerShell module: $($_.Exception.message)"
        }
        #endregion Remove WindowsAutoPilotIntune PowerShell module

        #region Remove Microsoft.Graph.Intune PowerShell module
        try {
            Write-Log -Message "Removing Microsoft.Graph.Intune PowerShell module"
            Uninstall-Module -Name Microsoft.Graph.Intune -Force -ErrorAction Stop
            Write-Log -Message "Removed Microsoft.Graph.Intune PowerShell module"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove Microsoft.Graph.Intune PowerShell module: $($_.Exception.message)"
        }
        #endregion Remove Microsoft.Graph.Intune PowerShell module

        #region RegistryChanges - Set W32Time Parameter Type to NTP
        #Handle registry changes
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
        $regProperties = @{
            Name         = "Type"
            Value        = "NTP"
            PropertyType = "String"
            ErrorAction  = "Stop"
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Updated Set W32Time Parameter Type to NTP in registry"
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Log -Message "Finished changing registry: W32Time Parameters - NTP"
        }
        #endregion RegistryChanges - Set W32Time Parameter Type to NTP

        #region RegistryChanges - Set Auto Time Sync Service to Automatic start
        #Handle registry changes
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate"
        $regProperties = @{
            Name         = "Start"
            Value        = "3"
            PropertyType = "DWORD"
            ErrorAction  = "Stop"
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Set Auto Time Sync Service to Automatic start in registry"
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Log -Message "Finished changing registry: tzautoupdate"
        }
        #endregion RegistryChanges - Set Auto Time Sync Service to Automatic start

        #region w32time trigger start
        #sc triggerinfo w32time start/networkon stop/networkoff
        $command = 'sc.exe'
        $workDir = "$env:SystemRoot\system32"
        $ArgumentList = 'triggerinfo w32time start/networkon stop/networkoff'

        Try {
            Start-Process -FilePath $command -ArgumentList $ArgumentList -WorkingDirectory $workDir -Wait -WindowStyle Hidden -ErrorAction Stop
            Write-Log -Message "Adjust w32time trigger start based on whether a device has an IP address"
        }
        Catch {
            Write-Log -Message "Error changing w32time trigger start: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Log -Message "Finished changing w32time trigger start"
        }
        #endregion w32time trigger start

        #region perform a time sync
        #%windir%\system32\sc.exe start w32time task_started
        $command = 'sc.exe'
        $workDir = "$env:SystemRoot\system32"
        $ArgumentList = 'start w32time task_started'
        Start-Process -FilePath $command -ArgumentList $ArgumentList -WorkingDirectory $workDir -Wait -WindowStyle Hidden -ErrorAction Stop
        Try {
            Start-Process -FilePath $command -ArgumentList $ArgumentList -WorkingDirectory $workDir -Wait -WindowStyle Hidden -ErrorAction Stop
            Write-Log -Message "Performed a w32time sync"
        }
        Catch {
            Write-Log -Message "Error performing w32time sync: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Log -Message "Ran w32time sync"
        }
        #endregion perform a time sync

        #region Remove Internet Explorer 11
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -NoRestart #-ErrorAction Stop
            Write-Log -Message "Removed Internet Explorer 11"
        }
        catch {
            Write-Log -Message "Error occurred trying to remove Internet Explorer 11: $($_.Exception.message)"
        }
        #endregion Remove Internet Explorer 11

        #region RegistryChanges - AppLocker DLL rulset registry fix
        #Handle registry changes
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp\DLL\2"
        Write-Log -Message "Check for registry path: $registryPath"
        if (!((Test-Path -Path $registryPath))) {
            Write-Log -Message "Path not found, creating..."
            Try {
                $Null = New-Item -Path $registryPath -Force
            }
            Catch {
                Write-Log -Message "Error changing registry: $($_.Exception.message)"
                Write-Warning "Error: $($_.Exception.message)"
                Exit
            }
            Finally {
                Write-Log -Message "Finished changing registry"
            }
        }
        else {
            Write-Host "Path already exists!"
        }
        #endregion RegistryChanges - AppLocker DLL rulset registry fix

        #region RegistryChanges - Defender ATP Device Tag registry fix
        if (!($defenderTag)) {
            $defenderTag = 'PAWCSM'
            Write-Host "Defender Tag empty, defaulting to: $defenderTag"
        }
        #Handle registry changes
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging"
        $regProperties = @{
            Name         = "Group"
            Value        = $defenderTag
            PropertyType = "String"
            ErrorAction  = "Stop"
        }

        $regValue = Get-ItemProperty -Path $registryPath -Name $regProperties.Name -ErrorAction SilentlyContinue
        if (!($regValue)) {
            Write-Log -Message 'Registry path not found'
            Try {
                Write-Log -Message "Attempting to create registry value: $registryPath\$($regProperties.Name)"
                $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            }
            Catch [System.Management.Automation.ItemNotFoundException] {
                Write-Log -Message "Error: $registryPath path not found, attempting to create..."
                $Null = New-Item -Path $registryPath -Force
                $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            }
            Catch {
                Write-Log -Message "Error cconfiguring registry: $($_.Exception.message)"
                Write-Warning "Error: $($_.Exception.message)"
                Exit
            }
            Finally {
                Write-Log -Message "New registry value exists as: $((Get-ItemProperty -Path $registryPath -Name $regProperties.Name).$($regProperties.Name))"
                Write-Log -Message "Finished configuring registry"
            }
        }
        else {
            Write-Log -Message "Registry value already exists as: $($regValue.$($regProperties.Name))"
        }
        #endregion RegistryChanges - Defender ATP Device Tag registry fix

        #region RegistryChanges - Set Security Registry Entries
        #New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name NC_StdDomainUserSetLocation -Value 1 -PropertyType DWORD -Force
        Write-Log -Message "Setting NC_StdDomainUserSetLocation registry value 1"
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
        $regProperties = @{
            Name         = 'NC_StdDomainUserSetLocation'
            Value        = '1'
            PropertyType = 'DWORD'
            ErrorAction  = 'Stop'
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Setting NC_StdDomainUserSetLocation registry value 1 to require domain users to elevate when setting a networks location..."
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Host "Finished changing registry"
        }

        #New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity -Name Enabled -Value 1 -PropertyType DWORD -Force
        Write-Log -Message "Setting HyperVisor Enforced Code Integrity HVCI registry values"

        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $regProperties = @{
            Name         = 'Enabled'
            Value        = '1'
            PropertyType = 'DWORD'
            ErrorAction  = 'Stop'
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Setting HyperVisor Enforced Code Integrity HVCI registry value Enabled set to 1 to provide additional Kernel tampering protection..."
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Host "Finished changing registry"
        }

        #New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity -Name Locked -Value 1 -PropertyType DWORD -Force
        Write-Log -Message "Setting HyperVisor Enforced Code Integrity HVCI registry value Locked"

        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $regProperties = @{
            Name         = 'Locked'
            Value        = '1'
            PropertyType = 'DWORD'
            ErrorAction  = 'Stop'
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Setting HyperVisor Enforced Code Integrity HVCI registry value Locked set to 1 to UEFI lock HVCI policy..."
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Host "Finished changing registry"
        }

        #New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name DisableDomainCreds -Value 1 -PropertyType DWORD -Force
        Write-Log -Message "Setting DisableDomainCreds registry value"
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regProperties = @{
            Name         = 'DisableDomainCreds'
            Value        = '1'
            PropertyType = 'DWORD'
            ErrorAction  = 'Stop'
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Setting DisableDomainCreds registry value to 1 to prevent the storage of passwords and credentials..."
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Host "Finished changing registry"
        }

        #New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -PropertyType DWORD -Force
        Write-Log -Message "Forces LSA to run as Protected Process Light PPL"

        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regProperties = @{
            Name         = 'RunAsPPL'
            Value        = '1'
            PropertyType = 'DWORD'
            ErrorAction  = 'Stop'
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Forces LSA to run as Protected Process Light PPL registry value RunAsPPL set to 1..."
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Host "Finished changing registry"
        }

        #HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name SafeModeBlockNonAdmins -Value 1 -PropertyType DWORD -Force
        Write-Log -Message "Prevents standard users from starting in Safe Mode"

        $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regProperties = @{
            Name         = 'SafeModeBlockNonAdmins'
            Value        = '1'
            PropertyType = 'DWORD'
            ErrorAction  = 'Stop'
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Prevents standard users from starting in Safe Mode registry value SafeModeBlockNonAdmins set to 1..."
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Host "Finished changing registry"
        }
        #endregion RegistryChanges - Set Security Registry Entries

        #region RegistryChanges - Intel unquoted service paths
        Write-Log -Message "Running Windows Unquoted Service Path Fix"
        Try {
            & $PSScriptRoot\Windows_Path_Enumerate.ps1 -FixUninstall -FixEnv -CreateBackup -BackupFolderPath "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName\" -LogName "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName\$scriptname-fix.log"
        }
        Catch {
            Write-Log -Message "Error occurred trying to run script: $($_.Exception.message)"
            Exit
        }
        #endregion RegistryChanges - Intel unquoted service paths

        #region Removable Drive ID Value
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name "IdentificationField" -Value 1 -PropertyType DWORD -Force

        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name "IdentificationFieldString" -Value PAWCSM -PropertyType String -Force

        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name "SecondaryIdentificationField" -Value PAWCSM -PropertyType String -Force
        #endregion Removable Drive ID Value


        #region Remove Office



        #Check if Office is installed...

        Write-Log -Message "Removing Microsoft Office..."
        Start-Process -FilePath "$PSScriptRoot\setup.exe" -ArgumentList "/configure $PSScriptRoot\configuration.xml" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Log -Message "Microsoft Office was removed if installed"
        #endregion Remove Office

        <#

#region Add NetFx3 (.NET 3.5 Framework)
    try {
	    Enable-WindowsOptionalFeature -online -FeatureName NetFx3 -All -ErrorAction Stop
	    Write-Log -Message "Added .NetFx3"
    }
    catch {
        Write-Log -Message "Error occurred trying to add .NetFx3: $($_.Exception.message)"
    }
#endregion Add NetFx3 (.NET 3.5 Framework)

#region InstallHotfix
    #Assumes the hotfix .msu file is in the same folder as the script
    $installHotfix = Install-Hotfix -HotFixID "windows10.0-kb4549951-x64_5411f88ea08bfc0ac98f388f5a3bdc8bcfea3261.msu"

    if ($installHotfix -eq "Installed") {
        Write-Log -Message "Hotfix successfully installed"
    }
    ElseIf ($installHotfix -eq "Failed") {
        Write-Log -Message "Hotfix not installed, exiting..."
        Exit
    }
#endregion InstallHotfix

#region RegistryChanges
    #Handle registry changes
    $registryPath = "HKLM:\Software\Microsoft\MCS\Scripts"
    $regProperties = @{
        Name = "Version"
        Value = "1"
        PropertyType = "DWORD"
        ErrorAction = "Stop"
    }

    Try {
        $Null = New-ItemProperty -Path $registryPath @regProperties -Force
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Log -Message "Error: $registryPath path not found, attempting to create..."
        $Null = New-Item -Path $registryPath -Force
        $Null = New-ItemProperty -Path $registryPath @regProperties -Force
    }
    Catch {
        Write-Log -Message "Error changing registry: $($_.Exception.message)"
        Write-Warning "Error: $($_.Exception.message)"
        Exit
    }
    Finally {
        Write-Log -Message "Finished changing registry"
    }
#endregion RegistryChanges

#>

        #region RegistryChanges - Disable Mounting of Disk Image Files
        #https://support.huntress.io/hc/en-us/articles/11477430445587-How-to-disable-ISO-mounting
        #reg add HKEY_CLASSES_ROOT\Windows.IsoFile\shell\mount /v ProgrammaticAccessOnly /t REG_SZ
        #Handle registry changes
        Write-Log -Message "Update registry to disable mounting of disk image (ISO) files"
        New-PSDrive -PSProvider Registry -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
        $registryPath = "HKCR:\Windows.IsoFile\shell\mount"
        Write-Log -Message "Configure registry path: $registryPath"
        $regProperties = @{
            Name         = 'ProgrammaticAccessOnly'
            PropertyType = 'String'
            ErrorAction  = 'Stop'
        }

        Try {
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
            Write-Log -Message "Setting IsoFile registry item mount to ProgrammaticAccessOnly"
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "Error: $registryPath path not found, attempting to create..."
            $Null = New-Item -Path $registryPath -Force
            $Null = New-ItemProperty -Path $registryPath @regProperties -Force
        }
        Catch {
            Write-Log -Message "Error changing registry: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            Exit
        }
        Finally {
            Write-Host "Finished changing registry"
        }
        #endregion RegistryChanges - Disable Mounting of Disk Image Files

        #region Enable firewall auditing: Filtering Platform Packet Drop failures
        #auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable
        $command = 'auditpol.exe'
        $workDir = "$env:SystemRoot\system32"
        $ArgumentList = '/set /subcategory:"Filtering Platform Packet Drop" /failure:enable'

        Try {
            Start-Process -FilePath $command -ArgumentList $ArgumentList -WorkingDirectory $workDir -Wait -WindowStyle Hidden -ErrorAction Stop
            Write-Log -Message "Enable firewall auditing: Filtering Platform Packet Drop"
        }
        Catch {
            Write-Log -Message "Error running command: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            #Exit
        }
        Finally {
            Write-Log -Message "Finished enabling firewall auditing: Filtering Platform Packet Drop"
        }
        #endregion Enable firewall auditing: Filtering Platform Packet Drop failures

        #region Enable firewall auditing: Filtering Platform Connection failures
        #auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
        $command = 'auditpol.exe'
        $workDir = "$env:SystemRoot\system32"
        $ArgumentList = '/set /subcategory:"Filtering Platform Connection" /failure:enable'

        Try {
            Start-Process -FilePath $command -ArgumentList $ArgumentList -WorkingDirectory $workDir -Wait -WindowStyle Hidden -ErrorAction Stop
            Write-Log -Message "Enable firewall auditing: Filtering Platform Connection failures"
        }
        Catch {
            Write-Log -Message "Error running command: $($_.Exception.message)"
            Write-Warning "Error: $($_.Exception.message)"
            #Exit
        }
        Finally {
            Write-Log -Message "Finished enabling firewall auditing: Filtering Platform Connection failures"
        }
        #endregion Enable firewall auditing: Filtering Platform Packet Drop failures

        #Handle Intune detection method
        if (! ($userInstall) ) {
            Write-Log -Message "Creating detection rule for System install"

            if ( $regTag ) {
                Write-Log -Message "Using RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                New-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            else {
                Write-Log -Message "Using FileTag"

                if ( ! ( IsNull ( $tagFile ) ) ) {
                    Write-Log -Message "Using tagFile name: $tagFile"
                    New-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
                }
                else {
                    Write-Log -Message "Using default tagFile name: $scriptName"
                    New-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
                }
            }
        }
        ElseIf ( $userInstall ) {
            Write-Log -Message "Creating detection rule for User install"

            if ( $regTag ) {
                Write-Log -Message "Using RegTag: HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                New-IntuneRegTag -TagRegPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            else {
                Write-Log -Message "Using FileTag: "

                if ( ! ( IsNull ( $tagFile ) ) ) {
                    Write-Log -Message "Using tagFile name: $tagFile"
                    New-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
                }
                else {
                    Write-Log -Message "Using default tagFile name: $scriptName"
                    New-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
                }
            }
        }
    }
    ElseIf ( $UnInstall ) {
        Write-Log -Message "Performing Uninstall steps..."

        #region Remove Registry entries
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name NC_StdDomainUserSetLocation -Force

        Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name DisableDomainCreds -Force
        #endregion Remove Registry entries

        #Handle Intune detection method
        if (! ($userInstall) ) {
            Write-Log -Message "Removing detection for System install"

            if ( $regTag ) {
                Write-Log -Message "Removing RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                Remove-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            else {
                Write-Log -Message "Removing FileTag"

                if ( ! ( IsNull ( $tagFile ) ) ) {
                    Write-Log -Message "Removing tagFile name: $tagFile"
                    Remove-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
                }
                else {
                    Write-Log -Message "Removing default tagFile name: $scriptName"
                    Remove-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
                }
            }
        }
        ElseIf ( $userInstall ) {
            Write-Log -Message "Removing detection for User install"

            if ( $regTag ) {
                Write-Log -Message "Removing RegTag: HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                Remove-IntuneRegTag -TagRegPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            else {
                Write-Log -Message "Removing FileTag: "

                if ( ! ( IsNull ( $tagFile ) ) ) {
                    Write-Log -Message "Removing tagFile name: $tagFile"
                    Remove-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
                }
                else {
                    Write-Log -Message "Removing default tagFile name: $scriptName"
                    Remove-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
                }
            }
        }
    }


    Write-Log "$ScriptName completed." -WriteEventLog
    if ($VerbosePreference -eq 'Continue') { Stop-Transcript }
    exit $exitCode

    ##########################################################################################################
    ##########################################################################################################
    #endregion Main Script work section
}
# SIG # Begin signature block
# MIIn0QYJKoZIhvcNAQcCoIInwjCCJ74CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCz+q8Stn5CO0Cj
# zdtgRsZp09mx2GKqJ9wdRgXLB9qTwaCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGaIwghmeAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAALN82S/+NRMXVEAAAAA
# As0wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGad
# 597I3QEY7D2pCbHAuUtTxYKTDzzkLjOTLI2urhOMMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAUo388GSyA9ngN2ef4uHul6DopEgn/SBGygMm
# I9bIU9mVa+YSKds5tuWaNLuIumy4qYOun8wTKpf0I0eeSbrABU0jfYWKUi8LKJBq
# mXCOHquzMjwweUoQzMPpT8AZuRKiug2xdHaSsMvT6MECS9OAfMDG6xkvNDSQ7a1H
# kKlXulI8ZnsnCLLxIh93oWK/2psOi8w++h6TDdsiFKr+OYcbFjQb/KlUY9pOcN0s
# 3UMkt/T784CrBzd+A2GUODMi7MVMuPx8VovVMTPvra3jRYHTUXp1mXf82FSZa0z+
# 3WmkLLK4Ysekae5x8kDBxGVkPOZnp6g0p76qjo2Ac6ZruZr1WKGCFywwghcoBgor
# BgEEAYI3AwMBMYIXGDCCFxQGCSqGSIb3DQEHAqCCFwUwghcBAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDi1AlkLkIhYIlACRtpVuo8a6MAxm7p+jke
# aOQLYDymvgIGZBslkL0jGBMyMDIzMDQxMjIxMTAxNy43OTNaMASAAgH0oIHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjg2REYtNEJCQy05MzM1MSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRezCCBycwggUPoAMCAQICEzMAAAG3ISca
# B6IqhkYAAQAAAbcwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjIwOTIwMjAyMjE0WhcNMjMxMjE0MjAyMjE0WjCB0jELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo4NkRGLTRCQkMtOTMzNTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMf9
# z1dQNBNkTBq3HJclypjQcJIlDAgpvsw4vHJe06n532RKGkcn0V7p65OeA1wOoO+8
# NsopnjPpVZ8+4s/RhdMCMNPQJXoWdkWOp/3puIEs1fzPBgTJrdmzdyUYzrAloICY
# x722gmdpbNf3P0y5Z2gRO48sWIYyYeNJYch+ZfJzXqqvuvq7G8Nm8IMQi8Zayvx+
# 5dSGBM5VYHBxCEjXF9EN6Qw7A60SaXjKjojSpUmpaM4FmVec985PNdSh8hOeP2tL
# 781SBan92DT19tfNHv9H0FAmE2HGRwizHkJ//mAZdS0s6bi/UwPMksAia5bpnIDB
# OoaYdWkV0lVG5rN0+ltRz9zjlaH9uhdGTJ+WiNKOr7mRnlzYQA53ftSSJBqsEpTz
# Cv7c673fdvltx3y48Per6vc6UR5e4kSZsH141IhxhmRR2SmEabuYKOTdO7Q/vlvA
# fQxuEnJ93NL4LYV1IWw8O+xNO6gljrBpCOfOOTQgWJF+M6/IPyuYrcv79Lu7lc67
# S+U9MEu2dog0MuJIoYCMiuVaXS5+FmOJiyfiCZm0VJsJ570y9k/tEQe6aQR9MxDW
# 1p2F3HWebolXj9su7zrrElNlHAEvpFhcgoMniylNTiTZzLwUj7TH83gnugw1FCEV
# Vh5U9lwNMPL1IGuz/3U+RT9wZCBJYIrFJPd6k8UtAgMBAAGjggFJMIIBRTAdBgNV
# HQ4EFgQUs/I5Pgw0JAVhDdYB2yPII8l4tOwwHwYDVR0jBBgwFoAUn6cVXQBeYl2D
# 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD
# ggIBAA2dZMybhVxSXTbJzFgvNiMCV5/Ayn5UuzJU495YDtcefold0ehR9QBGBhHm
# AMt10WYCHz2WQUyM3mQD4IsHfEL1JEwgG9tGq71ucn9dknLBHD30JvbQRhIKcvFS
# nvRCCpVpilM8F/YaWXC9VibSef/PU2GWA+1zs64VFxJqHeuy8KqrQyfF20SCnd8z
# RZl4YYBcjh9G0GjhJHUPAYEx0r8jSWjyi2o2WAHD6CppBtkwnZSf7A68DL4OwwBp
# mFB3+vubjgNwaICS+fkGVvRnP2ZgmlfnaAas8Mx7igJqciqq0Q6An+0rHj1kxisN
# dIiTzFlu5Gw2ehXpLrl59kvsmONVAJHhndpx3n/0r76TH+3WNS9UT9jbxQkE+t2t
# hif6MK5krFMnkBICCR/DVcV1qw9sg6sMEo0wWSXlQYXvcQWA65eVzSkosylhIlIZ
# ZLL3GHZD1LQtAjp2A5F7C3Iw4Nt7C7aDCfpFxom3ZulRnFJollPHb3unj9hA9xvR
# iKnWMAMpS4MZAoiV4O29zWKZdUzygp7gD4WjKK115KCJ0ovEcf92AnwMAXMnNs1o
# 0LCszg+uDmiQZs5eR7jzdKzVfF1z7bfDYNPAJvm5pSQdby3wIOsN/stYjM+EkaPt
# Uzr8OyMwrG+jpFMbsB4cfN6tvIeGtrtklMJFtnF68CcZZ5IAMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtcwggJAAgEBMIIBAKGB2KSB1TCB
# 0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
# TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjo4NkRGLTRCQkMtOTMzNTElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAyGdBGMObODlsGBZm
# SUX2oWgfqcaggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOfhUdcwIhgPMjAyMzA0MTIyMzUwNDdaGA8yMDIzMDQx
# MzIzNTA0N1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5+FR1wIBADAKAgEAAgIE
# PwIB/zAHAgEAAgITXTAKAgUA5+KjVwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAIA1tejqyItfpAj0hfgpyJkK5/aVK6KapYpfdc0jOvcQ8UBTfi1qlPPri7sd
# 6Buf+4thF+nssGveAPTPfStwaAHhVXG4BWQ1d+c8whWJ5Egno6nO/QnVfyeGmUVs
# 1Hfsh/F9DpDqyh3xeSNPnQDEnCF5EbJGM5v3zBiKNIXnfzt6MYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG3IScaB6IqhkYA
# AQAAAbcwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQg9WikPyIBvgoL6Gce38x4GE56VCcfSqUU+vRF
# IT470/IwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBsJ3jTsh7aL8hNeiYG
# L5/8IBn8zUfr7/Q7rkM8ic1wQTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABtyEnGgeiKoZGAAEAAAG3MCIEIL/oAa5A4rhkzfAaMt/n
# VJB+Z+n0fmTzxNUlZPnKggUxMA0GCSqGSIb3DQEBCwUABIICAI1wY2VBDFDsrsc1
# pb4ntR2wikxmVXARsNW7YaVRwZlpKj+sFI2C9xIdtABYuyf+vjImWWUqadyTt7lO
# BP40qLzYGrK6NtNPR4EvEgA56EaYCNaSBD7sXmcRy2Pyk7otBaSWuQI6904BnC1I
# WWoGgS9yDPbye348omoQMYL+DybLfsICazPpGHwtT59joec5G+64sKibzpvidKaF
# hEfE2rByQMeK8JKLcSctc6k7d9yfHTJvuvicaAHrhFdrh2cF56M/ALhlTXa72DHl
# bn6aXUZ4Wbkma9dic0nTus4txWdkNJd6uTeWS/XsX4PepdNAFbeHfbbs4dQRbkso
# k2Be3iFCNgNfoL5Dm1SeRwEelOTTNgYjr9Ci7bKlny6zfxS4Ghr/LLapGjBjSOrg
# Us0zkIfI8sBpdTHVdS5KrRl6A3ExI1WvTvVF1cZ4k6uSQU5AlThfLjcHnQEu7xEQ
# WNL0s/YEeOXDg1ygUHXikCHkZqU4GqZyF8y+J564AgyaDaYSPlBQbYjq4o5ZeyND
# JrsWXpipyOdw8qR6my6SsVFyTnQFsPaejZEBuf5J7k+1Ukcx93hnnNbdHvWTs3eS
# Eeitjyr3RngFiYw2m3mJmWCEUYukCx1y/BJ1xTqv1zaMqZS7wAyY9AKM7Kwh+seD
# pc/7d9tWkZ2gq7/QefSPrePYnsKN
# SIG # End signature block
