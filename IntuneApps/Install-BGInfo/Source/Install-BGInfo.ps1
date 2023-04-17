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
    foreach($Param in $PSBoundParameters.GetEnumerator())
    {
        if(-not $MyInvocation.MyCommand.Parameters[$Param.key].SwitchParameter)
        {
            $additionalArgs += "-$($Param.Key) $($Param.Value) "
        }
        else
        {
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
$script:EventLogName = "Application"
$script:EventLogSource = "EventSystem"
if ($VerbosePreference -eq 'Continue') {Start-Transcript -Path "$logPath\Transcript.log" -Append}
####################################################
####################################################
#Build Functions
####################################################

function Start-Log {
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

function Write-Log {
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

function New-IntuneTag {
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

function Remove-IntuneTag {
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

function New-IntuneRegTag {
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

function Remove-IntuneRegTag {
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

function New-RegKey {
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

function Get-XMLConfig {
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

function Show-PWPromptForm {
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

function Is-VM {
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

    Process
    {
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

function Install-Hotfix {
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

    Process
    {
        if (get-hotfix | Where-Object {$_.HotFixID -match $HotFixID}) {
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

    #Your code goes here

    New-Item "C:\Program Files\Tools\BGInfo" -type directory -Force -ErrorAction SilentlyContinue

    Copy-Item -Path "$PSScriptRoot\bginfo64.exe" -Destination "C:\Program Files\Tools\BGInfo\bginfo64.exe"

    Copy-Item -Path "$PSScriptRoot\eula.txt" -Destination "C:\Program Files\Tools\BGInfo\eula.txt"

    Copy-Item -Path "$PSScriptRoot\Bginfo64-Win10.bgi" -Destination "C:\Program Files\Tools\BGInfo\Bginfo64-Win10.bgi"

    Copy-Item -Path "$PSScriptRoot\DesktopBackground.bmp" -Destination "C:\Program Files\Tools\BGInfo\DesktopBackground.bmp"

    Copy-Item -Path "$PSScriptRoot\biosmode.vbs" -Destination "C:\Program Files\Tools\BGInfo\biosmode.vbs"

    Copy-Item -Path "$PSScriptRoot\secureboot.vbs" -Destination "C:\Program Files\Tools\BGInfo\secureboot.vbs"

    Copy-Item -Path "$PSScriptRoot\bginfo.lnk" -Destination "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

    Start-Process -FilePath "BGInfo.exe" -WorkingDirectory "C:\Program Files\Tools\BGInfo" -ArgumentList "$([char]34)C:\Program Files\Tools\BGInfo\Bginfo64-Win10.bgi$([char]34) /silent /timer:0 /nolicprompt"

    #update below to allow for different return code
    $script:exitCode = 0

<# Code Examples
#region CMTrace
    if (Test-Path -Path $PSScriptRoot\cmtrace.exe) { # cmtrace.exe exists in script folder
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

#region IsVM
    if (Is-VM){
        Write-Log -Message "Machine is a VM"
    }
    else {
       Write-Host "Machine is a physical device"

       #Enable Hibernate
       Write-Log -Message "Enabling Hibernation"
       $command = "PowerCfg.exe /HIBERNATE"
       #$workDir = $PSScriptRoot
       $workDir = "$env:SystemRoot\System32"
       Try {
            Start-Process -FilePath $command -WorkingDirectory $workDir -Wait -WindowStyle Hidden -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred trying to enable hibernate: $($_.Exception.message)"
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            Exit
        }
    }
#endregion IsVM

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
        Write-Host "Finished changing registry"
    }
#endregion RegistryChanges

#region RemoveLTIBootStrap
    #Remove MDT LTIBootStrap.vbs files from root of all drives:
    #Get-PSDrive -PSProvider FileSystem | ForEach-Object {Get-Childitem -Path $_.Root -Filter "LTIBootstrap.vbs"} -ErrorAction SilentlyContinue | Remove-Item -Force
    Write-Log -Message "Removing MDT LTIBootStrap.vbs files..."
    #Get-PSDrive -PSProvider FileSystem | ForEach-Object Root | Get-ChildItem -Recurse -File -Force -ErrorAction Ignore | Where-Object Name -eq 'LTIBootstrap.vbs' | Tee-Object -Variable deleted | Remove-Item -Force
    Get-PSDrive -PSProvider FileSystem | ForEach-Object Root | Get-ChildItem -File -Force -ErrorAction Ignore | Where-Object Name -eq 'LTIBootstrap.vbs' | Tee-Object -Variable deleted | Remove-Item -Force
    #$deleted | GM
    #$removed = $deleted.pspath -replace "Microsoft.PowerShell.Core\FileSystem::", ""
    #$removed = $deleted.pspath.replace("Microsoft.PowerShell.Core\FileSystem::", "")
    Write-Log -Message: "Removed files: $($deleted.pspath.replace("Microsoft.PowerShell.Core\FileSystem::", """))"
#endregion RemoveLTIBootStrap

#>
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

    #Your code goes here




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
if ($VerbosePreference -eq 'Continue') {Stop-Transcript}
exit $exitCode

##########################################################################################################
##########################################################################################################
#endregion Main Script work section
}
# SIG # Begin signature block
# MIIn0QYJKoZIhvcNAQcCoIInwjCCJ74CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBYQcZWiSveNHOj
# g+nMcqsWNCawiDhYY+eJFVyNPeJiNKCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJYi
# cT39X94gGfZ7F17wONgVJsopDoKLJGh03fOfaQAzMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAKdHq6Ve4BAmT5nAgjxlwpMgFVT+3FIpwRmE4
# U4nW3LbYjIIu0ul2T4g5gBPrlGoqCTIzE3GmnH9BUYAu4Jhct1PFrdYVEONSoSz5
# OYrxVVptA30KDTFgFd/JXk23gK4185sgsJqShYpS1jzxlZgGVBX0BSKyUATzwdsF
# LizrOygBA1IJA6N02j6EC2n698dkSoG82Ou1Rd4Q0SjRZJPULSQ1BVrOu9aK8e4F
# CYviAfek3rJpH/V7+QR4LP+dJZf3ivdckTcbSaUYR5adYXRRxJ/xNany+U5U+z5D
# sq7WhptGGPyNvZSjdZXAy5mq52INXuyHoaRYb873swEHGOeG36GCFywwghcoBgor
# BgEEAYI3AwMBMYIXGDCCFxQGCSqGSIb3DQEHAqCCFwUwghcBAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCA3z+pldSLudPvmzAF/dEKIeoEpYdYRds3J
# k6bAHHBHRgIGZBsTUZytGBMyMDIzMDQxMjIxMTAxNy42NzZaMASAAgH0oIHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjE3OUUtNEJCMC04MjQ2MSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRezCCBycwggUPoAMCAQICEzMAAAG1rRrf
# 14VwbRMAAQAAAbUwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjIwOTIwMjAyMjExWhcNMjMxMjE0MjAyMjExWjCB0jELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjoxNzlFLTRCQjAtODI0NjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJcL
# CrhlXoLCjYmFxcFPgkh57dmuz31sNsj8IlvmEZRCbB94mxSIj35P8m5TKfCRmp7b
# vuw4v/t3ucFjf52yVCDFIxFiZ3PCTI6D5hwlrDLSTrkf9UbuGmtUa8ULSHpatPfE
# wZeJOzbBBPO5e6ihZsvIsBjUI5MK9GzLuAScMuwVF4lx3oDklPfdq30OMTWaMc57
# +Nky0LHPTZnAauVrJZKlQE3HPD0n4ASxKXRtQ6dsKjcOCayRcCTQNW3800nGAAXO
# bJkWQYLD+CYiv/Ala5aHIXhMkKJ45t6xbba6IwK3klJ4sQC7vaQ67ASOA1Dxht+K
# CG4niNaKhZf8ZOwPu7jPJOKPInzFVjU2nM2z5XQ2LZ+oQa3u69uURA+LnnAsT/A8
# ct+GD1BJVpZTz9ywF6eXDMEY8fhFs4xLSCxCl7gHH8a1wk8MmIZuVzcwgmWIeP4B
# dlNsv22H3pCqWqBWMJKGXk+mcaEG1+Sn7YI/rWZBVdtVL2SJCem9+Gv+OHba7Cun
# Yk5lZzUzPSej+hIZZNrH3FMGxyBi/JmKnSjosneEcTgpkr3BTZGRIK5OePJhwmw2
# 08jvcUszdRJFsW6fJ/yx1Z2fX6eYSCxp7ZDM2g+Wl0QkMh0iIbD7Ue0P6yqB8oxa
# oLRjvX7Z8WL8cza2ynjAs8JnKsDK1+h3MXtEnimfAgMBAAGjggFJMIIBRTAdBgNV
# HQ4EFgQUbFCG2YKGVV1V1VkF9DpNVTtmx1MwHwYDVR0jBBgwFoAUn6cVXQBeYl2D
# 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD
# ggIBAJBRjqcoyldrNrAPsE6g8A3YadJhaz7YlOKzdzqJ01qm/OTOlh9fXPz+de8b
# oywoofx5ZT+cSlpl5wCEVdfzUA5CQS0nS02/zULXE9RVhkOwjE565/bS2caiBbSl
# cpb0Dcod9Qv6pAvEJjacs2pDtBt/LjhoDpCfRKuJwPu0MFX6Gw5YIFrhKc3RZ0Xc
# ly99oDqkr6y4xSqb+ChFamgU4msQlmQ5SIRt2IFM2u3JxuWdkgP33jKvyIldOgM1
# GnWcOl4HE66l5hJhNLTJnZeODDBQt8BlPQFXhQlinQ/Vjp2ANsx4Plxdi0FbaNFW
# LRS3enOg0BXJgd/BrzwilWEp/K9dBKF7kTfoEO4S3IptdnrDp1uBeGxwph1k1Vng
# BoD4kiLRx0XxiixFGZqLVTnRT0fMIrgA0/3x0lwZJHaS9drb4BBhC3k858xbpWde
# m/zb+nbW4EkWa3nrCQTSqU43WI7vxqp5QJKX5S+idMMZPee/1FWJ5o40WOtY1/dE
# BkJgc5vb7P/tm49Nl8f2118vL6ue45jV0NrnzmiZt5wHA9qjmkslxDo/ZqoTLeLX
# bzIx4YjT5XX49EOyqtR4HUQaylpMwkDYuLbPB0SQYqTWlaVn1OwXEZ/AXmM3S6CM
# 8ESw7Wrc+mgYaN6A/21x62WoMaazOTLDAf61X2+V59WEu/7hMIIHcTCCBVmgAwIB
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
# aGFsZXMgVFNTIEVTTjoxNzlFLTRCQjAtODI0NjElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAjTCfa9dUWY9D1rt7
# pPmkBxdyLFWggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOfhPzIwIhgPMjAyMzA0MTIyMjMxMTRaGA8yMDIzMDQx
# MzIyMzExNFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5+E/MgIBADAKAgEAAgII
# JwIB/zAHAgEAAgIR4TAKAgUA5+KQsgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBABYQGNEKohINuKC17wThlrO195wfs9BxerzB7vm0wUb8EWS4arNQ4/wseiDY
# New8nCXWLLqYAc9j5f3f075cRXvK9tTL4sp2/CP1HusB1sQlGm/+xoZBi7FnT8HY
# k2GgwSexyJAWCR+hrcC/5HbMHFXKZ9NmAZBa/jTV1LCUZx5xMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG1rRrf14VwbRMA
# AQAAAbUwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQgzw4iv9Y/czqGljTQ2cJnoHwXvz+e0trMWqcR
# Ag/uBSIwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAnyg01LWhnFon2HNzl
# ZyKae2JJ9EvCXJVc65QIBfHIgzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABta0a39eFcG0TAAEAAAG1MCIEIPToCRRnM7Cx8c/1HN2Z
# IKao0yXV501bCoKS8UVKs3wzMA0GCSqGSIb3DQEBCwUABIICAEx5Q/AAY0xd6DHr
# v3bQpYsRViLMzvlwRrMli4RfqdOemZ1uzXjZK80veyX7RSpgLgqouLHrJVhX20kS
# ZbNIY9tMi6k6aaBie8F0jxPiYsX+zNMolo67jxgS8w0ZESTn71Jrcby30slhbUrD
# TszBp1GNHsNMyIAoOuIQtKs9R8v3ymtG1Zk+HNPdp6X7q5HkW0aFM90KovhMMeAW
# 8zcu00yUAgkgsDgIYu7LDdhbdiyNo9aa1aiWiFQ4eecRGS729b9D2PdMBHXjYw8p
# sRBhcDLwMLu5MTJ+ok0eIZx6GMz34kOpyd1Klbfuzg/CZb5CQ+dTwR0bh4v6iRq1
# fzq224p+rmy67TlBqB2II16cijM9AlZ5XauhcR5bAqZAawCn8U7A6OCfNzQq9Uh7
# C3AWvKd8LEw3p7cjNUVsQsQE91uTGc1kByzV4Qg7RTZ1tp67W6YPkb6F3ziRStzF
# BMkLcu+iCtTUYdtqK2KCLpH9kdfwZ+iliP4CgLBvZ2PffveW1NPsozUgN7ZjIpFS
# QLp37+HyrVqN1FrYyoKiHXfUsQpkQkN6Yu7TQZMzwsuJSrlZCjPlDErx5a7S83I1
# zmC/TxXxtcTNCuuZmVSvIQ5BmxSnYXb4BIX8XlUgeiB7yEnmnpa2dBzJbQO5qJYC
# 01w8QbRSjrMvFUToys7TFvp2YBmH
# SIG # End signature block
