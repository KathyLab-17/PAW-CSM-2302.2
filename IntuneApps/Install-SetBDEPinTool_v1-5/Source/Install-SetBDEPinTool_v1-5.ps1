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
    #Add-Type -AssemblyName Microsoft.VisualBasic
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

    function Get-ActiveUser {
        <#
    .SYNOPSIS
        Retrive list of active users on windows machine

    .DESCRIPTION
        Uses WMI, CIM or Query.exe

        This module was created with a powershell.org blogpost in mind
        http://powershell.org/wp/2015/08/28/list-users-logged-on-to-your-machines/
        Created by Jonas Sommer Nielsen

    .PARAMETER ComputerName / CN / IP / Hostname
        Optional: Specifies a remote computer to target

    .PARAMETER Method
        Optional: Specifies the method to retrieve logged on users. Query, CIM, WMI

    .PARAMETER Credential
        Optional: Specifies alternative credentials to use for the WMI connection

    .EXAMPLE
        Get-ActiveUser
        Retrieves all users currently logged into the local machine

    .EXAMPLE
        Get-ActiveUser -ComputerName TestComputer -Method CIM
        Retrieves all users currently logged into the remote machine "TestComputer" using CIM

    .EXAMPLE
        Get-ActiveUser -ComputerName TestComputer -Method WMI -Credential (Get-Credential)
        Retrieves all users currently logged into the remote machine "TestComputer" using WMI.
        This will prompt for credentials to authenticate the connection.

    .ExternalHelp
        https://github.com/mrhvid/Get-ActiveUser

    .NOTES
        Author: Jonas Sommer Nielsen
        Revised: Ian Mott
    #>

        [CmdletBinding(DefaultParameterSetName = 'Standard Parameters',
            SupportsShouldProcess = $false,
            PositionalBinding = $false,
            HelpUri = 'https://github.com/mrhvid/Get-ActiveUser',
            ConfirmImpact = 'Medium')]
        [Alias()]
        [OutputType([string[]])]
        Param
        (
            # Computer name, IP, Hostname
            [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
                HelpMessage = "Default set to localhost",
                Position = 0)]
            [Alias("CN", "IP", "Hostname")]
            [String]
            $ComputerName = $ENV:COMPUTERNAME,

            # Choose method, WMI, CIM or Query
            [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
                HelpMessage = "Default set to WMI",
                Position = 1)]
            [ValidateSet('WMI', 'CIM', 'Query')]
            [String]
            $Method = "WMI",

            # Specify Credentials for the remote WMI/CIM queries
            [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
                HelpMessage = "This is only required for WMI connections. Try the Query or CIM method?",
                Position = 2)]
            [pscredential]
            $Credential
        )

        Begin {
            Write-Verbose -Message "VERBOSE: Starting Begin"

            $Params = @{}

            if ($ComputerName -notin ($ENV:COMPUTERNAME, "localhost", "127.0.0.1")) {
                if ($Method -in ("WMI", "CIM")) {
                    $Params.Add("ComputerName", $ComputerName)

                    if ($Credential -and $Method -eq "WMI") {
                        $Params.Add("Credential", $Credential)
                    }
                }

                if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {
                    Write-Verbose -Message "VERBOSE: Confirmed $ComputerName is reachable by ping"

                    if (Test-WSMan @Params -ErrorAction SilentlyContinue -ErrorVariable error_WSMan) {
                        Write-Verbose -Message "VERBOSE: Successfully connected with WSMan"
                    }
                    else {
                        Write-Error -Message "ERROR: Failed to connect with WSMan. ErrorMessage: $error_WSMan" -RecommendedAction Stop
                    }

                }
                else {
                    Write-Error -Message "ERROR: Could not reach $ComputerName by ping. Confirm the computer is reachable." -RecommendedAction Stop
                }

            }
            else {
                Write-Verbose -Message "VERBOSE: ComputerName not set to a remote machine. No need to check for connectivity."
            }

            Write-Verbose -Message "VERBOSE: Ending Begin"
        }
        Process {
            Write-Verbose -Message "VERBOSE: Starting Process"

            Write-Verbose "$Method selected as method"

            switch ($Method) {
                'WMI' {
                    Write-Verbose "Contacting $ComputerName via WMI"

                    $WMI = (Get-WmiObject Win32_LoggedOnUser @Params).Antecedent

                    $ActiveUsers = @()
                    foreach ($User in $WMI) {
                        $StartOfUsername = $User.LastIndexOf('=') + 2
                        $EndOfUsername = $User.Length - $User.LastIndexOf('=') - 3
                        $ActiveUsers += $User.Substring($StartOfUsername, $EndOfUsername)
                    }
                    $ActiveUsers = $ActiveUsers | Select-Object -Unique

                }
                'CIM' {
                    Write-Verbose "Contacting $ComputerName via CIM"
                    $ActiveUsers = (Get-CimInstance Win32_LoggedOnUser @Params).antecedent.name | Select-Object -Unique

                }
                'Query' {
                    Write-Verbose "Contacting $ComputerName via Query"
                    $Template = @'
USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>{USER*:jonas}                 console             1  Active    1+00:27  24-08-2015 22:22
{USER*:test}                                      2  Disc      1+00:27  25-08-2015 08:26
>{USER*:mrhvid}                rdp-tcp#2           2  Active          .  9/1/2015 8:54 PM
'@

                    $Query = query.exe user /server $ComputerName
                    $ActiveUsers = $Query | ConvertFrom-String -TemplateContent $Template | Select-Object -ExpandProperty User
                }

            }

            Write-Verbose -Message "VERBOSE: Ending process"
        }
        End {
            Write-Verbose -Message "VERBOSE: Starting End"

            # Create nice output format
            $UsersComputersToOutput = @()
            foreach ($User in $ActiveUsers) {
                $UsersComputersToOutput += New-Object psobject -Property @{ComputerName = $ComputerName; UserName = $User }
            }

            Write-Verbose -Message "VERBOSE: Ending End"

            # output data
            #$UsersComputersToOutput
            Return $UsersComputersToOutput
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

    If ($Install) {
        Write-Log -Message "Performing Install steps..."

        $EventLogName = "Bitlocker Setup"
        $EventLogSource = "PS-Bitlocker-SetupScript"

        $ProgramFilesPathTail = "\MCS\BitlockerScripts"

        $ForceScriptRootPath = "C:\Program Files"
        $RegistrySavePath = "\Software\MCS\SetBitlocker"
        #$RegistryFveLocation = "HKLM:\Software\Policies\Microsoft\FVE"
        #$RegistryConnectedStbyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"

        $SchTaskNamePrompt = "BLTOOL-USRPROMPT"
        $SchTaskNameBckgW = "BLTOOL-BCKGWTCH"
        $SchTaskNameStatusMessage = "StatusMessage"
        $SchTaskNameBDEPINReset = "BDE-PIN_Reset"

        $initialInstall = $True

        <#
    #Enable Max Performance Power Overlay
    Write-Log -Message "Enabling Max Performance Power Overlay"
    $command = "powercfg.exe /overlaysetactive overlay_scheme_max"
    $workDir = "$env:SystemRoot\System32"
    Try {
        Start-Process -FilePath $command -WorkingDirectory $workDir -Wait -WindowStyle Hidden -ErrorAction Stop
    }
    Catch {
        Write-Log -Message "Error occurred trying to enable Max Performance Power Overlay: $($_.Exception.message)"
    }

    # Enable Scheduled Tasks All History option
    $logName = 'Microsoft-Windows-TaskScheduler/Operational'
    $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
    $log.IsEnabled = $true
    $log.SaveChanges()
#>

        <# Setup Event Logging #>
        New-Eventlog -LogName $EventLogName -Source $EventLogSource -ErrorAction SilentlyContinue

        $eventSources = @("PS-Bitlocker-SetupScript", "PS-Bitlocker-BackgroundWatcher", "PS-Bitlocker-UserPrompt" )
        foreach ($source in $eventSources) {
            if ([System.Diagnostics.EventLog]::SourceExists($source) -eq $false) {
                [System.Diagnostics.EventLog]::CreateEventSource($source, $EventLogName)
            }
        }

        <# Announce Our Presence #>
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Bitlocker Tool Setup Script Started"  -Id 100 -Category 0 -EntryType Information

        # Check for existing tag files, to determine if previous deployment occurred.
        If (Test-Path -Path "C:\ProgramData\Microsoft\BDE-PIN\BDE-PIN.ps1.tag") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Existing tag file found: C:\ProgramData\Microsoft\BDE-PIN\BDE-PIN.ps1.tag"  -Id 100 -Category 0 -EntryType Information
            $initialInstall = $False
        }
        ElseIf (Test-Path -Path "C:\ProgramData\Microsoft\IntuneApps\Install-SetBDEPinTool\Install-SetBDEPinTool.tag") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Existing tag file found: C:\ProgramData\Microsoft\IntuneApps\Install-SetBDEPinTool\Install-SetBDEPinTool.tag"  -Id 100 -Category 0 -EntryType Information
            $initialInstall = $False
        }
        ElseIf (Test-Path -Path "C:\ProgramData\Microsoft\IntuneApps\Setup-BitlockerPinTool\Setup-BitlockerPinTool.tag") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Existing tag file found: C:\ProgramData\Microsoft\IntuneApps\Setup-BitlockerPinTool\Setup-BitlockerPinTool.tag"  -Id 100 -Category 0 -EntryType Information
            $initialInstall = $False
        }
        ElseIf (Test-Path -Path "C:\ProgramData\Microsoft\IntuneApps\Install-SetBDEPinTool_v1-5\Install-SetBDEPinTool_v1-5.tag") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Existing tag file found: C:\ProgramData\Microsoft\IntuneApps\Install-SetBDEPinTool_v1-5\Install-SetBDEPinTool_v1-5.tag"  -Id 100 -Category 0 -EntryType Information
            $initialInstall = $False
        }

        <# Figure Out Where This Script Is #>
        $InvocationPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Script is running at $InvocationPath"  -Id 100 -Category 0 -EntryType Information

        <# Check required scripts are with us #>
        if ( !(Test-Path "$InvocationPath\BackgroundWatcher-ImplementUserPin.ps1") -or !(Test-Path "$InvocationPath\UserInteract-EnterBitlockerPin.ps1")) {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Required scripts are not alongside setup script in folder, exiting"  -Id 100 -Category 0 -EntryType Information
            break
        }

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Required script files are present"  -Id 100 -Category 0 -EntryType Information

        <# Figure Out Where To Put Scripts #>
        $OSArchitecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture

        # Create Source Path
        If ($OSArchitecture -like '64*') { $ScriptRootLocation = "$env:ProgramFiles$ProgramFilesPathTail" } else { $ScriptRootLocation = "${env:ProgramFiles(x86)}$ProgramFilesPathTail" }
        if ($ForceScriptRootPath) { $ScriptRootLocation = "$ForceScriptRootPath$ProgramFilesPathTail" }

        # Does the path exist ?
        if (!(Test-Path $ScriptRootLocation)) {
            New-Item -ItemType Directory -Path $ScriptRootLocation -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created path: $ScriptRootLocation"  -Id 100 -Category 0 -EntryType Information
        }
        Else {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Detected existing path: $ScriptRootLocation - cleaning up first"  -Id 100 -Category 0 -EntryType Information

            Remove-Item -Path $ScriptRootLocation -Recurse -Force
            New-Item -ItemType Directory -Path $ScriptRootLocation -Force

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created path: $ScriptRootLocation"  -Id 100 -Category 0 -EntryType Information
        }

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Local root location will be $ScriptRootLocation"  -Id 100 -Category 0 -EntryType Information

        <# Copy Scripts #>
        if (Test-Path "$ScriptRootLocation\BackgroundWatcher-ImplementUserPin.ps1") { Remove-Item "$ScriptRootLocation\BackgroundWatcher-ImplementUserPin.ps1" -Force }
        if (Test-Path "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1") { Remove-Item "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1" -Force }
        Copy-Item -Path "$InvocationPath\BackgroundWatcher-ImplementUserPin.ps1" -Destination $ScriptRootLocation -Force
        Copy-Item -Path "$InvocationPath\UserInteract-EnterBitlockerPin.ps1" -Destination $ScriptRootLocation -Force
		Copy-Item -Path "$InvocationPath\StatusMessage.ps1" -Destination $ScriptRootLocation -Force
        Copy-Item -Path "$InvocationPath\AutoItX" -Destination "$ScriptRootLocation\AutoItX" -Recurse -Force

        Copy-Item -Path "$InvocationPath\Invoke-BDEPINReset.ps1" -Destination $ScriptRootLocation -Force
        Copy-Item -Path "$InvocationPath\ServiceUI.exe" -Destination $ScriptRootLocation -Force
        Copy-Item -Path "$InvocationPath\BDEPINReset.xml" -Destination $ScriptRootLocation -Force


        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Copied scripts to local root"  -Id 100 -Category 0 -EntryType Information

        <# Create Secure String Key #>
        $KeyFile = "$ScriptRootLocation\AES.key"
        $Key = New-Object Byte[] 16   # You can use 16, 24, or 32 for AES
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
        $Key | Out-File $KeyFile

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created shared AES key at $KeyFile"  -Id 100 -Category 0 -EntryType Information

        If ($initialInstall -eq $True) {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Initial install, so creating the user prompt scheduled task"  -Id 100 -Category 0 -EntryType Information

            <# Create User Prompting Scheduled Task #>
            Register-ScheduledTask -Xml (get-content "$PSScriptRoot\BLTOOL-USRPROMPT.xml" | out-string) -TaskName $SchTaskNamePrompt -Force

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created $SchTaskNamePrompt Scheduled Task"  -Id 100 -Category 0 -EntryType Information
        }
        Else {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Script ran previously, so creating the PIN reset scheduled task"  -Id 100 -Category 0 -EntryType Information

            If (Get-ScheduledTask | ? { $_.TaskName -eq $SchTaskNamePrompt }) {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Detected user prompt scheduled task, so removing it"  -Id 100 -Category 0 -EntryType Information

                <# Stop Scheduled Task #>
                #Disable-ScheduledTask -TaskName $SchTaskNameBckgW -InformationAction SilentlyContinue
                Disable-ScheduledTask -TaskName $SchTaskNamePrompt -InformationAction SilentlyContinue

                <# Remove Scheduled Task #>
                #Unregister-ScheduledTask -TaskName $SchTaskNameBckgW -Confirm:$false -InformationAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $SchTaskNamePrompt -Confirm:$false -InformationAction SilentlyContinue

                Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Scheduled Task: $SchTaskNamePrompt" -Id 100 -Category 0 -EntryType Information
            }

            # Create BDE-Pin Reset scheduled task
            Register-ScheduledTask -Xml (get-content "$PSScriptRoot\BDEPINReset.xml" | out-string) -TaskName $SchTaskNameBDEPINReset -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created $SchTaskNameBDEPINReset Scheduled Task"  -Id 100 -Category 0 -EntryType Information

            # Replace UserInteract-EnterBitlockerPin.ps1 with the one that calls the above scheduled task
            Rename-Item -Path "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1" -NewName "$ScriptRootLocation\UserInteract-EnterBitlockerPinInitial.ps1"
            Rename-Item -Path "$ScriptRootLocation\Invoke-BDEPINReset.ps1" -NewName "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1"
        }

        <# Create Background Watcher System Task To Ingest Pin #>
        Register-ScheduledTask -Xml (get-content "$PSScriptRoot\BLTOOL-BCKGWTCH.xml" | out-string) -TaskName $SchTaskNameBckgW -Force

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created $SchTaskNameBckgW Scheduled Task"  -Id 100 -Category 0 -EntryType Information

        <# Create Status Message Scheduled Task #>
        Register-ScheduledTask -Xml (get-content "$PSScriptRoot\StatusMessage.xml" | out-string) -TaskName $SchTaskNameStatusMessage -Force

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created $SchTaskNameStatusMessage Scheduled Task"  -Id 100 -Category 0 -EntryType Information

        <# Create Shortcut #>
        $WScriptShell = New-Object -ComObject WScript.Shell
        #$Shortcut = $WScriptShell.CreateShortcut("C:\Users\Public\Desktop\Set BitLocker PIN.lnk")
        $Shortcut = $WScriptShell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Manage BitLocker PIN.lnk")
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = '-ExecutionPolicy Bypass -WindowStyle Hidden -file "' + $ScriptRootLocation + '\UserInteract-EnterBitlockerPin.ps1"'
        $Shortcut.Save()

        <# End #>
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Setup Complete, Ready for the user"  -Id 100 -Category 0 -EntryType Information

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

        $EventLogName = "Bitlocker Setup"
        $EventLogSource = "PS-Bitlocker-SetupScript"

        $ProgramFilesPathTail = "\MCS\BitlockerScripts"
        $sourcePath = "$env:ProgramFiles$ProgramFilesPathTail"
        $ForceScriptRootPath = "C:\Program Files"
        $RegistrySavePath = "\Software\MCS\SetBitlocker"
        #$RegistryFveLocation = "HKLM:\Software\Policies\Microsoft\FVE"
        #$RegistryConnectedStbyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"

        $SchTaskNamePrompt = "BLTOOL-USRPROMPT"
        $SchTaskNameBckgW = "BLTOOL-BCKGWTCH"
        $SchTaskNameStatusMessage = "StatusMessage"
        $SchTaskNameBDEPINReset = "BDE-PIN_Reset"

        # Create Source Path
        If ($OSArchitecture -like '64*') { $ScriptRootLocation = "$env:ProgramFiles$ProgramFilesPathTail" } else { $ScriptRootLocation = "${env:ProgramFiles(x86)}$ProgramFilesPathTail" }
        if ($ForceScriptRootPath) { $ScriptRootLocation = "$ForceScriptRootPath$ProgramFilesPathTail" }

        #Find users and clean registry paths
        $users = Get-ActiveUser -Method Query
        ForEach ($user in $users.UserName) {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User detected: $user"  -Id 100 -Category 0 -EntryType Information

            <# Resolve User SID #>
            $WmiSid = (New-Object System.Security.Principal.NTAccount($WmiUsername)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            <# Build key location #>
            $UserKeyPath = ("HKU:\" + $WmiSid + $RegistrySavePath)

            <# Clean Up any registry values #>
            if (Test-Path $UserKeyPath) {
                Remove-Item -Path $UserKeyPath -Force
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Registry" -Id 100 -Category 0 -EntryType Information
            }

        }

        #Remove scheduled tasks
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Remove Scheduled Tasks" -Id 100 -Category 0 -EntryType Information
        <# Stop Scheduled Task #>
        Disable-ScheduledTask -TaskName $SchTaskNameBckgW -InformationAction SilentlyContinue
        Disable-ScheduledTask -TaskName $SchTaskNamePrompt -InformationAction SilentlyContinue
        Disable-ScheduledTask -TaskName $SchTaskNameStatusMessage -InformationAction SilentlyContinue
        Disable-ScheduledTask -TaskName $SchTaskNameBDEPINReset -InformationAction SilentlyContinue

        <# Remove Scheduled Task #>
        Unregister-ScheduledTask -TaskName $SchTaskNameBckgW -Confirm:$false -InformationAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $SchTaskNamePrompt -Confirm:$false -InformationAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $SchTaskNameStatusMessage -Confirm:$false -InformationAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $SchTaskNameBDEPINReset -Confirm:$false -InformationAction SilentlyContinue

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Scheduled Tasks" -Id 100 -Category 0 -EntryType Information

        #Remove shortcut files
        If (Test-Path -Path "C:\Users\Public\Desktop\Set BitLocker PIN.lnk") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removing Shortcut: C:\Users\Public\Desktop\Set BitLocker PIN.lnk" -Id 100 -Category 0 -EntryType Information
            Remove-Item -Path "C:\Users\Public\Desktop\Set BitLocker PIN.lnk" -Force
        }

        If (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Manage BitLocker PIN.lnk") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removing Shortcut: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Manage BitLocker PIN.lnk" -Id 100 -Category 0 -EntryType Information
            Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Manage BitLocker PIN.lnk" -Force
        }

        #Remove scriptroot path
        <# Remove Key #>
        If (Test-Path -Path "$ScriptRootLocation\AES.key") {
            Remove-Item -Path "$ScriptRootLocation\AES.key" -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removed Key" -Id 100 -Category 0 -EntryType Information
        }

        <# Clearing Folder #>
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleanup source folder" -Id 100 -Category 0 -EntryType Information
        If (((get-item $sourcePath).parent.EnumerateDirectories() | Measure-Object).Count -gt 1) {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "More folders found in parent path, do not remove parent folder." -Id 100 -Category 0 -EntryType Information
            Remove-Item -Path $sourcePath -Recurse -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Deleted Self Folder only" -Id 100 -Category 0 -EntryType Information
        }
        Else {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Only script folder found in parent path, remove parent folder and child items" -Id 100 -Category 0 -EntryType Information
            Remove-Item -Path ($sourcePath.Substring(0, $sourcePath.LastIndexOf('\'))) -Recurse -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Deleted Self & Root Folder" -Id 100 -Category 0 -EntryType Information
        }

        $SystemKeyPath = ("HKU:\S-1-5-18\$RegistrySavePath")
        if (Test-Path $SystemKeyPath) {
            Remove-Item -Path $SystemKeyPath -Force
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
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCVPqMth6Lrwpq/
# 6sUWjK11h7sRvjNvsKjFlm7WC1GHe6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKUJ2H/ITuR4UXk98q3/ONhE
# notUSzPY9DX4CoXGIV3RMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAdP/cNJ9Aj/uGKxMzWDZZ3ermKnGw92/YkiL6jveh+LiAMgON2SmuoE2U
# wI7ko4F4ivOBKjNeAUmIob+iC9GGdo/5S3ve9yMAokVtUcPJU+zPRZ0UKo0ABCVv
# HOuKmjHuyW399TRxUETwCVf4u1c1pgOTARD+vJ5AQssK52TxEXjo03ok9UtLWHXb
# VNKAqq4oL2sNu14bsVsmbER9CqG1Wko+9lSm+a5ow2FHejdE/PMMwyQbQM6lXpjs
# G/wuF8jU7qp6GZFMgaru9WkVODDkoLFGynHjz0vNRwMzN6HyejKuPuDFC35DlvAy
# DaNpFpwCzbAGH9PfCvaUaT5CJjFTIKGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCqRGGtAVuq4sxPtPrmth78J9w/cLC04DkeYPhkSWvA8gIGZBNduD++
# GBMyMDIzMDQxMjIxMTAyMS44NDJaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0OUJDLUUz
# N0EtMjMzQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABwFWkjcNkFcVLAAEAAAHAMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# NVoXDTI0MDIwMjE5MDEyNVowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjQ5QkMtRTM3QS0yMzNDMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAvO1g+2NhhmBQvlGlCTOMaFw3jbIhUdDTqkaQhRpdHVb+
# huU/0HNhLmoRYvrp7z5vIoL1MPAkVBFWJIkrcG7sSrednyZwreY207C9n8XivL9Z
# BOQeiUeL/TMlJ6VinrcafbhdnkNO5JDlPozC9dGySiubryds5GKtu69D1wNat9DI
# Ql6alFO6pncZK4RIzfv+KzkM7RkY3vHphV0C8EFUpF+lysaGJXFf9QsUUHwj9XKW
# Hfc9BfhLoCReXUzvgrspdFmVnA9ATYXmidSjrshf8A+E0/FpTdhXPI9XXqsZDHBq
# r7DlYoSCU3lvrVDRu1p5pHHf7s3kM16HpK6arDtY3ai1soASmEpv3C2N/y5MDBAp
# Dd4SpSkLMa7+6es/daeS7zdH1qdCa2RoJPM6Eh/6YmBfofhfLQofKPJl34ALlZWK
# 5AzVtFRNOXacoj6MAG2dT8Rc5fpKCH1E3n7Zje0dK24QVfSv/YOxw52ECaMLlW5P
# hHT3ZINNaCmRgcHCTClOKzC2FOr03YBc2zPOW6bIVdXloPmBMVaE+thXqPmANBw0
# YsncaOkVggjDb5O5VqOp98MklHpJoJI6pk5zAlx8/OtC7FutrdtYNUC6ykXzMAPF
# uYkWGgx/W7A0itKW8WzYzwO3bAhprwznouGZmRiw2k8pen80BzqzdyPvbzTxQsMC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBQARMZ480jwpK3P6quVWUEJ0c30hTAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQCtTh0EQn16kKQyCeVk9Vc10m6L0EwLRo3ATRouP7Yd2hWeEB2Y4ZF4CJKe9qfX
# WGJKzV7tMUm6DAsBKYH/nT+8ybI8uJiHGnfnVi6Sh7gFjnTpfh1j1T90H/uLeoFj
# pOn/+eoCoJmorW5Gb2ezlTlo5I0kNAubxtCxqbLizuPNPob8kRAKQgv+4/CC1Jmi
# UFG0uKINlKj9SsHcrWeBBQHX62nNgziIwT44JqHrA02I6cmQAi9BZcsf57OOLpRY
# lzoPH3x/+ldSySXAmyLq2uSbWtQuD84I/0ZgS/B5L3ewqTdiE1KbKX89MW5JqCK/
# yI/mAIQammAlHPqU9eZZTMPOHQs0XrpCijlk+qyo2JaHiySww6nuPqXzU3sEj3VW
# 00YiVSayKEu1IrRzzX3La8qe6OqLTvK/6gu5XdKq7TT852nB6IP0QM+Budtr4Fbx
# 4/svpKHGpK9/zBuaHHDXX5AoSksh/kSDYKfefQIhIfQJJzoE3X+MimMJrgrwZXlt
# b6j1IL0HY3qCpa03Ghgi0ITzqfkw3Man3G8kB1Ql+SeNciPUj73Kn2veJenGLtT8
# JkUM9RUi0woO0iuY4tJnYuS+SeqavXUOWqUYVY19FIr1PLqpmWkbrO5xKjkyOHoA
# mLxjNbKjOnkAwft+1G00kulKqzqPbm+Sn+47JsGQFhNGbTCCB3EwggVZoAMCAQIC
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
# U046NDlCQy1FMzdBLTIzM0MxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVABAQ7ExF19KkwVL1E3Ad8k0Peb6doIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDn4XLtMCIYDzIwMjMwNDEzMDIxMTU3WhgPMjAyMzA0MTQwMjExNTdaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOfhcu0CAQAwBwIBAAICAyMwBwIBAAICEbcw
# CgIFAOfixG0CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQB1Qtmrxo9W5yLA
# 1ntcgXAm9efQEpI6v/oFJU4c1Jvj+kgRmTcBtGqIbmFeez2CAPpRjZa7Rdsle8SF
# TI5Q/UCxE7aUL/WQ/Yd++uhmPFoLTu5baqE8Hj2eSHyjHJX+yjaSadxFLjG3cb7/
# dMH+nDbWlE+LTRD1M7lHguhYso0P5jGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABwFWkjcNkFcVLAAEAAAHAMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIJ8J9asM2gUoZ+Peo4rgOesRuxAQIObz7PWgPCs9owUbMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgWvFYolIIXME0zK/W6XsCkkYX7lYNb9yA8Jxw
# Y04Pk08wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AcBVpI3DZBXFSwABAAABwDAiBCArOhqXrS2Av8GiE2Qov3XZImgEh7IGrhHes2IA
# q9B9lTANBgkqhkiG9w0BAQsFAASCAgB/SyzppgfPBu59AGJppYhTgy9FLOSD10+6
# GvpRzkzkDKaRn84inIsa3cvWz/JF7OwnNxtbzxQkji4F0sqCXxXf0ivXGOdMmq/0
# iKPol/U1R8Xowt2UEsyF2wRT594PBc5F/rMaz/D7H8FvQrz+RlsvQVwI11aJdWPG
# GqQ51NJbQ+kRU6GCQogEbPGifHnENy/vgqC1N9d2mq3tcpS8dAOyG9OTnqWGtRPe
# QzcYO9Dn20hmjsZP8FFfJuv3VDIPJCFgXBUqkzd1mSeGVmxtvNkoN7vMJWMcoMxr
# g+pDUGJaZW5MWVSvF7S+r6Qcg32s6kK4EfZVC5WZm2NeqHHlk1omOAjOOgvKQ6q2
# ZS2EsSsobcOCKAQxMjOdL2NPkw9YQ9FqnQaXj7nj6jdybi6lsd0NLckaE7NLwZUG
# CnyMfb/NFobNfgOliUXqHQFjz/yJrtXDKQX4TjNkohaDckOm+Ka8KzELo0jnU1bp
# sdkAGtcLNCjJSolBU45Qyh9g+jIT+KS61mMd8Hli7VYu7pKOs/c7RffAfBSH2/ma
# gJ+3ARXTUe9UDJr8AOhGxuXVSwnJRtCSpdButs92VOOsrRAMSmGJX2MZUvWckEhz
# fSorP6TZJK1Ivp9EGygRMD0n+CN/ZeqER+d2KWHNkCFghQoJ/mk/tdWB9BddS3pj
# g8mgOrgMMg==
# SIG # End signature block
