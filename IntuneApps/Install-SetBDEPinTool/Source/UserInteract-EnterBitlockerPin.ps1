Import-Module -Name "$PSScriptRoot\AutoItX\AutoItX"
While($(Assert-AU3WinExists -Title "BitLocker" -Text "You are required") -ne 0){
    Close-AU3Win -Title "BitLocker" -Text "You are required" -Force
}

<# Script Variables #>
$ValidationPinMinLength = 6 # Min Pin length

$EventLogName = "Bitlocker Setup"
$EventLogSource = "PS-Bitlocker-UserPrompt"

$RegistrySavePath = "HKCU:\Software\MCS\SetBitlocker"
$StringKeyName = "UserSecureString"
$SkipKeyName = "SkipImplement"

$RegistryFveLocation = "HKLM:\Software\Policies\Microsoft\FVE"

$ProgramFilesPathTail = "\MCS\BitlockerScripts"
$ForceScriptRootPath = "C:\Program Files"

$IgnoreUserNames = "defaultuser100000","Administrator"


<# Announce Ourselves #>
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User Prompt Script Running!" -Id 100 -Category 0 -EntryType Information


function FreqAnalysis( $numstr )
{
    $counts = @(0,0,0,0,0,0,0,0,0,0)

    #Write-Host "FreqAnalysis $numstr"

    for ( $i=0; $i -lt $numstr.length; $i += 1)
    {
        $v1 = ([int] $numstr.substring($i,1));

        $counts[$v1] += 1
    }

    $total = 0
    $average = $numstr.Length / $counts.Length

    for ( $i=0; $i -lt $counts.length; $i += 1)
    {
        $dif = $counts[$i] - $average;
        $total += $dif  * $dif
    }

    #Write-Host "Square $total"
    return $total
}

####################################################

function IncSeq($numstr)
{
    $max = 1
    $count = 1
    $last = [int] $numstr.substring(0,1);

    for ( $i=1; $i -lt $numstr.length; $i += 1)
    {
        $v1 = [int] $numstr.substring($i,1);

        if ( ($v1 - $last) -ge -1 -and ($v1 - $last) -le 1 )
        {
            $count ++
            if ( $count -gt $max )
            {
                $max = $count;
            }
        }
        else
        {
            $count = 1
        }
        $last = $v1
    }

    return $max;
}

####################################################

function RepeatedSeq( $numstr )
{
    $longest = $null;

    for ( $l = [int] ($numstr.length / 2); $l -gt 0; $l -= 1)
    {
        for ( $i=0; $i -le $numstr.length-$l; $i += 1)
        {
            $v1 = $numstr.substring($i,$l);
#            Write-Host "$l $v1 $numstr"

            for ( $j=$l; $j -le $numstr.length-$l; $j += 1)
            {
                if ( $i -ne $j )
                {
                    $v2 = $numstr.substring($j,$l);
#                    Write-Host "$l $v1 $v2 $numstr"

                    if ( $v1 -eq $v2 )
                    {
#                        Write-Host "Found Longest Repeat $v1 in $numstr $i $j"
                        $longest = $v1
                        break;
                    }
                }
            }
            if ( $longest -ne $null )
            {
                break;
            }
        }
        if ( $longest -ne $null )
        {
            break;
        }
    }

    if ( $longest -eq $null )
    {
        # Write-Host "No Longest String";
        return 0;
    }

    $count = 0
    for ( $i=0; $i -le $numstr.length-$longest.length; $i += 1)
    {
        if ( $numstr.substring($i,$longest.length) -eq $longest )
        {
            $count += 1
        }
    }

    #Write-Host "Longest String $longest $count";

    return $longest.length * $count;
}

####################################################

function IsRandomEnough( $numstr )
{
#     Write-Host "$numstr"

    $freq = FreqAnalysis( $numstr )

#    Write-Host "$numstr $freq $longest"

    $longest = RepeatedSeq( $numstr )

#    Write-Host "$numstr $freq $longest"

    $longestIncSeq = IncSeq( $numstr )

#    Write-Host "$numstr $freq $longest $longestIncSeq"

    $OK = ""

    if ( $freq -gt 23 )
    {
        $OK = "Frequency Analysis"
    }

    if ( $longest -gt 6 )
    {
        if ( $OK.Length -gt 0 )
        {
            $OK = $OK + " : "
        }
        $OK = $OK + "Repeated Strings"
    }

    if ( $longestIncSeq -gt 5 )
    {
        if ( $OK.Length -gt 0 )
        {
            $OK = $OK + " : "
        }
        $OK = $OK + "Repeating, Incrementing and Decrementing Sequences"
    }

    if ( $OK.Length -eq 0 )
    {
        $OK = "OK"
    }
    $OK = $OK.Trim()

    Write-Host "$numstr $OK $freq $longest $longestIncSeq"

    return $OK
}

####################################################

<# Check if we are running as an ignored user #>
$WmiUsername = (Get-WmiObject -Class Win32_ComputerSystem).Username

foreach($Username in $IgnoreUserNames) {
    if($WmiUsername.Contains($Username)) {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Logged on user $Username is in the ignored users list, exiting") -Id 100 -Category 0 -EntryType Information
        Return
    }
}

<# Check the present Bitlocker state before running #>
$WmiSystemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive

$BitlockerSystemDrive = (Get-BitLockerVolume -MountPoint $WmiSystemDrive)

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Detected system drive $WmiSystemDrive is protected ? " + [bool]$BitlockerSystemDrive.ProtectionStatus )  -Id 100 -Category 0 -EntryType Information

$RegistryFveUseTpmPin = [int](Get-ItemProperty -Path $RegistryFveLocation -Name "UseTPMPIN").UseTpmPin

if( ($RegistryFveUseTpmPin -eq 1) -or ($RegistryFveUseTpmPin -eq 2) ) { $RegistryPrebootPinRequired = $true } else { $RegistryPrebootPinRequired = $false }

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Registry settings require Pin? $RegistryPrebootPinRequired"  -Id 100 -Category 0 -EntryType Information

if(($BitlockerSystemDrive.ProtectionStatus -eq "On") -and ($BitlockerSystemDrive.KeyProtector.KeyProtectorType -Contains "TpmPin"))
{
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker is enabled, and has a preboot PIN configured.  Setting Registry Skip & Exiting"  -Id 100 -Category 0 -EntryType Information

        # Check if the registry location exists
        if(!(Test-Path $RegistrySavePath)) {

            # Location Missing, Create It
            New-Item -Path $RegistrySavePath -Force

            # Create Value
            New-ItemProperty -Path $RegistrySavePath -Name $SkipKeyName -Value "1" -PropertyType String -Force

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created Skip Flag Registry Item" -Id 100 -Category 0 -EntryType Information

        }

        Return
}

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker requires configuration, continuing"  -Id 100 -Category 0 -EntryType Information

<# Figure Out Where the Script Root Is #>
$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

# Create Source Path
if ($OSArchitecture -like '64*') { $ScriptRootLocation = "$env:ProgramFiles$ProgramFilesPathTail" } else { $ScriptRootLocation = "${env:ProgramFiles(x86)}$ProgramFilesPathTail" }
if($ForceScriptRootPath) { $ScriptRootLocation = "$ForceScriptRootPath$ProgramFilesPathTail" }

# Does the path exist ?
if(!(Test-Path "$ScriptRootLocation\AES.key"))
{
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Could not find encryption key, check install directory. Exiting") -Id 100 -Category 0 -EntryType Information
    Return
}

<# Get the Key #>
$AesKey = Get-Content "$ScriptRootLocation\AES.key"

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Got AES Key" -Id 100 -Category 0 -EntryType Information

<# Check FVE in Registry #>

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Checking FVE Setttings In Registry" -Id 100 -Category 0 -EntryType Information

if( Get-ItemProperty -Path $RegistryFveLocation -Name "MinimumPIN" -ErrorAction SilentlyContinue ) {
    $ValidationPinMinLength = [int](Get-ItemProperty -Path $RegistryFveLocation -Name "MinimumPIN").MinimumPin
} else {
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Could not get MinimumPin from reg, defaulting to $ValidationPinMinLength" -Id 100 -Category 0 -EntryType Information
}

if( Get-ItemProperty -Path $RegistryFveLocation -Name "UseEnhancedPin" -ErrorAction SilentlyContinue ) {

    if((Get-ItemProperty -Path $RegistryFveLocation -Name "UseEnhancedPin").UseEnhancedPin -ne 0) {
        $ValidationEnhancedPinAllowed = $true
    } else {
        $ValidationEnhancedPinAllowed = $false
    }

} else {
    $ValidationEnhancedPinAllowed = $false
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Could not get UseEnhancedPin from reg, defaulting to disallowed" -Id 100 -Category 0 -EntryType Information

}

<# Event Log #>
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "FVE Checks Done, Got MinPin $ValidationPinMinLength and Enhanced is $ValidationEnhancedPinAllowed" -Id 100 -Category 0 -EntryType Information

<# Build Form #>

# Bring in the Windows Forms Library
Add-Type -assembly System.Windows.Forms

# Generate the form
$Form = New-Object System.Windows.Forms.Form

# Window Font
$Font = New-Object System.Drawing.Font("Segoe UI",10,[System.Drawing.FontStyle]::Regular)

# Font styles are: Regular, Bold, Italic, Underline, Strikeout
$Form.Font = $Font

# Window Basics
$Form.Text ='BitLocker - Set up a PIN'
$Form.Width = 350
$Form.Height = 275
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
$lbl_InstructionString = "You are required to set a pre-boot PIN for BitLocker.`nIt must be a minimum of $ValidationPinMinLength characters.`n"
if($ValidationEnhancedPinAllowed) { $lbl_InstructionString += "It may contain any character `n" } else { $lbl_InstructionString += "It can only contain numbers.`n" }

# Label Basics
$lbl_HeaderText.Text = $lbl_InstructionString
$lbl_HeaderText.Location  = New-Object System.Drawing.Point(10,5)
$lbl_HeaderText.AutoSize = $true

# Add to form
$Form.Controls.Add($lbl_HeaderText)

# Create the label
$lbl_TxbHeader1 = New-Object System.Windows.Forms.Label

# Label Basics
$lbl_TxbHeader1.Text = "New PIN"
$lbl_TxbHeader1.Location  = New-Object System.Drawing.Point(20,65)
$lbl_TxbHeader1.AutoSize = $true

# Add to form
$Form.Controls.Add($lbl_TxbHeader1)

# Create the label
$lbl_TxbHeader2 = New-Object System.Windows.Forms.Label

# Label Basics
$lbl_TxbHeader2.Text = "Confirm PIN"
$lbl_TxbHeader2.Location  = New-Object System.Drawing.Point(20,125)
$lbl_TxbHeader2.AutoSize = $true

# Add to form
$Form.Controls.Add($lbl_TxbHeader2)

# Create the label
$lbl_FeedbackMsg = New-Object System.Windows.Forms.Label

# Label Basics
$lbl_FeedbackMsg.Text = "The provided PINs do not match"
$lbl_FeedbackMsg.ForeColor = "Red"
$lbl_FeedbackMsg.Location  = New-Object System.Drawing.Point(20,210)
$lbl_FeedbackMsg.AutoSize = $true
$lbl_FeedbackMsg.Visible = $false

# Add to form
$Form.Controls.Add($lbl_FeedbackMsg)

<# Text Boxes #>

# Create Pin Box 1
$txb_PinEnter1 = New-Object System.Windows.Forms.MaskedTextBox

# Set Params
$txb_PinEnter1.Width = 200
$txb_PinEnter1.Height = 50
$txb_PinEnter1.Location  = New-Object System.Drawing.Point(20,90)
$txb_PinEnter1.PasswordChar = '*'

# Add to Form
$Form.Controls.Add($txb_PinEnter1)

# Create Pin Box 2
$txb_PinEnter2 = New-Object System.Windows.Forms.MaskedTextBox

# Set Params
$txb_PinEnter2.Width = 200
$txb_PinEnter2.Height = 50
$txb_PinEnter2.Location  = New-Object System.Drawing.Point(20,150)
$txb_PinEnter2.PasswordChar = '*'

# Add to Form
$Form.Controls.Add($txb_PinEnter2)

<# Buttons #>

# Create a button
$btn_SavePin = New-Object System.Windows.Forms.Button

# Button basics
$btn_SavePin.Location = New-Object System.Drawing.Size(19,180)
$btn_SavePin.Size = New-Object System.Drawing.Size(75,23)
$btn_SavePin.Text = "Set PIN"

# Check for ENTER and ESC presses
$Form.KeyPreview = $True
$Form.Add_KeyDown({if ($_.KeyCode -eq "Enter")
    {
    # if enter, perform click
    $btn_SavePin.PerformClick()
    }
})
$Form.Add_KeyDown({if ($_.KeyCode -eq "Escape")
    {
    # if escape, exit
    $Form.Close()
    }
})

# Set Function Handler
$btn_SavePin.Add_Click({

    # Set Error Conditions
    $InputErrorPresent = $false
    $InputErrorMessage = "Unspecified input error."

    # Check if the PINS Match
    if($txb_PinEnter1.Text -ne $txb_PinEnter2.Text)
    {
        # Set Error Conditions
        $InputErrorPresent = $true
        $InputErrorMessage = "Entered PINs do not match."

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User entered mismatched PINs" -Id 100 -Category 0 -EntryType Information
    }

    # Check if Min Length
    if(($txb_PinEnter1.Text.Length -lt $ValidationPinMinLength) -or ($txb_PinEnter2.Text.Length -lt $ValidationPinMinLength))
    {
        # Set Error Conditions
        $InputErrorPresent = $true
        $InputErrorMessage = "PIN does not meet minimum length."

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User entered a short PIN" -Id 100 -Category 0 -EntryType Information
    }

    # Check if the PIN is numeric
    if(!($txb_PinEnter1.Text -match '^[0-9]+$'))
    {
        # Set Error Conditions
        $InputErrorPresent = $true
        $InputErrorMessage = "PIN must contain numbers only."

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User entered a non numeric PIN" -Id 100 -Category 0 -EntryType Information
    }

    if ((IsRandomEnough $txb_PinEnter1.Text) -ne "OK")
    {
        # Set Error Conditions
        $InputErrorPresent = $true
        $InputErrorMessage = "PIN does not meet complexity requirements."

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User entered a PIN that does not meet complexity requirements." -Id 100 -Category 0 -EntryType Information
    }

    # Check if the error flag has been set
    if($InputErrorPresent)
    {
        # Set and show error
        $lbl_FeedbackMsg.Text = $InputErrorMessage
        $lbl_FeedbackMsg.Visible = $true

        #Return
        return

    } else {
        # Clear Error Message
        $lbl_FeedbackMsg.Visible = $false

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User managed to enter a valid PIN" -Id 100 -Category 0 -EntryType Information

    }

    # PIN has been validated, convert to PT secure string
    $PinSecureString = $txb_PinEnter1.Text | ConvertTo-SecureString -AsPlainText  -Force | ConvertFrom-SecureString -Key $AesKey

    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Converted PIN to SecureString" -Id 100 -Category 0 -EntryType Information

    # Check if the registry location exists
    if(!(Test-Path $RegistrySavePath)) {

        # Location Missing, Create It
        New-Item -Path $RegistrySavePath -Force

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created Registry Item" -Id 100 -Category 0 -EntryType Information

    }

    # Create Value
    New-ItemProperty -Path $RegistrySavePath -Name $StringKeyName -Value $PinSecureString -PropertyType String -Force

    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Setting Registry Value & Closing Form" -Id 150 -Category 0 -EntryType Information


    # Now Close the form
    $Form.Close()
})

# Add to Form
$Form.Controls.Add($btn_SavePin)


<# Show the Form #>
#$Env:BitLockerFormIsDisplayed = $true
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Form On Screen" -Id 100 -Category 0 -EntryType Information
#Set-Content -Path "C:\Windows\Temp\BLForm.tag" -Value "Running..."
$Form.ShowDialog()

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Finished, Exiting..." -Id 100 -Category 0 -EntryType Information

# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCfBuMdq/BhCEnW
# KOQ+xh2R1A514kBbiDYbMV47xVe1JKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPmchDwNyb1xw7ZknrOyyqnY
# hZJSL9SFH3wRh8n02J0/MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAfGoHV/bWX/6C6oK1JZC+vINFb17NaJ5SZsyWsTRoRqrKfLDJ/gmqpBtU
# nNhGlPncK5MHuzbWBfOUqxxkg98xIvUPj3yMt/ah3kdIIVRsVEDQ13XQbxyLhlVi
# URnhjquPUpAWYj/qJaqABkopIMxf0iJpoH0g8QohmaxMyXq5HOyF+d5faEmI17Mw
# VYWNVUszIEz7XksJBpOk16FDEDAPp8VoddCCl+1qOSFIjtk3oCSTN00Ax0QvmFb+
# jzFSnoJaMUxs7ZjBXoGfb41BXG2iT7WwCA+hc+r1Pph0B83++uTL1gLIPCfFte/f
# pv82ZROSxGU7Wl6ghVc/H88ndkF10aGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCC+enLBhZg+GaujOhPXGD9sPbFrX/6RMt0IQiV3B0oFxQIGZBMoguJf
# GBMyMDIzMDQxMjIxMTAxOS40OTVaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozRTdBLUUz
# NTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAAByfrVjiUgdAJeAAEAAAHJMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEz
# OFoXDTI0MDIwMjE5MDEzOFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNFN0EtRTM1OS1BMjVEMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA1nLi5Y5vz8K+Woxhk7qGW/vCxi5euTM01TiEbFOG8g7S
# FB0VMjYgo6TiRzgOQ+CN53OBOKlyMHWzRL4xvaS03ZlIgetIILYiASogsEtljzEl
# RHO7fDGDFWcdz+lCNYmJoztbG3PMrnxblUHHUkr4C7EBHb2Y07Gd5GJBgP8+5AZN
# sTlsHGczHs45mmP7rUgcMn//c8Q/GYSqdT4OXELp53h99EnyF4zcsd2ZFjxdj1lP
# 8QGwZZS4F82JBGe2pCrSakyFjTxzFKUOwcQerwBR/YaQly7mtCra4PNcyEQm+n/L
# Dce/VViQa8OM2nBZHKw6CyMqEzFJJy5Hizz8Z6xrqqLKti8viJUQ0FtqkTXSR3//
# w8PAKyBlvIYTFF/Ly3Jh3cbVeOgSmubOVwv8nMehcQb2AtxcU/ldyEUqy8/thEHI
# WNabzHXx5O9D4btS6oJdgLmHxrTBtGscVQqx0z5/fUIkLE7tbwfoq84cF/URLEyw
# 3q57KV2U4gOhc356XYEVQdJXo6VFWBQDYbzanQ25zY21UCkj821CyD90gqrO3rQP
# lcQo6erwW2DF2fsmgAbVqzQsz6Rkmafz4re17km7qe09PuwHw5e3x5ZIGEoVlfNn
# Jv6+851uwKX6ApZFxPzeQo7W/5BtaTmkZEhwY5AdCPgPv0aaIEQn2qF7MvFwCcsC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBQFb51nRsI8ob54OhTFeVF7RC4yyzAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQA2qLqcZt9HikIHcj7AlnHhjouxSjOeBaTE+EK8aXcVLm9cA8D2/ZY2OUpYvOdh
# uDEV9hElVmzopiJuk/xBYh6dWJTRhmS7hVjrGtqzSFW0LffsRysjxkpuqyhHiBDx
# MXMGZ6GdzUfqVP2Zd2O+J/BYQJgs9NHYz/CM4XaRP+T2VM3JE1mSO1qLa+mfB427
# QiLj/JC7TUYgh4RY+oLMFVuQJZvXYl/jITFfUppJoAakBr0Vc2r1kP5DiJaNvZWJ
# /cuYaiWQ4k9xpw6wGz3qq7xAWnlGzsawwFhjtwq5EH/s37LCfehyuCw8ZRJ9W3tg
# SFepAVM7sUE+Pr3Uu+iPvBV4TsTDNFL0CVIPX+1XOJ6YRGYJ2kHGpoGc/5sgA2IK
# Qcl97ZDYJIqixgwKNftyN70O0ATbpTVhsbN01FVli0H+vgcGhyzk6jpAywHPDSQ/
# xoEeGU4+6PFTXMRO/fMzGcUcf0ZHqZMm0UhoH8tOtk18k6B75KJXTtY3ZM7pTfur
# Sv2Qrv5zzCBiyystOPw/IJI+k9opTgatrC39L69/KwytD0x7t0jmTXtlLZaGvoSl
# jdyyr6QDRVkqsCaLUSSsAiWeav5qg64U3mLmeeko0E9TJ5yztN/jcizlHx0XsgOu
# N6sub3CPV7AAMMiKopdQYqiPXu9IxvqXT7CE/SMC2pcNyTCCB3EwggVZoAMCAQIC
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
# U046M0U3QS1FMzU5LUEyNUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAH3pi8v+HgGbjVQs4G36dRxWBt0OoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDn4T2/MCIYDzIwMjMwNDEyMjIyNTAzWhgPMjAyMzA0MTMyMjI1MDNaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOfhPb8CAQAwBwIBAAICHI4wBwIBAAICEa4w
# CgIFAOfijz8CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAbHQyi3+nhVbo/
# 73AskYh65mBH5pD24psoKqZJoZVEkUDpXNWfG+xQIJeoDQGh2tvwCg84iVRrx5N/
# FIZAmyJ9jkrKjtQVEDOJjnTK+d1jdzIEFZCK6zhjUNXAvryjqFw6YqIvHuuK7dWU
# B85PJvDUR588paj/DIzY1iOV0NqjHTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAByfrVjiUgdAJeAAEAAAHJMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIARpzZHwIDth1nBryY5NwRFyuVRdeHDcCvuIgAXw744IMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQggXXOf1LdUUsQJ3gp2H9gDSMhiQD/zX3hXXzh
# 2Tl2/YEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Acn61Y4lIHQCXgABAAAByTAiBCDzEt7P8cPLrK11G/AqcpLT3LzHpsgK4hH6lT+h
# DARQfjANBgkqhkiG9w0BAQsFAASCAgAuibyPVBiZCThG6EsLIX8QBgOR4QR0auew
# mLOEtPTWtgc4s9Gj60+/mPj6h6mpepb0Z6ebkWNcMGy102cW4z6se6L9q9VXQ9cL
# l4TQ6Q38L4FDCnzUP7vwgBxcQxy8ruYs8njjlXX8wtCAU9RhqnzHkFACtgMvlYsu
# WF4k7aNwsJCtibmyktJ5r2PiFKWtVQxObXrNwpd/DbE081t+YWrI+PGU0X6BC2LG
# lrhV5MBEGtbepwIhaj106I44bq049km9bKe4dIl3buxMEhMXa+Rr+Xt/FsUT8vHC
# r6fyJhJUKtsM0lVHn/E1zrSFEIAsJWDf7TylS7uFUz8CKEAH+KJRlGw5fBQI1Twg
# MrHHQTxbu4Qnbw9yfJ2IlQ+V9VvZ4IqSPCQpyHQhAGmW7kgLqhesKSMpp763KCF3
# Cf179QsSrWlJVWf40/mJEnJhhgYZRf/rP1rLicw0hrQAu4ZFYQPhcokVv6es4tMK
# 8cm1sew1sVGYXncn98QBXdttIVk4XeIHMhlO86PwqXruEnzeYoefenKy4l56Tl2P
# 879p8k2/Y8Cy18J4T2SwXCot34/5uj9gomcIF7fySbRJWTsLryj4uzCVlTWszOdE
# WmEUlkXwyZRozG5cD7cPwoA5zXLTLa3mUF2GjwwegTi1PAy35ZC7dGl+o6mVEgyP
# p2roMGsuiQ==
# SIG # End signature block
