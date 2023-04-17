<# Variables #>
$EventLogName = "Bitlocker Setup"
$EventLogSource = "PS-Bitlocker-BackgroundWatcher"

$ProgramFilesPathTail = "\MCS\BitlockerScripts"
$ForceScriptRootPath = "C:\Program Files"

$RegistrySavePath = "\Software\MCS\SetBitlocker"
$RegistryKeyName = "UserSecureString"
$SkipKeyName = "SkipImplement"

$RegistryFveLocation = "HKLM:\Software\Policies\Microsoft\FVE"
$RegistryConnectedStbyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"

$SchTaskNamePrompt = "BLTOOL-USRPROMPT"
$SchTaskNameBckgW = "BLTOOL-BCKGWTCH"

$ScriptRemoveFiles = $true
$ForceRemove=$true
#$ForceRestart=$true
#$ForceRestart=$false


<# Create Event Log #>
New-Eventlog -LogName $EventLogName -Source $EventLogSource -ErrorAction SilentlyContinue

<# Announce Our Presence #>
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Background Watcher Process is running!"  -Id 100 -Category 0 -EntryType Information


<# Figure Out Where the Script Root Is #>
$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

# Create Source Path
if ($OSArchitecture -like '64*') { $ScriptRootLocation = "$env:ProgramFiles$ProgramFilesPathTail" } else { $ScriptRootLocation = "${env:ProgramFiles(x86)}$ProgramFilesPathTail" }
if($ForceScriptRootPath) { $ScriptRootLocation = "$ForceScriptRootPath$ProgramFilesPathTail" }

<# Get the Key #>
try
{
    $AesKey = Get-Content "$ScriptRootLocation\AES.key" # <TODO>
}
catch
{
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Could not find encryption key, check install directory. Exiting") -Id 100 -Category 0 -EntryType Information
    exit
}

<# Check if the skip flag is present #>
$SkipImplementKeyValue = (Get-ItemProperty -Path $RegistrySavePath -Name $SkipKeyName).SkipImplement

if($SkipImplementKeyValue -eq "1")
{
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Skip flag has been set outside of script. Exiting") -Id 100 -Category 0 -EntryType Information
    exit
}

<# Check present state of FVE #>
$WmiSystemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive

$BitlockerSystemDrive = (Get-BitLockerVolume -MountPoint $WmiSystemDrive)

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Detected system drive $WmiSystemDrive is protected ? " + [bool]$BitlockerSystemDrive.ProtectionStatus )  -Id 100 -Category 0 -EntryType Information

$RegistryFveUseTpmPin = [int](Get-ItemProperty -Path $RegistryFveLocation -Name "UseTPMPIN").UseTpmPin

if( ($RegistryFveUseTpmPin -eq 1) -or ($RegistryFveUseTpmPin -eq 2) ) { $RegistryPrebootPinRequired = $true } else { $RegistryPrebootPinRequired = $false }

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Registry settings require Pin? $RegistryPrebootPinRequired"  -Id 100 -Category 0 -EntryType Information


if( ([bool]$BitlockerSystemDrive.ProtectionStatus) -and ($BitlockerSystemDrive.KeyProtector | Select-Object -ExpandProperty KeyProtectorType).Contains("TpmPin"))
{
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker is enabled, and has a preboot PIN configured. Exiting"  -Id 100 -Category 0 -EntryType Information
        exit
}

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker requires configuration, continuing"  -Id 100 -Category 0 -EntryType Information

<# Validate the device type and state #>
$WmiWin32ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem

if( ($WmiWin32ComputerSystem.PCSystemType -eq 2) -and ($WmiWin32ComputerSystem.PCSystemTypeEx -eq 8) )
{
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Device reports it is a Slate/Tablet (PcSystemType 2 + PcSystemTypeEx 8)"  -Id 100 -Category 0 -EntryType Information

    New-ItemProperty -Path $RegistryFveLocation -Name OSEnablePrebootInputProtectorsOnSlates -PropertyType DWORD -Value 1 -Force

    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Set OSEnablePrebootInputProtectorsOnSlates to 1"  -Id 100 -Category 0 -EntryType Information
}

$RegistryCsEnabled = [bool](Get-ItemProperty -Path $RegistryConnectedStbyLocation -Name "CsEnabled").CsEnabled

<# Figure Out Who Is Logged On #>
$WmiUsername = (Get-WmiObject -Class Win32_ComputerSystem).Username

<# If there is no logged on user, stop. Could be RDP User #>
if($WmiUsername -eq $null)
{
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("No logged on user found, are you using RDP? Exiting") -Id 100 -Category 0 -EntryType Information
    exit
}

<# Resolve User SID #>
$WmiSid = (New-Object System.Security.Principal.NTAccount($WmiUsername)).Translate([System.Security.Principal.SecurityIdentifier]).Value

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Discovered logged on user:  $WmiUsername ($WmiSid)") -Id 100 -Category 0 -EntryType Information

<# Hook up to the HKEY Users Hive #>
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

<# Build key location #>
$UserKeyPath = ("HKU:\" + $WmiSid + $RegistrySavePath)


<# Check if the registry location exists #>
if(!(Test-Path $UserKeyPath)) {

    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User PIN not present in registry, exiting" -Id 100 -Category 0 -EntryType Information

    # Nothing has been set, exit
    exit

}

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User PIN Present in Registry, Processing" -Id 100 -Category 0 -EntryType Information

<# Get the value set in registry #>
$SecureString = (Get-ItemProperty -Path $UserKeyPath -Name $RegistryKeyName).UserSecureString | ConvertTo-SecureString -Key $AesKey

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Preparing to configure BitLocker" -Id 100 -Category 0 -EntryType Information

if( !([bool]$BitlockerSystemDrive.ProtectionStatus) )
{
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker is not enabled for the target drive, enabling it with TpmAndPin" -Id 100 -Category 0 -EntryType Information

    try {
        Enable-BitLocker -MountPoint $WmiSystemDrive -EncryptionMethod XtsAes128 -UsedSpaceOnly -TpmAndPinProtector -Pin $SecureString -ErrorAction Stop -SkipHardwareTest -WarningAction SilentlyContinue
    } catch {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Crticial Failure Enabling BitLocker: "+$Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
        $NotComplete=$true
    }

} else {

    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Bitlocker is enabled, Adding Bitlocker Key Protector to Drive" -Id 100 -Category 0 -EntryType Information
    try {
        Add-BitLockerKeyProtector -MountPoint $WmiSystemDrive -Pin $SecureString -TpmAndPinProtector -ErrorAction Stop -WarningAction SilentlyContinue
    } catch {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Crticial Failure Adding Key Protector: "+$Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
        $NotComplete=$true
    }
}


<# Check for recovery keys on the drive, create if not present, and backup all found #>

$RecoveryPasswords = Get-BitLockerVolume -MountPoint $WmiSystemDrive | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'

if (!$RecoveryPasswords) {
    try {
	    Add-BitLockerKeyProtector -MountPoint $WmiSystemDrive -RecoveryPasswordProtector -ErrorAction Stop -WarningAction SilentlyContinue
	    $RecoveryPasswords = Get-BitLockerVolume -MountPoint C: | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'
    } catch {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Crticial Failure Creating RecoveryPassword: "+$Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
        $NotComplete=$true
    }
}
# In case there are multiple recovery passwords, lets copy them all just to make it sure.
foreach($RecoveryPassword in $RecoveryPasswords) {
    try {
        BackupToAAD-BitLockerKeyProtector -MountPoint $WmiSystemDrive -KeyProtectorId $RecoveryPassword.KeyProtectorId -ErrorAction Stop -WarningAction SilentlyContinue
    } catch {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Critical Failure Uploading Key Protector:"+$Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
        $NotComplete=$true
    }
}


$BitlockerSystemDrive = (Get-BitLockerVolume -MountPoint $WmiSystemDrive)
if( !($BitlockerSystemDrive.KeyProtector | Select-Object -ExpandProperty KeyProtectorType).Contains("TpmPin"))
{
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Something went wrong enabling the PIN. Exiting"  -Id 100 -Category 0 -EntryType Information
        exit
}


########################################################################################################################################################## DO BITLOCKER TO IT

<# Stop Scheduled Tasks #>
Disable-ScheduledTask -TaskName $SchTaskNameBckgW -InformationAction SilentlyContinue
Disable-ScheduledTask -TaskName $SchTaskNamePrompt -InformationAction SilentlyContinue

<# If not complete flag, don't let tidyup run and keep ticking background worker #>
if($NotComplete -and !($ForceRemove)) {
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Configuration did not complete, Scheduled Tasks Disabled, Script Stopped. Artefacts have not been cleared" -Id 100 -Category 0 -EntryType Error
    exit
}

<# Clean Up The Registry #>
Remove-Item -Path $UserKeyPath
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Registry" -Id 100 -Category 0 -EntryType Information

<# Remove Scheduled Task #>
Unregister-ScheduledTask -TaskName $SchTaskNameBckgW -Confirm:$false -InformationAction SilentlyContinue
Unregister-ScheduledTask -TaskName $SchTaskNamePrompt -Confirm:$false -InformationAction SilentlyContinue

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Scheduled Task" -Id 100 -Category 0 -EntryType Information

if($ScriptRemoveFiles -or $ForceRemove)
{
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removing shortcut files" -Id 100 -Category 0 -EntryType Information
    <# Remove Shortcuts from User Desktop #>
    $UserDirectories = Get-ChildItem -Path "C:\Users"

    foreach($User in $UserDirectories) {
        $shortcut = $User.FullName + "\Desktop\Set BitLocker Pin.lnk"
        Remove-Item -Path $shortcut -Force
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removed $shortcut" -Id 100 -Category 0 -EntryType Information
    }

    <# Remove Key #>
    Remove-Item -Path "$ScriptRootLocation\AES.key" -Force
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removed Key" -Id 100 -Category 0 -EntryType Information

    <# Clearing Folder #>
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleanup source folder" -Id 100 -Category 0 -EntryType Information
    if (((get-item $PSScriptRoot ).parent.EnumerateDirectories() | Measure-Object).Count -gt 1) {
        Write-Host "More folders found in parent path, do not remove parent folder."

        Remove-Item -Path $PSScriptRoot -Recurse
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Deleted Self Folder only" -Id 100 -Category 0 -EntryType Information
     }
     else {
        Write-Host "Only script folder found in parent path, remove parent folder and child items"

        #$ScriptRootLocation.Substring(0, $ScriptRootLocation.LastIndexOf('\'))
        Remove-Item -Path ($ScriptRootLocation.Substring(0, $ScriptRootLocation.LastIndexOf('\'))) -Recurse
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Deleted Self & Root Folder" -Id 100 -Category 0 -EntryType Information
     }

}

#Force Intune Device Sync
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Force Intune Device Sync" -Id 100 -Category 0 -EntryType Information
Get-ScheduledTask | ? {$_.TaskName -eq 'PushLaunch'} | Start-ScheduledTask

#Pause for 10 seconds
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Pause for 10 seconds" -Id 100 -Category 0 -EntryType Information
Start-Sleep -Seconds 10

#Cycle IME Service
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Restart Microsoft Intune Management Extension Service" -Id 100 -Category 0 -EntryType Information
Get-Service -Name "Microsoft Intune Management Extension" | Restart-Service

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker Pin Process completed, recommended to reboot at next available opportunity." -Id 100 -Category 0 -EntryType Information
Start-ScheduledTask -TaskName "StatusMessage"
Unregister-ScheduledTask -TaskName "StatusMessage" -Confirm:$false -InformationAction SilentlyContinue

<#
#<# Call A Restart # >
if($ForceRestart) {
    shutdown /t 90 /r /c "Your computer will restart shortly to finish configuring BitLocker. Please save your work."
}
#>
# SIG # Begin signature block
# MIInzgYJKoZIhvcNAQcCoIInvzCCJ7sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBZj/Gqy37oA1e5
# bFfCBEPQx2PBzwRGgKF0Lqk09jYFHKCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGZ8wghmbAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAALN82S/+NRMXVEAAAAA
# As0wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKEP
# 6U/jPZFJtDvTucLcTPN+CLDlxVMZ7uEQXIHMcrT9MEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAOlBkYaq7V3xomM+VvXfkK7xDJilpNgBw4nUm
# g8dCFyC4G5QhU8OwOCVnqYydK6Tr7QX1IIVrwV/dnOspo/erhna5bNcqXMVHGX0V
# Zo5dHUFINg+R2/gRxt3WySYsIujn+MHue40boF0FSVzZ4mjuIGuUAo8YO0Riwni7
# u6PVFj+7labIDoLel+b/9AHSF3uAlbGx3mmwklfEErk637EngZVmxvTUG5fE89bp
# mGpWjrvFg+QmlV+WeeQ9bDgM10tWyRaANGNuwxZ2PIBWth+tywBbV8dhRUkbSa/G
# /nj5SnljwpBD9EBenDsN6DAjwjydSMfHp1qDhbrbnOqE4anPrqGCFykwghclBgor
# BgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCAmKFlmv9zXPiPjGm+5L2reeLaEY70n/FEQ
# BBHkSSGRhwIGZBtTgDKfGBMyMDIzMDQxMjIxMTAxOC4yNTRaMASAAgH0oIHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOkQwODItNEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAG6Hz8Z
# 98F1vXwAAQAAAbowDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjIwOTIwMjAyMjE5WhcNMjMxMjE0MjAyMjE5WjCB0jELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpEMDgyLTRCRkQtRUVCQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIhO
# FYMzkjWAE9UVnXF9hRGv0xBRxc+I5Hu3hxVFXyK3u38xusEb0pLkwjgGtDsaLLbr
# lMxqX3tFb/3BgEPEC3L0wX76gD8zHt+wiBV5mq5BWop29qRrgMJKKCPcpQnSjs9B
# /4XMFFvrpdPicZDv43FLgz9fHqMq0LJDw5JAHGDS30TCY9OF43P4d44Z9lE7CaVS
# 2pJMF3L453MXB5yYK/KDbilhERP1jxn2yl+tGCRguIAsMG0oeOhXaw8uSGOhS6AC
# SHb+ebi0038MFHyoTNhKf+SYo4OpSY3xP4+swBBTKDoYP1wH+CfxG6h9fymBJQPQ
# Zaqfl0riiDLjmDunQtH1GD64Air5k9Jdwhq5wLmSWXjyFVL+IDfOpdixJ6f5o+Mh
# E6H4t31w+prygHmd2UHQ657UGx6FNuzwC+SpAHmV76MZYac4uAhTgaP47P2eeS1o
# ckvyhl9ya+9JzPfMkug3xevzFADWiLRMr066EMV7q3JSRAsnCS9GQ08C4FKPbSh8
# OPM33Lng0ffxANnHAAX/DE7cHcx7l9jaV3Acmkj7oqir4Eh2u5YxwiaTE37XaMum
# X2ES3PJ5NBaXq7YdLJwySD+U9pk/tl4dQ1t/Eeo7uDTliOyQkD8I74xpVB0T31/6
# 7KHfkBkFVvy6wye21V+9IC8uSD++RgD3RwtN2kE/AgMBAAGjggFJMIIBRTAdBgNV
# HQ4EFgQUimLm8QMeJa25j9MWeabI2HSvZOUwHwYDVR0jBBgwFoAUn6cVXQBeYl2D
# 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD
# ggIBAF/I8U6hbZhvDcn96nZ6tkbSEjXPvKZ6wroaXcgstEhpgaeEwleLuPXHLzEW
# tuJuYz4eshmhXqFr49lbAcX5SN5/cEsP0xdFayb7U5P94JZd3HjFvpWRNoNBhF3S
# DM0A38sI2H+hjhB/VfX1XcZiei1ROPAyCHcBgHLyQrEu6mnb3HhbIdr8h0Ta7WFy
# lGhLSFW6wmzKusP6aOlmnGSac5NMfla6lRvTYHd28rbbCgfSm1RhTgoZj+W8DTKt
# iEMwubHJ3mIPKmo8xtJIWXPnXq6XKgldrL5cynLMX/0WX65OuWbHV5GTELdfWvGV
# 3DaZrHPUQ/UP31Keqb2xjVCb30LVwgbjIvYS77N1dARkN8F/9pJ1gO4IvZWMwyMl
# KKFGojO1f1wbjSWcA/57tsc+t2blrMWgSNHgzDr01jbPSupRjy3Ht9ZZs4xN02ei
# X3eG297NrtC6l4c/gzn20eqoqWx/uHWxmTgB0F5osBuTHOe77DyEA0uhArGlgKP9
# 1jghgt/OVHoH65g0QqCtgZ+36mnCEg6IOhFoFrCc0fJFGVmb1+17gEe+HRMM7jBk
# 4O06J+IooFrI3e3PJjPrQano/MyE3h+zAuBWGMDRcUlNKCDU7dGnWvH3XWwLrCCI
# cz+3GwRUMsLsDdPW2OVv7v1eEJiMSIZ2P+M7L20Q8aznU4OAMIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB
# 0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
# TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjpEMDgyLTRCRkQtRUVCQTElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAdqNHe113gCJ87aZI
# Ga5QBUqIwvKggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOfhgFIwIhgPMjAyMzA0MTMwMzA5MDZaGA8yMDIzMDQx
# NDAzMDkwNlowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5+GAUgIBADAHAgEAAgIg
# NTAHAgEAAgIRPjAKAgUA5+LR0gIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# AI7fy60cbs7ZqadqeXwCoTVU0B5B5zoywwhpxr/By5gnQTqk2Bn46ZVALRxknhHm
# 9ejt+ZNxGhSXsUyRyk/6VQbFXyqqJmzpchfADN6QKgNTNliwIKmiD8qE8gzEUp7g
# awDAq/0gKUWoA6hXgk2nMVbg9ehXXoVAO5kXZw57yVADMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG6Hz8Z98F1vXwAAQAA
# AbowDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQg3ZGGMqGmDQ5JSoH/tjVbXtrUifWZn6KGMNCsMOuv
# ZnIwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCApVb08M25w+tYGWsmlGtp1
# gy1nPcqWfqgMF3nlWYVzBTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABuh8/GffBdb18AAEAAAG6MCIEIBQLjoingeleRDYAoLHUz8yi
# 0Qzkh2GYVhhhZB03CESFMA0GCSqGSIb3DQEBCwUABIICAEiXg9zeTE1S0gDmMeQy
# 9PkO6kRa4G79MInOLPREo8xBjmzcvPg9X5LDdlXU2scKCyCJPPnLXv74kfRDQq6L
# SEpGI7aPfG8+3iehnyLOGkMM822TokZ1050BkfdqsHvdKzJEi0CjMUULwoFxAg1x
# D8QD/PxUOp3ZWGAWhPszCVJM4Er3vKuLmjYhCnEFCyDJhLwijOuZRw78cXJRBWQf
# yCPUIJiE5VRL+KY3v72N6Dj3LuB88KgknamyuGHxHAJXz8S5bzbK3ILT1NfeN0XN
# 26IspaK02uIK3WuwLgdJgSmC/ghMRLjPq7iL5CxmwW48xJzgT2K21ie/M20Iwn6Z
# /SQ+gCyzBS7wQ9ItMoVvPF7S4K6tCZ8wN413OjRn6vGRDP0ZVpUni3NbCW8FhwgB
# AIgOcAw0/F4DJ/uQ29xI24Bxb1crIxaUumLp6KHkqdPzSs7V1w4uO8VjucFyJf2D
# I3rgmYHBa0ZNtUKFI3vijHsgKqWg0nV//KH83gncmrazrzGl4TC31MzOICRonFnA
# p31g/FeoS00rOPcmJDy4Quz+zCRUiAp6j+TeH5CYjLBG6k/H1JhFCCQ9SU6XuKJx
# uMtTq/MsHGvo1HPF47naRLkLtaCNYxlqtpvdVEbEgO+CxRw1q0VNYvrBOSCoBV4o
# hHSgMYShtRTapolcP0G8bihX
# SIG # End signature block
