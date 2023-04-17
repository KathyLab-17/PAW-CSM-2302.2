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
#$SchTaskNameBckgW = "BLTOOL-BCKGWTCH"
$SchTaskNameBDEPINReset = "BDE-PIN_Reset"

$ScriptRemoveFiles = $false
$ForceRemove = $false
#$ForceRestart=$true
#$ForceRestart=$false


<# Create Event Log #>
Try {
	New-Eventlog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
}
Catch {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Event log already exists."  -Id 100 -Category 0 -EntryType Information
}

<# Announce Our Presence #>
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Background Watcher Process is running!"  -Id 100 -Category 0 -EntryType Information


<# Figure Out Where the Script Root Is #>
$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

# Create Source Path
If ($OSArchitecture -like '64*') { $ScriptRootLocation = "$env:ProgramFiles$ProgramFilesPathTail" } else { $ScriptRootLocation = "${env:ProgramFiles(x86)}$ProgramFilesPathTail" }
if ($ForceScriptRootPath) { $ScriptRootLocation = "$ForceScriptRootPath$ProgramFilesPathTail" }

<# Get the Key #>
try {
	$AesKey = Get-Content "$ScriptRootLocation\AES.key" # <TODO>
}
catch {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Could not find encryption key, check install directory. Exiting") -Id 100 -Category 0 -EntryType Information
	exit
}

<#
#Check if the skip flag is present
$SkipImplementKeyValue = (Get-ItemProperty -Path $RegistrySavePath -Name $SkipKeyName).SkipImplement

if ($SkipImplementKeyValue -eq "1") {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Skip flag has been set outside of script. Exiting") -Id 100 -Category 0 -EntryType Information
	exit
}
#>

<# Check present state of FVE #>
$WmiSystemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive

$BitlockerSystemDrive = (Get-BitLockerVolume -MountPoint $WmiSystemDrive)

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Detected system drive $WmiSystemDrive is protected ? " + [bool]$BitlockerSystemDrive.ProtectionStatus )  -Id 100 -Category 0 -EntryType Information

$RegistryFveUseTpmPin = [int](Get-ItemProperty -Path $RegistryFveLocation -Name "UseTPMPIN").UseTpmPin

if ( ($RegistryFveUseTpmPin -eq 1) -or ($RegistryFveUseTpmPin -eq 2) ) { $RegistryPrebootPinRequired = $true } else { $RegistryPrebootPinRequired = $false }

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Registry settings require Pin? $RegistryPrebootPinRequired"  -Id 100 -Category 0 -EntryType Information

<#
if ( ([bool]$BitlockerSystemDrive.ProtectionStatus) -and ($BitlockerSystemDrive.KeyProtector | Select-Object -ExpandProperty KeyProtectorType).Contains("TpmPin")) {
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker is enabled, and has a preboot PIN configured. Exiting"  -Id 100 -Category 0 -EntryType Information
    exit
}
#>

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker requires configuration, continuing"  -Id 100 -Category 0 -EntryType Information

<# Validate the device type and state #>
$WmiWin32ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem

if ( ($WmiWin32ComputerSystem.PCSystemType -eq 2) -and ($WmiWin32ComputerSystem.PCSystemTypeEx -eq 8) ) {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Device reports it is a Slate/Tablet (PcSystemType 2 + PcSystemTypeEx 8)"  -Id 100 -Category 0 -EntryType Information

	New-ItemProperty -Path $RegistryFveLocation -Name OSEnablePrebootInputProtectorsOnSlates -PropertyType DWORD -Value 1 -Force

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Set OSEnablePrebootInputProtectorsOnSlates to 1"  -Id 100 -Category 0 -EntryType Information
}

#$RegistryCsEnabled = [bool](Get-ItemProperty -Path $RegistryConnectedStbyLocation -Name "CsEnabled").CsEnabled

<# Figure Out Who Is Logged On #>
$WmiUsername = (Get-WmiObject -Class Win32_ComputerSystem).Username

<# If there is no logged on user, stop. Could be RDP User #>
if ($null -eq $WmiUsername) {
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
$SystemKeyPath = ("HKU:\S-1-5-18\$RegistrySavePath")


<# Check if the registry location exists #>
if (Test-Path $UserKeyPath) {

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User PIN Present in registry, processing" -Id 100 -Category 0 -EntryType Information
	<# Get the value set in registry #>
	$SecureString = (Get-ItemProperty -Path $UserKeyPath -Name $RegistryKeyName).UserSecureString | ConvertTo-SecureString -Key $AesKey

}
ElseIf (Test-Path $SystemKeyPath) {

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "System PIN present in registry, processing" -Id 100 -Category 0 -EntryType Information
	<# Get the value set in registry #>
	$SecureString = (Get-ItemProperty -Path $SystemKeyPath -Name $RegistryKeyName).UserSecureString | ConvertTo-SecureString -Key $AesKey

	#region Remove existing PIN protector and replace with TPMOnly
	Foreach ($protector in $BitlockerSystemDrive.KeyProtector) {
		If ($protector.KeyProtectorType -eq "TpmPin") {
			Write-Host "ProtectorType: $($protector.KeyProtectorType)"
			Write-Host "ID: $($protector.KeyProtectorId)"

			Remove-BitlockerKeyProtector -MountPoint $WmiSystemDrive -KeyProtectorId $protector.KeyProtectorId
			Add-BitLockerProtector -MountPoint $WmiSystemDrive -TpmProtector
		}
	}
	#endregion Remove PIN protector and replace with TPMOnly

}
ElseIf (!(Test-Path $UserKeyPath)) {

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User PIN not present in registry, exiting" -Id 100 -Category 0 -EntryType Information

	# Nothing has been set, exit
	exit

}


Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Preparing to configure BitLocker" -Id 100 -Category 0 -EntryType Information

if ( !([bool]$BitlockerSystemDrive.ProtectionStatus) ) {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker is not enabled for the target drive, enabling it with TpmAndPin" -Id 100 -Category 0 -EntryType Information

	try {
		Enable-BitLocker -MountPoint $WmiSystemDrive -EncryptionMethod XtsAes128 -UsedSpaceOnly -TpmAndPinProtector -Pin $SecureString -ErrorAction Stop -SkipHardwareTest -WarningAction SilentlyContinue
	}
	catch {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Crticial Failure Enabling BitLocker: " + $Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
		$NotComplete = $true
	}

}
else {

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Bitlocker is enabled, Adding Bitlocker Key Protector to Drive" -Id 100 -Category 0 -EntryType Information
	try {
		Add-BitLockerKeyProtector -MountPoint $WmiSystemDrive -Pin $SecureString -TpmAndPinProtector -ErrorAction Stop -WarningAction SilentlyContinue
	}
	catch {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Crticial Failure Adding Key Protector: " + $Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
		$NotComplete = $true
	}
}

<# Check for recovery keys on the drive, create if not present, and backup all found #>

$RecoveryPasswords = Get-BitLockerVolume -MountPoint $WmiSystemDrive | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'

if (!$RecoveryPasswords) {
	try {
		Add-BitLockerKeyProtector -MountPoint $WmiSystemDrive -RecoveryPasswordProtector -ErrorAction Stop -WarningAction SilentlyContinue
		$RecoveryPasswords = Get-BitLockerVolume -MountPoint C: | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'
	}
	catch {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Crticial Failure Creating RecoveryPassword: " + $Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
		$NotComplete = $true
	}
}
# In case there are multiple recovery passwords, lets copy them all just to make it sure.
foreach ($RecoveryPassword in $RecoveryPasswords) {
	try {
		BackupToAAD-BitLockerKeyProtector -MountPoint $WmiSystemDrive -KeyProtectorId $RecoveryPassword.KeyProtectorId -ErrorAction Stop -WarningAction SilentlyContinue
	}
	catch {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Critical Failure Uploading Key Protector:" + $Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
		$NotComplete = $true
	}
}


$BitlockerSystemDrive = (Get-BitLockerVolume -MountPoint $WmiSystemDrive)
if ( !($BitlockerSystemDrive.KeyProtector | Select-Object -ExpandProperty KeyProtectorType).Contains("TpmPin")) {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Something went wrong enabling the PIN. Exiting"  -Id 100 -Category 0 -EntryType Information
	exit
}


########################################################################################################################################################## DO BITLOCKER TO IT

<# If not complete flag, don't let tidyup run and keep ticking background worker #>
if ($NotComplete -and !($ForceRemove)) {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Configuration did not complete, Scheduled Tasks Disabled, Script Stopped. Artefacts have not been cleared" -Id 100 -Category 0 -EntryType Error
	exit
}

If (Get-ScheduledTask | ? { $_.TaskName -eq $SchTaskNamePrompt }) {

	<# Stop Scheduled Task #>
	#Disable-ScheduledTask -TaskName $SchTaskNameBckgW -InformationAction SilentlyContinue
	Disable-ScheduledTask -TaskName $SchTaskNamePrompt -InformationAction SilentlyContinue

	<# Remove Scheduled Task #>
	#Unregister-ScheduledTask -TaskName $SchTaskNameBckgW -Confirm:$false -InformationAction SilentlyContinue
	Unregister-ScheduledTask -TaskName $SchTaskNamePrompt -Confirm:$false -InformationAction SilentlyContinue
	$errormsgs = $error | out-string
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Errors detected: `n$errormsgs" -Id 100 -Category 0 -EntryType Information

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Scheduled Task" -Id 100 -Category 0 -EntryType Information
}

<# Clean Up after initial run #>
if (Test-Path $UserKeyPath) {
	Remove-Item -Path $UserKeyPath -Force
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Registry" -Id 100 -Category 0 -EntryType Information

	# Create BDE-Pin Reset scheduled task
	Register-ScheduledTask -Xml (get-content "$PSScriptRoot\BDEPINReset.xml" | out-string) -TaskName $SchTaskNameBDEPINReset -Force
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created $SchTaskNameBDEPINReset Scheduled Task"  -Id 100 -Category 0 -EntryType Information

	# Replace UserInteract-EnterBitlockerPin.ps1 with the one that calls the above scheduled task
	Rename-Item -Path "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1" -NewName "$ScriptRootLocation\UserInteract-EnterBitlockerPinInitial.ps1"
	Rename-Item -Path "$ScriptRootLocation\Invoke-BDEPINReset.ps1" -NewName "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1"

	if ($ScriptRemoveFiles -or $ForceRemove) {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removing shortcut files" -Id 100 -Category 0 -EntryType Information
		<# Remove Shortcuts from User Desktop #>
		$UserDirectories = Get-ChildItem -Path "C:\Users"

		foreach ($User in $UserDirectories) {
			$shortcut = $User.FullName + "\Desktop\Set BitLocker Pin.lnk"
			Remove-Item -Path $shortcut -Force
			Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removed $shortcut" -Id 100 -Category 0 -EntryType Information
		}

		<# Remove Key #>
		Remove-Item -Path "$ScriptRootLocation\AES.key" -Force
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removed Key" -Id 100 -Category 0 -EntryType Information

		<# Clearing Folder #>
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleanup source folder" -Id 100 -Category 0 -EntryType Information
		If (((get-item $PSScriptRoot ).parent.EnumerateDirectories() | Measure-Object).Count -gt 1) {
			Write-Host "More folders found in parent path, do not remove parent folder."

			Remove-Item -Path $PSScriptRoot -Recurse
			Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Deleted Self Folder only" -Id 100 -Category 0 -EntryType Information
		}
		Else {
			Write-Host "Only script folder found in parent path, remove parent folder and child items"

			#$ScriptRootLocation.Substring(0, $ScriptRootLocation.LastIndexOf('\'))
			Remove-Item -Path ($ScriptRootLocation.Substring(0, $ScriptRootLocation.LastIndexOf('\'))) -Recurse
			Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Deleted Self & Root Folder" -Id 100 -Category 0 -EntryType Information
		}

	}

	#region Check for Windows Updates
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Run check for Windows Updates." -Id 100 -Category 0 -EntryType Information
	$command = 'usoclient.exe'
	$workDir = "$env:SystemRoot\system32"
	$ArgumentList = 'startinteractivescan'

	Try {
		Start-Process -FilePath $command -ArgumentList $ArgumentList -WorkingDirectory $workDir -Wait -WindowStyle Hidden -ErrorAction Stop
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Initiated check for Windows Updates." -Id 100 -Category 0 -EntryType Information
	}
	Catch {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Error running command: $($_.Exception.message)" -Id 100 -Category 0 -EntryType Information
		Write-Warning "Error: $($_.Exception.message)"
		#Exit
	}
	Finally {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Finished initiating check for Windows Updates." -Id 100 -Category 0 -EntryType Information
	}
	#endregion Check for Windows Updates

	#Force Intune Device Sync
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Force Intune Device Sync" -Id 100 -Category 0 -EntryType Information
	Get-ScheduledTask | ? { $_.TaskName -eq 'PushLaunch' } | Start-ScheduledTask

	#Pause for 10 seconds
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Pause for 10 seconds" -Id 100 -Category 0 -EntryType Information
	Start-Sleep -Seconds 10

	#Cycle IME Service
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Restart Microsoft Intune Management Extension Service" -Id 100 -Category 0 -EntryType Information
	Get-Service -Name "Microsoft Intune Management Extension" | Restart-Service
}

<# Clean Up after PIN reset #>
if (Test-Path $SystemKeyPath) {
	Remove-Item -Path $SystemKeyPath -Force
}

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker Pin Process completed, recommended to reboot at next available opportunity." -Id 100 -Category 0 -EntryType Information
Start-ScheduledTask -TaskName "StatusMessage"
# not removing this now, as it will be required when a PIN reset is used
#Unregister-ScheduledTask -TaskName "StatusMessage" -Confirm:$false -InformationAction SilentlyContinue

<#
#<# Call A Restart # >
if($ForceRestart) {
    shutdown /t 90 /r /c "Your computer will restart shortly to finish configuring BitLocker. Please save your work."
}
#>
# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDfSNEmGJ7NiWuz
# xWc38o2NOOu2Vn0LI1I2p9rQCh39/6CCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKmz
# onV2+rCJJ7Eh5SdZpM1BaoNcs5n1/V1uxVqNtRYWMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAf2y5lRnrp+5f0BLBaSUoUeV0ID6juJ+9RAHa
# uD4WWOi1PSyxaM5Ndi5RmPwPgrp0+K3j2tDt6rYb0Q0xIYjX+mcWJYX+XTfK0JZ3
# 5BYNAFJUkbnpyKNBXs3N9payBf/e5WqkJFD3e7a59g980mlZGANI1+mWKjxbHnQ/
# n7NVhDWUd+a40OyRFoQKroIZuXfBZgaGYrI0qKINjxOHwc+VXk60FMGGJ9t0QmcX
# +PGi32yg6EyA++7naBSolJeMOC97mmIhm23pAR9pEUCbSHNt7TbEYgQl6jssqJhp
# m+60nHGg7t2dn0zDq3LIjbxAAj/Zcnw1tYCmz+GVuWT+zsrrnaGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCBadnGJUyHnwLxYxz8NbEHTPxjiMfeDDtoh
# CtKLMRXgpQIGZBMoguJNGBMyMDIzMDQxMjIxMTAxOC43ODFaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAAByfrVjiUgdAJeAAEA
# AAHJMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEzOFoXDTI0MDIwMjE5MDEzOFowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNFN0EtRTM1
# OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1nLi5Y5vz8K+Woxhk7qGW/vC
# xi5euTM01TiEbFOG8g7SFB0VMjYgo6TiRzgOQ+CN53OBOKlyMHWzRL4xvaS03ZlI
# getIILYiASogsEtljzElRHO7fDGDFWcdz+lCNYmJoztbG3PMrnxblUHHUkr4C7EB
# Hb2Y07Gd5GJBgP8+5AZNsTlsHGczHs45mmP7rUgcMn//c8Q/GYSqdT4OXELp53h9
# 9EnyF4zcsd2ZFjxdj1lP8QGwZZS4F82JBGe2pCrSakyFjTxzFKUOwcQerwBR/YaQ
# ly7mtCra4PNcyEQm+n/LDce/VViQa8OM2nBZHKw6CyMqEzFJJy5Hizz8Z6xrqqLK
# ti8viJUQ0FtqkTXSR3//w8PAKyBlvIYTFF/Ly3Jh3cbVeOgSmubOVwv8nMehcQb2
# AtxcU/ldyEUqy8/thEHIWNabzHXx5O9D4btS6oJdgLmHxrTBtGscVQqx0z5/fUIk
# LE7tbwfoq84cF/URLEyw3q57KV2U4gOhc356XYEVQdJXo6VFWBQDYbzanQ25zY21
# UCkj821CyD90gqrO3rQPlcQo6erwW2DF2fsmgAbVqzQsz6Rkmafz4re17km7qe09
# PuwHw5e3x5ZIGEoVlfNnJv6+851uwKX6ApZFxPzeQo7W/5BtaTmkZEhwY5AdCPgP
# v0aaIEQn2qF7MvFwCcsCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQFb51nRsI8ob54
# OhTFeVF7RC4yyzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQA2qLqcZt9HikIHcj7AlnHhjouxSjOeBaTE+EK8aXcV
# Lm9cA8D2/ZY2OUpYvOdhuDEV9hElVmzopiJuk/xBYh6dWJTRhmS7hVjrGtqzSFW0
# LffsRysjxkpuqyhHiBDxMXMGZ6GdzUfqVP2Zd2O+J/BYQJgs9NHYz/CM4XaRP+T2
# VM3JE1mSO1qLa+mfB427QiLj/JC7TUYgh4RY+oLMFVuQJZvXYl/jITFfUppJoAak
# Br0Vc2r1kP5DiJaNvZWJ/cuYaiWQ4k9xpw6wGz3qq7xAWnlGzsawwFhjtwq5EH/s
# 37LCfehyuCw8ZRJ9W3tgSFepAVM7sUE+Pr3Uu+iPvBV4TsTDNFL0CVIPX+1XOJ6Y
# RGYJ2kHGpoGc/5sgA2IKQcl97ZDYJIqixgwKNftyN70O0ATbpTVhsbN01FVli0H+
# vgcGhyzk6jpAywHPDSQ/xoEeGU4+6PFTXMRO/fMzGcUcf0ZHqZMm0UhoH8tOtk18
# k6B75KJXTtY3ZM7pTfurSv2Qrv5zzCBiyystOPw/IJI+k9opTgatrC39L69/Kwyt
# D0x7t0jmTXtlLZaGvoSljdyyr6QDRVkqsCaLUSSsAiWeav5qg64U3mLmeeko0E9T
# J5yztN/jcizlHx0XsgOuN6sub3CPV7AAMMiKopdQYqiPXu9IxvqXT7CE/SMC2pcN
# yTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
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
# CxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEyNUQxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAH3pi8v+HgGb
# jVQs4G36dRxWBt0OoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDn4T2/MCIYDzIwMjMwNDEyMjIyNTAzWhgPMjAy
# MzA0MTMyMjI1MDNaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOfhPb8CAQAwBwIB
# AAICHI4wBwIBAAICEa4wCgIFAOfijz8CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQAbHQyi3+nhVbo/73AskYh65mBH5pD24psoKqZJoZVEkUDpXNWfG+xQIJeo
# DQGh2tvwCg84iVRrx5N/FIZAmyJ9jkrKjtQVEDOJjnTK+d1jdzIEFZCK6zhjUNXA
# vryjqFw6YqIvHuuK7dWUB85PJvDUR588paj/DIzY1iOV0NqjHTGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAByfrVjiUgdAJe
# AAEAAAHJMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEIAwQvypWw3uLb9o++JBnqS2A1yWoXg/PrOPG
# Pd7unh8cMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQggXXOf1LdUUsQJ3gp
# 2H9gDSMhiQD/zX3hXXzh2Tl2/YEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcn61Y4lIHQCXgABAAAByTAiBCDzEt7P8cPLrK11G/Aq
# cpLT3LzHpsgK4hH6lT+hDARQfjANBgkqhkiG9w0BAQsFAASCAgCi850AyAdWwihB
# 69PD4/X3VKTP7ctYJWCokwmFFmzsb7Pl+GwpmJG35avg10Fva1sP7FBjeHxgSDnQ
# 6r8XepUrFis5ys4AbYQsI6TdCVxegJo1NU/GGol7NdSttpV9mQ+GQkAsdDqPBanT
# 9kZ22JV3ZghBnjSLc3/Bd1sKfrm6Rj7PqJhAHXmgVtkszSSHGMTt7jAAmfKUti3Y
# emI8q4JrxXYj9f2nwiwLS3uT3L1s3TCOtsGIhBAfwhoozulKcob1og5UZylD2oxk
# s9Hif3/cgq9MlTyxStsFHRarke6AdgvUKoQJ87KRQuWlMkwOUBEutMVaOPrFWAUS
# AblsQcHBssvoVfr5BUIrarynqWWYLrG7EoJ4/ZNQbzHEqXSzGy3tLUHN+XJZVKzW
# iy9iAsfFvdgFeq+dOvVSktrfNiGOg7JlaDUTn4qGTmxmYMgEiG2QJudyoYhYKy8y
# uzhLzAJJHurD4halLJiIBvZpRVSCQtIMbVRKePkyjzmXdwjIZ8R08DQDrmMOBgOb
# 1pCAKSj+mol/m8qrCd552Cn6ogWaMGcb9UywywDyL/wWO4D8j8I2QvUPVrqEWkMY
# ZMqbcBYMrhDUshElDROXmrbuz7JwBSWT30LVx+gXjh/fS7eruXcGuWMQbXpm6sI3
# hoE9KBaRDKmdPufJL9aFL4OdWJQFWQ==
# SIG # End signature block
