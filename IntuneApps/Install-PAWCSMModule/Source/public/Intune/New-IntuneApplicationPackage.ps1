function New-IntuneApplicationPackage {
    <#
    .SYNOPSIS
    This function builds the necessary config scaffold for uploading the new IntuneWin package
    .DESCRIPTION
    This function builds the necessary config scaffold for uploading the new IntuneWin package
    .EXAMPLE
    New-IntuneApplicationPackage
    This function builds the necessary config scaffold for uploading the new IntuneWin package
    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory, ParameterSetName='default')]
        [ValidateSet('PS1','EXE','MSI','Edge')]
        [string] $AppType,

        [Parameter(ParameterSetName='default')]
        [ValidateSet('TAGFILE','FILE','REGTAG')]
        [string] $RuleType,

        [Parameter(ParameterSetName='default')]
        [string] $ReturnCodeType = 'Default',

        [Parameter(ParameterSetName='default')]
        [ValidateSet('System','User')]
        [string] $InstallExperience,

        [Parameter(ParameterSetName='default')]
        [string] $LogoFile,

        [Parameter(ParameterSetName='default')]
        [string] $RequiredGroupName,

        [Parameter(ParameterSetName='default')]
        [string] $AvailableGroupName,

        [Parameter(ParameterSetName='default')]
        [string] $UninstallGroupName,

        [Parameter(Mandatory, ParameterSetName='Manifest')]
        [psobject] $AppManifest
    )

    if ($AppManifest) {
        $AppType = $AppManifest.AppType
        $RuleType = $AppManifest.RuleType
        $ReturnCodeType = $AppManifest.ReturnCodeType
        $InstallExperience = $AppManifest.InstallExperience
        $LogoFile = $AppManifest.LogoFile
        $requiredgroup = $AppManifest.requiredgroup -replace "^(group-)"
        $AvailableGroup = $AppManifest.availablegroup -replace "^(group-)"
        $uninstallgroup = $AppManifest.uninstallgroup -replace "^(group-)"
        $installReqGroup = (Get-MgGroup -Filter "DisplayName eq '$requiredgroup'")
        $installAvailGroup = (Get-MgGroup -Filter "DisplayName eq '$AvailableGroup'")
        $uninstallGroup = ((Get-MgGroup -Filter "DisplayName eq '$uninstallgroup'"))
        $scopetag = $AppManifest.scopetag
    }
    else {
        $installReqGroup = Get-AADGroup -DisplayName $installReqGroup
        $installAvailGroup = Get-AADGroup -DisplayName $installAvailGroup
        $uninstallGroup = Get-AADGroup -DisplayName $uninstallGroup
    }

    if ($null -eq $installReqGroup ){
        Write-Host "$installReqGroup was not found"
        return
   }

    if ($null -eq $installAvailGroup ){
        Write-Host "$installAvailGroup was not found"
        return
    }

    if ($null -eq $uninstallGroup ){
        Write-Host "$uninstallGroup was not found"
        return
    }

    $packageName = $AppManifest.packageName

    if ( $AppType -ne "Edge" ) {
        if ( ( $AppType -eq "PS1" ) -and ( $RuleType -eq "TAGFILE" ) ) {
            Write-Log -Message "Building variables for AppType: $AppType with RuleType: $RuleType"

            if ($installExperience -eq "User") {
                $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install -userInstall"
                $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall -userInstall"
            }
            else {
                $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install"
                $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall"
            }

            Write-Log -Message "installCmdLine: [$installCmdLine]"
            Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
        }
        elseif ( ( $AppType -eq "PS1" ) -and ( $RuleType -eq "REGTAG" ) ) {
            Write-Log -Message "Building variables for AppType: $AppType with RuleType: $RuleType"

            if ($installExperience -eq "User") {
                $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install -userInstall -regTag"
                $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall -userInstall -regTag"
            }
            else {
                $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install -regTag"
                $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall -regTag"
            }

            Write-Log -Message "installCmdLine: [$installCmdLine]"
            Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
        }
        elseif ($AppType -eq "EXE") {
            Write-Log -Message "Building variables for AppType: $AppType"
            #$installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install"
            #$uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall"
            Write-Log -Message "installCmdLine: [$installCmdLine]"
            Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
        }
        elseif ($AppType -eq "MSI") {
            Write-Log -Message "Building variables for AppType: $AppType"
            #$installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install"
            #$uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall"
            Write-Log -Message "installCmdLine: [$installCmdLine]"
            Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
        }

        if ( ( $RuleType -eq "TAGFILE" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
            Write-Log -Message "Building variables for RuleType: $RuleType"
            if ($installExperience -eq "System") {
                Write-Log -Message "Creating TagFile detection rule for System install"
                $FileRule = New-DetectionRule -File -Path "%PROGRAMDATA%\Microsoft\IntuneApps\$PackageName" `
                    -FileOrFolderName "$PackageName.tag" -FileDetectionType exists -check32BitOn64System False
            }
            elseif ($installExperience -eq "User") {
                Write-Log -Message "Creating TagFile detection rule for User install"
                $FileRule = New-DetectionRule -File -Path "%LOCALAPPDATA%\Microsoft\IntuneApps\$PackageName" `
                    -FileOrFolderName "$PackageName.tag" -FileDetectionType exists -check32BitOn64System False
            }
            Write-Log -Message "FileRule: [$FileRule]"

            # Creating Array for detection Rule
            $DetectionRule = @($FileRule)
        }
        elseif ( ( $RuleType -eq "FILE" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
            Write-Log -Message "Building variables for RuleType: $RuleType"
            $fileDetectPath = split-path -parent $FilePath
            $fileDetectFile = split-path -leaf $FilePath
            Write-Log -Message "fileDetectPath: $fileDetectPath"
            Write-Log -Message "fileDetectFile: $fileDetectFile"

            $FileRule = New-DetectionRule -File -Path $fileDetectPath `
                -FileOrFolderName $fileDetectFile -FileDetectionType exists -check32BitOn64System False
            Write-Log -Message "FileRule: [$FileRule]"

            # Creating Array for detection Rule
            $DetectionRule = @($FileRule)
        }
        elseif ( ( $RuleType -eq "REGTAG" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
            Write-Log -Message "Building variables for RuleType: $RuleType"
            if ($installExperience -eq "System") {
                Write-Log -Message "Creating RegTag detection rule for System install"

                $RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$PackageName" `
                    -RegistryDetectionType exists -check32BitRegOn64System True -RegistryValue "Installed"
            }
            elseif ($installExperience -eq "User") {
                Write-Log -Message "Creating RegTag detection rule for User install"

                $RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$PackageName" `
                    -RegistryDetectionType exists -check32BitRegOn64System True -RegistryValue "Installed"
            }

            # Creating Array for detection Rule
            $DetectionRule = @($RegistryRule)
        }
        else {
            Write-Log -Message "Using MSI detection rule"
            $DetectionRule = "MSI"
        }
        if ($ReturnCodeType -eq "DEFAULT") {
            Write-Log -Message "Building variables for ReturnCodeType: $ReturnCodeType"
            $ReturnCodes = Get-DefaultReturnCodes
        }
        $Icon = New-IntuneWin32AppIcon -FilePath "$($AppManifest.packagePath)\$LogoFile"
    }

    $intuneApplication = Get-IntuneApplication -DisplayName $AppManifest.displayName

    #Check if package already exists
    if ( $intuneApplication.Id ) {
        Write-Log -Message "Detected existing package in Intune: $displayName"
        Write-Log -Message "Manual upload of the new IntuneWin package required."
        Write-Log -Message "Upload content: "
        Write-Host "$script:SourceFile" -ForegroundColor Cyan
        return
    }
    else {
        Write-Log -Message "Existing package not found"
    }

    switch ( $AppType ) {
        'PS1' {
            $win32LobParams = @{
                PS1 = $true
                SourceFile = $SourceFile
                publisher = $AppManifest.publisher
                Description = $AppManifest.description
                DetectionRules = $DetectionRule
                ReturnCodes = $ReturnCodes
                DisplayName = $AppManifest.displayName
                PS1InstallCommandLine = $InstallCmdLine
                PS1UninstallCommandLine = $UninstallCmdLine
                InstallExperience = $installExperience
                Logo = $Icon
                Category = $AppManifest.category
            }
            $intuneApplication = Upload-Win32Lob @win32LobParams
        }
        'EXE' {
            $win32LobParams = @{
                EXE = $true
                SourceFile = $SourceFile
                publisher = $AppManifest.publisher
                Description = $AppManifest.description
                DetectionRules = $DetectionRule
                ReturnCodes = $ReturnCodes
                DisplayName = $AppManifest.displayName
                InstallCommandLine = $InstallCmdLine
                UninstallCommandLine = $UninstallCmdLine
                InstallExperience = $installExperience
                Logo = $Icon
                Category = $AppManifest.category
            }
            $intuneApplication = Upload-Win32Lob @win32LobParams
        }
        'MSI' {
            if ( ( ! ( IsNull( $installCmdLine) ) ) -and ( ! ( IsNull( $uninstallCmdLine ) ) ) ) {
                $intuneApplication = Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -msiInstallCommandLine $installCmdLine -msiUninstallCommandLine $uninstallCmdLine -installExperience $installExperience -logo $Icon -Category $Category
            }
            elseif ( ( ! ( IsNull( $installCmdLine ) ) ) -and ( IsNull( $uninstallCmdLine ) ) ) {
                $intuneApplication = Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -msiInstallCommandLine $installCmdLine -installExperience $installExperience -logo $Icon -Category $Category
            }
            elseif ( ( IsNull( $installCmdLine ) ) -and ( ! ( IsNull( $uninstallCmdLine ) ) ) ) {
                $intuneApplication = Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -msiUninstallCommandLine $uninstallCmdLine -installExperience $installExperience -logo $Icon -Category $Category
            }
            elseif ( ( IsNull( $installCmdLine ) ) -and ( IsNull( $uninstallCmdLine ) ) ) {
                $intuneApplication = Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -installExperience $installExperience -logo $Icon -Category $Category
            }
        }
        'Edge' {
            $win32LobParams = @{
                Edge = $true
                Publisher = $AppManifest.publisher
                Description = $AppManifest.description
                DisplayName = $AppManifest.displayName
                Channel = $channel
            }
            $intuneApplication = Upload-Win32Lob @win32LobParams
        }
    }

    $assignment = Set-IntuneApplicationAssignment -ApplicationId $intuneApplication.Id -TargetGroupId $installReqGroup.id   -Intent 'Required'
    $assignment = Set-IntuneApplicationAssignment -ApplicationId $intuneApplication.Id -TargetGroupId $installAvailGroup.id -Intent 'Available'
    $assignment = Set-IntuneApplicationAssignment -ApplicationId $intuneApplication.Id -TargetGroupId $uninstallGroup.id    -Intent 'Uninstall'
    $assignment = Set-IntuneApplicationAssignment -ApplicationId $intuneApplication.Id -TargetGroupId $uninstallGroup.id    -Intent 'Required'  -Exclude
    $assignment = Set-IntuneApplicationAssignment -ApplicationId $intuneApplication.Id -TargetGroupId $uninstallGroup.id    -Intent 'Available' -Exclude

    #Removed requirement. Remove from code after next release 2201
  #  if ( $AppManifest.espApp -eq $true ) {
   #     $espReqGroup = (Get-MgGroup -Filter "DisplayName eq 'PAW-CSM-Devices-Autopilot-GroupTag'")
   #     $assignment = Set-IntuneApplicationAssignment -ApplicationId $intuneApplication.Id -TargetGroupId $espReqGroup.id   -Intent 'Required'
   # }

    set-RBACScopeTag -Application $AppManifest.displayName -scopetag $scopetag

}
# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBi234UhBqUl1RZ
# eFlymtBUYcw+a9taNg8cEQ+8iu5LS6CCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPTz
# MKhVFp5ynZntsRofsHDwVRNQU3lZPFDZ0iRHkRHHMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAMyKpcSgMttC+/LQPHEQGlTvaA2ZI2ACqr7Au
# pgjFqTHn9VeiCbNRiiKna5V60wTw3N9kygQcC6CpFA8R1kRdNdnfinEKqyRIC4Bd
# Q93gf77mvNrDw/AhgeqHda8yAzP165Rdxj+w1R9sVZRjJfdUYIlfuzrE0c5mXU0A
# Bd7X/5Op0fHSpmMOhVO2pnamq6NWRlHdqrSD65ttwX1GomDSJmakxWYwuYjAafZR
# ygUp/I32x+/Fp1/1zgnLKUDj1hD+9aKkTtBwDTm2pxCAhfuiBV92LMRV/5ORBbsp
# kuRzgB0uYEFqTuq2XNLHqBxFkJ08zHDCydQbkDsANsRNK0qnyaGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDQ2sjTzCiKomGZTcl5R9Cs5MpIfpK8U6Ik
# CjDT7J6AygIGZBMoguJFGBMyMDIzMDQxMjIxMTAxNy4zMzRaMASAAgH0oIHQpIHN
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
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEIFeh6y9qO2/UkdFumAipnWmpp1PBMVb8Zb2K
# S1uRHC1VMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQggXXOf1LdUUsQJ3gp
# 2H9gDSMhiQD/zX3hXXzh2Tl2/YEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcn61Y4lIHQCXgABAAAByTAiBCDzEt7P8cPLrK11G/Aq
# cpLT3LzHpsgK4hH6lT+hDARQfjANBgkqhkiG9w0BAQsFAASCAgCeT+oxGLKIHJpx
# ACYML+td6rvbc3vrvk0eqsIabRIkoCl+wHdG9c1ZFlwMQi2FphzPf8GI1Qkprwpg
# A6icTgZMZafCwZpVAmGX9MVj/xxL7tbftJmfVqZZx+Gc7GnvIqer8VTsNTm+q3Qn
# uvJ9M+BB+QLywHK/gWAUbV951FREZnUMJsv3zDUvTRhRzo1ERhhjo+qXLrhjLbUw
# 202rh1i74yG2YZpxU8+zsYYQUjbGKHuSgN1UndFvOcUFPTHbz+jjsLfv2UnZ+jVD
# r86eDpc7HYEbENI2A8i00R/GMgb4VTyVX9ZJu7CW4+vNhEBI9PNAmyqyS7A8v30B
# fjF3jcjCgQbPPTS5Wxd99YBlpjJWX19XYUsqQp6Qvwjnc1Rj6bWVQBGOnNvGix5L
# vn39sMf9WYci5Ggc2WmBqAoFKBTz3WFVKCqGY7+LaB1T3zvixG0x2aM3lDP71yUi
# Q66lYVAj97OE+DIR16yRMxlbqhPX3YYo7oCan8LzlEf1/yGjgprcfVuW4ToO49Ju
# wwACBSuW1T2naln76O/kIY9IbSjU7KFoDwqfLMDGuYbLR5h6tQHw3pVKFYHnVwNT
# mc4GC6NxLIhudPKzwtewWoDrFll+CnyY/4/QBnkVGaIRUZnDqhu6TjCbffKJKCYJ
# VvNGanSDgFptgK7VSpty8TH5236V+w==
# SIG # End signature block
