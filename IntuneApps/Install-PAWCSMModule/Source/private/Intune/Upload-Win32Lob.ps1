function Upload-Win32Lob {
    <#
    .SYNOPSIS
    This function is used to upload a Win32 Application to the Intune Service
    .DESCRIPTION
    This function is used to upload a Win32 Application to the Intune Service
    .EXAMPLE
    Upload-Win32Lob "C:\Packages\package.intunewin" -publisher "Microsoft" -description "Package"
    This example uses all parameters required to add an intunewin File into the Intune Service
    #>

    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ParameterSetName = "MSI", Position = 1)]
        [Switch] $MSI,

        [parameter(Mandatory, ParameterSetName = "EXE", Position = 1)]
        [Switch] $EXE,

        [parameter(Mandatory, ParameterSetName = "PS1", Position = 1)]
        [Switch] $PS1,

        [parameter(Mandatory, ParameterSetName = "Edge", Position = 1)]
        [Switch] $Edge,

        [parameter(Mandatory, ParameterSetName = "MSI", Position = 1)]
        [parameter(Mandatory, ParameterSetName = "EXE", Position = 1)]
        [parameter(Mandatory, ParameterSetName = "PS1", Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $SourceFile,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $displayName,

        [parameter(Mandatory, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $publisher,

        [parameter(Mandatory, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $description,

        [parameter(Mandatory, ParameterSetName = "MSI", Position = 4)]
        [parameter(Mandatory, ParameterSetName = "EXE", Position = 4)]
        [parameter(Mandatory, ParameterSetName = "PS1", Position = 4)]
        [ValidateNotNullOrEmpty()]
        $detectionRules,

        [parameter(Mandatory, ParameterSetName = "MSI", Position = 5)]
        [parameter(Mandatory, ParameterSetName = "EXE", Position = 5)]
        [parameter(Mandatory, ParameterSetName = "PS1", Position = 5)]
        [ValidateNotNullOrEmpty()]
        $returnCodes,

        [parameter(ParameterSetName = "MSI", Position = 6)]
        [parameter(ParameterSetName = "EXE", Position = 6)]
        [parameter(ParameterSetName = "PS1", Position = 6)]
        [ValidateSet('system', 'user')]
        [string] $installExperience = "system",

        [parameter(Mandatory, ParameterSetName = "MSI", Position = 7)]
        [parameter(Mandatory, ParameterSetName = "EXE", Position = 7)]
        [parameter(Mandatory, ParameterSetName = "PS1", Position = 7)]
        [ValidateNotNullOrEmpty()]
        $logo,

        [parameter(Mandatory, ParameterSetName = "MSI", Position = 8)]
        [parameter(Mandatory, ParameterSetName = "EXE", Position = 8)]
        [parameter(Mandatory, ParameterSetName = "PS1", Position = 8)]
        [ValidateNotNullOrEmpty()]
        [string] $Category,

        [parameter(Mandatory, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string] $installCommandLine,

        [parameter(Mandatory, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string] $uninstallCommandLine,

        [parameter(Mandatory, ParameterSetName = "PS1")]
        [ValidateNotNullOrEmpty()]
        [string] $ps1InstallCommandLine,

        [parameter(Mandatory, ParameterSetName = "PS1")]
        [ValidateNotNullOrEmpty()]
        [string] $ps1UninstallCommandLine,

        [parameter(ParameterSetName = "MSI")]
        [string] $msiInstallCommandLine,

        [parameter(ParameterSetName = "MSI")]
        [string] $msiUninstallCommandLine,

        [parameter(ParameterSetName = "Edge")]
        [string] $channel,

        [parameter()]
        [int] $sleep = 20
    )

    try	{
        $LOBType = "microsoft.graph.win32LobApp"
        Write-Host '    Creating: JSON data to pass to the service' -ForegroundColor Yellow

        if ( $AppType -ne "Edge" ) {
            Test-SourceFile "$SourceFile"

            $DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

            if ($displayName) {
                $DisplayName = $displayName
            }
            else {
                $DisplayName = $DetectionXML.ApplicationInfo.Name
            }

            $FileName = $DetectionXML.ApplicationInfo.FileName

            $SetupFileName = $DetectionXML.ApplicationInfo.SetupFile
        }
        if ($MSI) {
            $MsiExecutionContext = $DetectionXML.ApplicationInfo.MsiInfo.MsiExecutionContext
            $MsiPackageType = "DualPurpose"
            if ($MsiExecutionContext -eq "System") {
                $MsiPackageType = "PerMachine"
            }
            elseif ($MsiExecutionContext -eq "User") {
                $MsiPackageType = "PerUser"
            }

            $MsiProductCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode
            $MsiProductVersion = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion
            $MsiPublisher = $DetectionXML.ApplicationInfo.MsiInfo.MsiPublisher
            $MsiRequiresReboot = $DetectionXML.ApplicationInfo.MsiInfo.MsiRequiresReboot
            $MsiUpgradeCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiUpgradeCode

            if ($MsiRequiresReboot -eq "false") { $MsiRequiresReboot = $false }
            elseif ($MsiRequiresReboot -eq "true") { $MsiRequiresReboot = $true }

            $MSIRule = New-DetectionRule -MSI -MSIproductCode $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode

            # Creating Array for detection Rule
            $detectionRules = @($MSIRule)

            if ( ! ($null -eq $msiInstallCommandLine ) ) {
                $mobileAppBody = GetWin32AppBody `
                    -MSI `
                    -displayName $DisplayName `
                    -publisher $publisher `
                    -description $description `
                    -category $Category `
                    -filename $FileName `
                    -SetupFileName $SetupFileName `
                    -installExperience $installExperience `
                    -MsiPackageType $MsiPackageType `
                    -MsiProductCode $MsiProductCode `
                    -MsiProductName $displayName `
                    -MsiProductVersion $MsiProductVersion `
                    -MsiPublisher $MsiPublisher `
                    -MsiRequiresReboot $MsiRequiresReboot `
                    -MsiUpgradeCode $MsiUpgradeCode `
                    -logo $logo `
                    -msiInstallCommandLine $msiInstallCommandLine `
                    -msiUninstallCommandLine $msiUninstallCommandLine
            }
            else {
                $mobileAppBody = GetWin32AppBody `
                    -MSI `
                    -displayName $DisplayName `
                    -publisher $publisher `
                    -description $description `
                    -category $Category `
                    -filename $FileName `
                    -SetupFileName $SetupFileName `
                    -installExperience $installExperience `
                    -MsiPackageType $MsiPackageType `
                    -MsiProductCode $MsiProductCode `
                    -MsiProductName $displayName `
                    -MsiProductVersion $MsiProductVersion `
                    -MsiPublisher $MsiPublisher `
                    -MsiRequiresReboot $MsiRequiresReboot `
                    -MsiUpgradeCode $MsiUpgradeCode `
                    -logo $logo
            }
        }
        elseif ($EXE) {
            $mobileAppBody = GetWin32AppBody -EXE -displayName $DisplayName -publisher $publisher `
                -description $description -category $Category -filename $FileName -SetupFileName $SetupFileName `
                -installExperience $installExperience -logo $logo `
                -installCommandLine $installCommandLine -uninstallCommandLine $uninstallCommandLine
        }
        elseif ($PS1) {
            $mobileAppBody = GetWin32AppBody -EXE -displayName $DisplayName -publisher $publisher `
                -description $description -category $Category -filename $FileName -SetupFileName $SetupFileName `
                -installExperience $installExperience -logo $logo `
                -installCommandLine $ps1InstallCommandLine -uninstallCommandLine $ps1UninstallCommandLine
        }
        elseIf ($Edge) {
            Write-Host "Creating Edge ODATA construct" -ForegroundColor Yellow

            #$Publisher = 'Microsoft'
            #$Description = 'Microsoft Edge is the browser for business with modern and legacy web compatibility, new privacy features such as Tracking prevention, and built-in productivity tools such as enterprise-grade PDF support and access to Office and corporate search right from a new tab.'
            #$displayName = 'Microsoft Edge Stable1'
            #$channel = 'stable'

            $mobileAppBody = GetWin32AppBody -Edge -displayName "$DisplayName" -publisher "$publisher" `
                -description $description -channel $channel

            $mobileApp = MakeRequest "POST" "mobileApps" ($mobileAppBody | ConvertTo-Json)
            return
        }
        if ($detectionRules.'@odata.type' -contains "#microsoft.graph.win32LobAppPowerShellScriptDetection" -and @($detectionRules).'@odata.type'.Count -gt 1) {

            Write-Warning "A Detection Rule can either be 'Manually configure detection rules' or 'Use a custom detection script'"
            Write-Warning "It can't include both..."
            break
        }
        else {
            $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'detectionRules' -Value $detectionRules
        }

        if ($returnCodes) {
            $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'returnCodes' -Value @($returnCodes)
        }
        else {
            Write-Warning "Intunewin file requires ReturnCodes to be specified"
            Write-Warning "If you want to use the default ReturnCode run 'Get-DefaultReturnCodes'"
            break
        }

        Write-Host '    Creating: Application in Intune' -ForegroundColor Yellow
        $mobileApp = MakeRequest "POST" "mobileApps" ($mobileAppBody | ConvertTo-Json)

        # Get the content version for the new app (this will always be 1 until the new app is committed).
        $appId = $mobileApp.id
        $contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions"
        $contentVersion = MakeRequest "POST" $contentVersionUri "{}"


        Write-Host '    Getting: Encryption Information for sourceFile' -ForegroundColor Yellow

        ### IMPORTANT ### The keys in the hash table are case sensitive
        $fileEncryptionInfo = @{
            'fileEncryptionInfo' =  @{
                encryptionKey = $DetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
                macKey = $DetectionXML.ApplicationInfo.EncryptionInfo.macKey
                initializationVector = $DetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
                mac = $DetectionXML.ApplicationInfo.EncryptionInfo.mac
                profileIdentifier = "ProfileVersion1"
                fileDigest = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
                fileDigestAlgorithm = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm
            }
        }

        # Extracting encrypted file
        $IntuneWinFile = Get-IntuneWinFile "$SourceFile" -fileName "$filename"

        [int64] $Size = $DetectionXML.ApplicationInfo.UnencryptedContentSize
        $EncrySize = (Get-Item "$IntuneWinFile").Length

        # Create a new file for the app.
        Write-Host '    Creating: New file entry in Azure for the upload' -ForegroundColor Yellow
        $contentVersionId = $contentVersion.id
        $fileBody  = @{
            "@odata.type" = "#microsoft.graph.mobileAppContentFile"
            name = $FileName
            size = $size
            sizeEncrypted = $EncrySize
            manifest = $null
            isDependency = $false
        }

        $filesUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files"
        $file = MakeRequest "POST" $filesUri ($fileBody | ConvertTo-Json)

        # Wait for the service to process the new file request.
        Write-Host '    Waiting for the file entry URI to be created' -ForegroundColor Yellow
        $fileId = $file.id
        $fileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId"
        $file = WaitForFileProcessing $fileUri "AzureStorageUriRequest"

        # Upload the content to Azure Storage.
        Write-Host '    Uploading: File to Azure Storage' -f Yellow

        $response = UploadFileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri

        # Need to Add removal of IntuneWin file
        #$IntuneWinFolder = [System.IO.Path]::GetDirectoryName("$IntuneWinFile")
        Remove-Item "$IntuneWinFile" -Force

        # Commit the file.
        Write-Host '    Committing: File into Azure Storage' -ForegroundColor Yellow
        $commitFileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit"
        $response = MakeRequest "POST" $commitFileUri ($fileEncryptionInfo | ConvertTo-Json)

        # Wait for the service to process the commit file request.
        Write-Host '    Waiting: Service to process the commit file request' -ForegroundColor Yellow
        $file = WaitForFileProcessing $fileUri "CommitFile"

        # Commit the app.
        Write-Host '    Committing: File into Azure Storage' -ForegroundColor Yellow
        $commitAppUri = "mobileApps/$appId"
        $commitAppBody = GetAppCommitBody $contentVersionId $LOBType
        $response = MakeRequest "PATCH" $commitAppUri ($commitAppBody | ConvertTo-Json)

        Write-Host "    Sleeping: $sleep seconds to allow package upload completion" -f Magenta
        Start-Sleep -Seconds $sleep

        $mobileApp
    }
    catch {
        Write-Host -ForegroundColor Red "Aborting with exception: $($_.Exception.ToString())"
        throw
    }
}

# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAVtmxKccPGVObR
# ZXTAn83H0+0dztiM3xfWq8t3CSOSg6CCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEtG
# vU5VtqB6/e7eUUsRJap4XJgdEV5pQClq+hE7hIDsMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAneCZBF2D9VZHCahu1Fws24RLEWKMRJAWWpdj
# XkBBPXjqLCrwJ2LHWe/FYaeXwpOKrUjVOMRSWbSHv4zhZDzFhtTyKxGYXLiVwfCi
# r5Re3Uk+3fd/7d+QiUpapsWtvgjT6ITW9+bsyGMEWFCJ/Gsxi7oo9iM0/P3Y8HUz
# EvSoK9Ma9ujbwUl/eZjDxWAp9AYk5KoHA1ajPuIfKteSVhn3a2WykncEX4CZJAg0
# oKd0Y93OyO4Lgdv4MTXx0Rqqc6trXRcB/BCg8dHYAtLgTqWbG+JJTkZIhO4EBtxc
# EQwOGcxLtR3KXDqQkXy3a3rWxrh8TYE22O8VIFvkAUR/S/IvKaGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCAYiLi26A/tuzql9uVxxsGQtzAL600zsNhJ
# YpWElvYRMAIGZBMoguLHGBMyMDIzMDQxMjIxMTAyMS44NThaMASAAgH0oIHQpIHN
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
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEIJACQQT9YPhpuaYzBxmH/PWP8RA5XngaLHFp
# uzNREfw8MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQggXXOf1LdUUsQJ3gp
# 2H9gDSMhiQD/zX3hXXzh2Tl2/YEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcn61Y4lIHQCXgABAAAByTAiBCDzEt7P8cPLrK11G/Aq
# cpLT3LzHpsgK4hH6lT+hDARQfjANBgkqhkiG9w0BAQsFAASCAgAW7ToWygx4m67T
# WYUgiecddOYV7ZuvFetkSC6pZk2sa84+j4ozCUHoOr/cXoaSl8URPjzcaoWAYbgi
# h5fTjdI3XgDyGdCwG7GcG+YxCMjrm/oINIxsP3i0i5jBUKgCzNg41RzDjwy/sL1q
# kgrCOedzIbsfAeqIIpOwa2Wiogy0Z+jWcYX5+g2T7D8NvT42jFukrrt0r+UM5lVu
# q806kU1IbZr1/L+c+2IoyyBQXZZG9HhOTWPOO7whFL2u3MTJX4JT9ERkwoidWVGX
# iXl8EeS/KYHL+XMUemnhXS196UUtYqVzITEO1rBNeg5pdx4qhGDx8LZryOnE9CL8
# Iv6cyG/NPQwuFEPUUluNWYFm7KgB5AHvDuh+An/zv1Sc6qIzlJWiVT4RQCAQXS2X
# 3udolWX8t+Th9X8qGnG/e1RfqzWjGEDNRMTCzLXB4/NFL4O1EAOJ7U0y44HJcT8e
# 76+S9RR6a3Rtjd2jgycRdzDDDabN759NKl4yaoUNVC+xrkr+F96pkJEk0P191clA
# z81CZ8vJ4IoU7gHYfm8nGYDAfcvdmTLdp/jkbIK5iaWcagQrO/bgTcoC0ZXDux05
# ZOyFBPHOFTigFff+2PKy3y+LmXgUYlyNx50QBUrgjjTlREsMbCD79cid0slb0dwc
# Wygteh0WjXf0igDfKs0KJhwnJecS3w==
# SIG # End signature block
