﻿function Import-DeviceSettingsCatalog {
	<#
    .SYNOPSIS
    Imports a list of
    .PARAMETER JSONFileList
    The list of json files that contain the
    .EXAMPLE
    $jsonFileList = Get-ChildItems -Path .\JSON\DeviceSettingsCatalog\ | Select Fullname -Expand FullName
    Import-DeviceSettingsCatalog -JSONFileList $jsonFileList

    In this example, the list of json files is created with the Get-ChildItem cmdlet and the
    results are passed directly to the Import-DeviceSettingsCatalog for processing
    #>

	[cmdletbinding()]
	param (
		[Parameter(Mandatory)]
		[string[]] $JSONFileList
	)

	#Region Read this first!
	#!!! Important: for this code construct to work properly - in the csm.deploy.json file - under the section: "command": "Import-DeviceSettingsCatalog",
	#    the JSONFileList must have the 'csm.sinkholeproxyfqdnlist.json' entry in the list above the 'csm.wfasfqdnconfig.json' entry !!!
	#    Example:
	#"JSONFileList": [
	#			"[PROJECTPATH]\\json\\DeviceSettingsCatalog\\csm.sinkholeproxyfqdnlist.json",
	#			"[PROJECTPATH]\\json\\DeviceSettingsCatalog\\csm.wfasfqdnconfig.json",
	#			"[PROJECTPATH]\\json\\DeviceSettingsCatalog\\csm.win10Edge.json",
	#			"[PROJECTPATH]\\json\\DeviceSettingsCatalog\\csm.win10SystemHardening.json"
	#		]
	#EndRegion Read this first!

	Write-Log -Message "`n Device Settings Catalog:" -WriteHost White
	foreach ($JSONFile in $JSONFileList) {

		$deviceSettingsCatalogJSON = Get-JSONContent -JSONFile $JSONFile -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags

		#Region Determine the type of Settings Catalog JSON content we're dealing with
		if ($deviceSettingsCatalogJSON.settingDefinitionId -like "vendor_msft_firewall_mdmstore_dynamickeywords_addresses*") {
			$resource = 'deviceManagement/reusablePolicySettings' #Firewall Reusable Settings
			$identifier = 'displayName'
		}
		Else {
			$resource = 'deviceManagement/configurationPolicies' #Settings Catalog
			$identifier = 'Name'
		}
		#EndRegion Determine the type of Settings Catalog JSON content we're dealing with

		#Region Firewall Rules Settings Catalog prep
		if ($deviceSettingsCatalogJSON.templateReference.templateDisplayName -like "Microsoft Defender Firewall Rules*") {
			#Only associate re-usable settings if the dynamickeywords settingDefinitionId is present
			if ($deviceSettingsCatalogJSON.Settings.settingInstance.groupSettingCollectionValue.children.settingDefinitionId -like "*vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_remoteaddressdynamickeywords*") {
				#$fwReusableSettingsID will only be valid if Reusable Settings policy has successfully imported first!!!
				If ($fwReusableSettingsID) {
					Write-Log -Message "  Using reusable settings id: $fwReusableSettingsID" -WriteHost Magenta

					$fw = 'vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_remoteaddressdynamickeywords'
					$index = $deviceSettingsCatalogJSON.Settings.settingInstance.groupSettingCollectionValue.children.settingDefinitionId.IndexOf($fw)
					If ($index -eq -1) {
						Write-Log -Message "index of reusable setting ID in file: $JSONFile not found" -WriteHost Red
						break
					}

					#Modify the loaded JSON content to update the GUID reference for the Reusable Settings policy that was just imported from the csm.sinkholeproxyfqdnlist.json file
					$deviceSettingsCatalogJSON.Settings.settingInstance.groupSettingCollectionValue.children[$index].simpleSettingCollectionValue[0].value = $fwReusableSettingsID
				}
				Else {
					Write-Log -Message "fwReusableSettingsID not found (meaning reusable settings not imported properly first) ..." -WriteHost Red
					Return
				}
			}
		}
		#EndRegion Firewall Rules Settings Catalog prep

		#Region Regular Settings Catalog JSON uses .Name, new Firewall Rules Settings Catalog uses .displayName
		If ($deviceSettingsCatalogJSON.Name) {
			$policyName = $deviceSettingsCatalogJSON.Name
			Write-Log -Message "  Using policy name: $policyName" -WriteHost Yellow
		}
		ElseIf ($deviceSettingsCatalogJSON.displayName) {
			$policyName = $deviceSettingsCatalogJSON.displayName
			Write-Log -Message "  Using policy name: $policyName" -WriteHost Yellow
		}
		Else {
			Write-Log -Message "No name or displayName specified in JSON, please specify valid JSON for the Device Settings Catalog Policy..." -WriteHost Red
			Return
		}
		#EndRegion Regular Settings Catalog JSON uses .Name, new Firewall Rules Settings Catalog uses .displayName

		#Region Check for existing copy of the policy in the tenant
		$result = Test-DeviceSettingsCatalog -Name $policyName -Resource $resource -Identifier $identifier

		if ($result -ne $false) {
			#i.e. something was detected
			Write-Log -Message "  Existing: $policyName" -WriteHost Yellow

			#Check if what was returned was a Firewall Reusable Settings policy - grab it's GUID if it is
			if ($deviceSettingsCatalogJSON.settingDefinitionId -like "vendor_msft_firewall_mdmstore_dynamickeywords_addresses*") {
				#Store the Firewall Reusable Settings policy GUID, ready for next loop to import the corresponding Firewall Rules Policy
				$fwReusableSettingsID = $result.id
			}
		}
		#EndRegion Check for existing copy of the policy in the tenant
		#Region Import the policy as no previous copy with the same name/displayName was found
		else {
			Write-Log -Message "  Creating: $policyName" -WriteHost Yellow

			$deviceSettingsCatalog = Set-DeviceSettingsCatalog -JSON $deviceSettingsCatalogJSON -Resource $resource

			Write-Log -Message "Device Settings Catalog created as:  $($deviceSettingsCatalog.id)" -WriteHost Green

			#If we imported a Firewall Reusable Settings policy - grab it's GUID and skip group assignment targeting, as it's not valid for this policy type
			if ($deviceSettingsCatalogJSON.settingDefinitionId -like "vendor_msft_firewall_mdmstore_dynamickeywords_addresses*") {
				#Store the Firewall Reusable Settings policy GUID, ready for next loop to import the corresponding Firewall Rules Policy
				$fwReusableSettingsID = $deviceSettingsCatalog.id
			}
			Else {
				#Configure the group assignment targeting, as we imported a regular Settings Catalog policy
				foreach ($aadGroup in $deviceSettingsCatalogJSON.assignments.target ) {
					$aadDisplayName = ConvertTo-AADDisplayName -Id $aadGroup.groupid
					Write-Log -Message "      Adding: $aadDisplayName" -WriteHost Green
					$TargetGroup = Get-AADGroup -DisplayName $aadDisplayName

					$null = Set-DeviceSettingsCatalogAssignment -ConfigurationPolicyId $deviceSettingsCatalog.Id -TargetGroupId $TargetGroup.id
				}
			}
		}
		#EndRegion Import the policy as no previous copy with the same name/displayName was found
	}
}
# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDkXHY9rPxG3vN8
# WU3YI3D1FoaoDoDTVNhBTcDQIo1uwqCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHKd
# /uX70bjxXH3lkOdwSevWwgtbiHh4Uw+tKQDBuGHZMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAs7in/sN8KNu9K+Pg6qmEKvSk/UxSCDySLZck
# u/WhyPikG/oHxV2xBNqc0anmPZZ3B6qyHuo/TpjeAPaR9Gqa9orO7dqsVzT4zGDo
# 0KaZCE+B6PxFfZBU+MKL08aHZi2C2VFBbcmPsvtwHXsY029EpXwlhhyeknJS3xpG
# eCXv4Fz0PoxZxySKjX6B66fKLR4clywhyEYoLfUoNcoVsA3i/dIFTJ4TJqV0PQGt
# sauikHChsWbwqvgOegKumwBOtlAuz7sR6BsLyQgFsTiGv9L1arfeBZiGrPQkUWmT
# ajFQy04YsI9F8e6+uV7BjCjmFSuhDKE04f/21OhmmcxkO5CZ1aGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCD1v4yX3Qxpgl58nWzlLelxL6XFyk21Xpud
# YsTKifzgMwIGZBNQb4iZGBMyMDIzMDQxMjIxMTAxOS40NzhaMASAAgH0oIHQpIHN
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
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEID8z9U+hV6r3fpnqEvzSY8ReDCW2LlK41mNh
# pHhf4NO9MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg/Q4tRz63EiRj4K+1
# 9yNUwogBIOsp44CIuBfnZHCvBa4wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAb/fbrkEFVIoWAABAAABvzAiBCCNzwJaAZEc/Yf0/w74
# cmzprmq4oT5/HJRv+dViI7pOJTANBgkqhkiG9w0BAQsFAASCAgBV0tll12qNGmBH
# 5JCNfz9M2lfkTfoIo0gZ31QQ66VYrhyeeyGhIqPuv+Oq9E9ZJqLisFaaLDOtWf7a
# w5De/DpXw8arTPXIR6upeV81VE2rMwxh9PlK5JHNsMo2xjQSO7J4v2JAC5md/vZK
# HViD7FIaU5u+esBJ0GdbO1QYE/FVRKAPAQpy4Ng42NIJ2z13BbctSy77cY2quGKL
# HxGgSTPHIc8GUJGgaJ4KuFJveno0m9vp0YSTs67YnuEa3nu7KWIxM7kaONn1JduI
# xxwiU6451/ItapTjjN3WGs89EpcxqC5n5XUATby7F+FGxWXDrXa4A9vd7CnFR4MV
# g54d24/fxq4AV6/CUIiRSDNwhrh92H6GiUeVP4hfk1XJ13ChKJmb+DwlEqOwC9cO
# 6QLTCfofs1IhKXjg97LO4kc3TTJjB3xp1RcUIjrCC/W3X/BCsF7G6Gs1zWuN7S8y
# 5jvHztEodun1JJIfk/AboA7VX5IvOdncgo0ZJMYiUSv2A/U5d1hCJ0QKP5Iv1mGJ
# f4sW+BOsBxk6p5EADPPVfiQmoQScmowPFLCuJ23Ob+1HZ7Hl26xpr8xHsbGHL1Fw
# ECTppfB+XKuAp275HOpg7xk0vrO/gSh0jptSovbg/mE/GXQK7wBrpeJJjbL6W3AK
# 3fqOqsRFpSBNgh0T1+20w7KyI1a/hQ==
# SIG # End signature block
