<#
.SYNOPSIS
    Fix for Microsoft Windows Unquoted Service Path Enumeration

.DESCRIPTION
    Script for fixing vulnerability "Unquoted Service Path Enumeration" in Services and Uninstall strings. Script modifying registry values.
    Require Administrator rights and should be run on x64 powershell version in case if OS also have x64 architecture

.PARAMETER FixServices
    This bool parameter allow proceed Services with vulnerability. By default this parameter enabled.
    For disabling this parameter use -FixServices:$False

.PARAMETER FixUninstall
    Parameter allow find and fix vulnerability in UninstallPaths.
    Will be covered paths for x86 and x64 applications on x64 systems.

.PARAMETER FixEnv
    Find services with Environment variables in the ImagePath parameter, and replace Env. variable to the it value
    EX. %ProgramFiles%\service.exe will be replace to "C:\Program Files\service.exe"

.PARAMETER WhatIf
    Parameter should be used for checking possible system impact.
    With this parameter script would not change anything on your system,
    and only will show information about possible (needed) changes.

.PARAMETER CreateBackup
    When switch parameter enabled script will export registry tree`s
    specified for services or uninstall strings based on operator selection.
    Tree would be exported before any changes.

    [Note] For restoring backup could be used RestoreBackup parameter
    [Note] For providing full backup path could be used BackupName parameter

.PARAMETER RestoreBackup
    This parameter will allow restore previously created backup.
    If BackupName parameter would not be provided will be used last created backup,
    in other case script will try to find selected backup name

    [Note] For creation backup could be used CreateBackup parameter
    [Note] For providing full backup path could be used BackupName parameter

.PARAMETER BackupFolderPath
    Parameter would be proceeded only with CreateBackup or RestoreBackup
    If CreateBackup or RestoreBackup parameter will be provided, then path from this parameter will be used.

    During backup will be created reg file with original values per each service and application that will be modified
    During restoration all reg files in the specified format will be iterable imported to the registry

    Input example: C:\Backup\

    Backup file format:
      for -FixServices switch => Service_<ServiceName>_YYYY-MM-DD_HHmmss.reg
      for -FixUninstall switch => Software_<ApplicationName>_YYYY-MM-DD_HHmmss.reg

.PARAMETER Help
    Will display how to get this help message

.PARAMETER LogName
    Parameter allow to change output file location, or disable logging setting this parameter to empty string or $null.

.EXAMPLE
    # Run powershell as administrator and type path to this script. In case if it will not run type dot (.) before path.
    . C:\Scripts\Windows_Path_Enumerate.ps1


VERBOSE:
--------
    2017-02-19 15:43:50Z  :  INFO  :  ComputerName: W8-NB
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
    2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "%ProgramFiles%\bad driver\driver.exe" -k -l 'oper'
    2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - C:\Program Files\Strange Software\virus.exe -silent
    2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Program Files\Strange Software\virus.exe" -silent'
    2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

Description
-----------
    Fix 2 services 'BadDriver', 'NotAVirus'.
    Env variable %ProgramFiles% did not changed to full path in service 'BadDriver'


.EXAMPLE
    # This command, or similar could be used for running script from SCCM
    Powershell -ExecutionPolicy bypass -command ". C:\Scripts\Windows_Path_Enumerate.ps1 -FixEnv"


VERBOSE:
--------
    2017-02-19 15:43:50Z  :  INFO  :  ComputerName: W8-NB
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
    2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "C:\Program Files\bad driver\driver.exe" -k -l 'oper'
    2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - %SystemDrive%\Strange Software\virus.exe -silent
    2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Strange Software\virus.exe" -silent'
    2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

Description
-----------
    Fix 2 services 'BadDriver', 'NotAVirus'.
    Env variable %ProgramFiles% replaced to full path 'C:\Program Files' in service 'BadDriver'

.EXAMPLE
    # This command, or similar could be used for running script from SCCM
    Powershell -ExecutionPolicy bypass -command ". C:\Scripts\Windows_Path_Enumerate.ps1 -FixUninstall -FixServices:$False -WhatIf"


VERBOSE:
--------
    2018-07-02 22:23:02Z  :  INFO  :  ComputerName: test
    2018-07-02 22:23:04Z  :  Old Value : Software : 'FakeSoft32' - c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe -silent
    2018-07-02 22:23:04Z  :  Expected  : Software : 'FakeSoft32' - "c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe" -silent


Description
-----------
    Script will find and displayed


.NOTES
    Name:  Windows_Path_Enumerate.PS1
    Version: 3.4
    Author: Vector BCO
    Updated: 11 Apr 2020

.LINK
    https://github.com/VectorBCO/windows-path-enumerate/
    https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341
    https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-enumeration
    http://www.commonexploits.com/unquoted-service-paths/
#>

[CmdletBinding(DefaultParameterSetName = "Fixing")]

Param (
    [parameter(Mandatory=$false,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory = $False,
        ParameterSetName = "Restoring")]
    [Alias("s")]
        [Bool]$FixServices=$true,

    [parameter(Mandatory = $false,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory=$False,
        ParameterSetName = "Restoring")]
    [Alias("u")]
        [Switch]$FixUninstall,

    [parameter(Mandatory = $false,
        ParameterSetName = "Fixing")]
    [Alias("e")]
        [Switch]$FixEnv,

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
    [Alias("cb","backup")]
        [switch]$CreateBackup,

    [parameter(Mandatory=$False,
        ParameterSetName = "Restoring")]
    [Alias("rb","restore")]
        [switch]$RestoreBackup,

    [parameter(Mandatory=$False,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory = $False,
        ParameterSetName = "Restoring")]
        [string]$BackupFolderPath = "C:\Temp\PathEnumerationBackup",

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory = $False,
        ParameterSetName = "Restoring")]
        [string]$LogName = "C:\Temp\ServicesFix-3.4.Log",

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory = $False,
        ParameterSetName = "Restoring")]
    [Alias("ShowOnly")]
        [Switch]$WhatIf,

    [parameter(Mandatory = $true,
        ParameterSetName = "Help")]
    [Alias("h")]
        [switch]$Help
)

function Fix-ServicePath {
    <#
    .SYNOPSIS
        Microsoft Windows Unquoted Service Path Enumeration

    .DESCRIPTION
        Use Fix-ServicePath to fix vulnerability "Unquoted Service Path Enumeration".

    .PARAMETER FixServices
        This switch parameter allow proceed Services with vulnerability. By default this parameter enabled.
        For disable this parameter use -FixServices:$False

    .PARAMETER FixUninstall
        Parameter allow find and fix vulnerability in UninstallPath.
        Will be covered paths for x86 and x64 applications on x64 systems.

    .PARAMETER FixEnv
        Find services with Environment variables in the ImagePath parameter, and replace Env. variable to the it value
        EX. %ProgramFiles%\service.exe will be replace to "C:\Program Files\service.exe"

    .PARAMETER WhatIf
        Parameter should be used for checking possible system impact.
        With this parameter script would not be changing anything on your system,
        and only will show information about possible changes

    .EXAMPLE
        Fix-ServicePath


    VERBOSE:
    --------
        2017-02-19 15:43:50Z  :  INFO  :  ComputerName: W8-NB
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
        2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "%ProgramFiles%\bad driver\driver.exe" -k -l 'oper'
        2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - C:\Program Files\Strange Software\virus.exe -silent
        2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Program Files\Strange Software\virus.exe" -silent'
        2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

    Description
    -----------
        Fix 2 services 'BadDriver', 'NotAVirus'.
        Env variable %ProgramFiles% did not changed to full path in service 'BadDriver'


    .EXAMPLE
        Fix-ServicePath -FixEnv


    VERBOSE:
    --------
        2017-02-19 15:43:50Z  :  INFO  :  ComputerName: W8-NB
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
        2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "C:\Program Files\bad driver\driver.exe" -k -l 'oper'
        2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - %SystemDrive%\Strange Software\virus.exe -silent
        2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Strange Software\virus.exe" -silent'
        2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

    Description
    -----------
        Fix 2 services 'BadDriver', 'NotAVirus'.
        Env variable %ProgramFiles% replaced to full path 'C:\Program Files' in service 'BadDriver'

    .EXAMPLE
        Fix-ServicePath -FixUninstall -FixServices:$False -WhatIf


    VERBOSE:
    --------
        2018-07-02 22:23:02Z  :  INFO  :  ComputerName: test
        2018-07-02 22:23:04Z  :  Old Value : Software : 'FakeSoft32' - c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe -silent
        2018-07-02 22:23:04Z  :  Expected  : Software : 'FakeSoft32' - "c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe" -silent


    Description
    -----------
        Script will find problems and only display result but will not change anything


    .NOTES
        Name:  Fix-ServicePath
        Version: 3.4
        Author: Vector BCO
        Last Modified: 11 Apr 2020

    .LINK
        https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341
        https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-enumeration
        http://www.commonexploits.com/unquoted-service-paths/
    #>

    Param (
        [bool]$FixServices = $true,
        [Switch]$FixUninstall,
        [Switch]$FixEnv,
        [Switch]$Backup,
        [string]$BackupFolder = "C:\Temp\PathEnumeration",
        [Switch]$WhatIf
    )

    Write-Output "$(get-date -format u)  :  INFO  : ComputerName: $($Env:ComputerName)"

    # Get all services
    $FixParameters = @()
    if ($FixServices) {
        $FixParameters += @{"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\" ; "ParamName" = "ImagePath"}
    }
    if ($FixUninstall) {
        $FixParameters += @{"Path" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString"}
        # If OS x64 - adding paths for x86 programs
        if (Test-Path "$($env:SystemDrive)\Program Files (x86)\") {
            $FixParameters += @{"Path" = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString"}
        }
    }
    if ($Backup){
        if (! (Test-Path $BackupFolder)){
            New-Item $BackupFolder -Force -ItemType Directory | Out-Null
        }
    }

    foreach ($FixParameter in $FixParameters) {
        Get-ChildItem $FixParameter.Path -ErrorAction SilentlyContinue | ForEach-Object {
            $SpCharREGEX = '([\[\]])'
            $RegistryPath = $_.name -Replace 'HKEY_LOCAL_MACHINE', 'HKLM:' -replace $SpCharREGEX, '`$1'
            $OriginalPath = (Get-ItemProperty "$RegistryPath")
            $ImagePath = $OriginalPath.$($FixParameter.ParamName)
            if ($FixEnv) {
                if ($($OriginalPath.$($FixParameter.ParamName)) -match '%(?''envVar''[^%]+)%') {
                    $EnvVar = $Matches['envVar']
                    $FullVar = (Get-ChildItem env: | Where-Object {$_.Name -eq $EnvVar}).value
                    $ImagePath = $OriginalPath.$($FixParameter.ParamName) -replace "%$EnvVar%", $FullVar
                    Clear-Variable Matches
                } # End If
            } # End If $fixEnv
            # Get all services with vulnerability
            if (($ImagePath -like "* *") -and ($ImagePath -notLike '"*"*') -and ($ImagePath -like '*.exe*')) {
                # Skip MsiExec.exe in uninstall strings
                if ((($FixParameter.ParamName -eq 'UninstallString') -and ($ImagePath -NotMatch 'MsiExec(\.exe)?') -and ($ImagePath -Match '^((\w\:)|(%[-\w_()]+%))\\')) -or ($FixParameter.ParamName -eq 'ImagePath')) {
                    $NewPath = ($ImagePath -split ".exe ")[0]
                    $key = ($ImagePath -split ".exe ")[1]
                    $trigger = ($ImagePath -split ".exe ")[2]
                    $NewValue = ''
                    # Get service with vulnerability with key in ImagePath
                    if (-not ($trigger | Measure-Object).count -ge 1) {
                        if (($NewPath -like "* *") -and ($NewPath -notLike "*.exe")) {
                            $NewValue = "`"$NewPath.exe`" $key"
                        } # End If
                        # Get service with vulnerability with out key in ImagePath
                        ElseIf (($NewPath -like "* *") -and ($NewPath -like "*.exe")) {
                            $NewValue = "`"$NewPath`""
                        } # End ElseIf
                        if ((-not ([string]::IsNullOrEmpty($NewValue))) -and ($NewPath -like "* *")) {
                            try {
                                $soft_service = $(if ($FixParameter.ParamName -Eq 'ImagePath') {'Service'}else {'Software'})
                                Write-Output "$(get-date -format u)  :  Old Value : $soft_service : '$($OriginalPath.PSChildName)' - $($OriginalPath.$($FixParameter.ParamName))"
                                Write-Output "$(get-date -format u)  :  Expected  : $soft_service : '$($OriginalPath.PSChildName)' - $NewValue"
                                if ($Backup){
                                    $BcpFileName = "$BackupFolder\$soft_service`_$($OriginalPath.PSChildName)`_$(get-date -uFormat "%Y-%m-%d_%H%M%S").reg"
                                    $BcpRegistryPath = $RegistryPath -replace '\:'
                                    Write-Output "$(get-date -format u)  :  Creating registry backup : $BcpFileName"
                                    $ExportResult = REG EXPORT $BcpRegistryPath $BcpFileName | Out-String
                                    Write-Output "$(get-date -format u)  :  Result : $($ExportResult -split '\r\n' | Where-Object {$_ -NotMatch '^$'})"
                                }
                                if (! $WhatIf) {
                                    $OriginalPSPathOptimized = $OriginalPath.PSPath -replace $SpCharREGEX, '`$1'
                                    Set-ItemProperty -Path $OriginalPSPathOptimized -Name $($FixParameter.ParamName) -Value $NewValue -ErrorAction Stop
                                    $DisplayName = ''
                                    $keyTmp = (Get-ItemProperty -Path $OriginalPSPathOptimized)
                                    if ($soft_service -match 'Software') {
                                        $DisplayName = $keyTmp.DisplayName
                                    }
                                    if ($keyTmp.$($FixParameter.ParamName) -eq $NewValue) {
                                        Write-Output "$(get-date -format u)  :  SUCCESS  : Path value was changed for $soft_service '$(if($DisplayName){$DisplayName}else{$OriginalPath.PSChildName})'"
                                    } # End If
                                    else {
                                        Write-Output "$(get-date -format u)  :  ERROR  : Something is going wrong. Path was not changed for $soft_service '$(if($DisplayName){$DisplayName}else{$OriginalPath.PSChildName})'."
                                    } # End Else
                                } # End If
                            } # End try
                            Catch {
                                Write-Output "$(get-date -format u)  :  ERROR  : Something is going wrong. Value changing failed in service '$($OriginalPath.PSChildName)'."
                                Write-Output "$(get-date -format u)  :  ERROR  : $_"
                            } # End Catch
                            Clear-Variable NewValue
                        } # End If
                    } # End Main If
                } # End if (Skip not needed strings)
            } # End If
            if (($trigger | Measure-Object).count -ge 1) {
                Write-Output "$(get-date -format u)  :  ERROR  : Can't parse  $($OriginalPath.$($FixParameter.ParamName)) in registry  $($OriginalPath.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry\:\:') "
            } # End If
        } # End Foreach
    } # End Foreach
}

function Get-OSandPoShArchitecture {
    # Check OS architecture
    if ((Get-WmiObject Win32_OperatingSystem | Select-Object OSArchitecture).OSArchitecture -eq "64-bit"){
        if ([intptr]::Size -eq 8){
            Return $true, $true
        } else {
            Return $true, $false
        }
    } else { Return $false, $false }
}

if ((! $FixServices) -and (! $FixUninstall)){
    Throw "Should be selected at least one of two parameters: FixServices or FixUninstall. `r`n For more details use 'get-help Windows_Path_Enumerate.ps1 -full'"
}

if ($Help){
    Write-Output "For help use this command in powershell: Get-Help $($MyInvocation.MyCommand.Path) -full"
    powershell -command "& Get-Help $($MyInvocation.MyCommand.Path) -full"
    exit
}

$OS, $PoSh = Get-OSandPoShArchitecture
if (($OS -eq $true) -and ($PoSh -eq $true)){
    $validation = "$(get-date -format u)  :  INFO  : Executed x64 Powershell on x64 OS"
} elseIf (($OS -eq $true) -and ($PoSh -eq $false)) {
    $validation =  "$(get-date -format u)  :  WARNING  : !ATTENTION! : Executed x32 Powershell on x64 OS. Not all vulnerabilities could be fixed.`r`n"
    $validation += "$(get-date -format u)  :  WARNING  : For fixing all vulnerabilities should be used x64 Powershell."
} else {
    $validation = "$(get-date -format u)  :  INFO  : Executed x32 Powershell on x32 OS"
}

$DeleteLogFile = $false

if ([string]::IsNullOrEmpty($LogName)){
    # Log will be written to the temp file if file not specified
    $DeleteLogFile = $true
    $LogName = New-TemporaryFile
}
if (! (Test-Path $LogName)){
    # If path does not exists it should be created
    try{
        $tmpLogPath = $LogName
        if ($tmpLogPath -NotMatch '[\\\/]$') {
            $tmpLogName = ($tmpLogPath -split '[\\\/]')[-1]
            $tmpLogPath = $tmpLogPath -replace "$tmpLogName`$"
        } else {
            $tmpLogName = 'ServicesFix-3.X.Log'
        }
        if (! (Test-Path $tmpLogPath)) {
            New-Item -Path $tmpLogPath -Force -ItemType Directory | Out-Null
        }
        New-Item -Path "$tmpLogPath\$tmpLogName" -Force -ItemType File | Out-Null
        $LogName = "$tmpLogPath\$tmpLogName"
    } catch {
        Throw "Log file '$LogName' does not exists and cannot be created. Error: $_"
    }
}

'*********************************************************************' | Tee-Object -FilePath $LogName -Append
$validation | Tee-Object -FilePath $LogName -Append
if ($RestoreBackup){
    if ($FixServices -and (! $FixUninstall)){
        $RegexPart = "Service"
    } elseif ($FixUninstall -and (! $FixServices)) {
        $RegexPart = "Software"
    } elseif ($FixUninstall -and $FixServices) {
        $RegexPart = "(Service|Software)"
    }

    if (Test-Path $BackupFolderPath){
        $FilesToImport = Get-ChildItem "$BackupFolderPath\" | Where-Object {$_.Name -match "$RegexPart`_.+_\d{4}-\d{1,2}-\d{1,2}_\d{3,6}\.reg$"}
        if ([string]::IsNullOrEmpty($FilesToImport)){
            Write-Output "$(get-date -format u)  :  No backup files find in $BackupFolderPath" | Tee-Object -FilePath $LogName -Append
        } else {
            Foreach ($FileToImport in $FilesToImport) {
                Write-Output "$(get-date -format u)  :  Importing '$($FileToImport.Name)' file to the registry" | Tee-Object -FilePath $LogName -Append
                if ($WhatIf){
                    Write-Output "$(get-date -format u)  :  Whatif switch selected so nothing changed..." | Tee-Object -FilePath $LogName -Append
                } else {
                    REGEDIT /s $($FileToImport.FullName)
                }
                #Write-Output "$(get-date -format u)  :  Result : $($ImportResult -split '\r\n' | Where-Object {$_ -NotMatch '^$'})" | Tee-Object -FilePath $LogName -Append
            }
        }
    } else {
        Write-Output "$(get-date -format u)  :  Backup folder does not exists. Nothing to restore..." | Tee-Object -FilePath $LogName -Append
    }
} else {
    Fix-ServicePath `
        -FixUninstall:$FixUninstall `
        -FixServices:$FixServices `
        -WhatIf:$WhatIf `
        -FixEnv:$FixEnv `
        -Backup:$CreateBackup `
        -BackupFolder $BackupFolderPath | Tee-Object -FilePath $LogName -Append
}

if ($DeleteLogFile){
    Remove-Item $LogName -Force -ErrorAction "SilentlyContinue"
}
# SIG # Begin signature block
# MIIn0QYJKoZIhvcNAQcCoIInwjCCJ74CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCABDYWM8xiate/6
# U1HFhWDrzxOT51gxgedIlbJOQ6HP+qCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILle
# isYDmzATn0DgdMRDmZ6LiazwW55zu9Fhk2k57bhkMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAfsAuLceRNGQPMRxMLRqXNbo7Imkf7AW0uPn2
# z1Yfz7mthbjwE9QCCd1dspNbplA49Qc53tetJ5tGKUtWxSjjVCGF6QIcFuyQQ5sE
# egmBfqPJvwod0Bz+e+KxK6OPO+oopkWLtaYlD2lCtlDs2Kpc96slBX80KT1nEISv
# m8hO/SfBYFwzycpnvYIb4yjmAXT5M3J92fS77Nx5l5RdmjSjkAGmDZprLepty88T
# VnkZMvfFE2dFjiUCjti3AqJu9tMDd/RrLziUzRpD+uHcv5LNHO+gyesus9ZVu9RL
# Z67jM2xeMbFnmv8zddJr81GSeKftHzui+guEYtYva+rZfbCo0KGCFywwghcoBgor
# BgEEAYI3AwMBMYIXGDCCFxQGCSqGSIb3DQEHAqCCFwUwghcBAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCAIywBIzWLOieBAIib8MyeTBS0T7pOzPA3Q
# T5rWjwG/EQIGZBsTUZylGBMyMDIzMDQxMjIxMTAxNy41NTVaMASAAgH0oIHYpIHV
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
# CRABBDAvBgkqhkiG9w0BCQQxIgQg643aH6udrXk346Qx9owqpwt4gjO/urV8WItk
# JusdqgYwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAnyg01LWhnFon2HNzl
# ZyKae2JJ9EvCXJVc65QIBfHIgzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABta0a39eFcG0TAAEAAAG1MCIEIPToCRRnM7Cx8c/1HN2Z
# IKao0yXV501bCoKS8UVKs3wzMA0GCSqGSIb3DQEBCwUABIICAIi0HJLnm5n9R4YM
# LI3oQw4tZLJv3wN4HaeUYBS0vbg8M5I4eMPpNq6rwIWvaCl2C4iq2DcS/HsCVGUw
# sxrOomjUo9AKS8NIkUZzOX7J0UvONByRtYLuH3DaGSAurG+ZnlDlTCBBiaIwUBTp
# n0uwskBl9Bi8xTq2LTFy1lRxFOGnbkm4WE7NyWoEluxWB3qdOk7YcTwTnOJZ0jdd
# mzhqHpn5pcIZ/bqNV5NHab9B+90sUJIt5sH0BNIlMXl6Q70uyW0LmWMLX6aY+zw0
# DtnD/IJvIrX1B2sPzE4FZAQ/2HFHqK4JK4bd2LtzSz1vHxmkl/XaIcJ4W+kgWP19
# snkqOp4zXi1B60g1Sg+nUReLcJPoUIPwJzdDVdkB0B+Y1clcPBOmDBP8Gcwovu4Y
# p8ZbMDRu/iJaBAAU7bvT2nkCUumi9q8fQL5mkEUesuVTRmIpv9hfQVq4e9I1QyBW
# zwZBU2MNmKrMlNImZSY17LFec6ZnKstIMrqsbTQ3gDzAsbBsWef9et6Ex+Q1UN2D
# NI92rAuVOW7hmudaFzrTpFMKOmUnG2jXl1HrwFz4av2oPs5FnfI6Je75xHMAFsRJ
# kqLvtjPaiQboPetsqVUYls575ZCbJEo0YEJoP/lhXAOWyjbe4lJ5G6Wv8CdFmIOZ
# cKG/Y3kOckzDXjiTVJN/9teqDx0W
# SIG # End signature block
