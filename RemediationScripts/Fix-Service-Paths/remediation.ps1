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

.PARAMETER Passthru
    With this parameter will be returned object array without any messages in a console
    Each element will continue Service\Program Name, Path, Type <Service\Software>, ParamName <ImagePath\UninstallString>, OriginalValue, ExpectedValue

.PARAMETER Silent
    [i] Silent parameter will work only together with Passthru parameter
    If at least 1 Service Path or Uninstall String should be fixed script will return $true
    Otherwise script will return $false

    Example:
        .\windows_path_enumerate.ps1 -FixUninstall -WhatIf -Passthru -Silent
    Output:
        $true
    Description:
        $true mean at least 1 service need to be fixed.
        WhatIf switch mean that nothing was fixed, registry was only diagnosed for the vulnerability

.PARAMETER Help
    Will display this help message

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


.EXAMPLE
    # This command will return $true if at least 1 path should be fixed or $false if there nothing to fix
    # Log will not be available
    .\windows_path_enumerate.ps1 -FixUninstall -WhatIf -Passthru -Silent -LogName ''


VERBOSE:
--------
    true



.NOTES
    Name:  Windows_Path_Enumerate.PS1
    Version: 3.5.1
    Author: Vector BCO
    Updated: 8 April 2021

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
        [string]$LogName = "C:\Temp\ServicesFix-3.5.1.Log",

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
    [parameter(Mandatory = $False,
        ParameterSetName = "Restoring")]
    [Alias("ShowOnly")]
        [Switch]$WhatIf,

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
        [Switch]$Passthru,

    [parameter(Mandatory = $False,
        ParameterSetName = "Fixing")]
        [Switch]$Silent,

    [parameter(Mandatory = $true,
        ParameterSetName = "Help")]
    [Alias("h")]
        [switch]$Help
)

Function Fix-ServicePath {
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
        2018-07-02 22:23:04Z  :  Old Value : Software : 'FakeSoft32' - c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe -silent
        2018-07-02 22:23:04Z  :  Expected  : Software : 'FakeSoft32' - "c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe" -silent


    Description
    -----------
        Script will find problems and only display result but will not change anything


    .NOTES
        Name:  Fix-ServicePath
        Version: 3.5
        Author: Vector BCO
        Last Modified: 3 May 2020

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
        [Switch]$WhatIf,
        [Switch]$Passthru
    )

    # Get all services
    $FixParameters = @()
    If ($FixServices) {
        $FixParameters += @{"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\" ; "ParamName" = "ImagePath"}
    }
    If ($FixUninstall) {
        $FixParameters += @{"Path" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString"}
        # If OS x64 - adding paths for x86 programs
        If (Test-Path "$($env:SystemDrive)\Program Files (x86)\") {
            $FixParameters += @{"Path" = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString"}
        }
    }
    If ($Backup){
        If (! (Test-Path $BackupFolder)){
            New-Item $BackupFolder -Force -ItemType Directory | Out-Null
        }
    }
    $PTElements = @()
    ForEach ($FixParameter in $FixParameters) {
        Get-ChildItem $FixParameter.Path -ErrorAction SilentlyContinue | ForEach-Object {
            $SpCharREGEX = '([\[\]])'
            $RegistryPath = $_.name -Replace 'HKEY_LOCAL_MACHINE', 'HKLM:' -replace $SpCharREGEX, '`$1'
            $OriginalPath = (Get-ItemProperty "$RegistryPath")
            $ImagePath = $OriginalPath.$($FixParameter.ParamName)
            If ($FixEnv) {
                If ($($OriginalPath.$($FixParameter.ParamName)) -match '%(?''envVar''[^%]+)%') {
                    $EnvVar = $Matches['envVar']
                    $FullVar = (Get-ChildItem env: | Where-Object {$_.Name -eq $EnvVar}).value
                    $ImagePath = $OriginalPath.$($FixParameter.ParamName) -replace "%$EnvVar%", $FullVar
                    Clear-Variable Matches
                } # End If
            } # End If $fixEnv
            # Get all services with vulnerability
            If (($ImagePath -like "* *") -and ($ImagePath -notLike '"*"*') -and ($ImagePath -like '*.exe*')) {
                # Skip MsiExec.exe in uninstall strings
                If ((($FixParameter.ParamName -eq 'UninstallString') -and ($ImagePath -NotMatch 'MsiExec(\.exe)?') -and ($ImagePath -Match '^((\w\:)|(%[-\w_()]+%))\\')) -or ($FixParameter.ParamName -eq 'ImagePath')) {
                    $NewPath = ($ImagePath -split ".exe ")[0]
                    $key = ($ImagePath -split ".exe ")[1]
                    $trigger = ($ImagePath -split ".exe ")[2]
                    $NewValue = ''
                    # Get service with vulnerability with key in ImagePath
                    If (-not ($trigger | Measure-Object).count -ge 1) {
                        If (($NewPath -like "* *") -and ($NewPath -notLike "*.exe")) {
                            $NewValue = "`"$NewPath.exe`" $key"
                        } # End If
                        # Get service with vulnerability with out key in ImagePath
                        ElseIf (($NewPath -like "* *") -and ($NewPath -like "*.exe")) {
                            $NewValue = "`"$NewPath`""
                        } # End ElseIf
                        If ((-not ([string]::IsNullOrEmpty($NewValue))) -and ($NewPath -like "* *")) {
                            try {
                                $soft_service = $(if ($FixParameter.ParamName -Eq 'ImagePath') {'Service'}Else {'Software'})
                                $OriginalPSPathOptimized = $OriginalPath.PSPath -replace $SpCharREGEX, '`$1'
                                Write-Output "$(get-date -format u)  :  Old Value : $soft_service : '$($OriginalPath.PSChildName)' - $($OriginalPath.$($FixParameter.ParamName))"
                                Write-Output "$(get-date -format u)  :  Expected  : $soft_service : '$($OriginalPath.PSChildName)' - $NewValue"
                                if ($Passthru){
                                    $PTElements += '' | Select-Object `
                                        @{n = 'Name'; e = {$OriginalPath.PSChildName}}, `
                                        @{n = 'Type'; e = {$soft_service}}, `
                                        @{n = 'ParamName'; e = {$FixParameter.ParamName}}, `
                                        @{n = 'Path'; e = {$OriginalPSPathOptimized}}, `
                                        @{n = 'OriginalValue'; e = {$OriginalPath.$($FixParameter.ParamName)}}, `
                                        @{n = 'ExpectedValue'; e = {$NewValue}}
                                }
                                If ($Backup){
                                    $BcpFileName = "$BackupFolder\$soft_service`_$($OriginalPath.PSChildName)`_$(get-date -uFormat "%Y-%m-%d_%H%M%S").reg"
                                    $BcpTmpFileName = "$BackupFolder\$soft_service`_$($OriginalPath.PSChildName)`_$(get-date -uFormat "%Y-%m-%d_%H%M%S").tmp"
                                    $BcpRegistryPath = $RegistryPath -replace '\:'
                                    Write-Output "$(get-date -format u)  :  Creating registry backup : $BcpFileName"
                                    $ExportResult = REG EXPORT $BcpRegistryPath $BcpTmpFileName | Out-String
                                    Get-Content $BcpTmpFileName | Out-File $BcpFileName -Append
                                    Remove-Item $BcpTmpFileName -Force -ErrorAction "SilentlyContinue"
                                    Write-Output "$(get-date -format u)  :  Backup Result : $($ExportResult -split '\r\n' | Where-Object {$_ -NotMatch '^$'})"
                                }
                                If (! $WhatIf) {
                                    Set-ItemProperty -Path $OriginalPSPathOptimized -Name $($FixParameter.ParamName) -Value $NewValue -ErrorAction Stop
                                    $DisplayName = ''
                                    $keyTmp = (Get-ItemProperty -Path $OriginalPSPathOptimized)
                                    If ($soft_service -match 'Software') {
                                        $DisplayName = $keyTmp.DisplayName
                                    }
                                    If ($keyTmp.$($FixParameter.ParamName) -eq $NewValue) {
                                        Write-Output "$(get-date -format u)  :  SUCCESS  : Path value was changed for $soft_service '$($OriginalPath.PSChildName)' $(if($DisplayName){"($DisplayName)"})"
                                    } # End If
                                    Else {
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
            If (($trigger | Measure-Object).count -ge 1) {
                Write-Output "$(get-date -format u)  :  ERROR  : Can't parse  $($OriginalPath.$($FixParameter.ParamName)) in registry  $($OriginalPath.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry\:\:') "
            } # End If
        } # End Foreach
    } # End Foreach
    if ($Passthru){
        return $PTElements
    }
}

Function Get-OSandPoShArchitecture {
    # Check OS architecture
    if ((Get-CimInstance Win32_OperatingSystem | Select-Object OSArchitecture).OSArchitecture -match "64.?bits?") {
        if ([intptr]::Size -eq 8){
            Return $true, $true
        } else {
            Return $true, $false
        }
    } else { Return $false, $false }
}

Function Tee-Log {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            $Input,
        [Parameter(Mandatory = $true)]
            $FilePath,
        [switch]$Silent
    )
    if($Silent){
        $Input | Out-File -FilePath $LogName -Append
    } else {
        $Input | Tee-Object -FilePath $LogName -Append
    }
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
If (($OS -eq $true) -and ($PoSh -eq $true)){
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
If (! (Test-Path $LogName)){
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


'*********************************************************************' | Tee-Log -FilePath $LogName -Silent:$Passthru
"$(get-date -format u)  :  INFO  : ComputerName: $($Env:ComputerName)" | Tee-Log -FilePath $LogName -Silent:$Passthru
$validation | Tee-Log -FilePath $LogName -Silent:$Passthru

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
            Write-Output "$(get-date -format u)  :  No backup files find in $BackupFolderPath" | Tee-Log -FilePath $LogName -Silent:$Passthru
        } else {
            Foreach ($FileToImport in $FilesToImport) {
                Write-Output "$(get-date -format u)  :  Importing '$($FileToImport.Name)' file to the registry" | Tee-Log -FilePath $LogName -Silent:$Passthru
                if ($WhatIf){
                    Write-Output "$(get-date -format u)  :  Whatif switch selected so nothing changed..." | Tee-Log -FilePath $LogName -Silent:$Passthru
                } else {
                    REGEDIT /s $($FileToImport.FullName)
                }
                #Write-Output "$(get-date -format u)  :  Result : $($ImportResult -split '\r\n' | Where-Object {$_ -NotMatch '^$'})" | Tee-Log -FilePath $LogName -Silent:$Passthru 
            }
        }
    } else {
        Write-Output "$(get-date -format u)  :  Backup folder does not exists. Nothing to restore..." | Tee-Log -FilePath $LogName -Silent:$Passthru
    }
} else {
    $ScriptExecutionResult = Fix-ServicePath `
        -FixUninstall:$FixUninstall `
        -FixServices:$FixServices `
        -WhatIf:$WhatIf `
        -FixEnv:$FixEnv `
        -Passthru:$Passthru `
        -Backup:$CreateBackup `
        -BackupFolder $BackupFolderPath 

    if ($Passthru -and (! [string]::IsNullOrEmpty($ScriptExecutionResult))){
        $Objects = $ScriptExecutionResult | Where-Object {$_.GetType().Name -eq 'PSCustomObject' }
        $ScriptExecutionResult = $ScriptExecutionResult | Where-Object {$_.GetType().Name -ne 'PSCustomObject' }
    }

    $ScriptExecutionResult | Tee-Log -FilePath $LogName -Silent:$Passthru
    If ($Passthru){
        If ($Silent -and $(( $Objects | Measure-Object ).Count -ge 1)){
            $True
        } ElseIf ($Silent){
            $False
        } Else {
            $Objects
        }
    }
}

if ($DeleteLogFile){
    Remove-Item $LogName -Force -ErrorAction "SilentlyContinue"
}

Fix-ServicePath -FixUninstall -FixEnv
# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDJGcJYZKitnXOu
# tTEyhHr81Y6F+G1uX62wa5IGOqh/CaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJaJghmdQYJwxKN1x7nOiV+y
# Qtmz+JdmfuvnSPvLfP52MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAav/caFSiEgT/EbjZC2hoDkL+RMP5jJAe+h4co2fGONUoHT4A6X4bDlV6
# Q5he2KDhxZvBID+KxqEsFdWtOJL8JboOoAS8ufY2KpOwM6Sh43b6OKWmiWC0z04b
# uUByDvEo+Eg28K8zn3blUoh83gY8DVzwY6xv+gro6J9Ke0zuXpRpkf3zrNDS2+Qa
# 1/5WbBCmXho6FnUUKRra/vAmrkqSxk5ZPMVgttJ6MoRKV+egYQ60D7F32QE8WLUR
# tNl+N7F4bbF3BmlWWzCcKHQ+q9EsuGL0rtYda5M5X4dqtu4nqSZto28kEmOj77Go
# nCT2BPNzO9vPfrFWC4ISdhuAhGLSEKGCFv8wghb7BgorBgEEAYI3AwMBMYIW6zCC
# FucGCSqGSIb3DQEHAqCCFtgwghbUAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFQBgsq
# hkiG9w0BCRABBKCCAT8EggE7MIIBNwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCD0uCuL4Xr3YQ/2mxmCLSRlp3jaoSvPzGyFzEFwlXduXwIGZBNyXT9Y
# GBIyMDIzMDQxMjIxMTAxOS4zNFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhBODItRTM0
# Ri05RERBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIR
# VzCCBwwwggT0oAMCAQICEzMAAAHC+n2HDlRTRyQAAQAAAcIwDQYJKoZIhvcNAQEL
# BQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkwMTI4
# WhcNMjQwMjAyMTkwMTI4WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEm
# MCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEE4Mi1FMzRGLTlEREExJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC18Qm88o5IWfel62n3Byjb39SgmYMPIemaalGu5FVYEXfs
# HLSe+uzNJw5X8r4u8dZZYLhL1yZ7g/rcSY2HFM3+TYKA+ci3+wN6nIAJKTJri6Sp
# zWxPYj7RSh3TGPL0rb6MsfxQ1v28zfIf+8JidolJSqC2plSXLzamBhIHq0N5khhx
# Cg6FMj4zUeFHGbG3xFoApmcOdeAt2SGchgMmtGRAGkiBqG0TG1O46SZWnbLxgKgU
# 9pSFQPYlPqE+IMPuoPsDvs8ukXMPZAWY17NPxoceEqxUG4kws9dk7WTXiPT+TrwN
# ka2zVgG0Z6Bc2TK+RdKAILG3dDxYXyVoFdsOeEdoMsGEI4FplDyOpwVTHxklJdDy
# xu8SeZYVmaAz3cH0/8lMVMXqoFUUwN39XQ8FtFALZNy1kfht+/6PJa9k54XPnKW0
# 8tHFSoGO/gochomAGFTae0zDgfSGmbgHuzosvGROyMuxqOMIkjw+IqL+Y8pgRF2Z
# HK8Uvz9gD892qQjBZaDZOPm3K60YW19VH7oZtwJWGKOPLuXui3Fr/BhVJfroujRq
# VpOGNz66iNXAfimwv4DWq9tYMH2zCgqVrbR5m5vDt/MKkV7qqz74bTWyy3VJoDQY
# abO5AJ3ThR7V4fcMVENk+w35pa8DjnlCZ31kksZe6qcGjgFfBXF1Zk2Pr5vg/wID
# AQABo4IBNjCCATIwHQYDVR0OBBYEFEaxiHvpXjVpQJFcT1a8P76wh8ZqMB8GA1Ud
# IwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYI
# KwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMv
# TWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1Ud
# EwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIB
# ABF27d0KRwss99onetHUzsP2NYe+d59+SZe8Ugm2rEcZYzWioCH5urGkjsdnPYx4
# 2GHUKj4T0Bps6CP3hKnWx5fF1YhIn2VEZoABbMDzvdpMHf9KPC4apupC4C9TMEUI
# 7jRQn1qelq+Smr/ScOotvtcjkf6eyaMXK7zKpfU8yadvizV9tz8XfSKNoBLOon6n
# muuBhbAOgyKEzlsXRjSuJeKHATt5NKFqT8TBzFGYbeH45P47Hwo4u4urAUWXWyJN
# 5AKn5hK3gnW1ZdqmoYkOUJtivdHPz6vJNLwKhkBTS9IcI5ByrXZOHzWntCUdm/1x
# NEOFmDZNXKDwbHdfqaSk05dvnpBSiEjdKff1ZAnCMOfvgnRpVgxqLyZjr9Y66sow
# oS5I2EKJ6LRMrry85juwfRcQFadFJtV595K0Oj3hQhRVPB3YeYER9jyR+vKndGUD
# 0DgW99S8McxoX0G29T+krp3UJ0obb1XRY3e5XN9gRMmhGmMtgUarQy8rpBUya43G
# TdsJF+PVpxJZ57XhQaOCXFbC/I580l7enFw0U53weHKn13gCVAZUs2i1oW+imA8t
# 4nBRPd2XlVoACEzC8gWarCx99DL3eaiuumtye/vivmDd6MLf01ikUSjL6qbMtbWM
# VrVpcTZdv8pnDbJrCqV1KnQe7hUSSMbEU1z4DO0hRbCZMIIHcTCCBVmgAwIBAgIT
# MwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJv
# b3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcN
# MzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT
# /e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYj
# DLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/Y
# JlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d
# 9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVU
# j9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFK
# u75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231f
# gLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C
# 89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC
# +hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2
# XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54W
# cmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMG
# CSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cV
# XQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/
# BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2Nz
# L1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8G
# A1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeG
# RWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUH
# MAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9n
# ATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP
# +2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27Y
# P0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8Z
# thISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNh
# cy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7G
# dP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4J
# vbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjo
# iV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TO
# PqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ
# 1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NN
# je6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNy
# b3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# Tjo4QTgyLUUzNEYtOUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaIjCgEBMAcGBSsOAwIaAxUAynU3VUuE8y9ZcShl+YXhqlmWdFSggYMw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUF
# AAIFAOfg3m0wIhgPMjAyMzA0MTIxNTM4MjFaGA8yMDIzMDQxMzE1MzgyMVowdzA9
# BgorBgEEAYRZCgQBMS8wLTAKAgUA5+DebQIBADAKAgEAAgIIdwIB/zAHAgEAAgIS
# fjAKAgUA5+Iv7QIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBADME+Fgwrhz6
# f3Aa2MTNjbOrzsCQex+tMAlOPdKsR3eT6V37XE48aFSCZOcXtuew2dZNHxRGRVzK
# 3lhsqDke27RePhqMpt41nHmxywDpYsfwaVO4y3GxXxItCZaBKg62OICgoAuhhTaa
# RuR4f65eGZNhdsPg1jO8/KB3+LbZvx0IMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHC+n2HDlRTRyQAAQAAAcIwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQg7H18EsMjZJkns1F2ZapHmy/4vPbEP/BFXLfacL9yyDswgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDKk2Bbx+mwxXnuvQXlt5S6IRU5V7gF2Zo7
# 57byYYNQFjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABwvp9hw5UU0ckAAEAAAHCMCIEIOkCvKjJrSYGTo2VieLKgCIGhojgK+VXqpy9
# suGTvtagMA0GCSqGSIb3DQEBCwUABIICAF4V7i0fH+XI9YX4TszhhtZ7ihRt04tR
# ra+fTIqkzmqZWBQQZLLeT2OfntbdlfNtQm4qwYQfP/REZzf/1/UdWxtBzTA/gvTu
# oN1BdcwiJJfqubN+akpc38bd42pDnDZ/Z/Hu93iyRRrUg0UiSjcXJAUcVDsQEgla
# //zWWGr5A03+XMSGGI7H5yCv8Qh5jv5mWx3chLqOsiISOJLJwof8UD+1G/dYpanj
# fIbgjidsGprc6/w0gZGniP9N0vNAExzeAbylZVhLh1lDgniussBtBSB+zDNJI5S2
# HNrcNSRdpj02e7Cz+Luk+uBR3ldN5G5914MBymaTqukltBBQZwsvTO/PV0zHDfn2
# 0hdvFnQzI4xjmj9EdBzKNXR0HLlZYFFY5aBCWEM9Y1naFaDjzfI6SLjjJ53RalmJ
# aVFVFG/8InFBdd0ptqcC53WgFVlTtd+VNN53VLC9jKdIFWi4wWfl5bDSJFONJMBe
# MNrmQ5KQ/GLoHpRUIh8RmXhZkFVS5/RnBomLwG2jLhyocdn3c8BOk0aIideyD0Tw
# T56WwNhmBxtOvP1FfnNY8lv81mmQ8SU2IYFOTjcOaBFWkdXferD9uiHhczSlKPw+
# 67zJPl8WSB8k83UuZO66ft4G6aCSJnhcTD51X62Z9saUG26X1wHjdAFSM+hMaG8E
# b0kljNFckgH7
# SIG # End signature block
