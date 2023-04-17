# Intune App Config

The Intune application installer had be aligned to the new module structure and several components have be relocated.

## Options/Parameters

The old XML structure has been replaced with json to simplify processing the configuration files. Below is a list of all the
possile

### AppType

The AppType element - supported options are MSI, EXE or PS1

### RuleType

The RuleType element [TAGFILE|FILE|REGTAG] Ignored if AppType is MSI

### ReturnCodeType

Do NOT Edit the ReturnCodeType element

### InstallExperience

The InstallExperience element [System|User]

### PackageName

The PackageName element to match the name of the .PS1 script that the IntuneWinAppUtil should reference For MSI or EXE AppType - this must be the name of the MSI or executable file in the ..\\Source folder - without the .exe in the name

### DisplayName

The displayName shown the Intune console

### Description

The description shown in the Intune console

### Publisher

The Publisher name shown in the Intune console

### Category

The category shown in the Intune console

### LogoFile

The Logo shown in Company Portal

#### GroupList

The list of AAD Group ID's stored in the groups.apps.json file