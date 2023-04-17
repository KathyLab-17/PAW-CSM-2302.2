
# about Windows Defender Application Control (WDAC)
WDAC was introduced with Windows 10 and allows organizations to control which drivers and applications are allowed to run on their Windows 10 clients. It was designed as a security feature under the servicing criteria, defined by the Microsoft Security Response Center (MSRC).

WDAC policies apply to the managed computer as a whole and affects all users of the device. WDAC rules can be defined based on:

* Attributes of the codesigning certificate(s) used to sign an app and its binaries
* Attributes of the app's binaries that come from the signed metadata for the files, such as Original Filename and version, or the hash of the file
* The reputation of the app as determined by Microsoft's Intelligent Security Graph
* The identity of the process that initiated the installation of the app and its binaries (managed installer)
* The path from which the app or file is launched (beginning with Windows 10 version 1903)
* The process that launched the app or binary

Note that prior to Windows 10 version 1709, Windows Defender Application Control was known as configurable code integrity (CCI). WDAC was also one of the features that comprised the now-defunct term "Device Guard."

WDAC was introduced with Windows 10 and allows organizations to control which drivers and applications are allowed to run on their Windows 10 clients. It was designed as a security feature under the servicing criteria, defined by the Microsoft Security Response Center (MSRC).

This module makes use of the **[Configurable Code Integrity Cmdlets of the the ConfigCI module](https://docs.microsoft.com/en-us/powershell/module/configci/?view=windowsserver2019-ps)**

# about the ApplicationControl module
The ApplicationControl PowerShell module was created by Microsoft Consulting Services (MCS) to ensure the use of recommended settings and increase deployment consistency when creating WDAC policies. To achieve this the module includes:

* helpful cmdlets that streamline WDAC policy operations
* light-touch creation of WDAC based solutions

Cmdlets:

* Add-WDACPolicyContent
* Add-WDACPolicyDefaultFilePathRules
* Add-WDACPolicyFiles
* Add-WDACSupplementalPolicyToBasePolicy
* Convert-WDACPolicyToBinary
* Export-WDACPolicyWorkspace
* New-WDACPolicy
* New-WDACPolicyWorkspace
* New-WDACSolution
* Remove-WDACPolicyWorkspace
* Set-WDACPolicy

Active Solutions:

* Privileged Access Workstation for Cloud Services Management (PAW-CSM)

Planned Solutions:

* Privileged Access Workstation for Compromised Recovery (PAW-CR)
* Light-touch Zero Trust Workstation (ZTworkstation)

# Documentation
ApplicationControl Module documentation is currently provided in the ApplicationControl.psm1 in the form of function annotations.

# Privileged Access Workstation for Cloud Services Management (PAW-CSM) Solution
The following guide shows how to create an enforced WDAC Policy for a PAW-CSM

1. Copy the 
1. Open a PowerShell session and import the module:

    `import-module C:\code\msft\trejo.code\dev_wdac\Multi-Policy\ApplicationControl.psm1`

2. Identify a folder where you want to save your solution. For this example c:\temp will be used.

3. Identify the folder with your policy files. The folder should contain the following content. A copy of the content is included in the **Policy_Templates** folder of the is repo

```
├───Custom
│       Block_Unwanted_MS.xml
│       Microsoft_Recommended_Block_Rules.xml│
└───Microsoft
        AllowMicrosoft.xml
        DefaultWindows_Enforced.xml
```

3. Launch a PowerShell 5.1 session (7.x will not work). 
4. Use the `New-WDACSolution` cmdlet to Identify a folder where you want to save your solution. Replace the variables with your values:


    `.\New-WDACSolution -Solution PAWCSM -policyversion 10.0.0.5 -org abc -PolicyFileDir C:\code\msft\trejo.code\dev_wdac\Policy_Templates -OutputDirectory c:\temp`

5. Review the ouput. Solutions are exported as a ZIP file containing the following content:

```
├───Logs
├───policy_binaries
│       abc.10.0.0.5.Base_Policy.bin
│       abc.10.0.0.5.Supplemental_Policy.bin
│       OMA-URIs.txt
│
├───policy_files
│   │   DefaultWindows_Enforced.xml
│   │
│   └───Custom
│           Block_Unwanted_MS.xml
│           Microsoft_Recommended_Block_Rules.xml
│
└───policy_xml
        abc.10.0.0.5.Base_Policy.xml
        abc.10.0.0.5.Base_Policy_Blank.xml
        abc.10.0.0.5.Base_Policy_WithTemplates.xml
        abc.10.0.0.5.Supplemental_Policy.xml
        abc.10.0.0.5.Supplemental_Policy_Blank.xml
        abc.10.0.0.5.Supplemental_Policy_WithDefaultPaths.xml

```

6. Open the **OMA-URIs.txt** file and review the OMA-URIs required for policy deployment

``` 
To deploy these policies via Intune, use these custom OMA-URI values

 OMA-URIs for Policies:

         Base Policy:   ./Vendor/MSFT/ApplicationControl/Policies/D079D446-EF6F-4339-8025-B7B95C76CF33/Policy
 Supplemental Policy:   ./Vendor/MSFT/ApplicationControl/Policies/327071B3-D7C0-4911-93D3-6E5429DCF755/Policy

```

7. Deploy the policies via Microsoft Endpoint Manager using a custom policy


# Notes
You break it, you buy it. Twice.