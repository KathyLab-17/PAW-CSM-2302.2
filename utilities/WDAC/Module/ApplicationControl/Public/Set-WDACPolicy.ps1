function Set-WDACPolicy {

    <#
        .SYNOPSIS
        This function configures a WDAC Policy according to recommended settings.
    
        .DESCRIPTION
    
       This function configures recommended WDAC Policy settings including whether the policy is in audit mode or whether the policy is enforced.
         
        .INPUTS
    
            $PolicyFile - input policy file
    
                    ex: "C:\temp\xyz.10.0.0.7.Base_Policy.xml"
    
    
            $PolicyMode - policy enforcement mode
    
                    ex: "Audit"
                    ex: "Enforced"                
    
            $SupportsSupplementalPolicy - applied to a base policy to enable Supplemental policy support
               
    
        .OUTPUTS
        
            Only the Supplemental Policy is modified: 
    
                    ex: "C:\temp\xyz.10.0.0.7.Policy.xml (modified)"
    
    
                    Default Policy Rules:
    
                    <Rules>
                        <Rule>
                        <Option>Enabled:UMCI</Option>
                        </Rule>
                        <Rule>
                        <Option>Required:WHQL</Option>
                        </Rule>
                        <Rule>
                        <Option>Disabled:Flight Signing</Option>
                        </Rule>
                        <Rule>
                        <Option>Enabled:Unsigned System Integrity Policy</Option>
                        </Rule>
                        <Rule>
                        <Option>Required:EV Signers</Option>
                        </Rule>
                        <Rule>
                        <Option>Disabled:Script Enforcement</Option>
                        </Rule>
                        <Rule>
                        <Option>Required:Enforce Store Applications</Option>
                        </Rule>
                        <Rule>
                        <Option>Enabled:Update Policy No Reboot</Option>
                        </Rule>
                        <Rule>
                        <Option>Enabled:Dynamic Code Security</Option>
                        </Rule>
                        <Rule>
                        <Option>Enabled:Allow Supplemental Policies</Option>
                        </Rule>
                    </Rules>
        .EXAMPLE
    
            ex: .\Set-WDACPolicy -$PolicyFile $PolicyFile -PolicyMode Enforced -PolicyMode Enforced
    
        .NOTES
    #>
    
    
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [string]$PolicyFile,
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [ValidateSet('Audit', 'Enforced')]
            [string]$PolicyMode,
            [Parameter(ValueFromPipeline = $true)]
            [switch]$SupportsSupplementalPolicy
        
    
        )
    
        #Set default rules
    
        #removes all possible rules in place (if found) so we can start from scratch
        Set-RuleOption -option 0 -delete  $PolicyFile
        Set-RuleOption -option 1 -delete  $PolicyFile
        Set-RuleOption -option 2 -delete  $PolicyFile
        Set-RuleOption -option 3 -delete  $PolicyFile
        Set-RuleOption -option 4 -delete  $PolicyFile
        Set-RuleOption -option 5 -delete  $PolicyFile
        Set-RuleOption -option 6 -delete  $PolicyFile
        Set-RuleOption -option 7 -delete  $PolicyFile
        Set-RuleOption -option 8 -delete  $PolicyFile
        Set-RuleOption -option 9 -delete  $PolicyFile
        Set-RuleOption -option 10 -delete $PolicyFile
        Set-RuleOption -option 11 -delete $PolicyFile
        Set-RuleOption -option 12 -delete $PolicyFile
        Set-RuleOption -option 13 -delete $PolicyFile
        Set-RuleOption -option 14 -delete $PolicyFile
        Set-RuleOption -option 15 -delete $PolicyFile
        Set-RuleOption -option 16 -delete $PolicyFile
        Set-RuleOption -option 17 -delete $PolicyFile
        Set-RuleOption -option 18 -delete $PolicyFile
        Set-RuleOption -option 19 -delete $PolicyFile
    
        # Rule 0 - Enabled:UMCI
        # WDAC policies restrict both kernel-mode and user-mode binaries
        Set-RuleOption -Option 0 $PolicyFile
    
        # Rule 1 - Enabled:Boot Menu Protection
        # Not supported
    
        # Rule 2 - Required:WHQL
        # Requires that every executed driver is WHQL signed
        Set-RuleOption -Option 2 $PolicyFile
    
        # Rule 3 - Enable Audit Mode
        # Enables the execution of binaries outside of the WDAC policy but logs each occurrence in the CodeIntegrity event log
        # Set-RuleOption -Option 3 $PolicyFile
    
        # Rule 4 - Disabled:Flight Signing
        # WDAC policies will not trust flightroot-signed binaries  (Insider Builds)
        Set-RuleOption -Option 4 $PolicyFile
    
        # Rule 5 - Enabled:Inherit Default Policy
        # Not supported
    
        # Rule 6 -  Enabled:Unsigned System Integrity Policy (Default)
        # Allows the policy to remain unsigned
        Set-RuleOption -Option 6 $PolicyFile
    
        # Rule 7 - Allowed:Debug Policy Augmented
        # Not supported
    
        # Rule 8 - Required:EV Signers
        # Requires that drivers must have been submitted by a partner that has an Extended Verification (EV) certificate
        Set-RuleOption -Option 8 $PolicyFile
    
        # Rule 9 - Enabled:Advanced Boot Options Menu
        # Allows the F8 menu to appear to physically present users
        # Set-RuleOption -Option 9 $PolicyFile
    
        # Rule 10 -  Enabled:Boot Audit on Failure
        # When a driver fails during startup, the WDAC policy will be placed in audit mode so that Windows will load
        # Set-RuleOption -Option 10 $PolicyFile
    
        # Rule 11 - Disabled:Script Enforcement
        # Disables script enforcement options. Unsigned PowerShell scripts and interactive PowerShell are no longer restricted to Constrained Language Mode
        Set-RuleOption -Option 11 $PolicyFile
    
        # Rule 12 - Required:Enforce Store Applications
        # WDAC policies will also apply to Universal Windows applications
        Set-RuleOption -Option 12 $PolicyFile
    
        # Rule 13 - Enabled:Managed Installer
        # Automatically allow applications installed by a software distribution solution, such as Microsoft Endpoint Configuration Manager
        # Set-RuleOption -Option 13 $PolicyFile
    
        # Rule 14 - Enabled:Intelligent Security Graph Authorization
        # Automatically allow applications with "known good" reputation as defined by Microsoft’s Intelligent Security Graph (ISG)
        # Set-RuleOption -Option 14 $PolicyFile
    
        # Rule 15 - Enabled:Invalidate EAs on Reboot
        # This option will cause WDAC to periodically re-validate the reputation for files that were authorized by the ISG
        # Set-RuleOption -Option 15 $PolicyFile
    
        # Rule 16 - Enabled:Update Policy No Reboot
        # Allow future WDAC policy updates to apply without requiring a system reboot
        Set-RuleOption -Option 16 $PolicyFile
    
        # Rule 17 - Enabled:Allow Supplemental Policies
        # Use this option on a base policy to allow supplemental policies to expand it
        # Set-RuleOption -Option 18 $PolicyFile
    
        # Rule 18 - Disabled:Runtime FilePath Rule Protection
        # Disable default FilePath rule protection for any FileRule that allows a file based on FilePath
        # apps and executables allowed based on file path rules must come from a file path that’s only writable by an administrator
        # Set-RuleOption -Option 18 $PolicyFile
    
        #Rule 19 - Applies WDAC Policies to .NET Applications and DLLs  (Not ready to test this now)
        Set-RuleOption -Option 19 $PolicyFile
    
    
        If ($PolicyMode -eq 'Audit') {
                
    
            # Rule 3 - Enable Audit Mode
            # Enables the execution of binaries outside of the WDAC policy but logs each occurrence in the CodeIntegrity event log
            Set-RuleOption -Option 3 $PolicyFile
    
            # Rule 9 - Enabled:Advanced Boot Options Menu
            # Allows the F8 menu to appear to physically present users
            Set-RuleOption -Option 9 $PolicyFile
    
            #Rule 10 -  Enabled:Boot Audit on Failure
            # When a driver fails during startup, the WDAC policy will be placed in audit mode so that Windows will load
            Set-RuleOption -Option 10 $PolicyFile
             
        }
    
        If ($PolicyMode -eq 'Enforced') {
    
            # Rule 9 - Enabled:Advanced Boot Options Menu - optional
            # Allows the F8 menu to appear to physically present users
            # Set-RuleOption -Option 9 $PolicyFile
                         
        }
                       
        If ($SupportsSupplementalPolicy -eq $true) {
    
            # Rule 17 - Enabled:Allow Supplemental Policies
            # Use this option on a base policy to allow supplemental policies to expand it
            Set-RuleOption -Option 17 $PolicyFile
                  
            
                            
        }
            
        
    }