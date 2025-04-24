<#
.SYNOPSIS
    Validates current system settings against reference GPO settings and exports results to CSV.
.DESCRIPTION
    This script checks various security policies and registry settings against a reference set
    of GPO configurations and reports compliance status in a CSV file.
.OUTPUTS
    Generates a CSV file with validation results.
#>

# Output file path
$outputFile = "GPO_Validation_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# Initialize results array
$results = @()

# Function to check registry value
function Check-RegistryValue {
    param (
        [string]$path,
        [string]$name,
        [string]$expectedValue,
        [string]$settingName
    )
    
    $result = [PSCustomObject]@{
        SettingName = $settingName
        ExpectedValue = $expectedValue
        ActualValue = $null
        Status = "Not Checked"
    }
    
    try {
        $regValue = Get-ItemProperty -Path "Registry::$path" -Name $name -ErrorAction Stop
        $actualValue = $regValue.$name
        
        $result.ActualValue = $actualValue
        
        if ($actualValue -eq $expectedValue) {
            $result.Status = "Compliant"
        } else {
            $result.Status = "Non-Compliant"
        }
    } catch {
        $result.ActualValue = "Not Found"
        $result.Status = "Error"
    }
    
    return $result
}

# Function to check security policy
function Check-SecurityPolicy {
    param (
        [string]$policyName,
        [string]$expectedValue,
        [string]$settingName
    )
    
    $result = [PSCustomObject]@{
        SettingName = $settingName
        ExpectedValue = $expectedValue
        ActualValue = $null
        Status = "Not Checked"
    }
    
    try {
        $policy = secedit /export /cfg $env:TEMP\secpol.cfg /areas SECURITYPOLICY
        $secpol = Get-Content "$env:TEMP\secpol.cfg"
        
        $line = $secpol | Where-Object { $_ -like "*$policyName*" }
        
        if ($line) {
            $actualValue = ($line -split "=")[1].Trim()
            $result.ActualValue = $actualValue
            
            if ($actualValue -eq $expectedValue) {
                $result.Status = "Compliant"
            } else {
                $result.Status = "Non-Compliant"
            }
        } else {
            $result.ActualValue = "Not Found"
            $result.Status = "Error"
        }
        
        Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
    } catch {
        $result.ActualValue = "Error"
        $result.Status = "Error"
    }
    
    return $result
}

# Function to check user rights assignment
function Check-UserRightsAssignment {
    param (
        [string]$rightName,
        [string]$expectedUsers,
        [string]$settingName
    )
    
    $result = [PSCustomObject]@{
        SettingName = $settingName
        ExpectedValue = $expectedUsers
        ActualValue = $null
        Status = "Not Checked"
    }
    
    try {
        $actualUsers = (secedit /export /cfg $env:TEMP\userrights.cfg /areas USER_RIGHTS | Out-String)
        $content = Get-Content "$env:TEMP\userrights.cfg"
        
        $line = $content | Where-Object { $_ -like "*$rightName*" }
        
        if ($line) {
            $actualValue = ($line -split "=")[1].Trim()
            $result.ActualValue = $actualValue
            
            # Compare user lists (order doesn't matter)
            $expectedArray = $expectedUsers -split "," | ForEach-Object { $_.Trim() } | Sort-Object
            $actualArray = $actualValue -split "," | ForEach-Object { $_.Trim() } | Sort-Object
            
            if (Compare-Object $expectedArray $actualArray -SyncWindow 0) {
                $result.Status = "Non-Compliant"
            } else {
                $result.Status = "Compliant"
            }
        } else {
            $result.ActualValue = "Not Found"
            $result.Status = "Error"
        }
        
        Remove-Item "$env:TEMP\userrights.cfg" -Force -ErrorAction SilentlyContinue
    } catch {
        $result.ActualValue = "Error"
        $result.Status = "Error"
    }
    
    return $result
}

# Validate settings from the GPO file

# 1. AutoAdminLogon
$results += Check-RegistryValue -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoAdminLogon" -expectedValue "0" -settingName "AutoAdminLogon"

# 2. Renamed accounts (check via security policy)
$results += Check-SecurityPolicy -policyName "NewGuestName" -expectedValue "jameskm" -settingName "Accounts: Rename guest account"
$results += Check-SecurityPolicy -policyName "NewAdministratorName" -expectedValue "wilsonjp" -settingName "Accounts: Rename administrator account"

# 3. Password policies
$results += Check-SecurityPolicy -policyName "PasswordHistorySize" -expectedValue "24" -settingName "Enforce password history"
$results += Check-SecurityPolicy -policyName "MinimumPasswordLength" -expectedValue "14" -settingName "Minimum password length"
$results += Check-SecurityPolicy -policyName "MinimumPasswordAge" -expectedValue "3" -settingName "Minimum password age"
$results += Check-SecurityPolicy -policyName "MaximumPasswordAge" -expectedValue "60" -settingName "Maximum password age"
$results += Check-SecurityPolicy -policyName "PasswordComplexity" -expectedValue "1" -settingName "Password must meet complexity requirements"

# 4. Account lockout policies
$results += Check-SecurityPolicy -policyName "LockoutBadCount" -expectedValue "5" -settingName "Account lockout threshold"
$results += Check-SecurityPolicy -policyName "LockoutDuration" -expectedValue "30" -settingName "Account lockout duration"
$results += Check-SecurityPolicy -policyName "ResetLockoutCount" -expectedValue "5" -settingName "Reset account lockout counter after"

# 5. Interactive logon settings
$results += Check-SecurityPolicy -policyName "CachedLogonsCount" -expectedValue "0" -settingName "Interactive logon: Number of previous logons to cache"
$results += Check-RegistryValue -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "InactivityTimeoutSecs" -expectedValue "900" -settingName "Interactive logon: Machine inactivity limit"
$results += Check-RegistryValue -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "DontDisplayLastUserName" -expectedValue "1" -settingName "Interactive logon: Display user information when the session is locked"

# 6. Network security settings
$results += Check-SecurityPolicy -policyName "LSAAnonymousNameLookup" -expectedValue "0" -settingName "Network access: Allow anonymous SID/Name translation"
$results += Check-SecurityPolicy -policyName "RestrictAnonymousSAM" -expectedValue "1" -settingName "Network access: Do not allow anonymous enumeration of SAM accounts"
$results += Check-SecurityPolicy -policyName "RestrictAnonymous" -expectedValue "1" -settingName "Network access: Do not allow anonymous enumeration of SAM accounts and shares"
$results += Check-SecurityPolicy -policyName "NoLMHash" -expectedValue "1" -settingName "Network security: Do not store LAN Manager hash value on next password change"
$results += Check-SecurityPolicy -policyName "NTLMMinClientSec" -expectedValue "537395200" -settingName "Network security: Minimum session security for NTLM SSP based clients"

# 7. User rights assignments
$results += Check-UserRightsAssignment -rightName "SeInteractiveLogonRight" -expectedUsers "BUILTIN\Administrators" -settingName "Allow log on locally"
$results += Check-UserRightsAssignment -rightName "SeDenyInteractiveLogonRight" -expectedUsers "SKV-VER\GADI-SvcAcctRestrict, BUILTIN\Guests" -settingName "Deny log on locally"
$results += Check-UserRightsAssignment -rightName "SeRemoteInteractiveLogonRight" -expectedUsers "BUILTIN\Remote Desktop Users, BUILTIN\Administrators" -settingName "Allow log on through Terminal Services"

# 8. Device restrictions
$results += Check-RegistryValue -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AllocateDASD" -expectedValue "0" -settingName "Devices: Restrict floppy access to locally logged-on user only"
$results += Check-RegistryValue -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AllocateCDRoms" -expectedValue "1" -settingName "Devices: Restrict CD-ROM access to locally logged-on user only"

# 9. Audit policies
$results += Check-RegistryValue -path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name "SCENoApplyLegacyAuditPolicy" -expectedValue "1" -settingName "Audit: Force audit policy subcategory settings to override audit policy category settings"

# 10. Microsoft accounts
$results += Check-RegistryValue -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "NoConnectedUser" -expectedValue "3" -settingName "Accounts: Block Microsoft accounts"

# Export results to CSV
$results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

Write-Host "Validation complete. Results saved to $outputFile" -ForegroundColor Green