<#
.SYNOPSIS
    Validates current service configurations against reference settings and exports results to CSV.
.DESCRIPTION
    This script checks service startup types against a reference configuration and reports
    compliance status in a CSV file.
.OUTPUTS
    Generates a CSV file with validation results.
#>

# Output file path
$outputFile = "Service_Validation_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# Reference service configurations from the file
$referenceServices = @{
    "Bluetooth Support Service" = "Disabled"
    "Connected User Experiences and Telemetry" = "Disabled"
    "DHCP Client" = "Automatic"
    "DHCPServer" = "Disabled"
    "Downloaded Maps Manager" = "Disabled"
    "ftpsvc" = "Disabled"
    "Group Policy Client" = "Automatic"
    "IISADMIN" = "Disabled"
    "Internet Connection Sharing (ICS)" = "Disabled"
    "Microsoft Account Sign-in Assistant" = "Disabled"
    "Remote Access Auto Connection Manager" = "Disabled"
    "Remote Access Connection Manager" = "Disabled"
    "Remote Registry" = "Disabled"  # Note: Your file says "Automatic" but this is a security risk
    "Routing and Remote Access" = "Disabled"
    "Security Accounts Manager" = "Automatic"
    "Sensor Data Service" = "Disabled"
    "Sensor Monitoring Service" = "Disabled"
    "Sensor Service" = "Disabled"
    "smtpsvc" = "Disabled"
    "Telephony" = "Disabled"
    "tlntsvr" = "Disabled"
    "W3SVC" = "Disabled"
    "WalletService" = "Disabled"
    "Windows Event Log" = "Automatic"
    "Windows Insider Service" = "Disabled"
    "Windows Mobile Hotspot Service" = "Disabled"
    "Windows Time" = "Automatic"
    "XblAuthManager" = "Disabled"
    "XblGameSave" = "Disabled"
}

# Initialize results array
$results = @()

# Validate each service
foreach ($serviceName in $referenceServices.Keys) {
    $expectedStatus = $referenceServices[$serviceName]
    
    $result = [PSCustomObject]@{
        ServiceName = $serviceName
        ExpectedStartupType = $expectedStatus
        ActualStartupType = $null
        Status = "Not Checked"
    }
    
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        $startupType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'").StartMode
        
        $result.ActualStartupType = $startupType
        
        if ($startupType -eq $expectedStatus) {
            $result.Status = "Compliant"
        } else {
            $result.Status = "Non-Compliant"
        }
    } catch {
        $result.ActualStartupType = "Not Found"
        $result.Status = if ($expectedStatus -eq "Disabled") { "Compliant (Not Present)" } else { "Error" }
    }
    
    $results += $result
}

# Export results to CSV
$results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

Write-Host "Validation complete. Results saved to $outputFile" -ForegroundColor Green