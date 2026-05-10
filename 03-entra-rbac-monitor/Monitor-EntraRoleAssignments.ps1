<#
.SYNOPSIS
    Monitors Entra ID role assignments for anomalies and outputs findings to console and CSV.

.DESCRIPTION
    On-demand standalone script. Retrieves all active Entra ID role assignments across all
    principal types and exports a complete privilege inventory. Each assignment is evaluated
    and tagged:

    - [FOUND] Disabled account that still holds an active role assignment
    - [FOUND] Service Principal with a direct Entra ID role assignment
    - [FOUND] Active enabled user account with a role assignment

    All assignments are included in the CSV output. Anomalies are highlighted in the console.
    An optional JSON exceptions file can be used to suppress known/approved assignments.

.NOTES
    Author         : Andrzej Berndt
    Platform       : Standalone PowerShell 7.x
    Requires       : Microsoft.Graph modules

    Authentication — Certificate-based:
        TENANT_ID        Entra tenant ID (GUID)
        CLIENT_ID        App registration client ID (GUID)
        CERT_THUMBPRINT  Certificate thumbprint in Cert:\CurrentUser\My\

        Certificate setup (one-time):
        1. Create an app registration with the required Graph API permissions (Application type).
        2. Generate or obtain a certificate; upload the .cer public key to the app registration.
        3. Import the .pfx (private key) into the current user certificate store.
        4. Set the three environment variables above.

    Required Graph API permissions:
      - RoleManagement.Read.All
      - User.Read.All
      - Application.Read.All

    (Optional) Create an exceptions file at .\rbac-exceptions.json to suppress known assignments.
    See rbac-exceptions.json.example in this directory for the format.
#>

Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.Governance
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Identity.DirectoryManagement
Import-Module Microsoft.Graph.Authentication

# Authentication — Certificate-based
$TenantId       = $env:TENANT_ID
$ClientId       = $env:CLIENT_ID
$CertThumbprint = $env:CERT_THUMBPRINT

if (-not $TenantId -or -not $ClientId -or -not $CertThumbprint) {
    throw "Missing required environment variables. Ensure TENANT_ID, CLIENT_ID, and CERT_THUMBPRINT are set."
}

Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertThumbprint -NoWelcome

$AllRoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
$AllAssignments     = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal

$Results = foreach ($Assignment in $AllAssignments) {
    $RoleDef = $AllRoleDefinitions | Where-Object { $_.Id -eq $Assignment.RoleDefinitionId }
    if ($RoleDef) {
        [PSCustomObject]@{
            RoleName       = $RoleDef.DisplayName
            RoleIsCustom   = $RoleDef.IsBuiltIn -eq $false
            PrincipalName  = $Assignment.Principal.AdditionalProperties["displayName"]
            PrincipalType  = $Assignment.Principal.AdditionalProperties["@odata.type"]
            AssignmentId   = $Assignment.Id
            AccountEnabled = $Assignment.Principal.AdditionalProperties["accountEnabled"]
        }
    }
}

Disconnect-MgGraph

# Load exceptions — suppress known approved assignments
$ExceptionsList = @()
$ExceptionsFile = "$PSScriptRoot\rbac-exceptions.json"
if (Test-Path $ExceptionsFile) {
    try {
        $ExceptionsList = Get-Content $ExceptionsFile -Raw | ConvertFrom-Json
        Write-Host "Loaded $($ExceptionsList.Count) exception(s) from $ExceptionsFile" -ForegroundColor DarkGray
    }
    catch {
        Write-Warning "Could not parse exceptions file: $_"
    }
}

$HighPrivRoles = @(
    'Global Administrator'
    'Privileged Role Administrator'
    'Privileged Authentication Administrator'
    'User Administrator'
    'Application Administrator'
    'Cloud Application Administrator'
    'Authentication Administrator'
    'Hybrid Identity Administrator'
    'Identity Governance Administrator'
    'Security Administrator'
    'Compliance Administrator'
    'Conditional Access Administrator'
    'Directory Writers'
    'Directory Synchronization Accounts'
    'Partner Tier1 Support'
    'Partner Tier2 Support'
    'Exchange Administrator'
    'SharePoint Administrator'
    'Teams Administrator'
    'Intune Administrator'
    'Groups Administrator'
    'Azure AD Joined Device Local Administrator'
)

Write-Host "`n=== Entra ID RBAC Inventory — $(Get-Date -Format 'yyyy-MM-dd HH:mm') ===" -ForegroundColor Cyan

$reportRows = @()
$anomalyCount = 0
$skippedCount = 0

foreach ($result in $Results) {

    $exceptionRule = $ExceptionsList | Where-Object {
        ($_.ref_id -eq $result.AssignmentId) -and
        ($_.account_enabled -eq $result.AccountEnabled)
    }

    if ($exceptionRule) {
        Write-Host "[SKIP] Exception applies: $($result.PrincipalName) (ref: $($result.AssignmentId))" -ForegroundColor DarkGray
        $skippedCount++
        continue
    }

    # Evaluate anomaly conditions
    $anomalies = @()
    if ($result.AccountEnabled -eq $false) {
        $anomalies += "Disabled account holds active permissions"
    }
    if ($result.PrincipalType -eq '#microsoft.graph.servicePrincipal') {
        $anomalies += "Entra ID role assigned directly to a Service Principal"
    }
    if ($HighPrivRoles -contains $result.RoleName) {
        $anomalies += "High-privilege role assignment: $($result.RoleName)"
    }

    $isAnomaly   = $anomalies.Count -gt 0
    $status      = "FOUND"
    $reasonText  = if ($isAnomaly) { $anomalies -join "; " } else { "Active role assignment" }
    $principalType = $result.PrincipalType -replace '#microsoft\.graph\.', ''

    $headerColor = if ($isAnomaly) { 'Red' }    else { 'Green' }
    $detailColor = if ($isAnomaly) { 'Yellow' } else { 'Green' }
    $reasonColor = if ($isAnomaly) { 'Red' }    else { 'Green' }

    Write-Host "`n[FOUND] $($result.PrincipalName)" -ForegroundColor $headerColor
    Write-Host "  Role         : $($result.RoleName)$(if ($result.RoleIsCustom) { ' (Custom)' })" -ForegroundColor $detailColor
    Write-Host "  Principal    : $principalType" -ForegroundColor $detailColor
    Write-Host "  Acct Enabled : $($result.AccountEnabled)" -ForegroundColor $detailColor
    Write-Host "  Reason       : $reasonText" -ForegroundColor $reasonColor
    Write-Host "  Assignment ID: $($result.AssignmentId)" -ForegroundColor DarkGray

    if ($isAnomaly) { $anomalyCount++ }

    $reportRows += [PSCustomObject]@{
        Status         = $status
        PrincipalName  = $result.PrincipalName
        PrincipalType  = $principalType
        RoleName       = $result.RoleName
        RoleIsCustom   = $result.RoleIsCustom
        AccountEnabled = $result.AccountEnabled
        Reason         = $reasonText
        AssignmentId   = $result.AssignmentId
        ReviewUrl      = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles"
        DetectedAt     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
}

Write-Host "`n=== Summary: $($reportRows.Count) found | $anomalyCount with anomaly reason | $skippedCount skipped ===" -ForegroundColor Cyan

if ($reportRows.Count -gt 0) {
    $outputPath = "$PSScriptRoot\RBAC_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $reportRows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Report saved: $outputPath" -ForegroundColor Green
}
