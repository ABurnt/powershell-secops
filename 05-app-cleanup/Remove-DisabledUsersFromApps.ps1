<#
.SYNOPSIS
    Removes disabled Entra ID users from enterprise application ownership and membership roles.

.DESCRIPTION
    Iterates through all enterprise application service principals in the tenant and removes
    any disabled user accounts found in:
    - Application ownership (service principal owners)
    - Application role assignments (members assigned app roles)

    This script supports the lifecycle process by ensuring that
    when user accounts are disabled (e.g., on offboarding), their residual access
    to enterprise applications is automatically revoked.

    All actions are logged to a timestamped transcript file in the script directory.

.NOTES
    Author      : Andrzej Berndt
    Requires    : Microsoft.Graph.Applications, Microsoft.Graph.Authentication
    Permissions : Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, User.Read.All
    Env Vars    :
        TENANT_ID        - Entra tenant ID (GUID)
        CLIENT_ID        - App registration client ID (GUID)
        CERT_THUMBPRINT  - Certificate thumbprint in local cert store (Cert:\CurrentUser\My\)

    Certificate setup (one-time):
    1. Create an app registration in Entra ID with the required Graph API permissions (Application type).
    2. Generate a self-signed certificate or use your PKI.
    3. Upload the .cer public key file to the app registration under Certificates & secrets.
    4. Import the .pfx (private key) into the current user's certificate store.
    5. Set the three environment variables above.

    Run frequency: Recommended daily via Task Scheduler or Azure Automation.
    Safe to run repeatedly - only acts on accounts where AccountEnabled = false.

    Parameters:
        -Force  Skip the interactive confirmation prompt and proceed automatically.
                Use this flag for unattended / Azure Automation runs.
#>

#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Authentication

param(
    [switch]$Force
)

# Logging - transcript written to script directory
$logFile = Join-Path -Path $PSScriptRoot -ChildPath "Remove-DisabledUsersFromApps_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $logFile -IncludeInvocationHeader -Append

# Authentication - Certificate-based
$TenantId       = $env:TENANT_ID
$ClientId       = $env:CLIENT_ID
$CertThumbprint = $env:CERT_THUMBPRINT

if (-not $TenantId -or -not $ClientId -or -not $CertThumbprint) {
    Stop-Transcript
    throw "Missing required environment variables. Ensure TENANT_ID, CLIENT_ID and CERT_THUMBPRINT are set."
}

Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertThumbprint -NoWelcome

# Discovery - collect findings without removing anything
$servicePrincipals = Get-MgServicePrincipal `
    -Filter "servicePrincipalType eq 'Application'" `
    -ConsistencyLevel eventual `
    -All

$pendingRemovals = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "`nScanning applications for disabled user accounts..." -ForegroundColor Cyan

foreach ($sp in $servicePrincipals) {

    # Disabled owners
    $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id
    foreach ($owner in $owners) {
        $user = Get-MgUser -UserId $owner.Id `
            -Property DisplayName, Id, Mail, UserPrincipalName, AccountEnabled `
            -ErrorAction SilentlyContinue

        if ($null -ne $user -and $user.AccountEnabled -eq $false) {
            $pendingRemovals.Add([PSCustomObject]@{
                Type             = 'Owner'
                AppName          = $sp.DisplayName
                AppId            = $sp.Id
                UserUPN          = $user.UserPrincipalName
                UserId           = $user.Id
                RoleAssignmentId = $null
            })
        }
    }

    # Disabled role members (users only)
    $members = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id
    foreach ($member in $members) {
        if ($member.PrincipalType -eq "User") {
            $user = Get-MgUser -UserId $member.PrincipalId `
                -Property DisplayName, Id, Mail, UserPrincipalName, AccountEnabled `
                -ErrorAction SilentlyContinue

            if ($null -ne $user -and $user.AccountEnabled -eq $false) {
                $pendingRemovals.Add([PSCustomObject]@{
                    Type             = 'Member'
                    AppName          = $sp.DisplayName
                    AppId            = $sp.Id
                    UserUPN          = $user.UserPrincipalName
                    UserId           = $user.Id
                    RoleAssignmentId = $member.Id
                })
            }
        }
    }
}

# Display findings and confirm
if ($pendingRemovals.Count -eq 0) {
    Write-Host "`nNo disabled users found in any application. Nothing to remove." -ForegroundColor Green
    Disconnect-MgGraph | Out-Null
    Stop-Transcript
    exit
}

Write-Host "`nFound $($pendingRemovals.Count) item(s) to remove:`n" -ForegroundColor Yellow
$pendingRemovals | Format-Table -AutoSize -Property Type, AppName, UserUPN

if (-not $Force) {
    $answer = Read-Host "Proceed with removal of all $($pendingRemovals.Count) item(s)? [Y/N]"
    if ($answer -notin @('Y', 'y')) {
        Write-Host "Aborted. No changes made." -ForegroundColor Red
        Disconnect-MgGraph | Out-Null
        Stop-Transcript
        exit
    }
}

# Removal
$removedOwners  = 0
$removedMembers = 0

foreach ($item in $pendingRemovals) {
    if ($item.Type -eq 'Owner') {
        Write-Host "Removing owner : $($item.UserUPN) from app: $($item.AppName)" -ForegroundColor Yellow
        Remove-MgServicePrincipalOwnerByRef -ServicePrincipalId $item.AppId -DirectoryObjectId $item.UserId -Confirm:$false
        $removedOwners++
    } else {
        Write-Host "Removing member: $($item.UserUPN) from app: $($item.AppName)" -ForegroundColor Cyan
        Remove-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $item.AppId -AppRoleAssignmentId $item.RoleAssignmentId -Confirm:$false
        $removedMembers++
    }
}

Disconnect-MgGraph | Out-Null

Write-Host "`nCleanup complete." -ForegroundColor Green
Write-Host "  Owners removed : $removedOwners" -ForegroundColor Cyan
Write-Host "  Members removed: $removedMembers" -ForegroundColor Cyan

Stop-Transcript
