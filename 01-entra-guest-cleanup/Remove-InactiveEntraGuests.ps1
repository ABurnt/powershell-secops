<#
.SYNOPSIS
    Audits and removes inactive or disabled Entra ID guest accounts.

.DESCRIPTION
    Retrieves all guest accounts (userType eq 'Guest') from Entra ID and evaluates
    each one against configurable inactivity thresholds.

    Candidates for removal are guests that meet ANY of the following criteria:
    - Account is disabled (AccountEnabled = false)
    - No interactive or non-interactive sign-in activity has ever been recorded
    - Last sign-in (interactive or non-interactive) is older than -InactiveDays days

    The script runs in two stages:
    1. REPORT  - exports all guests with sign-in activity to CSV (always runs)
    2. CLEANUP - exports removal candidates to CSV, then prompts for confirmation
                 before deleting (interactive mode, no silent deletions)

.PARAMETER InactiveDays
    Number of days of inactivity after which a guest is considered a removal candidate.
    Defaults to 90 days. Set to 0 to only target accounts with no sign-in activity ever.

.EXAMPLE
    .\Remove-InactiveEntraGuests.ps1
    # Uses default threshold of 90 days

.EXAMPLE
    .\Remove-InactiveEntraGuests.ps1 -InactiveDays 180
    # Flags guests inactive for 6+ months

.NOTES
    Author      : Andrzej Berndt
    Requires    : Microsoft.Graph.Users, Microsoft.Graph.Authentication
    Permissions : User.Read.All, AuditLog.Read.All (for SignInActivity), User.EnableDisableAccount.All, User.DeleteRestore.All
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

    Note: A guest with null SignInActivity may have genuinely never signed in, may fall outside
    the sign-in log retention window, or the host tenant may not have P1/P2 licensing enabled.
    P1/P2 is a tenant-level requirement - individual guest accounts do not need a license assigned.
    Review the candidate list carefully before confirming deletion.
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Authentication

param (
    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 3650)]
    [int]$InactiveDays = 90
)

Clear-Host

# Authentication - Certificate-based
$TenantId       = $env:TENANT_ID
$ClientId       = $env:CLIENT_ID
$CertThumbprint = $env:CERT_THUMBPRINT

if (-not $TenantId -or -not $ClientId -or -not $CertThumbprint) {
    throw "Missing required environment variables. Ensure TENANT_ID, CLIENT_ID, and CERT_THUMBPRINT are set."
}

Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertThumbprint -NoWelcome

$cutoffDate = if ($InactiveDays -gt 0) { (Get-Date).AddDays(-$InactiveDays) } else { $null }

Write-Host "=== Entra Guest Account Cleanup ===" -ForegroundColor Cyan
Write-Host "Inactivity threshold : $InactiveDays days$(if ($cutoffDate) { " (before $($cutoffDate.ToString('yyyy-MM-dd')))" })" -ForegroundColor DarkGray
Write-Host ""

# Export full guest activity report
Write-Host "Fetching all guest accounts..." -ForegroundColor DarkGray

$guests = Get-MgUser `
    -Filter "userType eq 'Guest'" `
    -Property UserPrincipalName, DisplayName, SignInActivity, AccountEnabled, CreatedDateTime `
    -All

Write-Host "Total guests found: $($guests.Count)" -ForegroundColor Cyan

$activityReport = $guests | Select-Object `
    AccountEnabled,
    UserPrincipalName,
    DisplayName,
    @{Name = 'CreatedDateTime';              Expression = { $_.CreatedDateTime }},
    @{Name = 'LastSignIn';                   Expression = { $_.SignInActivity.LastSignInDateTime }},
    @{Name = 'LastNonInteractiveSignIn';     Expression = { $_.SignInActivity.LastNonInteractiveSignInDateTime }},
    @{Name = 'LastSignInRequestId';          Expression = { $_.SignInActivity.LastSignInRequestId }}

$activityPath = "$PSScriptRoot\Guests_Activity_$(Get-Date -Format 'yyyyMMdd').csv"
$activityReport | Export-Csv -Delimiter ";" -Encoding UTF8 -Path $activityPath -NoTypeInformation
Write-Host "Activity report saved: $activityPath" -ForegroundColor Green

# Identify removal candidates
$removalCandidates = $guests | Where-Object {
    $lastInteractive    = $_.SignInActivity.LastSignInDateTime
    $lastNonInteractive = $_.SignInActivity.LastNonInteractiveSignInDateTime

    $neverSignedIn = (-not $lastInteractive) -and (-not $lastNonInteractive)

    $inactive = if ($cutoffDate) {
        ((-not $lastInteractive)    -or ($lastInteractive    -lt $cutoffDate)) -and
        ((-not $lastNonInteractive) -or ($lastNonInteractive -lt $cutoffDate))
    } else {
        $false
    }

    (-not $_.AccountEnabled) -or $neverSignedIn -or $inactive
}

if ($removalCandidates.Count -eq 0) {
    Write-Host "`nNo guest accounts meet the removal criteria." -ForegroundColor Green
    Disconnect-MgGraph | Out-Null
    return
}

$candidateReport = $removalCandidates | Select-Object `
    UserPrincipalName,
    AccountEnabled,
    @{Name = 'LastSignIn';               Expression = { $_.SignInActivity.LastSignInDateTime }},
    @{Name = 'LastNonInteractiveSignIn'; Expression = { $_.SignInActivity.LastNonInteractiveSignInDateTime }},
    @{Name = 'RemovalReason';            Expression = {
        $reasons = @()
        if (-not $_.AccountEnabled)                                { $reasons += "Account disabled" }
        if (-not $_.SignInActivity.LastSignInDateTime -and
            -not $_.SignInActivity.LastNonInteractiveSignInDateTime) { $reasons += "Never signed in" }
        elseif ($cutoffDate -and
            ((-not $_.SignInActivity.LastSignInDateTime) -or ($_.SignInActivity.LastSignInDateTime -lt $cutoffDate)) -and
            ((-not $_.SignInActivity.LastNonInteractiveSignInDateTime) -or ($_.SignInActivity.LastNonInteractiveSignInDateTime -lt $cutoffDate))) {
            $reasons += "Inactive >$InactiveDays days"
        }
        $reasons -join "; "
    }}

$candidatePath = "$PSScriptRoot\Guests_For_Removal_$(Get-Date -Format 'yyyyMMdd').csv"
$candidateReport | Export-Csv -Delimiter ";" -Encoding UTF8 -Path $candidatePath -NoTypeInformation
Write-Host "`nRemoval candidates saved: $candidatePath" -ForegroundColor Yellow

Write-Host "`nCandidates for removal ($($removalCandidates.Count)):" -ForegroundColor Yellow
$candidateReport | Format-Table UserPrincipalName, AccountEnabled, LastSignIn, RemovalReason -AutoSize

# Confirm and delete
$confirmation = Read-Host "Delete these $($removalCandidates.Count) guest account(s)? (Y/N)"

if ($confirmation -match '^(Y|y)$') {
    $removed = 0
    $failed  = 0
    foreach ($guest in $removalCandidates) {
        try {
            Remove-MgUser -UserId $guest.UserPrincipalName -ErrorAction Stop
            Write-Host "[OK] Removed: $($guest.UserPrincipalName)" -ForegroundColor Green
            $removed++
        }
        catch {
            Write-Host "[!!] Failed: $($guest.UserPrincipalName) - $_" -ForegroundColor Red
            $failed++
        }
    }
    Write-Host "`nDone. Removed: $removed | Failed: $failed" -ForegroundColor Cyan
} else {
    Write-Host "Deletion canceled." -ForegroundColor Yellow
}

Disconnect-MgGraph | Out-Null
