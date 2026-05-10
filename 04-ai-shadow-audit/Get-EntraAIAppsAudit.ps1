<#
.SYNOPSIS
    Audits AI, Copilot, and LLM-related applications registered in Entra ID.

.DESCRIPTION
    Identifies service principals (enterprise applications) that are likely AI/LLM tools
    using multiple detection strategies:
    - Entra native agent identity type (@odata.type = agentIdentity)
    - Service identity type
    - "AgentIdentity" tag
    - Display name regex matching known AI product names
      (OpenAI, Claude, Copilot, Gemini, ChatGPT, Jasper, Perplexity, PVA, LLM, GenAI, etc.)
    - Publisher matching known AI vendors (OpenAI, Anthropic, Midjourney)

    For each match, retrieves:
    - Delegated permissions (OAuth2 permission grants - on behalf of user)
    - Application permissions (app role assignments to Microsoft Graph, Exchange, etc.)
    - Application owners (UPN or display name)
    - Description / Notes field

    Output is exported to CSV for review by the security team or IT governance.
    Use this report to identify shadow AI tools, overly permissive applications,
    and applications lacking a designated owner.

.NOTES
    Author      : Andrzej Berndt
    Requires    : Microsoft.Graph.Applications, Microsoft.Graph.Authentication
    Permissions : Application.Read.All, AppRoleAssignment.ReadWrite.All (or read-equivalent)
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
#>

#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Authentication

# Authentication - Certificate-based
$TenantId       = $env:TENANT_ID
$ClientId       = $env:CLIENT_ID
$CertThumbprint = $env:CERT_THUMBPRINT

if (-not $TenantId -or -not $ClientId -or -not $CertThumbprint) {
    throw "Missing required environment variables. Ensure TENANT_ID, CLIENT_ID, and CERT_THUMBPRINT are set."
}

Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertThumbprint -NoWelcome

# AI/LLM detection pattern - extend regex to add product names
$aiRegex = "(?i)(\b|_|-)(AI|Agent|Agents|Copilot|ChatGPT|OpenAI|Claude|Gemini|Perplexity|Jasper|Bot|Bots|PVA|LLM|GenAI|GPT)(\b|_|-)"

# Retrieve Description and Notes fields for full application context
$agents = Get-MgServicePrincipal -All `
    -Property Id, DisplayName, AppId, Tags, PublisherName, ServicePrincipalType, AdditionalProperties, Description, Notes |
    Where-Object {
        ($_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.agentIdentity') -or
        ($_.ServicePrincipalType -eq 'ServiceIdentity') -or
        ($_.Tags -contains "AgentIdentity") -or
        ($_.DisplayName -match $aiRegex) -or
        ($_.PublisherName -match "\b(OpenAI|Anthropic|Midjourney)\b")
    }

$exportData = @()
$total      = $agents.Count
$counter    = 1

foreach ($agent in $agents) {
    Write-Progress -Activity "Auditing AI applications" `
        -Status "Processing $($agent.DisplayName) ($counter of $total)" `
        -PercentComplete (($counter / $total) * 100)

    # Delegated permissions (OAuth2 grants - on behalf of user)
    $delegatedGrants = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $agent.Id

    # Application permissions (app role assignments - no user context)
    $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $agent.Id |
        Where-Object { $_.PrincipalType -eq "ServicePrincipal" }
    $appPermissions = ($appRoleAssignments | Select-Object -ExpandProperty ResourceDisplayName -Unique) -join ", "

    # Owners - prefer UPN, fall back to DisplayName, then Object ID
    $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $agent.Id
    $ownerNames = $owners | ForEach-Object {
        if ($_.AdditionalProperties.userPrincipalName) {
            $_.AdditionalProperties.userPrincipalName
        } elseif ($_.AdditionalProperties.displayName) {
            $_.AdditionalProperties.displayName
        } else {
            $_.Id
        }
    }

    # Description may live in Description or Notes depending on app type
    $appDescription = $agent.Description
    if ([string]::IsNullOrWhiteSpace($appDescription)) {
        $appDescription = $agent.Notes
    }

    $exportData += [PSCustomObject]@{
        AppName                = $agent.DisplayName
        AppId                  = $agent.AppId
        Publisher              = $agent.PublisherName
        Description            = $appDescription
        Owners                 = $ownerNames -join "; "
        Type                   = if ($agent.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.agentIdentity') {
                                     "Native Agent Identity"
                                 } else {
                                     "Standard App"
                                 }
        DelegatedPermissions   = ($delegatedGrants.Scope) -join ", "
        ApplicationPermissions = $appPermissions
    }
    $counter++
}

Write-Progress -Activity "Auditing AI applications" -Completed

$outputPath = "$PSScriptRoot\Entra_AI_Agents_Audit_$(Get-Date -Format 'yyyyMMdd').csv"
$exportData | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

Disconnect-MgGraph

Write-Host "Audit complete. $($exportData.Count) AI/LLM applications found." -ForegroundColor Green
Write-Host "Report saved: $outputPath" -ForegroundColor Cyan
