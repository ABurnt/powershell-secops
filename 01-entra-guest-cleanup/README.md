# Remove-InactiveEntraGuests

**Domain:** Identity Lifecycle / Guest Account Governance  
**Requires:** PowerShell 7.x, Microsoft.Graph module, Entra ID P1/P2 (for SignInActivity)  
**Auth:** Certificate-based (see root README)

## What it does

Audits all Entra ID guest accounts and removes those that are inactive or disabled, based on configurable thresholds. Runs interactively - always asks for confirmation before any deletion.

## Removal criteria

A guest is flagged for removal if it meets **any** of the following:

| Condition | Description |
|-----------|-------------|
| Account disabled | `AccountEnabled = false` |
| Never signed in | No interactive or non-interactive sign-in on record |
| Inactive | Last sign-in (both types) older than `-InactiveDays` days |

## Stages

1. **Activity report** - exports all guests with sign-in timestamps to `Guests_Activity_yyyyMMdd.csv`
2. **Candidate report** - exports removal candidates with reason to `Guests_For_Removal_yyyyMMdd.csv`
3. **Confirmation + deletion** - shows the list, prompts `Y/N`, then deletes

## Setup

```powershell
$env:TENANT_ID       = "<your-tenant-id>"
$env:CLIENT_ID       = "<your-app-registration-client-id>"
$env:CERT_THUMBPRINT = "<certificate-thumbprint>"
```

Required Graph API permissions (Application type):
- `User.Read.All`
- `AuditLog.Read.All` (for SignInActivity data)
- `User.EnableDisableAccount.All`
- `User.DeleteRestore.All`

See the [root README](../README.md) for certificate setup instructions.

## Usage

```powershell
# Default: flag guests inactive for 90+ days
.\Remove-InactiveEntraGuests.ps1

# Custom threshold: 180 days
.\Remove-InactiveEntraGuests.ps1 -InactiveDays 180

# Only target never-signed-in and disabled guests (no time threshold)
.\Remove-InactiveEntraGuests.ps1 -InactiveDays 0
```
