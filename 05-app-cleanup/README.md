# Remove-DisabledUsersFromApps

**Domain:** Identity Lifecycle Management  
**Requires:** PowerShell 7.x, Microsoft.Graph module  
**Auth:** Certificate-based (see root README)

## What it does

Secures the employee offboarding process by automatically revoking access to enterprise applications.

When a user account is disabled in Entra ID (e.g., during offboarding), this script automatically removes their presence from:
- **Application ownership** - disabled users who own enterprise apps or service principals
- **Application role assignments** - disabled users with app roles (members) in enterprise apps

This prevents offboarded employees from retaining residual access to enterprise applications even after their account is disabled.

## Setup

```powershell
$env:TENANT_ID       = "<your-tenant-id>"
$env:CLIENT_ID       = "<your-app-registration-client-id>"
$env:CERT_THUMBPRINT = "<certificate-thumbprint>"
```

Required Graph API permissions (Application type):
- `Application.ReadWrite.All`
- `AppRoleAssignment.ReadWrite.All`
- `User.Read.All`

See the [root README](../README.md) for certificate setup instructions.

## Usage

```powershell
# Interactive - shows findings table, prompts Y/N before removing
.\Remove-DisabledUsersFromApps.ps1

# Unattended - skips confirmation prompt (for scheduled/automated runs)
.\Remove-DisabledUsersFromApps.ps1 -Force
```

A timestamped transcript log is written to the script directory automatically.

## Scheduling

Recommended: run daily via Task Scheduler. Always pass `-Force` for unattended runs.

```powershell
# Task Scheduler example (runs daily at 02:00)
$action  = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NonInteractive -File C:\Scripts\Remove-DisabledUsersFromApps.ps1 -Force"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
Register-ScheduledTask -TaskName "EntraAppCleanup" -Action $action -Trigger $trigger -RunLevel Highest
```

## Safety

The script only removes accounts where `AccountEnabled = $false`. Active accounts are never touched. Safe to run repeatedly - idempotent by design.
