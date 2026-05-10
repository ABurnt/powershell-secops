# Monitor-EntraRoleAssignments

**Domain:** Identity & Access Management (IAM) / Privileged Access Management (PAM)  
**Platform:** Standalone PowerShell 7.x  
**Auth:** Certificate-based (app registration + certificate thumbprint)

## What it does

Produces a **complete inventory** of all Entra ID role assignments and tags each one.

Every assignment is evaluated. Anomalies are highlighted in **red**; standard findings in green. All assignments appear in the CSV.

| Anomaly condition | Reason text |
|-------------------|-------------|
| Account disabled | `Disabled account holds active permissions` |
| Direct Service Principal assignment | `Entra ID role assigned directly to a Service Principal` |
| High-privilege role | `High-privilege role assignment: <role name>` |

### High-privilege role list

The following roles trigger a red anomaly flag regardless of account state:

`Global Administrator` · `Privileged Role Administrator` · `Privileged Authentication Administrator` · `User Administrator` · `Application Administrator` · `Cloud Application Administrator` · `Authentication Administrator` · `Hybrid Identity Administrator` · `Identity Governance Administrator` · `Security Administrator` · `Compliance Administrator` · `Conditional Access Administrator` · `Directory Writers` · `Directory Synchronization Accounts` · `Partner Tier1 Support` · `Partner Tier2 Support` · `Exchange Administrator` · `SharePoint Administrator` · `Teams Administrator` · `Intune Administrator` · `Groups Administrator` · `Azure AD Joined Device Local Administrator`

Edit the `$HighPrivRoles` array in the script to adjust this list for your environment.

Known approved assignments can be suppressed via the exceptions file.

## Setup

### Required Graph API permissions
```
RoleManagement.Read.All
User.Read.All
Application.Read.All
```

### Authentication

Set the following environment variables before running:

```powershell
$env:TENANT_ID        # Entra tenant ID (GUID)
$env:CLIENT_ID        # App registration client ID (GUID)
$env:CERT_THUMBPRINT  # Certificate thumbprint in Cert:\CurrentUser\My\
```

Certificate setup (one-time):
1. Create an app registration in Entra ID with the permissions listed above (Application type).
2. Generate or obtain a certificate; upload the `.cer` public key to the app registration.
3. Import the `.pfx` (private key) into `Cert:\CurrentUser\My\`.
4. Set the three environment variables above.

### Exceptions file (optional)

Copy `rbac-exceptions.json.example` to `rbac-exceptions.json` and populate it with approved assignments to suppress from the report. Each entry requires `ref_id` (the AssignmentId GUID) and `account_enabled`. A `description` field is recommended for audit trail purposes:

```json
[
  {
    "ref_id": "<AssignmentId GUID>",
    "account_enabled": true,
    "description": "Break-glass account - approved by CISO 2024-01-15"
  }
]
```

## Output

- **Console** - color-coded findings printed during execution
- **CSV** - `RBAC_Report_yyyyMMdd_HHmmss.csv` saved to the script directory
