<h1 align="center">Hi 👋, I'm Andrzej</h1>
<h3 align="center">SecOps and IT Administrator from Poland.</h3>

- 👨‍💻 My projects and scripts are available at [https://github.com/ABurnt/MyRepository](https://github.com/ABurnt/MyRepository)

- 📝 LinkedIn activity [https://www.linkedin.com/in/andrzej-berndt/recent-activity/shares/](https://www.linkedin.com/in/andrzej-berndt/recent-activity/shares/)

- 💬 Let's talk about **Security and Automation** 

- 📫 How to reach me **andrzej.berndt@outlook.com**

<h3 align="left">Connect with me:</h3>
<p align="left">
<a href="https://www.linkedin.com/in/andrzej-berndt/" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="https://www.linkedin.com/feed/" height="30" width="40" /></a>
</p>

<h3 align="left">Technologies & Skills</h3>
<p align="left">
  <a href="https://learn.microsoft.com/powershell/" target="_blank" rel="noreferrer">
    <img src="https://upload.wikimedia.org/wikipedia/commons/a/af/PowerShell_Core_6.0_icon.png" alt="PowerShell" width="40" height="40"/>
  </a>
  <a href="https://azure.microsoft.com/" target="_blank" rel="noreferrer">
    <img src="https://www.vectorlogo.zone/logos/microsoft_azure/microsoft_azure-icon.svg" alt="Azure" width="40" height="40"/>
  </a>
  <a href="https://www.microsoft.com/" target="_blank" rel="noreferrer">
    <img src="https://www.vectorlogo.zone/logos/microsoft/microsoft-icon.svg" alt="Windows" width="40" height="40"/>
  </a>
  <a href="https://www.linux.org/" target="_blank" rel="noreferrer">
    <img src="https://www.vectorlogo.zone/logos/linux/linux-icon.svg" alt="Linux" width="40" height="40"/>
  </a>
  <a href="https://www.eset.com/fi/yritys/protect-platform/" target="_blank" rel="noreferrer">
    <img src="https://upload.wikimedia.org/wikipedia/commons/6/63/ESET_antivir_7_logo.png" alt="ESET" width="40" height="40"/>
  </a>
    <a href="https://www.crowdstrike.com/en-us/" target="_blank" rel="noreferrer">
    <img src="https://companieslogo.com/img/orig/CRWD-442a5e7d.png" alt="ESET" width="40" height="40"/>
  </a>
</p>

<ul>
  <li>AV/EDR: administration, policy management, incident analysis</li>
  <li>SIEM: KQL (Microsoft Sentinel) & EQL (Elastic/Kibana) - Machine Learning jobs, alerts, exceptions</li>
  <li>PowerShell: automation, hardening, deployment scripting</li>
  <li>Azure/Entra ID hardening: reporting, monitoring, targeted modifications</li>
  <li>Windows & Linux system administration</li>
</ul>

# PowerShell SecOps Toolkit

A collection of production-grade PowerShell scripts for security operations and identity governance.

**Author:** Andrzej Berndt  
**Stack:** PowerShell 7.x · Microsoft Graph API · NIST NVD API

---

## Directory Structure

```
ps-secops/
├── setup/
│   └── New-GraphAuthCertificate.ps1   # One-time cert setup for all Graph scripts
│
├── 01-entra-guest-cleanup/
│   └── Remove-InactiveEntraGuests.ps1 # Guest account lifecycle cleanup
│
├── 02-cve-by-cpe/
│   └── Get-CVEsByCPE.ps1              # CVE intel by CPE watch list
│
├── 03-entra-rbac-monitor/
│   └── Monitor-EntraRoleAssignments.ps1 # Entra ID RBAC audit & anomaly detection
│
├── 04-ai-shadow-audit/
│   └── Get-EntraAIAppsAudit.ps1       # AI/LLM shadow app discovery
│
└── 05-app-cleanup/
    └── Remove-DisabledUsersFromApps.ps1 # App access cleanup on offboarding
```

---

## Script Catalog

### Identity & Access Management

| Script | Description |
|--------|-------------|
| [Monitor-EntraRoleAssignments](./03-entra-rbac-monitor/) | Full inventory of all Entra ID role assignments. Flags anomalies in red: disabled accounts with active roles, direct Service Principal assignments and assignments to high-privilege roles (Global Administrator, Privileged Role Administrator and 20 others). Exports to CSV. Supports an optional exceptions file to suppress approved assignments. |
| [Get-EntraAIAppsAudit](./04-ai-shadow-audit/) | Discovers AI, Copilot and LLM applications registered in Entra ID using type, tag, name regex and publisher detection. Reports delegated and application permissions, owners and description. Use this to find shadow AI tools, over-permissioned apps and orphaned applications. |

### Identity Lifecycle

| Script | Description |
|--------|-------------|
| [Remove-InactiveEntraGuests](./01-entra-guest-cleanup/) | Audits all Entra ID guest accounts and flags disabled or inactive ones based on a configurable `-InactiveDays` threshold. Exports an activity report and a removal candidate report before prompting for confirmation. |
| [Remove-DisabledUsersFromApps](./05-app-cleanup/) | Implements the leaver step of the JML lifecycle for enterprise applications. Removes disabled users from application ownership and role assignments. Runs interactively by default; use `-Force` for scheduled/automated runs. |

### Threat Intelligence

| Script | Description |
|--------|-------------|
| [Get-CVEsByCPE](./02-cve-by-cpe/) | Queries the NIST NVD API for HIGH and CRITICAL CVEs published in the last 14 days, filtered to a configurable CPE watch list. Enriches results with PoC links from the Trickest CVE repository. Deduplicates across runs using a local tracking file. |

---

## Getting Started

### Prerequisites

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

| Component | Version |
|-----------|---------|
| PowerShell | 7.2+ |
| Microsoft.Graph | 2.x+ |

Scripts 01, 03, 04 and 05 authenticate against Microsoft Graph using a certificate. Script 02 uses an API key.

### Certificate Setup (One-Time, Scripts 01 / 03 / 04 / 05)

Run the setup script to generate a self-signed certificate and get the exact environment variable values to copy-paste:

```powershell
.\setup\New-GraphAuthCertificate.ps1
```

It will print your `$env:CERT_THUMBPRINT` and the path to the `.cer` public key file. Upload that file to your app registration in Entra ID under **Certificates & secrets → Certificates → Upload certificate**.

Then set these three environment variables before running any Graph script:

```powershell
$env:TENANT_ID        = "<your-entra-tenant-id>"
$env:CLIENT_ID        = "<your-app-registration-client-id>"
$env:CERT_THUMBPRINT  = "<thumbprint-from-setup-script>"
```

### NVD API Key (Script 02 Only)

Register for a free API key at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key), then:

```powershell
$env:NIST_API_KEY = "<your-api-key>"
```

---

## Notes

- **Script 01** (`Remove-InactiveEntraGuests`) requires an Entra ID P1 or P2 license for `SignInActivity` data. Accounts with null sign-in records may simply lack the license - review the candidate list before confirming deletion.
- **Script 02** (`Get-CVEsByCPE`) ships with a small example CPE list. Edit the `$cpeList` array in the script to match your environment's actual software stack.
- **Script 03** (`Monitor-EntraRoleAssignments`) ships with a `rbac-exceptions.json.example` file. Copy it to `rbac-exceptions.json` and populate it with approved assignments to suppress from the report.
- **Script 05** (`Remove-DisabledUsersFromApps`) writes a timestamped transcript to the script directory on every run.
