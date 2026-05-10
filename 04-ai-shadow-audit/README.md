# Get-EntraAIAppsAudit

**Domain:** AI Governance / Shadow IT Detection  
**Requires:** PowerShell 7.x, Microsoft.Graph module  
**Auth:** Certificate-based (see root README)

## What it does

Discovers AI, LLM, and Copilot applications registered in Entra ID using multiple detection strategies. Exports a full audit report with permissions and ownership details.

Use this report to:
- Identify **shadow AI tools** introduced without IT/security approval
- Detect applications with **excessive Graph API permissions** (Mail.Read, Files.ReadWrite, etc.)
- Find applications **without an owner** (orphaned apps)
- Audit **native Copilot/Agent identities** introduced by Microsoft 365

## Detection strategies

| Method | Description |
|--------|-------------|
| `@odata.type` | Native Entra Agent Identity type |
| `ServicePrincipalType` | ServiceIdentity type |
| `Tags` | "AgentIdentity" tag |
| Display name regex | Matches: AI, Agent, Copilot, ChatGPT, OpenAI, Claude, Gemini, Perplexity, Jasper, Bot, PVA, LLM, GenAI, GPT |
| Publisher name | Exact match: OpenAI, Anthropic, Midjourney |

## Setup

```powershell
$env:TENANT_ID       = "<your-tenant-id>"
$env:CLIENT_ID       = "<your-app-registration-client-id>"
$env:CERT_THUMBPRINT = "<certificate-thumbprint>"
```

See the [root README](../README.md) for certificate setup instructions.

## Usage

```powershell
.\Get-EntraAIAppsAudit.ps1
```

Output: `Entra_AI_Agents_Audit_yyyyMMdd.csv` in the script directory.

## Output fields

`AppName`, `AppId`, `Publisher`, `Description`, `Owners`, `Type`, `DelegatedPermissions`, `ApplicationPermissions`
