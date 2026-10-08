# Azure Connection

How the platform gets **read-only** access to a client's Azure subscription, how a
client grants it, and how to test it against your own sandbox.
Decisions: [ADR 0005](decisions/0005-cloud-access-model.md),
[ADR 0002](decisions/0002-read-only-security-boundary.md),
[ADR 0017](decisions/0017-azure-connector.md).

## How it works

```
SubtleTech's Entra application (ONE app, "multi-tenant")
        │
        │ 1. The client's admin opens a consent link once → the app appears in THEIR
        │    directory (as a "service principal"). This alone grants no access.
        │ 2. The client gives that app a custom read-only role with exactly the
        │    permissions the checks use (or, alternatively, "Reader" + "Security Reader").
        ▼
Platform asks Entra ID for a token for the CLIENT's tenant (valid ~1 hour)
        │
        ▼
GET requests to Azure Resource Manager (management.azure.com) → configuration only
```

| Term | Meaning |
|---|---|
| **Microsoft Entra ID** | Azure's identity service (formerly Azure Active Directory). |
| **Tenant** | One organization's Entra directory. Each client has its own tenant ID (a GUID). |
| **Subscription** | A billing and access boundary containing Azure resources. |
| **App registration / multi-tenant app** | An identity for software. Multi-tenant means other organizations can let it into their tenant. |
| **Service principal** | The app's representation inside a specific tenant, created by admin consent. Roles are assigned to it. |
| **Custom role** | A role the client defines with an exact list of permissions. Ours lists only `.../read` permissions. |
| **Reader / Security Reader** | Built-in roles that can read (almost) all configuration and security settings, and cannot change anything. Broader than needed; the alternative to the custom role. |
| **Azure Resource Manager (ARM)** | The API behind the Azure portal: `https://management.azure.com`. |

### The two read-only layers

1. **In the client's subscription:** by default a **custom role** with only the seven
   read permissions the checks use (below). Alternatively the built-in `Reader` and
   `Security Reader` roles. None of these can create, change or delete anything, or call
   "actions" such as `listKeys`.
2. **In the platform** (`backend/app/providers/azure/guard.py`): every Azure SDK client
   is built with a pipeline policy that runs before each request (before a token is even
   attached) and refuses anything that is not:
   - a **GET** request (writes are PUT/PATCH/DELETE; actions such as `listKeys` are POST),
   - to **`management.azure.com`** (never Key Vault, Storage or other data hosts where
     secrets and business data live),
   - for a resource type on the **allowlist** derived from the enabled rules.

### The exact permissions (custom role, recommended)

Generated from the code ([ADR 0025](decisions/0025-least-privilege-and-security-review.md));
template: `infra/azure/assessment-role.json`. No data actions.

```
Microsoft.Insights/diagnosticSettings/read     Microsoft.Sql/servers/firewallRules/read
Microsoft.Network/networkSecurityGroups/read   Microsoft.Sql/servers/read
Microsoft.Resources/subscriptions/read         Microsoft.Storage/storageAccounts/read
Microsoft.Security/pricings/read
```

The platform also adds its guard **twice** to every Azure SDK client: first, and again
just before a request is sent. The second one catches requests the SDK creates on its
own, such as automatic resource-provider registration (a write) or following a
redirect to another host.

### What the platform stores

Tenant ID and subscription ID only. **No client secrets**: the platform signs in with its
own app identity, scoped to one client tenant at a time.

## Client onboarding (what a client's administrator does)

The consultant runs `azure connect` (below), which prints the exact links and commands.

1. **Consent:** open the printed link
   `https://login.microsoftonline.com/<client-tenant>/adminconsent?client_id=<app-id>`
   while signed in as a Global Administrator, Application Administrator or Cloud
   Application Administrator → **Accept**.
2. **Role** (needs Owner or User Access Administrator on the subscription). In **Azure
   Cloud Shell**, run the two commands printed by `azure connect` (also shown on the
   client page of the dashboard). They create the custom role
   "SubtleTech Security Assessment (read-only)" for this subscription and assign it to
   the app:
   ```bash
   az role definition create --role-definition '<the JSON printed for this client>'
   az role assignment create --assignee <app-id> --role 'SubtleTech Security Assessment (read-only)' --scope /subscriptions/<sub-id>
   ```
   **Alternative** (broader access, no custom role): assign the built-in `Reader` and
   `Security Reader` roles instead (portal: subscription → **Access control (IAM)** →
   **Add role assignment**, or the fallback commands that are also printed).
3. Send the consultant the **tenant ID** and **subscription ID**.
4. To revoke access at any time: remove the role assignment(s) (and the custom role), and
   optionally delete the app from **Entra ID → Enterprise applications**.

## Testing against your sandbox

You play both SubtleTech and the client, in one free Azure account. Free of charge.

### A. Create a free Azure account
1. https://azure.microsoft.com/free → **Start free** → sign in with a Microsoft account.
2. Verify identity (phone + payment card; no charge for the free tier).
3. Portal: https://portal.azure.com. Set up **MFA** on your account if prompted.
4. Add a cost alert: search **Cost Management** → **Budgets** → **Add** → amount `5`.

### B. Register the SubtleTech app (plays "the consultancy")
1. Portal → **Microsoft Entra ID** → **App registrations** → **New registration**.
2. Name `SubtleTech Security Assessment`; **Supported account types: Accounts in any
   organizational directory (Multitenant)**; no redirect URI → **Register**.
3. Copy the **Application (client) ID** → `AZURE_CLIENT_ID` in your `.env`.
4. **Certificates & secrets** → **New client secret** → expiry **90 days** → copy the
   **Value** once → `AZURE_CLIENT_SECRET` in your `.env`.
5. **No API permissions are needed** (the default "User.Read" may stay or be removed):
   access to resources comes only from role assignments.

### C. Onboard your own subscription (plays "the client")
1. Find your **tenant ID**: Entra ID → **Overview** → *Tenant ID*.
2. Find your **subscription ID**: search **Subscriptions** → copy the ID.
3. Register and print the steps:
   ```powershell
   .\scripts\dev.ps1 clients add "Azure Sandbox"
   .\scripts\dev.ps1 azure connect --client "Azure Sandbox" --tenant-id <tenant> --subscription-id <sub>
   ```
4. In your own tenant the app already exists, so the consent step is not needed. Assign the
   two roles (portal or the printed Cloud Shell commands). Role assignments can take a few
   minutes to apply.

### D. Validate
```powershell
.\scripts\dev.ps1 azure validate --client "Azure Sandbox" --subscription-id <sub>
```
Expected:
```
[ OK ] Platform Azure identity  app ...
[ OK ] Sign in to client tenant  <tenant>
[ OK ] Expected subscription  <subscription name>
[ OK ] Permission Microsoft.Network/networkSecurityGroups/read
[ OK ] Permission Microsoft.Storage/storageAccounts/read
[ OK ] Read-only guard  Write operations are blocked locally.

Connection is ready.
```

### E. Plant test weaknesses and scan

1. In your **sandbox only**: portal → search **Deploy a custom template** → **Build your own
   template in the editor** → paste the contents of `infra/azure/sandbox-test-fixtures.json`
   → **Save** → Resource group: **Create new** `cvs-test-rg` → **Review + create** → **Create**.
   It creates four NSGs attached to nothing and one empty storage account (near-zero cost).
2. Scan:
   ```powershell
   .\scripts\dev.ps1 azure scan --client "Azure Sandbox" --subscription-id <sub>
   ```
3. Expected: `NET-001` for `cvs-test-ssh-open` and `cvs-test-all-open`, `NET-002` for
   `cvs-test-rdp-open` and `cvs-test-all-open`, nothing for `cvs-test-ssh-restricted`, and
   `AZ-STO-001` for the `cvstest…` storage account. (A test in the repository proves the
   template produces exactly these.) The scan is saved; export it with
   `assessments export`.
4. When finished, **delete the `cvs-test-rg` resource group**.

### Housekeeping
- The client secret is for development only. Let it expire or delete it when not needed;
  production will use keyless workload identity federation (decided at deployment).
- Gitleaks scans for committed secrets; never put the secret anywhere but `.env`.

## What a scan collects

| Data | API (GET, subscription-wide) | Kept |
|---|---|---|
| Network security groups | `Microsoft.Network/networkSecurityGroups` | ID, name, location, resource group, tags, **inbound custom rules** (protocol, ports, source, allow/deny, priority, name) |
| Storage accounts | `Microsoft.Storage/storageAccounts` | ID, name, location, resource group, tags, `allowBlobPublicAccess`, `supportsHttpsTrafficOnly`, `minimumTlsVersion` |
| SQL servers | `Microsoft.Sql/servers`, `{server}/firewallRules` | ID, name, location, tags, public network access, firewall rule names and IP ranges |
| Activity Log export | `Microsoft.Insights/diagnosticSettings` (subscription) | per setting: name, has a destination yes/no, enabled categories (no destination IDs) |
| Defender for Cloud | `Microsoft.Security/pricings` | plan name and tier (Free/Standard) |

Nothing else: no outbound rules, no keys, no blob or database contents.

- **Scope:** Azure lists resources across the whole subscription. `--regions uksouth,ukwest`
  keeps only resources in those locations; others are discarded, not stored.
  Subscription-wide settings (Activity Log export, Defender plans) are always kept.
- **Gaps:** if a list call is denied, that resource type is "not evaluated" and other
  types are still assessed.
- **Safety order:** the scan confirms the subscription belongs to the expected tenant and
  is enabled **before** collecting anything.
- **Known limitation:** an allow rule is reported even if a higher-priority deny rule in
  the same NSG blocks it (see the rule's limitations); Azure's built-in default rules are
  not collected because they never allow internet inbound.

## Troubleshooting

| Message | Usual cause |
|---|---|
| The platform has no Azure identity configured | `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` missing in `.env` |
| The platform app is not present in the client's tenant | Admin consent not given (or wrong tenant ID) |
| The platform app's client secret is wrong / has expired | Copy the secret **Value** (not its ID); create a new one if expired |
| Belongs to tenant …, not the one given | Tenant and subscription IDs do not belong together |
| Azure denied the request … Reader / Security Reader | Role assignments missing, on another scope, or not yet applied (wait a few minutes) |
