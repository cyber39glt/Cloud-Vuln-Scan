# Hosting Options

Where to run CloudSecura in production. **The choice is yours**: it determines cost,
where client data lives, and how the platform signs in to AWS and Azure. Whatever you
choose, the same production stack is used ([deployment.md](deployment.md),
[ADR 0026](decisions/0026-production-deployment.md)): one Linux server running Docker,
with Caddy for HTTPS.

## What matters for this platform

1. **The platform's own cloud identity is the most valuable secret.** With it (plus
   the database) someone could read every client's configuration. The best hosts let
   the platform sign in **without any stored key**.
2. **Client data location.** Findings are sensitive; pick a region that fits your
   clients' contracts and data-protection rules (for example UK or EU).
3. **Simplicity.** One server, one `docker compose` command, automatic HTTPS. No
   Kubernetes or managed container services needed at this size.
4. **Cost.** A small server (2 vCPU, 4 GB RAM, 40+ GB disk) is enough to start.

## Options

| | **A. Azure virtual machine** | **B. AWS EC2 / Lightsail** | **C. Hetzner Cloud (or similar VPS)** |
|---|---|---|---|
| Server | Ubuntu VM, B-series (2 vCPU / 4 GB) | Ubuntu EC2 t3.medium-class or Lightsail | CX/CPX-class VPS (2 vCPU / 4 GB) |
| Typical cost | Highest of the three (tens of USD/month) | Mid (tens of USD/month) | Lowest (a few EUR/month) |
| Platform → AWS sign-in | **Keyless possible**: the VM's managed identity token exchanged at AWS STS (`AssumeRoleWithWebIdentity`) | **Keyless today**: the server's IAM role; the code already uses it automatically | Access key stored on the server (can only call `sts:AssumeRole`) |
| Platform → Azure sign-in | **Keyless possible**: managed identity as the app's federated credential (Microsoft lists it as *preview*) | Keyless possible via AWS outbound identity federation (new) | Client secret or certificate stored on the server |
| Code work needed for keyless | Azure: small (a new credential type). AWS: small (token refresh) | Azure: small (a new credential type) | None (keys) |
| Backups | Azure Backup / disk snapshots + the built-in nightly dumps | EBS snapshots + nightly dumps | Hetzner snapshots/backups + nightly dumps |
| Console complexity | Medium | Medium (Lightsail: low) | Low |

Costs vary by region and change often: check the providers' pricing pages before
deciding.

## Recommendation

- **Best security for a security consultancy: A (Azure VM)** or **B (AWS)**. Either
  removes the stored platform keys once the matching keyless sign-in is enabled, and
  you already need accounts in both clouds to assess clients. Choose the cloud you
  are most comfortable administering; pick a region that fits your clients.
- **Lowest cost and simplest: C (Hetzner or a similar VPS)**. Acceptable to start:
  the stored AWS key can only *request* client roles (each also needs its ExternalId),
  and the Azure secret is short-lived (rotate it every 90 days or use a certificate).
  Plan to move to keyless access before serving many clients.

In every case: server disk encryption on, SSH by key only, a firewall that allows
only ports 22 (ideally from your IP only), 80 and 443, and off-server backups.

## Sources

- Microsoft: [Access cloud resources across tenants without secrets](https://devblogs.microsoft.com/identity/access-cloud-resources-across-tenants-without-secrets/) (managed identity as a federated identity credential, preview)
- AWS: [Access AWS resources from Microsoft Entra ID tenants using AWS STS](https://aws.amazon.com/blogs/security/how-to-access-aws-resources-from-microsoft-entra-id-tenants-using-aws-security-token-service/)
- AWS: [Federating AWS identities to external services](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound.html) (outbound identity federation)
