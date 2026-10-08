# Deploying CloudSecura

Step by step, on one Linux server with Docker. Works the same on Azure, AWS, Hetzner
or any other provider ([hosting.md](hosting.md) compares them). Design:
[ADR 0026](decisions/0026-production-deployment.md).

```
Internet ──443──► Caddy (HTTPS, automatic certificates) ──► API ──► PostgreSQL
                                                    worker ─┘   └──► client clouds (read-only)
```

What you get: automatic HTTPS (Let's Encrypt), HTTP redirected to HTTPS, a database
not reachable from outside, an API without internet access, read-only containers
without Linux capabilities, a restricted database login for the application, nightly
database dumps, and log rotation.

## 1. Before you start

- A **domain name** you control, for example `cloudsecura.example.com`.
- A **server**: Ubuntu 24.04 LTS, 2 vCPU, 4 GB RAM, 40 GB disk or more, disk
  encryption on (default on most providers). Add your **SSH public key** when creating
  it; do not use password login.
- **Firewall** (provider's network firewall or security group): allow inbound
  **22** (SSH, ideally only from your own IP address), **80** and **443**. Nothing else.

From Windows, connect with PowerShell: `ssh <user>@<server-ip>` (all commands below
run on the server).

## 2. Point your domain at the server

At your DNS provider, create an **A record** for `cloudsecura.example.com` with the
server's public IPv4 address (and an AAAA record if it has IPv6). Wait until
`ping cloudsecura.example.com` shows that address.

## 3. Install Docker

Follow the official guide, "Install Docker Engine on Ubuntu" (apt repository method):
https://docs.docker.com/engine/install/ubuntu/ . Then let your user run it:

```bash
sudo usermod -aG docker $USER   # log out and back in afterwards
docker run --rm hello-world     # checks the installation
```

Turn on automatic security updates: `sudo apt install unattended-upgrades`.

## 4. Get the code

The repository is private, so give the server **read-only** access with a deploy key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/cloudsecura_deploy -N ""
cat ~/.ssh/cloudsecura_deploy.pub
```

On GitHub: repository → **Settings → Deploy keys → Add deploy key** → paste it, leave
"Allow write access" **unticked**. Then:

```bash
GIT_SSH_COMMAND="ssh -i ~/.ssh/cloudsecura_deploy" \
  git clone git@github.com:cyber39glt/Cloud-Vuln-Scan.git cloudsecura
cd cloudsecura
git config core.sshCommand "ssh -i ~/.ssh/cloudsecura_deploy"
```

## 5. Create the settings (once)

```bash
cd deploy
./init-env.sh
```

It asks for the domain, an e-mail for certificate notices and the consultancy name,
then writes `deploy/.env` with fresh random secrets (readable only by you).
**Back up `deploy/.env` in your password manager**: `APP_SECRET_KEY` cannot be
changed later without invalidating every MFA enrolment and every stored signature.

## 6. Start it

```bash
docker compose -f compose.prod.yml up -d --build
docker compose -f compose.prod.yml ps        # all "running"/"healthy" after a minute
```

The first start builds the image (a few minutes), creates the database, runs the
migrations as the owner login and creates the restricted application login.
Caddy then obtains the HTTPS certificate (needs DNS from step 2).

## 7. Create the first administrator

```bash
docker compose -f compose.prod.yml exec api python -m app.cli users setup-code
```

Open `https://cloudsecura.example.com` → **Set up this installation** → enter the code,
your details, and set up your authenticator app. Invite colleagues from **Users**.

## 8. Give the platform its cloud identity

Without it, scans fail with a clear message. Add the values to `deploy/.env`, then
`docker compose -f compose.prod.yml up -d` (only the worker uses them).

- **AWS:** create the platform identity as in [aws-connection.md](aws-connection.md)
  (section A): its only permission is `sts:AssumeRole` on client assessment roles.
  - On an **AWS server**, attach that permission to the server's **IAM role** instead and
    leave the keys empty: the platform uses the role automatically, no keys stored.
  - Elsewhere: set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`; rotate every 90 days.
- **Azure:** register the multi-tenant app as in [azure-connection.md](azure-connection.md)
  (section B); set `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` (expiry 90 days at most).
  Keyless sign-in from an Azure server (managed identity) is planned once the host is
  chosen ([hosting.md](hosting.md)).

## 9. Updating

```bash
cd ~/cloudsecura && git pull
cd deploy && docker compose -f compose.prod.yml up -d --build
```

Migrations run automatically; the database is kept. Read the release notes (commit
messages) before updating.

## 10. Backups and restore

- The `backup` container writes a compressed dump every 24 hours to the `backups`
  volume and keeps 14 days. List them:
  `docker compose -f compose.prod.yml exec backup ls -l /backups`
- **Copy them off the server** (a dump on the same disk does not survive losing the
  server): for example your provider's volume snapshots, or
  `docker compose -f compose.prod.yml cp backup:/backups ./backups-copy` followed by
  `chmod -R go-rwx ./backups-copy` and an encrypted upload to storage you control.
  Dumps contain client findings: keep them encrypted and access-controlled.
- Also keep `deploy/.env` (step 5). Without `APP_SECRET_KEY` a restored database
  cannot verify its stored results or MFA.
- **Restore** (into an installation started with the same `deploy/.env`; tested in M14):
  ```bash
  docker compose -f compose.prod.yml up -d
  docker compose -f compose.prod.yml stop api worker
  docker compose -f compose.prod.yml exec -T db \
    pg_restore -U cloudsecura_owner -d cloudsecura --clean --if-exists < ./cloudsecura-<date>.dump
  docker compose -f compose.prod.yml up -d   # re-applies migrations and the app login
  ```
  (The dump is streamed in: the database container's file system is read-only.)
  Practise a restore once before you rely on it.

## 11. Day to day

| Task | Command (in `deploy/`) |
|---|---|
| Status | `docker compose -f compose.prod.yml ps` |
| Logs | `docker compose -f compose.prod.yml logs --tail=100 api worker caddy` |
| Health | `curl https://cloudsecura.example.com/health` |
| Restart | `docker compose -f compose.prod.yml restart api worker` |
| Network range clash | set `EDGE_NET=172.31.251` (any free private /29 prefix) in `deploy/.env` |
| Unlock a user / new MFA | the **Users** page, or `... exec api python -m app.cli users reset-password --email ...` |

## Security checklist

- [ ] SSH key login only; SSH port restricted to your IP; automatic updates on.
- [ ] Only ports 22, 80, 443 open; database not published (it is not, by design).
- [ ] `deploy/.env` backed up in a password manager; never committed or e-mailed.
- [ ] Backups copied off the server, encrypted; a test restore done.
- [ ] Platform cloud keys rotated every 90 days, or keyless (server role / managed identity).
- [ ] `https://<domain>` shows a valid certificate; `http://` redirects to it.
