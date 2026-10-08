# Public Release Checklist

The repository is prepared for release (M15,
[ADR 0027](decisions/0027-licence-and-public-release.md)). These steps need the
repository owner, in GitHub. Do them in this order.

## 1. Bring the work into the main branch

All work so far is on the branch `claude/cloud-security-assessment-overview-4ycjkb`.
Open a pull request from it into `main`, check that CI is green, and merge it.
`main` is what visitors see.

## 2. Protect the repository (Settings), before it is public

- **Security** (Settings → Code security):
  - **Private vulnerability reporting: Enable.** SECURITY.md points reporters there.
  - **Dependabot alerts** and **Dependabot security updates: Enable.**
  - **Secret scanning** and **Push protection: Enable** (free for public repositories).
- **Branch protection** (Settings → Rules → Rulesets → New branch ruleset for `main`):
  require a pull request before merging, require the CI checks to pass, block force
  pushes, restrict deletions.
- **Actions** (Settings → Actions → General): workflow permissions **Read repository
  contents** (already used by CI); tick **Require approval for all outside
  collaborators** for workflows from forks.

## 3. Final look

- Read `README.md` as a newcomer would. Optionally rename the repository to
  `CloudSecura` (Settings → General; GitHub redirects the old address). If you do,
  update the links containing `cyber39glt/Cloud-Vuln-Scan` (README badges,
  SECURITY.md, CONTRIBUTING.md, `.github/ISSUE_TEMPLATE/config.yml`,
  docs/deployment.md).
- Commit messages end with a link to the Claude Code session that produced them.
  Only your account can open those links; they will be visible but are harmless.
- `SubtleTech` is the example consultancy name throughout (the default
  `CONSULTANCY_NAME`). Keep it as the example or change the default.

## 4. Make it public

Settings → General → Danger Zone → **Change repository visibility** → Public.
Everything in the git history becomes public: it was scanned for secrets (Gitleaks,
full history, in CI) and checked for personal data before release.

## 5. Publish version 0.1.0

Releases → **Draft a new release** → tag `v0.1.0` on `main` → title
"CloudSecura 0.1.0" → paste the 0.1.0 section of [CHANGELOG.md](../CHANGELOG.md)
→ mark as **pre-release** → Publish. Then change "unreleased" in CHANGELOG.md to the
release date.

## 6. After release

- Watch the Security tab (vulnerability reports, Dependabot alerts) and the pull
  requests Dependabot opens each week.
- First real-world test: run the sandbox tests in docs/aws-connection.md and
  docs/azure-connection.md, and remove the "simulated APIs only" note from the README
  once they pass.
