import { Link } from "react-router-dom";
import { Brand, SiteFooter, ThemeToggle } from "../components/brand";
import {
  CloudIcon,
  EyeIcon,
  FileIcon,
  KeyIcon,
  ListCheckIcon,
  LockIcon,
  MapIcon,
  ReviewIcon,
  ShieldIcon,
} from "../components/icons";
import { SeverityBars } from "../components/ui";
import { useApi } from "../hooks";

// Public showcase: what the platform does. Static content only: no client data is
// ever shown here, and nothing on this page needs an account.

const FEATURES = [
  {
    icon: ShieldIcon,
    title: "Strictly read-only",
    text: "Read-only cloud roles on the client side, and a guard inside the platform that blocks any call that is not a read before it leaves.",
  },
  {
    icon: CloudIcon,
    title: "AWS and Azure",
    text: "AWS through a role with an ExternalId; Azure through a multi-tenant app with Reader roles. No agents, nothing installed.",
  },
  {
    icon: ListCheckIcon,
    title: "19 security checks",
    text: "Identity, storage, network exposure, databases, logging and Defender. Every check records whether it passed, failed or could not be evaluated.",
  },
  {
    icon: EyeIcon,
    title: "Evidence for every finding",
    text: "The exact configuration observed and the API call it came from, so every finding can be verified.",
  },
  {
    icon: MapIcon,
    title: "Framework mapping",
    text: "Findings linked to CIS Benchmarks, NIST CSF 2.0 and SOC 2 controls, with unverified references clearly marked.",
  },
  {
    icon: ReviewIcon,
    title: "Consultant review",
    text: "Confirm, mark false positives, accept risks or adjust severity, always with a written reason and a full history.",
  },
  {
    icon: FileIcon,
    title: "Client-ready reports",
    text: "PDF, CSV and JSON from one dataset. Finalizing freezes the reviewed report with a SHA-256 fingerprint.",
  },
  {
    icon: LockIcon,
    title: "Secure by default",
    text: "Mandatory authenticator-app MFA, per-client access for consultants, and an append-only audit log.",
  },
  {
    icon: KeyIcon,
    title: "Invitation only",
    text: "No public sign-up. Administrators invite people with one-time links that expire.",
  },
];

const STEPS = [
  { title: "Connect", text: "The client grants read-only access with a ready-made template or two role assignments." },
  { title: "Scan", text: "A background worker collects configuration and runs every check, with live progress." },
  { title: "Review", text: "Consultants confirm each finding, record decisions and adjust severities." },
  { title: "Report", text: "Finalize to freeze the reviewed report, then deliver it as PDF, CSV or JSON." },
];

const CHECKS = [
  ["NET-001", "SSH open to the internet (AWS, Azure)"],
  ["NET-002", "RDP open to the internet (AWS, Azure)"],
  ["AWS-IAM-001", "Root user without MFA"],
  ["AWS-IAM-002", "Root user has access keys"],
  ["AWS-IAM-003", "Console users without MFA"],
  ["AWS-IAM-004", "Access keys unused for 45+ days"],
  ["AWS-IAM-005", "Weak or missing password policy"],
  ["AWS-IAM-006", "AdministratorAccess on users or groups"],
  ["AWS-STO-001", "S3 account-level Block Public Access off"],
  ["AWS-STO-002", "Publicly accessible S3 buckets"],
  ["AWS-EXP-001", "Publicly accessible RDS databases"],
  ["AWS-LOG-001", "No multi-region CloudTrail logging"],
  ["AZ-STO-001", "Anonymous blob access allowed"],
  ["AZ-STO-002", "Storage accepts unencrypted HTTP"],
  ["AZ-STO-003", "Storage minimum TLS below 1.2"],
  ["AZ-EXP-001", "SQL firewall open to the whole internet"],
  ["AZ-EXP-002", "SQL open to all Azure services"],
  ["AZ-LOG-001", "Activity Log not exported"],
  ["AZ-SEC-001", "Defender plans not enabled"],
];

// Illustration only (clearly labelled on the page): not real data.
const SAMPLE = { critical: 2, high: 6, medium: 9, low: 3, informational: 1 };

export function LandingPage() {
  const setup = useApi<{ needed: boolean }>("/setup");
  const needsSetup = setup.data?.needed === true;

  return (
    <div className="public">
      <header className="public-nav">
        <Brand product="Read-only cloud security assessments" />
        <div className="public-nav-actions">
          <ThemeToggle small />
          {needsSetup ? (
            <Link className="btn btn-primary" to="/setup">
              Set up
            </Link>
          ) : (
            <Link className="btn btn-primary" to="/login">
              Log in
            </Link>
          )}
        </div>
      </header>

      <main>
        <section className="landing-hero">
          <div>
            <span className="pill">
              <i className="dot" />
              Read-only by design · AWS and Azure
            </span>
            <h1>
              Cloud security assessments that <em>never touch</em> what they inspect.
            </h1>
            <p className="lead">
              Find misconfigurations in your clients' AWS accounts and Azure subscriptions, back every finding with
              evidence, review it, and deliver a report mapped to CIS, NIST CSF 2.0 and SOC 2.
            </p>
            <div className="hero-actions">
              {needsSetup ? (
                <Link className="btn btn-primary btn-large" to="/setup">
                  Set up this installation
                </Link>
              ) : (
                <Link className="btn btn-primary btn-large" to="/login">
                  Log in to the dashboard
                </Link>
              )}
              <a className="btn btn-ghost btn-large" href="#features">
                See the features
              </a>
            </div>
          </div>
          <div className="preview" aria-label="Illustration of the dashboard">
            <div className="preview-bar">
              <span />
              <span />
              <span />
            </div>
            <div className="preview-tiles">
              <div className="tile tile-critical">
                <span className="tile-value">8</span>
                <span className="tile-label">Critical + high</span>
              </div>
              <div className="tile tile-accent">
                <span className="tile-value">19</span>
                <span className="tile-label">Checks</span>
              </div>
              <div className="tile tile-low">
                <span className="tile-value">3</span>
                <span className="tile-label">Frameworks</span>
              </div>
            </div>
            <SeverityBars counts={SAMPLE} />
            <p className="preview-note">Illustration with sample numbers, not real client data.</p>
          </div>
        </section>

        <section className="section" id="features">
          <div className="section-head">
            <div className="eyebrow">Features</div>
            <h2>Everything a consultancy needs for a cloud assessment</h2>
            <p>From read-only access to a reviewed, client-ready report, in one place.</p>
          </div>
          <div className="feature-grid">
            {FEATURES.map(({ icon: Icon, title, text }) => (
              <article className="feature" key={title}>
                <div className="feature-icon">
                  <Icon />
                </div>
                <h3>{title}</h3>
                <p>{text}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="section">
          <div className="section-head">
            <div className="eyebrow">How it works</div>
            <h2>Four steps from access to report</h2>
          </div>
          <div className="steps-grid">
            {STEPS.map((s) => (
              <div className="step" key={s.title}>
                <h3>{s.title}</h3>
                <p>{s.text}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="section">
          <div className="section-head">
            <div className="eyebrow">Coverage</div>
            <h2>The checks it runs today</h2>
            <p>Each finding includes what is wrong, why it matters, how to fix it, and the evidence.</p>
          </div>
          <div className="check-grid">
            {CHECKS.map(([id, title]) => (
              <div className="check-item" key={id}>
                <code>{id}</code>
                <span>{title}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="section">
          <div className="section-head">
            <div className="eyebrow">Security boundary</div>
            <h2>Defensive by construction</h2>
          </div>
          <div className="boundary">
            <div className="card">
              <h3>It does</h3>
              <ul>
                <li>Read configuration with read-only permissions</li>
                <li>Collect evidence and evaluate it with security rules</li>
                <li>Store each client's results separately, hash-verified</li>
                <li>Produce reviewed reports for the client</li>
              </ul>
            </div>
            <div className="card">
              <h3>It never</h3>
              <ul>
                <li>Exploits vulnerabilities or attacks systems</li>
                <li>Modifies, deletes or deploys anything in a client environment</li>
                <li>Changes security settings automatically</li>
                <li>Reads stored data contents or secret values</li>
              </ul>
            </div>
          </div>
        </section>

        <section className="cta">
          <h2>Ready to start?</h2>
          <p>Accounts are created by invitation from your administrator.</p>
          <Link className="btn btn-primary btn-large" to={needsSetup ? "/setup" : "/login"}>
            {needsSetup ? "Set up this installation" : "Log in"}
          </Link>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
