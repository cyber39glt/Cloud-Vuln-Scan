import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Brand, Handle, ThemeToggle } from "./brand";
import { CheckIcon } from "./icons";

const POINTS = [
  "Read-only access to AWS and Azure, enforced twice: by the client's permissions and inside the platform",
  "Findings with evidence, mapped to CIS, NIST CSF 2.0 and SOC 2",
  "Consultant review, then a frozen, fingerprinted final report",
  "Every account protected by an authenticator app; every action audit-logged",
];

/** Two-column frame for sign-in, first-run setup and invitations. */
export function AuthShell({ children }: { children: ReactNode }) {
  return (
    <div className="auth-shell">
      <aside className="auth-aside">
        <Link to="/" aria-label="Home">
          <Brand large product="Read-only cloud security assessments" />
        </Link>
        <div>
          <h2>Know exactly where your clients' clouds are exposed.</h2>
          <ul className="auth-points">
            {POINTS.map((p) => (
              <li key={p}>
                <CheckIcon />
                {p}
              </li>
            ))}
          </ul>
        </div>
        <span className="muted">
          Built by <Handle />
        </span>
      </aside>
      <main className="auth-main">
        <div className="auth-card">{children}</div>
        <div className="row-between auth-footer">
          <span>Authorized users only. Accounts are created by invitation.</span>
          <ThemeToggle small />
        </div>
      </main>
    </div>
  );
}
