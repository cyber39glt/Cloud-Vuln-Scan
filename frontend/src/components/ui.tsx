import type { ReactNode } from "react";
import { SEVERITY_LABEL } from "../format";
import { SEVERITIES, type Severity } from "../types";

export function ErrorBox({ message }: { message: string | null | undefined }) {
  if (!message) return null;
  return (
    <div className="alert alert-error" role="alert">
      {message}
    </div>
  );
}

export function Notice({ children, kind = "info" }: { children: ReactNode; kind?: "info" | "warn" | "ok" }) {
  return <div className={`alert alert-${kind}`}>{children}</div>;
}

export function Loading() {
  return <p className="muted">Loading…</p>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{SEVERITY_LABEL[severity]}</span>;
}

export function Tag({ children, kind = "neutral" }: { children: ReactNode; kind?: string }) {
  return <span className={`tag tag-${kind}`}>{children}</span>;
}

/** Severity counts as a stacked bar (SVG: no inline styles, which the CSP forbids). */
export function SeverityBar({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const total = SEVERITIES.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  if (total === 0) return <span className="muted">No findings</span>;
  let x = 0;
  return (
    <div className="sevbar">
      <svg viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">
        {SEVERITIES.map((s) => {
          const width = ((counts[s] ?? 0) / total) * 100;
          const rect = <rect key={s} x={x} y={0} width={width} height={8} className={`fill-${s}`} />;
          x += width;
          return rect;
        })}
      </svg>
      <span className="sevbar-legend">
        {SEVERITIES.filter((s) => (counts[s] ?? 0) > 0).map((s) => (
          <span key={s} className={`sev-text-${s}`}>
            {counts[s]} {SEVERITY_LABEL[s].toLowerCase()}
          </span>
        ))}
      </span>
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  // The hint sits outside the <label>, so the field's accessible name is just the label.
  return (
    <div className="field">
      <label>
        <span className="field-label">{label}</span>
        {children}
      </label>
      {hint && <span className="field-hint">{hint}</span>}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}
