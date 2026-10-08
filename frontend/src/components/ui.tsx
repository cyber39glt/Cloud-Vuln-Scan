import { useEffect, useRef, useState, type ReactNode, type RefObject } from "react";
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

/** Width of an element in pixels, kept up to date (charts draw at real size so
 * gaps and rounded ends stay crisp). Falls back to a default where unsupported. */
export function useWidth<T extends Element>(fallback = 320): [RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    const element = ref.current;
    if (!element || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => {
      if (entry) setWidth(Math.max(40, Math.floor(entry.contentRect.width)));
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}

const GAP = 2; // px of surface between touching segments

/** Severity counts as one stacked bar, with a legend (SVG: no inline styles, which
 * the CSP forbids). Hovering a segment shows its count. */
export function SeverityBar({ counts, legend = true }: { counts: Partial<Record<Severity, number>>; legend?: boolean }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const total = SEVERITIES.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  if (total === 0) return <span className="muted">No findings</span>;
  const present = SEVERITIES.filter((s) => (counts[s] ?? 0) > 0);
  const usable = width - GAP * (present.length - 1);
  let x = 0;
  return (
    <div className="sevbar" ref={ref}>
      <svg viewBox={`0 0 ${width} 8`} height={8} role="img" aria-label={present.map((s) => `${counts[s]} ${SEVERITY_LABEL[s]}`).join(", ")}>
        {present.map((s) => {
          const w = Math.max(2, ((counts[s] ?? 0) / total) * usable);
          const rect = (
            <rect key={s} x={x} y={0} width={w} height={8} rx={2} className={`fill-${s}`}>
              <title>{`${SEVERITY_LABEL[s]}: ${counts[s]}`}</title>
            </rect>
          );
          x += w + GAP;
          return rect;
        })}
      </svg>
      {legend && (
        <span className="sevbar-legend">
          {present.map((s) => (
            <span key={s} className={`sev-text-${s}`}>
              <i className={`dot dot-${s}`} />
              {counts[s]} {SEVERITY_LABEL[s].toLowerCase()}
            </span>
          ))}
        </span>
      )}
    </div>
  );
}

/** One horizontal bar per severity, on a shared scale, value at the tip. */
export function SeverityBars({ counts }: { counts: Record<Severity, number> }) {
  const [ref, width] = useWidth<HTMLDivElement>(240);
  const max = Math.max(1, ...SEVERITIES.map((s) => counts[s]));
  return (
    <div className="hbar-chart" ref={ref}>
      {SEVERITIES.map((s) => {
        const w = counts[s] > 0 ? Math.max(4, (counts[s] / max) * width) : 0;
        return (
          <div className="hbar-row" key={s}>
            <span className="hbar-label">
              <i className={`dot dot-${s}`} />
              {SEVERITY_LABEL[s]}
            </span>
            <svg viewBox={`0 0 ${width} 14`} height={14} aria-hidden="true">
              <rect x={0} y={5} width={width} height={4} rx={2} className="fill-track" />
              {w > 0 && (
                <rect x={0} y={1} width={w} height={12} rx={4} className={`fill-${s}`}>
                  <title>{`${SEVERITY_LABEL[s]}: ${counts[s]}`}</title>
                </rect>
              )}
            </svg>
            <span className="hbar-value">{counts[s]}</span>
          </div>
        );
      })}
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

export function PageHeader({
  title,
  subtitle,
  actions,
  eyebrow,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  eyebrow?: string;
}) {
  return (
    <div className="page-header">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}
