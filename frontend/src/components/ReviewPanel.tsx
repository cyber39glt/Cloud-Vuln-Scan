import { useState, type FormEvent } from "react";
import { api } from "../api";
import { formatDate, humanize, SEVERITY_LABEL } from "../format";
import { useAction } from "../hooks";
import { SEVERITIES, type Finding, type ReviewEvent, type ReviewStatus, type Severity } from "../types";
import { ErrorBox, Field } from "./ui";

export const REVIEW_LABEL: Record<ReviewStatus, string> = {
  open: "Not reviewed",
  confirmed: "Confirmed",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
};

const NEEDS_REASON: ReviewStatus[] = ["false_positive", "accepted_risk"];

/** Record a review decision for one finding. Justification is required for false
 * positives, accepted risks and severity changes (the server enforces it too). */
export function ReviewPanel({
  finding,
  basePath,
  editable,
  onSaved,
}: {
  finding: Finding;
  basePath: string;
  editable: boolean;
  onSaved: () => void;
}) {
  const review = finding.review;
  const [status, setStatus] = useState<ReviewStatus>(review.status);
  const [severity, setSeverity] = useState<Severity | "">(review.severity_overridden ? finding.severity : "");
  const [justification, setJustification] = useState(review.justification ?? "");
  const [history, setHistory] = useState<ReviewEvent[] | null>(null);
  const { busy, error, run } = useAction();
  const reasonNeeded = NEEDS_REASON.includes(status) || severity !== "";
  const path = `${basePath}/reviews/${finding.finding_id}`;

  async function submit(event: FormEvent) {
    event.preventDefault();
    const ok = await run(async () => {
      await api.put(path, {
        status,
        severity_override: severity || null,
        justification: justification.trim() || null,
      });
      return true;
    });
    if (ok) onSaved();
  }

  async function loadHistory() {
    setHistory(await api.get<ReviewEvent[]>(`${path}/history`));
  }

  return (
    <div className="review-panel">
      <h4>Review</h4>
      {review.reviewed_by ? (
        <p className="muted">
          {REVIEW_LABEL[review.status]}
          {review.severity_overridden && ` · severity changed from ${SEVERITY_LABEL[review.original_severity]}`}
          {" · "}
          {review.reviewed_by}, {formatDate(review.reviewed_at)}
          {review.justification && <> — “{review.justification}”</>}
        </p>
      ) : (
        <p className="muted">Not reviewed yet.</p>
      )}
      {editable && (
        <form className="inline-form" onSubmit={submit}>
          <Field label="Decision">
            <select value={status} onChange={(e) => setStatus(e.target.value as ReviewStatus)}>
              {(Object.keys(REVIEW_LABEL) as ReviewStatus[]).map((s) => (
                <option key={s} value={s}>
                  {REVIEW_LABEL[s]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Severity">
            <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
              <option value="">Scanner: {SEVERITY_LABEL[review.original_severity]}</option>
              {SEVERITIES.filter((s) => s !== review.original_severity).map((s) => (
                <option key={s} value={s}>
                  Change to {SEVERITY_LABEL[s]}
                </option>
              ))}
            </select>
          </Field>
          <Field label={reasonNeeded ? "Justification (required)" : "Note (optional)"}>
            <input
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              maxLength={2000}
              required={reasonNeeded}
              minLength={reasonNeeded ? 10 : undefined}
              placeholder={reasonNeeded ? "Why? (at least 10 characters)" : ""}
            />
          </Field>
          <button className="btn btn-primary" disabled={busy}>
            Save decision
          </button>
          <ErrorBox message={error} />
        </form>
      )}
      <button type="button" className="btn-link" onClick={() => void loadHistory()}>
        Show history
      </button>
      {history && (
        <ul className="history">
          {history.length === 0 && <li className="muted">No decisions recorded yet.</li>}
          {history.map((h, i) => (
            <li key={i}>
              {formatDate(h.occurred_at)} · {h.actor}: {h.previous_status ? `${humanize(h.previous_status)} → ` : ""}
              <strong>{REVIEW_LABEL[h.status]}</strong>
              {h.severity_override && ` (severity ${SEVERITY_LABEL[h.severity_override]})`}
              {h.justification && <> — “{h.justification}”</>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
