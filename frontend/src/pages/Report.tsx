import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, download } from "../api";
import { REVIEW_LABEL, ReviewPanel } from "../components/ReviewPanel";
import { ErrorBox, Loading, Notice, PageHeader, SeverityBadge, SeverityBar, Tag } from "../components/ui";
import { formatDate, humanize, providerLabel, SEVERITY_LABEL, slug } from "../format";
import { useAction, useApi } from "../hooks";
import { SEVERITIES, type Finding, type Report, type Severity } from "../types";

export function ReportPage() {
  const { clientId, scanId } = useParams();
  const path = `/clients/${clientId}/scans/${scanId}/report`;
  const { data: report, error, notFound, reload } = useApi<Report>(path);
  const bulk = useAction();
  const [severities, setSeverities] = useState<Set<Severity>>(new Set());
  const [category, setCategory] = useState("");
  const [search, setSearch] = useState("");
  const downloads = useAction();

  const findings = useMemo(() => {
    const term = search.trim().toLowerCase();
    return (report?.findings ?? []).filter(
      (f) =>
        (severities.size === 0 || severities.has(f.severity)) &&
        (!category || f.category === category) &&
        (!term ||
          [f.title, f.rule_id, f.resource_name, f.resource_id, f.region, f.message]
            .filter(Boolean)
            .some((v) => v!.toLowerCase().includes(term))),
    );
  }, [report, severities, category, search]);

  if (notFound) return <Notice kind="warn">This scan does not exist or is not assigned to you.</Notice>;
  if (!report) return error ? <ErrorBox message={error} /> : <Loading />;

  const name = `${slug(report.source.client_name)}_${report.source.scan_id.slice(0, 8)}`;
  const reviewBase = `/clients/${clientId}/assessments/${report.source.assessment_id}`;
  const final = report.source.report_status === "final";
  // Reviews can change only while the assessment is not finalized.
  const editable = !final && report.source.assessment_status !== "finalized";
  const counts = report.summary.by_review_status;
  const allFindings = report.findings.length + report.accepted_risks.length + report.false_positives.length;
  const unreviewed = counts.open ?? 0;

  async function confirmRemaining() {
    if (!window.confirm(`Mark the ${unreviewed} finding(s) not yet reviewed as confirmed?`)) return;
    const done = await bulk.run(() => api.post(`${reviewBase}/reviews/confirm-remaining`, { scan_id: report!.source.scan_id }));
    if (done !== undefined) await reload();
  }
  const categories = Object.entries(report.summary.by_category).filter(([, n]) => n > 0);

  function toggle(severity: Severity) {
    const next = new Set(severities);
    if (next.has(severity)) next.delete(severity);
    else next.add(severity);
    setSeverities(next);
  }

  return (
    <>
      <PageHeader
        title={`${report.source.client_name} — ${report.source.assessment_name}`}
        subtitle={
          <>
            <Link to={`/clients/${clientId}/assessments/${report.source.assessment_id}`}>← Assessment</Link> ·{" "}
            {providerLabel(report.provider)} <code>{report.account_id}</code> · scanned {formatDate(report.scan_completed_at)}
            {" · "}regions: {report.regions.join(", ") || "all"}
          </>
        }
        actions={
          <>
            <button className="btn btn-primary" disabled={downloads.busy} onClick={() => void downloads.run(() => download(`${path}.pdf`, `${name}.pdf`))}>
              {downloads.busy ? "Preparing…" : "Download PDF report"}
            </button>
            <button className="btn" disabled={downloads.busy} onClick={() => void downloads.run(() => download(`${path}.csv`, `${name}.csv`))}>
              Download CSV
            </button>
            <button className="btn" disabled={downloads.busy} onClick={() => void downloads.run(() => download(path, `${name}.json`))}>
              Download JSON
            </button>
          </>
        }
      />
      <ErrorBox message={downloads.error} />
      {final ? (
        <Notice kind="ok">
          <strong>Final report</strong> — finalized {formatDate(report.source.finalized_at)} by {report.source.finalized_by}. This is
          the frozen, reviewed version delivered to the client; it can no longer change.
        </Notice>
      ) : (
        <Notice kind={unreviewed > 0 ? "warn" : "info"}>
          <strong>Draft</strong> — {allFindings - unreviewed} of {allFindings} findings reviewed
          {counts.false_positive ? `, ${counts.false_positive} false positive(s)` : ""}
          {counts.accepted_risk ? `, ${counts.accepted_risk} accepted risk(s)` : ""}.{" "}
          {editable &&
            (unreviewed > 0 ? (
              <button className="btn btn-small" disabled={bulk.busy} onClick={() => void confirmRemaining()}>
                Confirm all {unreviewed} remaining
              </button>
            ) : (
              <>
                All reviewed: finalize it on the{" "}
                <Link to={`/clients/${clientId}/assessments/${report.source.assessment_id}`}>assessment page</Link>.
              </>
            ))}
          <ErrorBox message={bulk.error} />
        </Notice>
      )}

      <section className="tiles">
        {SEVERITIES.map((s) => (
          <button key={s} className={`tile tile-${s} tile-button ${severities.has(s) ? "selected" : ""}`} onClick={() => toggle(s)} aria-pressed={severities.has(s)}>
            <span className="tile-value">{report.summary.by_severity[s] ?? 0}</span>
            <span className="tile-label">{SEVERITY_LABEL[s]}</span>
          </button>
        ))}
        <div className="tile">
          <span className="tile-value">{report.summary.rules_run}</span>
          <span className="tile-label">Checks run</span>
        </div>
      </section>
      <SeverityBar counts={report.summary.by_severity} />

      {report.not_evaluated.length > 0 && (
        <details className="card warn-card">
          <summary>
            <strong>{report.not_evaluated.length} check(s) could not be evaluated</strong> — their absence from the
            findings does not mean those areas are secure.
          </summary>
          <ul>
            {report.not_evaluated.map((n, i) => (
              <li key={i}>
                <code>{n.rule_id}</code>
                {n.region && ` (${n.region})`}: {n.reason}
              </li>
            ))}
          </ul>
        </details>
      )}

      <section className="card">
        <div className="filters">
          <input type="search" placeholder="Search title, rule, resource, region…" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search findings" />
          <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Category">
            <option value="">All categories</option>
            {categories.map(([c, n]) => (
              <option key={c} value={c}>
                {humanize(c)} ({n})
              </option>
            ))}
          </select>
          <span className="muted">
            {findings.length} of {report.findings.length} findings
          </span>
        </div>
        {findings.length === 0 ? (
          <p className="muted">{report.findings.length === 0 ? "No findings in this scan." : "No findings match the filters."}</p>
        ) : (
          <div className="findings">
            {findings.map((f) => (
              <FindingRow key={f.finding_id} finding={f} basePath={reviewBase} editable={editable} onSaved={() => void reload()} />
            ))}
          </div>
        )}
      </section>

      {[
        { title: "Accepted risks", items: report.accepted_risks, note: "Real weaknesses the client has decided to accept. Not counted above." },
        { title: "False positives", items: report.false_positives, note: "Not actual weaknesses in this environment. Excluded from the report body." },
      ].map(
        (section) =>
          section.items.length > 0 && (
            <section className="card" key={section.title}>
              <h2>
                {section.title} ({section.items.length})
              </h2>
              <p className="muted">{section.note}</p>
              <div className="findings">
                {section.items.map((f) => (
                  <FindingRow key={f.finding_id} finding={f} basePath={reviewBase} editable={editable} onSaved={() => void reload()} />
                ))}
              </div>
            </section>
          ),
      )}

      <section className="notes muted">
        {report.notes.map((n) => (
          <p key={n}>{n}</p>
        ))}
        <p>
          Scan integrity (SHA-256): <code className="wrap">{report.source.scan_sha256}</code>
        </p>
      </section>
    </>
  );
}

function FindingRow({
  finding: f,
  basePath,
  editable,
  onSaved,
}: {
  finding: Finding;
  basePath: string;
  editable: boolean;
  onSaved: () => void;
}) {
  return (
    <details className="finding">
      <summary>
        <SeverityBadge severity={f.severity} />
        <span className="finding-title">
          {f.title}{" "}
          {f.review.status !== "open" && <Tag kind={`review-${f.review.status}`}>{REVIEW_LABEL[f.review.status]}</Tag>}
          {f.review.severity_overridden && <Tag kind="queued">Severity adjusted</Tag>}
        </span>
        <span className="finding-resource">
          {f.resource_name ?? "Account-wide"}
          {f.region && <span className="muted"> · {f.region}</span>}
        </span>
        <code className="muted">{f.rule_id}</code>
      </summary>
      <div className="finding-body">
        <p>
          <strong>{f.message}</strong>
        </p>
        <h4>What is wrong</h4>
        <p>{f.description}</p>
        <h4>Why it matters</h4>
        <p>{f.risk}</p>
        <h4>Recommendation</h4>
        <p>{f.recommendation}</p>
        {f.resource_id && (
          <p className="muted">
            Resource: <code className="wrap">{f.resource_id}</code>
          </p>
        )}
        <h4>Evidence</h4>
        {f.evidence.map((e, i) => (
          <div key={i} className="evidence">
            <p>
              {e.summary} <span className="muted">({e.source_operation}, {formatDate(e.collected_at)})</span>
            </p>
            {Object.keys(e.observed).length > 0 && <pre>{JSON.stringify(e.observed, null, 2)}</pre>}
          </div>
        ))}
        <h4>Frameworks</h4>
        <ul className="refs">
          {f.framework_refs.map((r) => (
            <li key={`${r.framework}-${r.control_id}`}>
              <Tag>{r.framework_name}</Tag> <code>{r.control_id}</code> {r.title}
              {!r.verified && <span className="muted"> (unverified)</span>}
            </li>
          ))}
        </ul>
        <ReviewPanel finding={f} basePath={basePath} editable={editable} onSaved={onSaved} />
      </div>
    </details>
  );
}
