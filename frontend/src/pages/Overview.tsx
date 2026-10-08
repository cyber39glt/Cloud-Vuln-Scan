import { Link } from "react-router-dom";
import { useAuth } from "../auth";
import { ErrorBox, Loading, PageHeader, SeverityBar, SeverityBars, Tag } from "../components/ui";
import { formatDate, humanize, providerLabel, SEVERITY_LABEL } from "../format";
import { useApi } from "../hooks";
import { SEVERITIES, type Overview, type OverviewItem, type Severity } from "../types";

function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
}

/** Most severe first: compare critical counts, then high, and so on. */
function byExposure(a: OverviewItem, b: OverviewItem): number {
  for (const s of SEVERITIES) {
    const diff = (b.latest_scan?.by_severity[s] ?? 0) - (a.latest_scan?.by_severity[s] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

export function OverviewPage() {
  const { me } = useAuth();
  const { data, error, loading } = useApi<Overview>("/overview");

  const totals = emptyCounts();
  for (const item of data?.items ?? []) {
    for (const s of SEVERITIES) totals[s] += item.latest_scan?.by_severity[s] ?? 0;
  }
  const items = data?.items ?? [];
  const running = items.filter((i) => i.active_job).length;
  const finalized = items.filter((i) => i.assessment_status === "finalized").length;
  const scanned = items.filter((i) => i.latest_scan);
  const exposed = [...scanned].filter((i) => (i.latest_scan?.findings ?? 0) > 0).sort(byExposure).slice(0, 5);
  const urgent = totals.critical + totals.high;

  return (
    <>
      <PageHeader
        eyebrow="Dashboard"
        title={`Welcome back, ${me?.display_name.split(" ")[0] ?? ""}`}
        subtitle={
          me?.role === "admin"
            ? "Security posture across all clients, from each assessment's latest scan."
            : "Security posture of the clients assigned to you, from each assessment's latest scan."
        }
        actions={
          <Link className="btn" to="/clients">
            View clients
          </Link>
        }
      />
      <ErrorBox message={error} />
      {loading && !data && <Loading />}
      {data && (
        <>
          <section className="overview-top">
            <div className="hero-tile">
              <span className="hero-label">Open critical and high findings</span>
              <span className="hero-value">{urgent}</span>
              <span className="muted">
                {totals.critical} critical · {totals.high} high, after review decisions. Accepted risks and false positives
                are not counted.
              </span>
            </div>
            <div className="tiles">
              <div className="tile tile-accent">
                <span className="tile-value">{data.clients}</span>
                <span className="tile-label">Clients</span>
              </div>
              <div className="tile tile-accent">
                <span className="tile-value">{items.length}</span>
                <span className="tile-label">Assessments</span>
              </div>
              <div className="tile tile-accent">
                <span className="tile-value">{scanned.length}</span>
                <span className="tile-label">Scanned</span>
              </div>
              <div className="tile tile-medium">
                <span className="tile-value">{running}</span>
                <span className="tile-label">Scans in progress</span>
              </div>
              <div className="tile tile-low">
                <span className="tile-value">{finalized}</span>
                <span className="tile-label">Finalized reports</span>
              </div>
              <div className="tile tile-informational">
                <span className="tile-value">{items.filter((i) => !i.latest_scan).length}</span>
                <span className="tile-label">Never scanned</span>
              </div>
            </div>
          </section>

          <section className="grid-2">
            <div className="card">
              <div className="card-head">
                <h2>Findings by severity</h2>
                <span className="muted">{SEVERITIES.reduce((n, s) => n + totals[s], 0)} total</span>
              </div>
              {scanned.length === 0 ? <p className="empty">No scans yet.</p> : <SeverityBars counts={totals} />}
            </div>
            <div className="card">
              <div className="card-head">
                <h2>Most exposed assessments</h2>
                <span className="muted">Top {exposed.length || 5}</span>
              </div>
              {exposed.length === 0 ? (
                <p className="empty">Nothing to show yet.</p>
              ) : (
                <>
                  <ol className="rank-list">
                    {exposed.map((item) => (
                      <li key={item.assessment_id}>
                        <div className="rank-head">
                          <Link to={`/clients/${item.client_id}/scans/${item.latest_scan!.id}`}>
                            {item.client_name} · {item.assessment_name}
                          </Link>
                          <span className="muted">{item.latest_scan!.findings} findings</span>
                        </div>
                        <SeverityBar counts={item.latest_scan!.by_severity} legend={false} />
                      </li>
                    ))}
                  </ol>
                  <div className="legend">
                    {SEVERITIES.map((s) => (
                      <span key={s}>
                        <i className={`dot dot-${s}`} />
                        {SEVERITY_LABEL[s]}
                      </span>
                    ))}
                  </div>
                </>
              )}
            </div>
          </section>

          <section className="card">
            <div className="card-head">
              <h2>Assessments</h2>
              <span className="muted">{items.length}</span>
            </div>
            {items.length === 0 ? (
              <p className="empty">
                Nothing yet.{" "}
                {me?.role === "admin" ? <Link to="/clients">Add a client</Link> : "Ask an administrator to assign you to a client."}
              </p>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Client</th>
                      <th>Assessment</th>
                      <th>Account</th>
                      <th>Latest scan</th>
                      <th>Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr key={item.assessment_id}>
                        <td>
                          <Link to={`/clients/${item.client_id}`}>{item.client_name}</Link>
                        </td>
                        <td>
                          <Link to={`/clients/${item.client_id}/assessments/${item.assessment_id}`}>{item.assessment_name}</Link>{" "}
                          <Tag>{humanize(item.assessment_status)}</Tag>
                        </td>
                        <td>
                          <Tag kind={item.provider}>{providerLabel(item.provider)}</Tag> <code>{item.account_id}</code>
                        </td>
                        <td>
                          {item.active_job ? (
                            <Tag kind="running">Scan {item.active_job.status === "queued" ? "queued" : item.active_job.stage}</Tag>
                          ) : item.latest_scan ? (
                            <Link to={`/clients/${item.client_id}/scans/${item.latest_scan.id}`}>{formatDate(item.latest_scan.completed_at)}</Link>
                          ) : (
                            <span className="muted">Never scanned</span>
                          )}
                        </td>
                        <td className="cell-wide">{item.latest_scan ? <SeverityBar counts={item.latest_scan.by_severity} /> : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </>
  );
}
