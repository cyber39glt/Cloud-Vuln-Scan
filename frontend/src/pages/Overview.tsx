import { Link } from "react-router-dom";
import { useAuth } from "../auth";
import { ErrorBox, Loading, PageHeader, SeverityBar, Tag } from "../components/ui";
import { formatDate, humanize, providerLabel } from "../format";
import { useApi } from "../hooks";
import { SEVERITIES, type Overview, type Severity } from "../types";

export function OverviewPage() {
  const { me } = useAuth();
  const { data, error, loading } = useApi<Overview>("/overview");

  const totals: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const item of data?.items ?? []) {
    for (const s of SEVERITIES) totals[s] += item.latest_scan?.by_severity[s] ?? 0;
  }
  const running = data?.items.filter((i) => i.active_job).length ?? 0;

  return (
    <>
      <PageHeader
        title={`Welcome, ${me?.display_name ?? ""}`}
        subtitle={me?.role === "admin" ? "All clients" : "Clients assigned to you"}
      />
      <ErrorBox message={error} />
      {loading && !data && <Loading />}
      {data && (
        <>
          <section className="tiles">
            <div className="tile">
              <span className="tile-value">{data.clients}</span>
              <span className="tile-label">Clients</span>
            </div>
            <div className="tile">
              <span className="tile-value">{data.items.length}</span>
              <span className="tile-label">Assessments</span>
            </div>
            <div className="tile">
              <span className="tile-value">{running}</span>
              <span className="tile-label">Scans in progress</span>
            </div>
            {(["critical", "high", "medium"] as Severity[]).map((s) => (
              <div key={s} className={`tile tile-${s}`}>
                <span className="tile-value">{totals[s]}</span>
                <span className="tile-label">{humanize(s)} findings (latest scans)</span>
              </div>
            ))}
          </section>

          <section className="card">
            <h2>Assessments</h2>
            {data.items.length === 0 ? (
              <p className="muted">
                Nothing yet. {me?.role === "admin" ? <Link to="/clients">Add a client</Link> : "Ask an administrator to assign you to a client."}
              </p>
            ) : (
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
                  {data.items.map((item) => (
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
            )}
          </section>
        </>
      )}
    </>
  );
}
