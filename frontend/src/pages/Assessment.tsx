import { useEffect, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Field, Loading, Notice, PageHeader, Tag } from "../components/ui";
import { formatDate, humanize, providerLabel } from "../format";
import { useAction, useApi } from "../hooks";
import type { AssessmentDetail, Finalization, ScanJob, Stage } from "../types";

const STAGES: Stage[] = ["connecting", "collecting", "evaluating", "saving"];
const STAGE_LABEL: Record<Stage, string> = {
  waiting: "Waiting for the worker",
  connecting: "Connecting (read-only) and confirming the account",
  collecting: "Collecting configuration",
  evaluating: "Running security checks",
  saving: "Saving results",
  done: "Done",
};
const POLL_MS = 2000;

export function AssessmentPage() {
  const { clientId, assessmentId } = useParams();
  const base = `/clients/${clientId}/assessments/${assessmentId}`;
  const detail = useApi<AssessmentDetail>(base);
  const jobs = useApi<ScanJob[]>(`${base}/scan-jobs`);
  const active = jobs.data?.find((j) => j.status === "queued" || j.status === "running");

  // While a scan is queued or running, refresh its progress every few seconds.
  const { reload: reloadJobs } = jobs;
  const { reload: reloadDetail } = detail;
  const activeId = active?.id;
  useEffect(() => {
    if (!activeId) return;
    const timer = window.setInterval(() => void reloadJobs(), POLL_MS);
    return () => {
      window.clearInterval(timer);
      void reloadDetail(); // the scan just finished: show the new result
    };
  }, [activeId, reloadJobs, reloadDetail]);

  if (detail.notFound) return <Notice kind="warn">This assessment does not exist or is not assigned to you.</Notice>;
  if (!detail.data) return detail.error ? <ErrorBox message={detail.error} /> : <Loading />;
  const a = detail.data;
  const latestJob = jobs.data?.[0];

  return (
    <>
      <PageHeader
        title={a.name}
        subtitle={
          <>
            <Link to={`/clients/${clientId}`}>← Client</Link> · <Tag>{humanize(a.status)}</Tag>
          </>
        }
      />

      <FinalizationCard
        base={base}
        detail={a}
        clientId={clientId!}
        scanRunning={Boolean(active)}
        onChanged={() => {
          void detail.reload();
          void jobs.reload();
        }}
      />

      <section className="card">
        <h2>Scan</h2>
        {active ? (
          <Progress job={active} />
        ) : (
          <>
            {latestJob?.status === "failed" && (
              <div className="alert alert-error">
                <strong>The last scan failed</strong> ({formatDate(latestJob.finished_at)}): {latestJob.error_message}
              </div>
            )}
            <StartScan base={base} disabled={a.status === "finalized"} onStarted={() => void jobs.reload()} />
          </>
        )}
      </section>

      <section className="card">
        <h2>Results</h2>
        {a.scans.length === 0 ? (
          <p className="muted">No completed scans yet.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Completed</th>
                <th>Account</th>
                <th>Regions</th>
                <th>Findings</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {a.scans.map((s) => (
                <tr key={s.id}>
                  <td>{formatDate(s.completed_at)}</td>
                  <td>
                    {providerLabel(s.provider)} <code>{s.account_id}</code>
                  </td>
                  <td>{s.regions.join(", ") || "all"}</td>
                  <td>{s.findings}</td>
                  <td>
                    <Link to={`/clients/${clientId}/scans/${s.id}`}>Open report →</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {jobs.data && jobs.data.length > 0 && (
        <section className="card">
          <h2>Scan history</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Requested</th>
                <th>Status</th>
                <th>Regions</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {jobs.data.map((j) => (
                <tr key={j.id}>
                  <td>{formatDate(j.requested_at)}</td>
                  <td>
                    <Tag kind={j.status}>{humanize(j.status)}</Tag>
                  </td>
                  <td>{j.regions?.join(", ") ?? "all"}</td>
                  <td className="cell-wide">
                    {j.status === "succeeded" && j.scan_run_id ? (
                      <Link to={`/clients/${clientId}/scans/${j.scan_run_id}`}>Report</Link>
                    ) : (
                      (j.error_message ?? STAGE_LABEL[j.stage])
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}

function Progress({ job }: { job: ScanJob }) {
  const current = STAGES.indexOf(job.stage);
  return (
    <div className="progress" aria-live="polite">
      <p>
        <strong>{job.status === "queued" ? "Queued" : "Scanning…"}</strong>{" "}
        <span className="muted">requested {formatDate(job.requested_at)}</span>
      </p>
      <ol className="stepper">
        {STAGES.map((stage, i) => (
          <li key={stage} className={i < current ? "done" : i === current ? "current" : ""}>
            {STAGE_LABEL[stage]}
          </li>
        ))}
      </ol>
      <p className="muted">This page updates by itself. You can leave it; the scan continues in the background.</p>
    </div>
  );
}

function StartScan({ base, disabled, onStarted }: { base: string; disabled: boolean; onStarted: () => void }) {
  const [regions, setRegions] = useState("");
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const list = regions
      .split(",")
      .map((r) => r.trim())
      .filter(Boolean);
    const job = await run(() => api.post<ScanJob>(`${base}/scans`, list.length ? { regions: list } : {}));
    if (job) onStarted();
  }

  return (
    <form className="inline-form" onSubmit={submit}>
      <Field label="Regions (optional)" hint="Comma-separated, e.g. eu-west-2 or uksouth. Empty = all.">
        <input value={regions} onChange={(e) => setRegions(e.target.value)} placeholder="all regions" />
      </Field>
      <button className="btn btn-primary" disabled={busy || disabled}>
        Run read-only scan
      </button>
      <ErrorBox message={error} />
    </form>
  );
}

function FinalizationCard({
  base,
  detail,
  clientId,
  scanRunning,
  onChanged,
}: {
  base: string;
  detail: AssessmentDetail;
  clientId: string;
  scanRunning: boolean;
  onChanged: () => void;
}) {
  const { me } = useAuth();
  const { busy, error, run } = useAction();
  const [reason, setReason] = useState("");
  const latest = detail.scans[0];
  const final = detail.finalization;

  async function finalize() {
    if (!latest) return;
    const confirmed = window.confirm(
      "Finalize this assessment? The reviewed report of the latest scan is frozen and becomes the final " +
        "version for the client. Reviews and new scans are locked until an administrator reopens it.",
    );
    if (!confirmed) return;
    const done = await run(() => api.post<Finalization>(`${base}/finalize`, { scan_id: latest.id }));
    if (done) onChanged();
  }

  async function reopen(event: FormEvent) {
    event.preventDefault();
    const done = await run(async () => {
      await api.post(`${base}/reopen`, { reason });
      return true;
    });
    if (done) {
      setReason("");
      onChanged();
    }
  }

  if (final) {
    return (
      <section className="card final-card">
        <h2>Finalized</h2>
        <p>
          Finalized {formatDate(final.finalized_at)} by {final.finalized_by}. Every output (dashboard, PDF, CSV, JSON) of
          the <Link to={`/clients/${clientId}/scans/${final.scan_run_id}`}>final report</Link> comes from the frozen
          snapshot.
        </p>
        <p className="muted">
          Snapshot SHA-256: <code className="wrap">{final.report_sha256}</code>
        </p>
        {me?.role === "admin" ? (
          <form className="inline-form" onSubmit={reopen}>
            <Field label="Reopen for changes (administrators)" hint="The reason is recorded in the audit log.">
              <input required minLength={10} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why does it need to change?" />
            </Field>
            <button className="btn" disabled={busy}>
              Reopen assessment
            </button>
            <ErrorBox message={error} />
          </form>
        ) : (
          <p className="muted">To change it, ask an administrator to reopen it.</p>
        )}
      </section>
    );
  }

  if (!latest) return null;
  return (
    <section className="card">
      <h2>Review and finalize</h2>
      <p>
        Review every finding of the latest scan in its{" "}
        <Link to={`/clients/${clientId}/scans/${latest.id}`}>report</Link> (confirm, mark as false positive or accepted
        risk, or adjust severity), then finalize to produce the final client report.
      </p>
      <button className="btn btn-primary" disabled={busy || scanRunning} onClick={() => void finalize()}>
        Finalize assessment
      </button>
      {scanRunning && <span className="muted"> Wait for the running scan to finish.</span>}
      <ErrorBox message={error} />
    </section>
  );
}
