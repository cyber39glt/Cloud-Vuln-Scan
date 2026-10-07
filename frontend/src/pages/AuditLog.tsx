import { useState } from "react";
import { ErrorBox, Loading, PageHeader, Tag } from "../components/ui";
import { formatDate } from "../format";
import { useApi } from "../hooks";
import type { AuditEvent, Client } from "../types";

export function AuditLogPage() {
  const [clientId, setClientId] = useState("");
  const [action, setAction] = useState("");
  const clients = useApi<Client[]>("/clients");
  const params = new URLSearchParams({ limit: "200" });
  if (clientId) params.set("client_id", clientId);
  if (action.trim()) params.set("action", action.trim());
  const events = useApi<AuditEvent[]>(`/admin/audit-events?${params.toString()}`);
  const clientName = new Map((clients.data ?? []).map((c) => [c.id, c.name]));

  return (
    <>
      <PageHeader title="Audit log" subtitle="Append-only record of logins, changes, data access, scans and exports (latest 200)" />
      <section className="card">
        <div className="filters">
          <select value={clientId} onChange={(e) => setClientId(e.target.value)} aria-label="Client">
            <option value="">All clients</option>
            {(clients.data ?? []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
          <input placeholder="Exact action, e.g. auth.login" value={action} onChange={(e) => setAction(e.target.value)} aria-label="Action" />
        </div>
        <ErrorBox message={events.error} />
        {!events.data ? (
          <Loading />
        ) : (
          <table className="table table-compact">
            <thead>
              <tr>
                <th>When</th>
                <th>Action</th>
                <th>Outcome</th>
                <th>Who</th>
                <th>Client</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {events.data.map((e) => (
                <tr key={e.id}>
                  <td>{formatDate(e.occurred_at)}</td>
                  <td>
                    <code>{e.action}</code>
                  </td>
                  <td>
                    <Tag kind={e.outcome === "success" ? "succeeded" : "failed"}>{e.outcome}</Tag>
                  </td>
                  <td>
                    {e.actor_email ?? e.actor_type}
                    {e.ip_address && <span className="muted"> · {e.ip_address}</span>}
                  </td>
                  <td>{e.client_id ? (clientName.get(e.client_id) ?? e.client_id.slice(0, 8)) : "—"}</td>
                  <td className="cell-wide">
                    {Object.keys(e.details).length > 0 && <code className="wrap">{JSON.stringify(e.details)}</code>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
