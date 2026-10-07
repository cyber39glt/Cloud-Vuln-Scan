import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { ErrorBox, Field, Loading, Notice, PageHeader, Tag } from "../components/ui";
import { formatDate, humanize, providerLabel } from "../format";
import { useAction, useApi } from "../hooks";
import type { Assessment, Client, Connection } from "../types";

interface Onboarding {
  provider: "aws" | "azure";
  role_name: string | null;
  external_id: string | null;
  template: string | null;
  admin_consent_url: string | null;
  role_commands: string[];
  guide: string;
}

export function ClientPage() {
  const { clientId } = useParams();
  const client = useApi<Client>(`/clients/${clientId}`);
  const connections = useApi<Connection[]>(`/clients/${clientId}/connections`);
  const assessments = useApi<Assessment[]>(`/clients/${clientId}/assessments`);

  if (client.notFound) return <Notice kind="warn">This client does not exist or is not assigned to you.</Notice>;
  if (!client.data) return client.error ? <ErrorBox message={client.error} /> : <Loading />;

  const byId = new Map((connections.data ?? []).map((c) => [c.id, c]));
  return (
    <>
      <PageHeader title={client.data.name} subtitle={<Link to="/clients">← All clients</Link>} />

      <section className="card">
        <h2>Cloud accounts</h2>
        <p className="muted">
          Registering an account contacts nothing. The client then grants <strong>read-only</strong> access using the
          setup steps.
        </p>
        <ErrorBox message={connections.error} />
        {connections.data && connections.data.length > 0 && (
          <ul className="list">
            {connections.data.map((c) => (
              <ConnectionItem key={c.id} clientId={client.data!.id} connection={c} />
            ))}
          </ul>
        )}
        <AddConnection clientId={client.data.id} onAdded={() => void connections.reload()} />
      </section>

      <section className="card">
        <h2>Assessments</h2>
        <ErrorBox message={assessments.error} />
        {assessments.data && assessments.data.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Account</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {assessments.data.map((a) => {
                const c = byId.get(a.connection_id);
                return (
                  <tr key={a.id}>
                    <td>
                      <Link to={`/clients/${client.data!.id}/assessments/${a.id}`}>{a.name}</Link>
                    </td>
                    <td>{c ? `${providerLabel(c.provider)} ${c.account_id}` : "—"}</td>
                    <td>
                      <Tag>{humanize(a.status)}</Tag>
                    </td>
                    <td>{formatDate(a.created_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <p className="muted">No assessments yet.</p>
        )}
        {connections.data && connections.data.length > 0 ? (
          <NewAssessment clientId={client.data.id} connections={connections.data} />
        ) : (
          <p className="muted">Add a cloud account first.</p>
        )}
      </section>
    </>
  );
}

function ConnectionItem({ clientId, connection }: { clientId: string; connection: Connection }) {
  const [open, setOpen] = useState(false);
  const steps = useApi<Onboarding>(open ? `/clients/${clientId}/connections/${connection.id}/onboarding` : null);
  return (
    <li>
      <div className="row-between">
        <span>
          <Tag kind={connection.provider}>{providerLabel(connection.provider)}</Tag>{" "}
          {connection.provider === "aws" ? "Account" : "Subscription"} <code>{connection.account_id}</code>
          {connection.tenant_id && (
            <span className="muted">
              {" "}
              · tenant <code>{connection.tenant_id}</code>
            </span>
          )}
        </span>
        <button className="btn-link" onClick={() => setOpen(!open)}>
          {open ? "Hide setup steps" : "Setup steps"}
        </button>
      </div>
      {open && steps.data && <OnboardingSteps steps={steps.data} />}
      <ErrorBox message={steps.error} />
    </li>
  );
}

function OnboardingSteps({ steps }: { steps: Onboarding }) {
  if (steps.provider === "aws") {
    return (
      <div className="onboarding">
        <p>
          The client creates a read-only role in their AWS account with the CloudFormation template{" "}
          <code>{steps.template}</code>, using:
        </p>
        <dl className="kv">
          <dt>Role name</dt>
          <dd>
            <code>{steps.role_name}</code>
          </dd>
          <dt>ExternalId</dt>
          <dd>
            <code>{steps.external_id}</code>
          </dd>
        </dl>
        <p className="muted">Full guide: {steps.guide}</p>
      </div>
    );
  }
  return (
    <div className="onboarding">
      <ol>
        <li>
          The client’s administrator grants consent (gives no access by itself):{" "}
          {steps.admin_consent_url ? (
            <code className="wrap">{steps.admin_consent_url}</code>
          ) : (
            <span className="muted">platform Azure app not configured (AZURE_CLIENT_ID)</span>
          )}
        </li>
        <li>
          …then assigns read-only roles on the subscription (Azure Cloud Shell):
          {steps.role_commands.map((c) => (
            <pre key={c}>{c}</pre>
          ))}
        </li>
      </ol>
      <p className="muted">Full guide: {steps.guide}</p>
    </div>
  );
}

function AddConnection({ clientId, onAdded }: { clientId: string; onAdded: () => void }) {
  const [provider, setProvider] = useState<"aws" | "azure">("aws");
  const [accountId, setAccountId] = useState("");
  const [tenantId, setTenantId] = useState("");
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const ok = await run(async () => {
      if (provider === "aws") await api.post(`/clients/${clientId}/connections/aws`, { account_id: accountId.trim() });
      else
        await api.post(`/clients/${clientId}/connections/azure`, {
          tenant_id: tenantId.trim(),
          subscription_id: accountId.trim(),
        });
      return true;
    });
    if (ok) {
      setAccountId("");
      setTenantId("");
      onAdded();
    }
  }

  return (
    <form className="inline-form" onSubmit={submit}>
      <Field label="Cloud">
        <select value={provider} onChange={(e) => setProvider(e.target.value as "aws" | "azure")}>
          <option value="aws">AWS</option>
          <option value="azure">Azure</option>
        </select>
      </Field>
      {provider === "azure" && (
        <Field label="Tenant ID">
          <input required value={tenantId} onChange={(e) => setTenantId(e.target.value)} placeholder="00000000-0000-…" />
        </Field>
      )}
      <Field label={provider === "aws" ? "AWS account ID (12 digits)" : "Subscription ID"}>
        <input required value={accountId} onChange={(e) => setAccountId(e.target.value)} />
      </Field>
      <button className="btn" disabled={busy}>
        Register account
      </button>
      <ErrorBox message={error} />
    </form>
  );
}

function NewAssessment({ clientId, connections }: { clientId: string; connections: Connection[] }) {
  const [connectionId, setConnectionId] = useState(connections[0]?.id ?? "");
  const [name, setName] = useState("");
  const navigate = useNavigate();
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const created = await run(() =>
      api.post<Assessment>(`/clients/${clientId}/assessments`, { connection_id: connectionId, name }),
    );
    if (created) navigate(`/clients/${clientId}/assessments/${created.id}`);
  }

  return (
    <form className="inline-form" onSubmit={submit}>
      <Field label="New assessment">
        <input required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} placeholder="Q1 review" />
      </Field>
      <Field label="Cloud account">
        <select value={connectionId} onChange={(e) => setConnectionId(e.target.value)}>
          {connections.map((c) => (
            <option key={c.id} value={c.id}>
              {providerLabel(c.provider)} {c.account_id}
            </option>
          ))}
        </select>
      </Field>
      <button className="btn btn-primary" disabled={busy}>
        Create assessment
      </button>
      <ErrorBox message={error} />
    </form>
  );
}
