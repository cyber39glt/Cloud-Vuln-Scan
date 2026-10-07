import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Field, Loading, PageHeader } from "../components/ui";
import { formatDate } from "../format";
import { useAction, useApi } from "../hooks";
import type { Client } from "../types";

export function ClientsPage() {
  const { me } = useAuth();
  const { data, error, loading } = useApi<Client[]>("/clients");
  return (
    <>
      <PageHeader title="Clients" subtitle={me?.role === "admin" ? "Every client of the consultancy" : "Clients assigned to you"} />
      {me?.role === "admin" && <NewClientForm />}
      <ErrorBox message={error} />
      {loading && !data && <Loading />}
      {data && (
        <section className="card">
          {data.length === 0 ? (
            <p className="muted">No clients yet.</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Added</th>
                </tr>
              </thead>
              <tbody>
                {data.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <Link to={`/clients/${c.id}`}>{c.name}</Link>
                    </td>
                    <td>{formatDate(c.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}
    </>
  );
}

function NewClientForm() {
  const [name, setName] = useState("");
  const navigate = useNavigate();
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const client = await run(() => api.post<Client>("/clients", { name }));
    if (client) navigate(`/clients/${client.id}`);
  }

  return (
    <form className="card inline-form" onSubmit={submit}>
      <Field label="New client name">
        <input required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Ltd" />
      </Field>
      <button className="btn btn-primary" disabled={busy}>
        Add client
      </button>
      <ErrorBox message={error} />
    </form>
  );
}
