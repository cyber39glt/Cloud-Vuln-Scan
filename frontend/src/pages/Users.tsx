import { useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Field, Loading, Notice, PageHeader, Tag } from "../components/ui";
import { formatDate } from "../format";
import { useAction, useApi } from "../hooks";
import type { AdminUser, Client, Role, TemporaryPassword } from "../types";

export function UsersPage() {
  const users = useApi<AdminUser[]>("/admin/users");
  const clients = useApi<Client[]>("/clients");
  const [secret, setSecret] = useState<TemporaryPassword | null>(null);

  return (
    <>
      <PageHeader title="Users" subtitle="Accounts, roles and which clients each consultant may access" />
      {secret && <TemporaryPasswordNotice result={secret} onClose={() => setSecret(null)} />}
      <NewUserForm
        onCreated={(result) => {
          setSecret(result);
          void users.reload();
        }}
      />
      <ErrorBox message={users.error} />
      {!users.data ? (
        <Loading />
      ) : (
        <section className="card">
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last login</th>
                <th>Clients</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.data.map((u) => (
                <UserRow
                  key={u.id}
                  user={u}
                  clients={clients.data ?? []}
                  onChanged={() => void users.reload()}
                  onPassword={setSecret}
                />
              ))}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}

function TemporaryPasswordNotice({ result, onClose }: { result: TemporaryPassword; onClose: () => void }) {
  return (
    <Notice kind="warn">
      <p>
        Temporary password for <strong>{result.user.email}</strong>: <code className="secret">{result.temporary_password}</code>
      </p>
      <p>{result.note}</p>
      <button className="btn btn-small" onClick={onClose}>
        I have passed it on — hide it
      </button>
    </Notice>
  );
}

function NewUserForm({ onCreated }: { onCreated: (result: TemporaryPassword) => void }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("consultant");
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const result = await run(() =>
      api.post<TemporaryPassword>("/admin/users", { email, display_name: name, role }),
    );
    if (result) {
      setEmail("");
      setName("");
      onCreated(result);
    }
  }

  return (
    <form className="card inline-form" onSubmit={submit}>
      <Field label="E-mail">
        <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      <Field label="Name">
        <input required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Role">
        <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
          <option value="consultant">Consultant</option>
          <option value="admin">Admin</option>
        </select>
      </Field>
      <button className="btn btn-primary" disabled={busy}>
        Create user
      </button>
      <ErrorBox message={error} />
    </form>
  );
}

function UserRow({
  user,
  clients,
  onChanged,
  onPassword,
}: {
  user: AdminUser;
  clients: Client[];
  onChanged: () => void;
  onPassword: (result: TemporaryPassword) => void;
}) {
  const { me } = useAuth();
  const { busy, error, run } = useAction();
  const self = me?.id === user.id;
  const assigned = new Set(user.client_ids);

  async function act(action: () => Promise<unknown>, confirmText?: string) {
    if (confirmText && !window.confirm(confirmText)) return;
    const ok = await run(async () => {
      await action();
      return true;
    });
    if (ok) onChanged();
  }

  return (
    <tr className={user.is_active ? "" : "inactive"}>
      <td>
        <strong>{user.display_name}</strong>
        <br />
        <span className="muted">{user.email}</span>
        <ErrorBox message={error} />
      </td>
      <td>
        <select
          value={user.role}
          disabled={busy || self}
          onChange={(e) => void act(() => api.patch(`/admin/users/${user.id}`, { role: e.target.value }))}
          aria-label="Role"
        >
          <option value="consultant">Consultant</option>
          <option value="admin">Admin</option>
        </select>
      </td>
      <td>
        {!user.is_active && <Tag kind="failed">Deactivated</Tag>} {user.locked && <Tag kind="failed">Locked</Tag>}{" "}
        {!user.mfa_enabled && <Tag kind="queued">MFA not set up</Tag>}{" "}
        {user.must_change_password && <Tag kind="queued">Temporary password</Tag>}
        {user.is_active && user.mfa_enabled && !user.locked && !user.must_change_password && <Tag kind="succeeded">Active</Tag>}
      </td>
      <td>{formatDate(user.last_login_at)}</td>
      <td>
        {user.role === "admin" ? (
          <span className="muted">All clients</span>
        ) : (
          <div className="checklist">
            {clients.map((c) => (
              <label key={c.id} className="checkbox">
                <input
                  type="checkbox"
                  checked={assigned.has(c.id)}
                  disabled={busy}
                  onChange={(e) =>
                    void act(() =>
                      e.target.checked
                        ? api.put(`/admin/users/${user.id}/clients/${c.id}`)
                        : api.delete(`/admin/users/${user.id}/clients/${c.id}`),
                    )
                  }
                />
                {c.name}
              </label>
            ))}
            {clients.length === 0 && <span className="muted">No clients yet</span>}
          </div>
        )}
      </td>
      <td>
        <div className="actions">
        <button
          className="btn btn-small"
          disabled={busy || self}
          onClick={() =>
            void act(
              () => api.patch(`/admin/users/${user.id}`, { is_active: !user.is_active }),
              user.is_active ? `Deactivate ${user.email}? Their sessions end immediately.` : undefined,
            )
          }
        >
          {user.is_active ? "Deactivate" : "Reactivate"}
        </button>
        <button
          className="btn btn-small"
          disabled={busy || !user.mfa_enabled}
          onClick={() =>
            void act(
              () => api.post(`/admin/users/${user.id}/reset-mfa`),
              `Reset MFA for ${user.email}? They must set up their authenticator again at next login.`,
            )
          }
        >
          Reset MFA
        </button>
        <button
          className="btn btn-small"
          disabled={busy}
          onClick={() =>
            void act(async () => {
              const result = await api.post<TemporaryPassword>(`/admin/users/${user.id}/reset-password`);
              onPassword(result);
            }, `Give ${user.email} a new temporary password? Their sessions end and the account is unlocked.`)
          }
        >
          Reset password
        </button>
        </div>
      </td>
    </tr>
  );
}
