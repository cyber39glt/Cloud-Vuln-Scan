import { useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Field, Loading, Notice, PageHeader, Tag } from "../components/ui";
import { formatDate } from "../format";
import { useAction, useApi } from "../hooks";
import { MailIcon } from "../components/icons";
import type { AdminUser, Client, Invite, InviteCreated, Role, TemporaryPassword } from "../types";

export function UsersPage() {
  const users = useApi<AdminUser[]>("/admin/users");
  const invites = useApi<Invite[]>("/admin/invites");
  const clients = useApi<Client[]>("/clients");
  const [secret, setSecret] = useState<TemporaryPassword | null>(null);
  const [created, setCreated] = useState<InviteCreated | null>(null);

  return (
    <>
      <PageHeader
        eyebrow="Administration"
        title="Users"
        subtitle="Invite people, set their role, and choose which clients each consultant may access."
      />
      {secret && <TemporaryPasswordNotice result={secret} onClose={() => setSecret(null)} />}
      <section className="card">
        <div className="card-head">
          <h2>Invite someone</h2>
        </div>
        <p className="muted">
          They get a one-time link to choose a password and set up their authenticator app. Nothing is e-mailed: copy
          the link and send it yourself.
        </p>
        {created && <InviteLinkNotice created={created} onClose={() => setCreated(null)} />}
        <InviteForm
          onCreated={(result) => {
            setCreated(result);
            void invites.reload();
          }}
        />
      </section>
      {invites.data && invites.data.length > 0 && (
        <PendingInvites invites={invites.data} onChanged={() => void invites.reload()} />
      )}
      <ErrorBox message={users.error} />
      {!users.data ? (
        <Loading />
      ) : (
        <section className="card">
          <div className="card-head">
            <h2>Accounts</h2>
            <span className="muted">{users.data.length}</span>
          </div>
          <div className="table-wrap">
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
          </div>
        </section>
      )}
    </>
  );
}

function inviteLink(token: string): string {
  // The token goes after "#": browsers never send that part to the server.
  return `${window.location.origin}/invite#${token}`;
}

function InviteLinkNotice({ created, onClose }: { created: InviteCreated; onClose: () => void }) {
  const link = inviteLink(created.token);
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(link);
      setCopied(true);
    } catch {
      setCopied(false); // Clipboard blocked: the link can still be selected by hand.
    }
  }

  return (
    <Notice kind="ok">
      <p>
        Invitation link for <strong>{created.invite.email}</strong> (valid until {formatDate(created.invite.expires_at)}):
      </p>
      <div className="invite-link">
        <input readOnly value={link} aria-label="Invitation link" onFocus={(e) => e.target.select()} />
        <button className="btn" type="button" onClick={() => void copy()}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <p className="muted">{created.note}</p>
      <button className="btn btn-small" onClick={onClose}>
        Done — hide the link
      </button>
    </Notice>
  );
}

function InviteForm({ onCreated }: { onCreated: (result: InviteCreated) => void }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("consultant");
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const result = await run(() => api.post<InviteCreated>("/admin/invites", { email, display_name: name, role }));
    if (result) {
      setEmail("");
      setName("");
      onCreated(result);
    }
  }

  return (
    <form className="inline-form" onSubmit={submit}>
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
        <MailIcon />
        Create invitation
      </button>
      <ErrorBox message={error} />
    </form>
  );
}

function PendingInvites({ invites, onChanged }: { invites: Invite[]; onChanged: () => void }) {
  const { busy, error, run } = useAction();

  async function revoke(invite: Invite) {
    if (!window.confirm(`Revoke the invitation for ${invite.email}? The link stops working.`)) return;
    const ok = await run(async () => {
      await api.delete(`/admin/invites/${invite.id}`);
      return true;
    });
    if (ok) onChanged();
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2>Pending invitations</h2>
        <span className="muted">{invites.length}</span>
      </div>
      <ErrorBox message={error} />
      <div className="table-wrap">
        <table className="table table-compact">
          <thead>
            <tr>
              <th>Person</th>
              <th>Role</th>
              <th>Invited</th>
              <th>Expires</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {invites.map((i) => (
              <tr key={i.id}>
                <td>
                  <strong>{i.display_name}</strong> <span className="muted">{i.email}</span>
                </td>
                <td>{i.role === "admin" ? "Admin" : "Consultant"}</td>
                <td>
                  {formatDate(i.created_at)} <span className="muted">by {i.created_by}</span>
                </td>
                <td>{formatDate(i.expires_at)}</td>
                <td>
                  <button className="btn btn-small" disabled={busy} onClick={() => void revoke(i)}>
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
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
