import { useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Field, Notice, PageHeader } from "../components/ui";
import { useAction } from "../hooks";
import type { RecoveryCodes } from "../types";
import { ChangePasswordForm } from "./ChangePassword";

export function AccountPage() {
  const { me } = useAuth();
  return (
    <>
      <PageHeader title="Your account" subtitle={`${me?.email} · ${me?.role === "admin" ? "Admin" : "Consultant"}`} />
      <section className="card">
        <h2>Password</h2>
        <ChangePasswordForm />
      </section>
      <section className="card">
        <h2>Recovery codes</h2>
        <NewRecoveryCodes />
      </section>
    </>
  );
}

function NewRecoveryCodes() {
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const result = await run(() => api.post<RecoveryCodes>("/auth/mfa/recovery-codes", { code: code.replace(/\s/g, "") }));
    setCode("");
    if (result) setCodes(result.recovery_codes);
  }

  if (codes.length > 0) {
    return (
      <>
        <Notice kind="warn">New codes created; the old ones no longer work. Save these now: they are not shown again.</Notice>
        <ul className="recovery-codes">
          {codes.map((c) => (
            <li key={c}>
              <code>{c}</code>
            </li>
          ))}
        </ul>
      </>
    );
  }
  return (
    <form className="inline-form" onSubmit={submit}>
      <p className="muted">Used some codes, or lost them? Create a new set (replaces all previous codes).</p>
      <Field label="Current authenticator code">
        <input inputMode="numeric" autoComplete="one-time-code" required maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} />
      </Field>
      <button className="btn" disabled={busy}>
        Create new recovery codes
      </button>
      <ErrorBox message={error} />
    </form>
  );
}
