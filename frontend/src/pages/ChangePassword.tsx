import { useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { AuthShell } from "../components/AuthShell";
import { ErrorBox, Field, Notice } from "../components/ui";
import { useAction } from "../hooks";

/** Change password. Shown on its own (forced) while a temporary password is in use. */
export function ChangePasswordForm({ forced = false, onChanged }: { forced?: boolean; onChanged?: () => void }) {
  const { refresh } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [done, setDone] = useState(false);
  const { busy, error, setError, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (next !== repeat) {
      setError("The new passwords do not match.");
      return;
    }
    const ok = await run(async () => {
      await api.post("/auth/password", { current_password: current, new_password: next });
      return true;
    });
    if (ok) {
      setCurrent("");
      setNext("");
      setRepeat("");
      setDone(true);
      await refresh();
      onChanged?.();
    }
  }

  return (
    <form onSubmit={submit} className="stack narrow">
      {forced && (
        <Notice kind="warn">You are using a temporary password. Choose your own before continuing.</Notice>
      )}
      {done && !forced && <Notice kind="ok">Password changed. Your other sessions have been logged out.</Notice>}
      <ErrorBox message={error} />
      <Field label={forced ? "Temporary password" : "Current password"}>
        <input type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
      </Field>
      <Field label="New password" hint="At least 12 characters. A few random words work well.">
        <input type="password" autoComplete="new-password" required minLength={12} value={next} onChange={(e) => setNext(e.target.value)} />
      </Field>
      <Field label="Repeat new password">
        <input type="password" autoComplete="new-password" required value={repeat} onChange={(e) => setRepeat(e.target.value)} />
      </Field>
      <button className="btn btn-primary" disabled={busy}>
        {busy ? "Saving…" : "Change password"}
      </button>
    </form>
  );
}

export function ForcedPasswordChangePage() {
  const { logout } = useAuth();
  return (
    <AuthShell>
      <div className="stack">
        <h1>Choose your password</h1>
        <ChangePasswordForm forced />
        <button className="btn-link" onClick={() => void logout()}>
          Log out
        </button>
      </div>
    </AuthShell>
  );
}
