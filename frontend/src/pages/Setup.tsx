import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { AuthShell } from "../components/AuthShell";
import { ErrorBox, Field, Loading, Notice } from "../components/ui";
import { useAction, useApi } from "../hooks";
import { MfaEnrollment } from "./Login";

/** First-run setup: create the first administrator (only while no users exist). */
export function SetupPage() {
  const status = useApi<{ needed: boolean }>("/setup");
  const [created, setCreated] = useState(false);

  return (
    <AuthShell>
      {created ? (
        <MfaEnrollment />
      ) : !status.data ? (
        <>
          <ErrorBox message={status.error} />
          {status.loading && <Loading />}
        </>
      ) : status.data.needed ? (
        <SetupForm onDone={() => setCreated(true)} />
      ) : (
        <div className="stack">
          <h1>Already set up</h1>
          <p className="muted">
            This installation already has an administrator. Log in, or ask an administrator for an invitation.
          </p>
          <Link className="btn btn-primary" to="/login">
            Go to log in
          </Link>
        </div>
      )}
    </AuthShell>
  );
}

function SetupForm({ onDone }: { onDone: () => void }) {
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const { busy, error, setError, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (password !== repeat) {
      setError("The passwords do not match.");
      return;
    }
    const ok = await run(async () => {
      await api.post("/setup", { setup_code: code, email, display_name: name, password });
      return true;
    });
    if (ok) onDone();
  }

  return (
    <form onSubmit={submit} className="stack">
      <div>
        <div className="eyebrow">First-run setup</div>
        <h1>Create the administrator</h1>
        <p className="muted">This page works only once, while the installation has no users.</p>
      </div>
      <Notice kind="info">
        Get the setup code from the computer running the platform: <code>.\scripts\dev.ps1 users setup-code</code>{" "}
        (on a server: <code>python -m app.cli users setup-code</code>).
      </Notice>
      <ErrorBox message={error} />
      <Field label="Setup code">
        <input required autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} placeholder="XXXX-XXXX-XXXX-XXXX" autoFocus />
      </Field>
      <Field label="Your name">
        <input required maxLength={200} autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="E-mail">
        <input type="email" required autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      <Field label="Password" hint="At least 12 characters. A few random words work well.">
        <input type="password" required minLength={12} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      <Field label="Repeat password">
        <input type="password" required autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} />
      </Field>
      <button className="btn btn-primary btn-large" disabled={busy}>
        {busy ? "Creating…" : "Create administrator"}
      </button>
      <p className="muted">Next you will set up an authenticator app: it is required for every account.</p>
    </form>
  );
}
