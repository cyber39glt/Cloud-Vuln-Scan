import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { AuthShell } from "../components/AuthShell";
import { ErrorBox, Field, Loading } from "../components/ui";
import { useAction } from "../hooks";
import type { InviteInfo } from "../types";
import { MfaEnrollment } from "./Login";

/** The token is in the link's #fragment, which browsers never send to the server.
 * After reading it, it is removed from the address bar (and so from the history). */
export function InvitePage() {
  const [token] = useState(() => window.location.hash.replace(/^#/, ""));
  const [info, setInfo] = useState<InviteInfo | null>(null);
  const [accepted, setAccepted] = useState(false);
  const { run, error: lookupError } = useAction();

  useEffect(() => {
    if (!token) return;
    window.history.replaceState(null, "", window.location.pathname);
    void run(async () => setInfo(await api.post<InviteInfo>("/invites/lookup", { token })));
  }, [token, run]);

  let body;
  if (accepted) body = <MfaEnrollment />;
  else if (!token || lookupError)
    body = (
      <div className="stack">
        <h1>Invitation not valid</h1>
        <ErrorBox message={lookupError ?? "This link is incomplete. Open the full link you were sent."} />
        <p className="muted">Ask your administrator for a new invitation. Each link works once and expires.</p>
        <Link to="/login">Already have an account? Log in</Link>
      </div>
    );
  else if (!info) body = <Loading />;
  else body = <AcceptForm token={token} info={info} onDone={() => setAccepted(true)} />;

  return <AuthShell>{body}</AuthShell>;
}

function AcceptForm({ token, info, onDone }: { token: string; info: InviteInfo; onDone: () => void }) {
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
      await api.post("/invites/accept", { token, password });
      return true;
    });
    if (ok) onDone();
  }

  return (
    <form onSubmit={submit} className="stack">
      <div>
        <div className="eyebrow">Invitation · {info.consultancy}</div>
        <h1>Welcome, {info.display_name}</h1>
        <p className="muted">
          You are invited as {info.role === "admin" ? "an administrator" : "a consultant"} with the e-mail address{" "}
          <strong>{info.email}</strong>. Choose a password to create your account.
        </p>
      </div>
      <ErrorBox message={error} />
      {/* Lets password managers save the right user name. */}
      <input type="email" autoComplete="username" value={info.email} readOnly hidden />
      <Field label="Password" hint="At least 12 characters. A few random words work well.">
        <input type="password" required minLength={12} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
      </Field>
      <Field label="Repeat password">
        <input type="password" required autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} />
      </Field>
      <button className="btn btn-primary btn-large" disabled={busy}>
        {busy ? "Creating…" : "Create my account"}
      </button>
      <p className="muted">Next you will set up an authenticator app: it is required for every account.</p>
    </form>
  );
}
