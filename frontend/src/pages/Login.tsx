import QRCode from "qrcode";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Field, Notice } from "../components/ui";
import { useAction } from "../hooks";
import type { LoginResult, MfaSetup, RecoveryCodes } from "../types";

type Step = "password" | "mfa_verify" | "mfa_setup" | "recovery_codes";

/** Two-step login. MFA is mandatory: first-time users set up an authenticator here. */
export function LoginPage() {
  const { refresh, sessionExpired } = useAuth();
  const [step, setStep] = useState<Step>("password");
  const [codes, setCodes] = useState<string[]>([]);

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="brand brand-large">
          <img src="/favicon.svg" alt="" width={32} height={32} />
          <span>Cloud Vuln Scan</span>
        </div>
        {step === "password" && (
          <>
            {sessionExpired && <Notice kind="warn">Your session ended. Please log in again.</Notice>}
            <PasswordStep onDone={(result) => setStep(result.next_step)} />
          </>
        )}
        {step === "mfa_verify" && (
          <VerifyStep onDone={() => void refresh()} onRestart={() => setStep("password")} />
        )}
        {step === "mfa_setup" && (
          <SetupStep
            onDone={(recovery) => {
              setCodes(recovery);
              setStep("recovery_codes");
            }}
            onRestart={() => setStep("password")}
          />
        )}
        {step === "recovery_codes" && <RecoveryCodesStep codes={codes} onDone={() => void refresh()} />}
      </div>
      <p className="auth-footer muted">Read-only cloud security assessments. Authorized users only.</p>
    </div>
  );
}

function PasswordStep({ onDone }: { onDone: (result: LoginResult) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const result = await run(() => api.post<LoginResult>("/auth/login", { email, password }));
    if (result) {
      setPassword("");
      onDone(result);
    }
  }

  return (
    <form onSubmit={submit} className="stack">
      <h1>Log in</h1>
      <ErrorBox message={error} />
      <Field label="E-mail">
        <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
      </Field>
      <Field label="Password">
        <input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      <button className="btn btn-primary" disabled={busy}>
        {busy ? "Checking…" : "Continue"}
      </button>
    </form>
  );
}

function VerifyStep({ onDone, onRestart }: { onDone: () => void; onRestart: () => void }) {
  const [useRecovery, setUseRecovery] = useState(false);
  const [value, setValue] = useState("");
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const body = useRecovery ? { recovery_code: value } : { code: value.replace(/\s/g, "") };
    const ok = await run(async () => {
      await api.post("/auth/mfa/verify", body);
      return true;
    });
    if (ok) onDone();
    else setValue("");
  }

  return (
    <form onSubmit={submit} className="stack">
      <h1>Authenticator code</h1>
      <p className="muted">
        {useRecovery
          ? "Enter one of your saved recovery codes. Each code works only once."
          : "Open your authenticator app and enter the 6-digit code for Cloud Vuln Scan."}
      </p>
      <ErrorBox message={error === "Not logged in." ? "Too many attempts. Please log in again." : error} />
      <Field label={useRecovery ? "Recovery code" : "6-digit code"}>
        <input
          inputMode={useRecovery ? "text" : "numeric"}
          autoComplete="one-time-code"
          required
          value={value}
          onChange={(e) => setValue(e.target.value)}
          autoFocus
          maxLength={useRecovery ? 32 : 7}
        />
      </Field>
      <button className="btn btn-primary" disabled={busy}>
        {busy ? "Checking…" : "Log in"}
      </button>
      <div className="row-between">
        <button type="button" className="btn-link" onClick={() => setUseRecovery(!useRecovery)}>
          {useRecovery ? "Use the authenticator app" : "Lost your phone? Use a recovery code"}
        </button>
        <button type="button" className="btn-link" onClick={onRestart}>
          Start again
        </button>
      </div>
    </form>
  );
}

function SetupStep({ onDone, onRestart }: { onDone: (codes: string[]) => void; onRestart: () => void }) {
  const [setup, setSetup] = useState<MfaSetup>();
  const [qr, setQr] = useState<string>();
  const [code, setCode] = useState("");
  const { busy, error, run } = useAction();
  // Each setup call creates a NEW secret: make sure it happens only once (React's
  // development mode runs effects twice), or the QR code would not match.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void run(async () => {
      const result = await api.post<MfaSetup>("/auth/mfa/setup");
      setSetup(result);
      // Rendered in the browser: the secret never goes to any other service.
      setQr(await QRCode.toDataURL(result.otpauth_uri, { margin: 1, width: 200 }));
    });
  }, [run]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const result = await run(() => api.post<RecoveryCodes>("/auth/mfa/activate", { code: code.replace(/\s/g, "") }));
    if (result) onDone(result.recovery_codes);
    else setCode("");
  }

  return (
    <form onSubmit={submit} className="stack">
      <h1>Set up your authenticator</h1>
      <p className="muted">
        Multi-factor authentication is required for every account. Use an authenticator app such as Microsoft
        Authenticator, Google Authenticator, 1Password or Bitwarden.
      </p>
      <ErrorBox message={error} />
      {setup && (
        <>
          <ol className="steps">
            <li>In the app, choose “add account” and scan this code:</li>
          </ol>
          {qr && <img className="qr" src={qr} alt="QR code for your authenticator app" width={200} height={200} />}
          <details>
            <summary>Can’t scan? Enter the key by hand</summary>
            <code className="secret">{setup.secret.match(/.{1,4}/g)?.join(" ")}</code>
          </details>
          <ol className="steps" start={2}>
            <li>Enter the 6-digit code the app now shows:</li>
          </ol>
          <Field label="6-digit code">
            <input inputMode="numeric" autoComplete="one-time-code" required value={code} onChange={(e) => setCode(e.target.value)} maxLength={7} />
          </Field>
          <button className="btn btn-primary" disabled={busy}>
            {busy ? "Checking…" : "Turn on MFA"}
          </button>
        </>
      )}
      <button type="button" className="btn-link" onClick={onRestart}>
        Start again
      </button>
    </form>
  );
}

function RecoveryCodesStep({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <div className="stack">
      <h1>Save your recovery codes</h1>
      <Notice kind="warn">
        If you lose your phone, each of these codes lets you log in once. Store them in a password manager now: they
        will not be shown again.
      </Notice>
      <ul className="recovery-codes">
        {codes.map((c) => (
          <li key={c}>
            <code>{c}</code>
          </li>
        ))}
      </ul>
      <label className="checkbox">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />I have saved these codes
        somewhere safe
      </label>
      <button className="btn btn-primary" disabled={!saved} onClick={onDone}>
        Continue
      </button>
    </div>
  );
}
