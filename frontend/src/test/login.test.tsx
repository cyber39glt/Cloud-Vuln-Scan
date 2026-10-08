import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth";
import { LoginPage } from "../pages/Login";

type Handler = (url: string, init: RequestInit) => [number, unknown];

function stubApi(handler: Handler) {
  const calls: { url: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, body: init.body ? JSON.parse(String(init.body)) : undefined });
      const [status, body] = handler(url, init);
      return new Response(body === undefined ? null : JSON.stringify(body), { status });
    }),
  );
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe("login", () => {
  it("asks for the authenticator code after a correct password", async () => {
    const calls = stubApi((url) => {
      if (url.endsWith("/auth/me")) return [401, { detail: "Not logged in." }];
      if (url.endsWith("/auth/login")) return [200, { mfa_enrolled: true, next_step: "mfa_verify" }];
      return [204, undefined];
    });
    render(
      <MemoryRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>,
    );
    fill("E-mail", "me@example.com");
    fill("Password", "a long passphrase");
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByText("Authenticator code");
    fill("6-digit code", "123 456");
    fireEvent.click(screen.getByRole("button", { name: "Log in" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/auth/mfa/verify"))).toBe(true));
    const verify = calls.find((c) => c.url.endsWith("/auth/mfa/verify"))!;
    expect(verify.body).toEqual({ code: "123456" });
  });

  it("shows the server's generic error for a wrong password", async () => {
    stubApi((url) => {
      if (url.endsWith("/auth/me")) return [401, { detail: "Not logged in." }];
      return [401, { detail: "Invalid e-mail or password, or the account is temporarily locked." }];
    });
    render(
      <MemoryRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>,
    );
    fill("E-mail", "me@example.com");
    fill("Password", "wrong");
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      "Invalid e-mail or password, or the account is temporarily locked.",
    );
  });

  it("requires acknowledging the recovery codes after setting up MFA", async () => {
    stubApi((url) => {
      if (url.endsWith("/auth/me")) return [401, { detail: "Not logged in." }];
      if (url.endsWith("/auth/login")) return [200, { mfa_enrolled: false, next_step: "mfa_setup" }];
      if (url.endsWith("/auth/mfa/setup"))
        return [200, { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/SubtleTech:me?secret=JBSWY3DPEHPK3PXP" }];
      if (url.endsWith("/auth/mfa/activate")) return [200, { recovery_codes: ["aaaa-bbbb-cccc", "dddd-eeee-ffff"], note: "" }];
      return [204, undefined];
    });
    render(
      <MemoryRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>,
    );
    fill("E-mail", "new@example.com");
    fill("Password", "temporary");
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByText("Set up your authenticator");
    await screen.findByText("JBSW Y3DP EHPK 3PXP");
    fill("6-digit code", "123456");
    // The button reads "Checking…" until the QR code has been drawn.
    fireEvent.click(await screen.findByRole("button", { name: "Turn on MFA" }));
    await screen.findByText("aaaa-bbbb-cccc");
    const proceed = screen.getByRole("button", { name: "Continue" });
    expect(proceed).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByLabelText(/I have saved these codes/));
    expect(proceed).toHaveProperty("disabled", false);
  });
});
