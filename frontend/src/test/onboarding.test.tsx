import type { ReactNode } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth";
import { InvitePage } from "../pages/Invite";
import { LandingPage } from "../pages/Landing";
import { SetupPage } from "../pages/Setup";

const FAKE_TOKEN = "tok_" + "0123456789abcdefghijklmnop"; // gitleaks:allow (test-only)

type Handler = (url: string, method: string) => [number, unknown];

function stubApi(handler: Handler) {
  const calls: { url: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, body: init.body ? JSON.parse(String(init.body)) : undefined });
      const [status, body] = handler(url, init.method ?? "GET");
      return new Response(body === undefined ? null : JSON.stringify(body), { status });
    }),
  );
  return calls;
}

function renderPage(page: ReactNode) {
  return render(
    <MemoryRouter>
      <AuthProvider>{page}</AuthProvider>
    </MemoryRouter>,
  );
}

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

describe("landing page", () => {
  it("shows the features and the X handle, and asks only whether setup is needed", async () => {
    const calls = stubApi((url) => (url.endsWith("/setup") ? [200, { needed: false }] : [401, { detail: "Not logged in." }]));
    const { container } = renderPage(<LandingPage />);
    expect(screen.getByText("Strictly read-only")).toBeTruthy();
    expect(screen.getByText("AZ-SEC-001")).toBeTruthy();
    const handle = screen.getAllByRole("link", { name: /@cyber39glt/ })[0]!;
    expect(handle.getAttribute("href")).toBe("https://x.com/cyber39glt");
    expect(handle.getAttribute("rel")).toContain("noopener");
    await screen.findAllByRole("link", { name: /Log in/ });
    // No client data: the only API calls are the session check and the setup status.
    expect(new Set(calls.map((c) => c.url))).toEqual(new Set(["/api/v1/auth/me", "/api/v1/setup"]));
    expect(container.querySelector("[style]")).toBeNull(); // no inline styles (CSP)
  });

  it("offers setup on a fresh installation", async () => {
    stubApi((url) => (url.endsWith("/setup") ? [200, { needed: true }] : [401, { detail: "Not logged in." }]));
    renderPage(<LandingPage />);
    expect((await screen.findAllByRole("link", { name: /Set up/ })).length).toBeGreaterThan(0);
  });
});

describe("first-run setup", () => {
  it("sends the setup code and the new administrator, then starts MFA setup", async () => {
    const calls = stubApi((url, method) => {
      if (url.endsWith("/auth/me")) return [401, { detail: "Not logged in." }];
      if (url.endsWith("/api/v1/setup"))
        return method === "POST" ? [200, { mfa_enrolled: false, next_step: "mfa_setup" }] : [200, { needed: true }];
      if (url.endsWith("/auth/mfa/setup")) return [200, { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" }];
      return [204, undefined];
    });
    renderPage(<SetupPage />);
    await screen.findByText("Create the administrator");
    fill("Setup code", "abcd-efgh-ijkl-mnop");
    fill("Your name", "Owner");
    fill("E-mail", "owner@example.com");
    fill("Password", "a long passphrase here");
    fill("Repeat password", "a long passphrase here");
    fireEvent.click(screen.getByRole("button", { name: "Create administrator" }));
    await screen.findByText("Set up your authenticator");
    const sent = calls.find((c) => c.url.endsWith("/api/v1/setup") && c.body)!;
    expect(sent.body).toEqual({
      setup_code: "abcd-efgh-ijkl-mnop",
      email: "owner@example.com",
      display_name: "Owner",
      password: "a long passphrase here",
    });
  });

  it("refuses mismatched passwords before calling the server", async () => {
    const calls = stubApi((url) => (url.endsWith("/setup") ? [200, { needed: true }] : [401, { detail: "Not logged in." }]));
    renderPage(<SetupPage />);
    await screen.findByText("Create the administrator");
    fill("Setup code", "x");
    fill("Your name", "Owner");
    fill("E-mail", "owner@example.com");
    fill("Password", "a long passphrase here");
    fill("Repeat password", "something else entirely");
    fireEvent.click(screen.getByRole("button", { name: "Create administrator" }));
    expect((await screen.findByRole("alert")).textContent).toBe("The passwords do not match.");
    expect(calls.some((c) => c.body)).toBe(false);
  });
});

describe("invitation", () => {
  it("reads the token from the #fragment, removes it from the address bar and accepts", async () => {
    window.history.replaceState(null, "", `/invite#${FAKE_TOKEN}`);
    const calls = stubApi((url) => {
      if (url.endsWith("/auth/me")) return [401, { detail: "Not logged in." }];
      if (url.endsWith("/invites/lookup"))
        return [200, { email: "new@example.com", display_name: "New Person", role: "consultant", consultancy: "SubtleTech" }];
      if (url.endsWith("/invites/accept")) return [200, { mfa_enrolled: false, next_step: "mfa_setup" }];
      if (url.endsWith("/auth/mfa/setup")) return [200, { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" }];
      return [204, undefined];
    });
    renderPage(<InvitePage />);
    await screen.findByText("Welcome, New Person");
    expect(window.location.hash).toBe("");
    fill("Password", "a long passphrase here");
    fill("Repeat password", "a long passphrase here");
    fireEvent.click(screen.getByRole("button", { name: "Create my account" }));
    await screen.findByText("Set up your authenticator");
    const accept = calls.find((c) => c.url.endsWith("/invites/accept"))!;
    expect(accept.body).toEqual({ token: FAKE_TOKEN, password: "a long passphrase here" });
    // The token never appears in a URL the server sees.
    expect(calls.every((c) => !c.url.includes("tok_"))).toBe(true);
  });

  it("explains an invalid link", async () => {
    window.history.replaceState(null, "", "/invite#expired_token_value_1234567890");
    stubApi((url) =>
      url.endsWith("/auth/me")
        ? [401, { detail: "Not logged in." }]
        : [404, { detail: "This invitation link is not valid. It may have expired or been used already." }],
    );
    renderPage(<InvitePage />);
    await screen.findByText("Invitation not valid");
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("may have expired"));
  });
});
