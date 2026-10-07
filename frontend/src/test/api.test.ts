import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, onSessionEnded } from "../api";

function respond(status: number, body?: unknown) {
  // A new Response per call: a body can be read only once.
  return vi.fn(
    async (_url: string, _init?: RequestInit) =>
      new Response(body === undefined ? null : JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("api client", () => {
  it("sends every POST as JSON with the session cookie", async () => {
    const fetchMock = respond(200, { ok: true });
    vi.stubGlobal("fetch", fetchMock);
    await api.post("/auth/logout");
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/v1/auth/logout");
    expect(init?.credentials).toBe("same-origin");
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(init?.body).toBe("{}");
  });

  it("turns validation errors into a readable message", async () => {
    vi.stubGlobal("fetch", respond(422, { detail: [{ loc: ["body", "account_id"], msg: "String should match pattern" }] }));
    await expect(api.post("/clients/x/connections/aws", {})).rejects.toThrow("account_id: String should match pattern");
  });

  it("hides server internals on 5xx", async () => {
    vi.stubGlobal("fetch", respond(500, { trace: "boom" }));
    await expect(api.get("/clients")).rejects.toThrow("The server had a problem");
  });

  it("reports an ended session, except for the login endpoints themselves", async () => {
    const listener = vi.fn();
    const stop = onSessionEnded(listener);
    vi.stubGlobal("fetch", respond(401, { detail: "Not logged in." }));
    await expect(api.get("/clients")).rejects.toBeInstanceOf(ApiError);
    expect(listener).toHaveBeenCalledTimes(1);
    await expect(api.post("/auth/login", {})).rejects.toBeInstanceOf(ApiError);
    expect(listener).toHaveBeenCalledTimes(1);
    stop();
  });
});
