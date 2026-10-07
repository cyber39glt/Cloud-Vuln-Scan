// The only place that talks to the API. The session lives in an HttpOnly cookie the
// browser sends automatically (same origin); this code never sees or stores it.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type Listener = () => void;
const sessionEndedListeners = new Set<Listener>();

/** Called when the API says the session has ended (401), e.g. after a timeout. */
export function onSessionEnded(listener: Listener): () => void {
  sessionEndedListeners.add(listener);
  return () => sessionEndedListeners.delete(listener);
}

function messageFrom(body: unknown, status: number): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      // Validation errors: [{loc: ["body", "name"], msg: "..."}]
      return detail
        .map((d: { loc?: unknown[]; msg?: string }) => {
          const field = (d.loc ?? []).filter((p) => p !== "body").join(".");
          return field ? `${field}: ${d.msg}` : String(d.msg);
        })
        .join("; ");
    }
  }
  return status >= 500 ? "The server had a problem. Try again later." : `Request failed (${status}).`;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = {
    method,
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  };
  if (method === "POST" || body !== undefined) {
    // Every POST must be JSON (the API's protection against cross-site requests).
    init.headers = { ...init.headers, "Content-Type": "application/json" };
    init.body = JSON.stringify(body ?? {});
  }
  const response = await fetch(`/api/v1${path}`, init);
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  const data: unknown = text ? JSON.parse(text) : undefined;
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/auth/")) {
      sessionEndedListeners.forEach((listener) => listener());
    }
    throw new ApiError(response.status, messageFrom(data, response.status));
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  put: <T>(path: string) => request<T>("PUT", path),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  delete: <T>(path: string) => request<T>("DELETE", path),
};

/** Download a file from the API (same-origin, with the session cookie). */
export async function download(path: string, filename: string): Promise<void> {
  const response = await fetch(`/api/v1${path}`, { credentials: "same-origin" });
  if (!response.ok) throw new ApiError(response.status, `Download failed (${response.status}).`);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
