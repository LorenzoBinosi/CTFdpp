const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
const unsafeMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export class ApiError extends Error {
  constructor(message, status, payload = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export async function apiRequest(path, options = {}) {
  if (!path.startsWith("/api/v1/") && path !== "/api/v1") {
    throw new TypeError("Only CTFZone API paths can pass through the BFF");
  }
  const method = String(options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  headers.set("accept", "application/json");
  if (unsafeMethods.has(method) && csrfToken) headers.set("csrf-token", csrfToken);

  let body = options.body;
  if (body !== undefined && body !== null && !(body instanceof FormData) && typeof body !== "string") {
    headers.set("content-type", "application/json");
    body = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(`/bff${path}`, {
      ...options,
      method,
      headers,
      body,
      credentials: "same-origin",
    });
  } catch (error) {
    const unavailable = new ApiError(
      "The platform is unreachable. Check your connection and try again.",
      0,
    );
    unavailable.cause = error;
    throw unavailable;
  }

  const contentType = response.headers.get("content-type") || "";
  let payload = null;
  if (contentType.includes("application/json")) {
    try {
      payload = await response.json();
    } catch (_error) {
      payload = null;
    }
  }
  if (!response.ok) {
    const message = payload?.message || payload?.error?.message || `Request failed (${response.status})`;
    throw new ApiError(message, response.status, payload);
  }
  return { response, payload, data: payload?.data ?? payload };
}

export function idempotencyHeaders() {
  const key = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return { "idempotency-key": key };
}
