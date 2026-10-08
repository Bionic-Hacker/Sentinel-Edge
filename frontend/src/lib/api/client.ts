/**
 * Secure API client.
 *
 * - Same-origin only: accepts relative `/api/v<n>/` paths and rejects absolute or
 *   protocol-relative URLs, so a bug can never send credentials or data to another origin.
 *   Query strings are built from structured values, never concatenated by callers.
 * - Every request has a timeout and refuses redirects.
 * - Responses are validated at runtime before the UI trusts them; TypeScript types alone are
 *   not a security boundary.
 * - Server error envelopes are surfaced with their correlation ID so analysts can trace a
 *   failure to the exact log line, without the UI ever displaying raw server internals.
 * - Authentication (ADR-0003): the access token lives in memory only (see lib/auth/session.ts)
 *   and is attached as a bearer header. On a 401 the client refreshes once, then retries once.
 *   Every request carries the CSRF header the server requires on cookie-bearing endpoints.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly correlationId: string | null;

  constructor(status: number, code: string, message: string, correlationId: string | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.correlationId = correlationId;
  }
}

export type Validator<T> = (value: unknown) => value is T;

/** Supplied by the auth session module; the client itself never stores tokens. */
export interface AuthHooks {
  getAccessToken: () => string | null;
  refresh: () => Promise<boolean>;
}

let authHooks: AuthHooks | null = null;
export function configureAuth(hooks: AuthHooks | null): void {
  authHooks = hooks;
}

export type QueryValue = string | number | boolean | null | undefined;

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  query?: Record<string, QueryValue>;
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Attach the bearer token and refresh on 401 (default true). */
  authenticated?: boolean;
}

export const CSRF_HEADER = "X-SentinelEdge-CSRF";
const DEFAULT_TIMEOUT_MS = 8000;
const SAFE_PATH = /^\/api\/v\d+\/[A-Za-z0-9/_\-.]*$/;

export function assertSafePath(path: string): void {
  if (!SAFE_PATH.test(path) || path.includes("..") || path.includes("//")) {
    throw new ApiError(0, "unsafe_path", "Refused to call a non-API or cross-origin path", null);
  }
}

function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  assertSafePath(path);
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function toApiError(response: Response): Promise<ApiError> {
  const headerId = response.headers.get("X-Request-ID");
  try {
    const body: unknown = await response.json();
    const err = isRecord(body) && isRecord(body.error) ? body.error : null;
    if (err && typeof err.code === "string" && typeof err.message === "string") {
      const id = typeof err.correlation_id === "string" ? err.correlation_id : headerId;
      return new ApiError(response.status, err.code, err.message, id);
    }
  } catch {
    // Non-JSON error body (e.g. an upstream proxy page). Fall through to a generic error.
  }
  return new ApiError(response.status, "http_error", `Request failed (${response.status})`, headerId);
}

async function send(url: string, options: RequestOptions, token: string | null): Promise<Response> {
  const timeout = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;
  const headers: Record<string, string> = { Accept: "application/json", [CSRF_HEADER]: "1" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  try {
    return await fetch(url, {
      method: options.method ?? "GET",
      headers,
      body: options.body === undefined ? null : JSON.stringify(options.body),
      credentials: "same-origin",
      redirect: "error", // an API redirect is unexpected; never follow it silently
      signal,
    });
  } catch (cause) {
    const timedOut = cause instanceof DOMException && cause.name === "TimeoutError";
    throw new ApiError(
      0,
      timedOut ? "timeout" : "network_error",
      timedOut ? "The API did not respond in time" : "The API could not be reached",
      null,
    );
  }
}

/** Make a request. Pass `validate` to type-check a JSON body, or `null` for empty responses. */
export async function apiRequest<T>(
  path: string,
  validate: Validator<T> | null,
  options: RequestOptions = {},
): Promise<T> {
  const url = buildUrl(path, options.query);
  const hooks = (options.authenticated ?? true) ? authHooks : null;
  let response = await send(url, options, hooks ? hooks.getAccessToken() : null);

  if (response.status === 401 && hooks?.getAccessToken()) {
    // Access token expired or revoked: refresh once, then retry once.
    if (await hooks.refresh()) {
      response = await send(url, options, hooks.getAccessToken());
    }
  }

  if (!response.ok) throw await toApiError(response);
  if (validate === null) return undefined as T;

  const body: unknown = await response.json();
  if (!validate(body)) {
    throw new ApiError(
      response.status,
      "invalid_response",
      "The API returned an unexpected response shape",
      response.headers.get("X-Request-ID"),
    );
  }
  return body;
}

export function apiGet<T>(
  path: string,
  validate: Validator<T>,
  options: Omit<RequestOptions, "method" | "body"> = {},
): Promise<T> {
  return apiRequest(path, validate, { ...options, method: "GET" });
}

export { isRecord };
