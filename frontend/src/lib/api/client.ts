/**
 * Secure API client.
 *
 * - Same-origin only: accepts relative `/api/` paths and rejects absolute or protocol-relative
 *   URLs, so a bug can never send credentials or data to another origin.
 * - Every request has a timeout.
 * - Responses are validated at runtime before the UI trusts them; TypeScript types alone are
 *   not a security boundary.
 * - Server error envelopes are surfaced with their correlation ID so analysts can trace a
 *   failure to the exact log line, without the UI ever displaying raw server internals.
 *
 * Authentication (Phase 2) will attach to this client: access token held in memory only,
 * refresh via an HttpOnly cookie. Tokens are never written to web storage.
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

const DEFAULT_TIMEOUT_MS = 8000;
const SAFE_PATH = /^\/api\/v\d+\/[A-Za-z0-9/_\-.]*$/;

export function assertSafePath(path: string): void {
  if (!SAFE_PATH.test(path) || path.includes("..") || path.includes("//")) {
    throw new ApiError(0, "unsafe_path", "Refused to call a non-API or cross-origin path", null);
  }
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

export async function apiGet<T>(
  path: string,
  validate: Validator<T>,
  options: { timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<T> {
  assertSafePath(path);
  const timeout = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;

  let response: Response;
  try {
    response = await fetch(path, {
      method: "GET",
      headers: { Accept: "application/json" },
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

  if (!response.ok) throw await toApiError(response);

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

export { isRecord };
