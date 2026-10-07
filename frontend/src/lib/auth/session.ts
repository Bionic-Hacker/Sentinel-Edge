/**
 * The browser side of the session (ADR-0003).
 *
 * - The access token exists only in this module's memory: never localStorage/sessionStorage
 *   (an XSS could read those), never a cookie the page can read. A reload drops it; the
 *   HttpOnly refresh cookie silently restores the session.
 * - Refresh is single-flight within a tab and serialized *across* tabs with the Web Locks API.
 *   This matters: the server treats a reused refresh token as theft and ends the session, so two
 *   tabs racing to refresh with the same cookie would log the user out everywhere.
 * - The token is refreshed shortly before it expires, so normal use never sees a 401.
 */
import { apiRequest, ApiError, configureAuth } from "../api/client";
import { isAuthenticated } from "../api/validators";
import type { AuthenticatedResponse, UserProfile } from "../types";

const REFRESH_LOCK = "sentineledge-refresh";
const REFRESH_EARLY_SECONDS = 60;

let accessToken: string | null = null;
let refreshTimer: ReturnType<typeof setTimeout> | null = null;
let inflight: Promise<AuthenticatedResponse | null> | null = null;
type Listener = (user: UserProfile | null) => void;
const listeners = new Set<Listener>();

export function getAccessToken(): string | null {
  return accessToken;
}

export function onSessionChange(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function notify(user: UserProfile | null): void {
  for (const listener of listeners) listener(user);
}

export function startSession(response: AuthenticatedResponse): void {
  accessToken = response.access_token;
  if (refreshTimer) clearTimeout(refreshTimer);
  const delay = Math.max(response.expires_in - REFRESH_EARLY_SECONDS, 10) * 1000;
  refreshTimer = setTimeout(() => void refreshSession(), delay);
  notify(response.user);
}

export function endSession(): void {
  accessToken = null;
  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = null;
  notify(null);
}

async function doRefresh(): Promise<AuthenticatedResponse | null> {
  try {
    const response = await apiRequest("/api/v1/auth/refresh", isAuthenticated, {
      method: "POST",
      authenticated: false,
    });
    startSession(response);
    return response;
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
      endSession();
      return null;
    }
    throw error; // network trouble: keep the current state, let the caller decide
  }
}

/** Refresh the session. Concurrent callers (in this tab or others) share one exchange. */
export function refreshSession(): Promise<AuthenticatedResponse | null> {
  inflight ??= (
    typeof navigator !== "undefined" && "locks" in navigator && navigator.locks
      ? navigator.locks.request(REFRESH_LOCK, doRefresh)
      : doRefresh()
  ).finally(() => {
    inflight = null;
  });
  return inflight;
}

configureAuth({
  getAccessToken,
  refresh: async () => (await refreshSession().catch(() => null)) !== null,
});
