import type { AuthenticatedResponse, Capability, Role, UserProfile } from "../lib/types";

export const CAPS: Capability[] = [
  { key: "platform.health", name: "Health endpoint", area: "Platform", provenance: "LOCAL", status: "implemented", phase: 1, note: "Local." },
  { key: "aws.waf", name: "AWS WAF on CloudFront", area: "WAF", provenance: "REAL_AWS", status: "planned", phase: 5, note: "Terraform." },
  { key: "sim.waf_toggle", name: "In-dashboard WAF rule toggling", area: "WAF", provenance: "SIMULATED", status: "planned", phase: 7, note: "Simulation only." },
];

export function profile(overrides: Partial<UserProfile> = {}): UserProfile {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    email: "analyst@example.com",
    display_name: "Ana Lyst",
    role: "ANALYST" as Role,
    mfa_enabled: false,
    pending_steps: [],
    ...overrides,
  };
}

export function authenticated(user: UserProfile = profile(), token = "access.token.one"): AuthenticatedResponse {
  return { status: "authenticated", access_token: token, token_type: "bearer", expires_in: 900, user };
}

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

export const unauthorized = () =>
  jsonResponse({ error: { code: "session_expired", message: "Your session has ended. Sign in again." } }, 401);

type Handler = (init: RequestInit | undefined) => Response | Promise<Response>;

/** Route fetch calls by "METHOD /path" (query string ignored) or by "/path" for any method. */
export function mockApi(routes: Record<string, Handler>) {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const path = raw.split("?")[0] ?? raw;
    const method = (init?.method ?? "GET").toUpperCase();
    const handler = routes[`${method} ${path}`] ?? routes[path];
    return Promise.resolve(
      handler ? handler(init) : jsonResponse({ error: { code: "not_found", message: "Not Found" } }, 404),
    );
  };
}
