import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../app/App";
import { authenticated, CAPS, jsonResponse, mockApi, profile } from "../../test/fixtures";
import { renderSettled } from "../../test/render";
import type { Inventory, InventoryItem, OwaspCoverage, Role } from "../../lib/types";

const metrics = (over: Partial<InventoryItem["metrics"]> = {}): InventoryItem["metrics"] => ({
  requests: 0,
  error_rate: 0,
  client_errors: 0,
  server_errors: 0,
  unauthenticated: 0,
  forbidden: 0,
  throttled: 0,
  security_rejections: 0,
  ...over,
});

const item = (over: Partial<InventoryItem>): InventoryItem => ({
  method: "GET",
  path: "/api/v1/health",
  summary: "Liveness probe",
  authentication: "None (public)",
  authorization: "None",
  roles: [],
  object_rule: null,
  csrf_protected: false,
  risk: "low",
  rate_limit: "120 / min per IP",
  owasp: ["API8"],
  data: "Version string",
  metrics: metrics({ requests: 40 }),
  last_scan: null,
  scan_note: "Not scanned yet: authenticated DAST runs arrive in Phase 8.",
  status: "protected",
  status_reasons: ["Authentication, authorization and rate limit enforced"],
  ...over,
});

const INVENTORY: Inventory = {
  generated_at: "2026-10-07T20:00:00.000000+00:00",
  window_hours: 24,
  metrics_enabled: true,
  summary: {
    endpoints: 2,
    public: 2,
    critical: 1,
    high: 0,
    requests: 52,
    security_rejections: 12,
    throttled: 3,
    unmatched_requests: 4,
    needs_attention: 1,
  },
  items: [
    item({
      method: "POST",
      path: "/api/v1/auth/login",
      summary: "Password sign-in",
      authorization: "Same-origin request with CSRF header",
      csrf_protected: true,
      risk: "critical",
      rate_limit: "20 / 2 min per IP",
      owasp: ["API2", "API4", "API6"],
      data: "Credentials",
      metrics: metrics({ requests: 12, error_rate: 1, client_errors: 12, unauthenticated: 9, throttled: 3, security_rejections: 12 }),
      status: "elevated",
      status_reasons: ["3 request(s) throttled in 24h"],
    }),
    item({}),
  ],
};

const OWASP: OwaspCoverage = {
  edition: "OWASP API Security Top 10 (2023)",
  items: [
    {
      code: "API1",
      name: "Broken Object Level Authorization",
      status: "mitigated",
      controls: ["Object-level checks in the service layer"],
      evidence: ["tests/integration/test_users_and_audit_api.py::test_users_can_read_only_their_own_record"],
      planned: null,
      exposed_endpoints: 4,
    },
    {
      code: "API7",
      name: "Server Side Request Forgery",
      status: "not_exposed",
      controls: ["No endpoint fetches a caller-supplied URL"],
      evidence: ["tests/unit/test_egress.py::test_internal_addresses_are_refused"],
      planned: "Applied to every outbound call when AI integrations arrive (Phase 9)",
      exposed_endpoints: 0,
    },
  ],
};

async function renderAs(role: Role, inventory: unknown = INVENTORY) {
  const user = profile({ role, mfa_enabled: true });
  const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(
    mockApi({
      "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(user)),
      "/api/v1/health": () => jsonResponse({ status: "ok", version: "0.3.0" }),
      "/api/v1/platform/capabilities": () => jsonResponse({ items: CAPS }),
      "/api/v1/api-security/inventory": () => jsonResponse(inventory),
      "/api/v1/api-security/owasp": () => jsonResponse(OWASP),
    }),
  );
  await renderSettled(
    <MemoryRouter initialEntries={["/apis"]}>
      <AppRoutes />
    </MemoryRouter>,
  );
  return fetchMock;
}

const calledInventory = (fetchMock: Awaited<ReturnType<typeof renderAs>>) =>
  fetchMock.mock.calls.some(([url]) => String(url).includes("/api-security/"));

describe("API Security Center", () => {
  it("shows the summary, every spec column and the OWASP coverage", async () => {
    await renderAs("SECURITY_ENGINEER");
    const table = await screen.findByRole("table", { name: /API endpoints/ });
    const headers = within(table).getAllByRole("columnheader").map((h) => h.textContent);
    for (const column of ["Endpoint", "Authentication", "Authorization", "Risk", "Rate limit", "Requests", "Error rate", "Attacks", "Last scan", "Status"]) {
      expect(headers).toContain(column);
    }
    const login = within(table).getByText("/api/v1/auth/login").closest("tr");
    expect(login).not.toBeNull();
    const cells = within(login as HTMLElement);
    expect(cells.getByText("critical")).toBeInTheDocument();
    expect(cells.getByText("100.0%")).toBeInTheDocument();
    expect(cells.getByText("Elevated")).toBeInTheDocument();

    const overview = screen.getByRole("region", { name: "Overview" });
    expect(within(overview).getByText("Unknown-path requests").nextSibling).toHaveTextContent("4");

    expect(screen.getByRole("heading", { name: "OWASP API Security Top 10 (2023)" })).toBeInTheDocument();
    expect(screen.getByText("Not exposed")).toBeInTheDocument();
    expect(screen.getByText(/AI integrations arrive \(Phase 9\)/)).toBeInTheDocument();
  });

  it("filters by risk and expands endpoint details", async () => {
    const user = userEvent.setup();
    await renderAs("DEVELOPER");
    const table = await screen.findByRole("table", { name: /API endpoints/ });
    await user.selectOptions(screen.getByLabelText("Risk"), "critical");
    expect(screen.getByText("1 of 2 endpoints")).toBeInTheDocument();
    expect(within(table).queryByText("/api/v1/health")).not.toBeInTheDocument();

    await user.click(within(table).getByRole("button", { name: "Show details for POST /api/v1/auth/login" }));
    expect(within(table).getByText("API2, API4, API6")).toBeInTheDocument();
    expect(within(table).getByText(/Origin check and X-SentinelEdge-CSRF header/)).toBeInTheDocument();
    expect(within(table).getByText(/3 throttled/)).toBeInTheDocument();
  });

  it("does not request the inventory for roles without access", async () => {
    const fetchMock = await renderAs("ANALYST");
    expect(await screen.findByText(/available to administrators, security engineers and developers/)).toBeInTheDocument();
    expect(calledInventory(fetchMock)).toBe(false);
  });

  it("rejects a response that does not match the expected shape", async () => {
    await renderAs("ADMIN", { ...INVENTORY, items: [{ method: "GET", path: "/x" }] });
    expect(await screen.findByRole("alert")).toHaveTextContent("unexpected response shape");
  });
});
