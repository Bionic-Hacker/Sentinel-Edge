import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../app/App";
import { isEventSummary } from "../../lib/api/secopsValidators";
import { isVulnerabilityDetail, isVulnerabilityOverview } from "../../lib/api/vulnValidators";
import type {
  Role,
  SbomDetail,
  SbomSummary,
  ScanSummary,
  VulnerabilityDetail,
  VulnerabilityOverview,
  VulnerabilitySummary,
} from "../../lib/types";
import { authenticated, CAPS, jsonResponse, mockApi, profile } from "../../test/fixtures";
import { renderSettled } from "../../test/render";

type Handler = (init: RequestInit | undefined) => Response | Promise<Response>;

interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
}

const NOW = "2026-10-08T12:00:00+00:00";
const APP = { id: "5e7e1ed6-0000-4000-8000-000000000001", slug: "sentineledge", name: "SentinelEdge" };
const SCAN = { id: "aaaaaaaa-0000-4000-8000-000000000001", reference: "SCAN-0002", imported_at: NOW };
const VID = "bbbbbbbb-0000-4000-8000-000000000001";

async function renderAs(role: Role, path: string, routes: Record<string, Handler> = {}) {
  const calls: Call[] = [];
  const api = mockApi({
    "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(profile({ role, mfa_enabled: true }))),
    "/api/v1/health": () => jsonResponse({ status: "ok", version: "0.7.0" }),
    "/api/v1/platform/capabilities": () => jsonResponse({ items: CAPS }),
    ...routes,
  });
  vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(raw, "http://localhost");
    const body = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    calls.push({ method: (init?.method ?? "GET").toUpperCase(), path: url.pathname, query: url.searchParams, body });
    return api(input, init);
  });
  await renderSettled(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes />
    </MemoryRouter>,
  );
  return calls;
}

const callsTo = (calls: Call[], method: string, path: string) => calls.filter((c) => c.method === method && c.path === path);
const apiError = (status: number, code: string, message: string) => jsonResponse({ error: { code, message } }, status);

afterEach(() => {
  vi.restoreAllMocks();
});

// --- Fixtures ----------------------------------------------------------------------------------

function finding(over: Partial<VulnerabilitySummary> = {}): VulnerabilitySummary {
  return {
    id: VID,
    reference: "VULN-0001",
    application: APP,
    tool: "semgrep",
    category: "sast",
    rule_id: "sentineledge-sql-built-from-strings",
    title: "SQL text built from a formatted string",
    severity: "critical",
    component: "backend/app/services/example.py",
    location: "backend/app/services/example.py:42",
    cve: null,
    fixed_version: null,
    fixable: true,
    status: "open",
    first_seen_at: NOW,
    last_seen_at: NOW,
    resolved_at: null,
    sla_due_at: "2026-10-15T12:00:00+00:00",
    overdue: false,
    times_reopened: 0,
    version: 1,
    ...over,
  };
}

function detail(over: Partial<VulnerabilityDetail> = {}): VulnerabilityDetail {
  return {
    ...finding(),
    cvss: null,
    recommendation: "Use bound parameters.",
    references: ["https://owasp.org/Top10/A03_2021-Injection/", "javascript:alert(1)"],
    status_note: null,
    first_scan: SCAN,
    last_scan: SCAN,
    acceptances: [],
    allowed_statuses: ["in_progress", "false_positive"],
    can_accept_risk: true,
    can_revoke_acceptance: false,
    max_acceptance_days: 30,
    ...over,
  };
}

function overviewOf(over: Partial<VulnerabilityOverview> = {}): VulnerabilityOverview {
  return {
    active: { critical: 1, high: 44, medium: 64, low: 62, info: 0 },
    active_total: 171,
    awaiting_fix: 44,
    overdue: 2,
    accepted: 0,
    false_positive: 0,
    fixed_30d: 4,
    by_category: { container: 150, sast: 21 },
    last_scan: {
      id: SCAN.id,
      reference: "SCAN-0002",
      application: APP,
      source: "local",
      imported_at: NOW,
      generated_at: NOW,
      commit_sha: "c6e4894" + "0".repeat(33),
      gate_passed: true,
    },
    ...over,
  };
}

const scan = (over: Partial<ScanSummary> = {}): ScanSummary => ({
  id: SCAN.id,
  reference: "SCAN-0002",
  application: APP,
  source: "local",
  commit_sha: "c6e4894" + "0".repeat(33),
  branch: "phase/8-appsec-scanning",
  imported_by_label: "cli:owner@example.com",
  imported_at: NOW,
  generated_at: NOW,
  reports: ["semgrep.json"],
  gate_passed: true,
  summary: { total: 170, new: 0, fixed: 4 },
  ...over,
});

const listRoutes = (items: VulnerabilitySummary[], over: Partial<VulnerabilityOverview> = {}) => ({
  "/api/v1/vulnerabilities": () => jsonResponse({ items, next_before: null }),
  "/api/v1/vulnerabilities/overview": () => jsonResponse(overviewOf(over)),
  "/api/v1/scans": () => jsonResponse({ items: [scan()] }),
});

// --- Vulnerabilities list -----------------------------------------------------------------------

describe("Vulnerabilities page", () => {
  it("shows the overview, the last scan and open findings by default", async () => {
    const calls = await renderAs("VIEWER", "/vulnerabilities", listRoutes([finding()]));
    expect(await screen.findByRole("link", { name: /VULN-0001: SQL text built/ })).toBeInTheDocument();
    expect(screen.getByText("Past SLA").parentElement).toHaveTextContent("2");
    expect(screen.getByText(/gate passed/)).toBeInTheDocument();
    expect(screen.getByText(/commit c6e4894/)).toBeInTheDocument();
    const list = callsTo(calls, "GET", "/api/v1/vulnerabilities")[0];
    expect(list?.query.getAll("status")).toEqual(["open", "in_progress"]);
    const scans = screen.getByRole("table", { name: "The last five scan imports" });
    expect(within(scans).getByText("SCAN-0002")).toBeInTheDocument();
  });

  it("filters are sent to the API and kept in the URL", async () => {
    const user = userEvent.setup();
    const calls = await renderAs("VIEWER", "/vulnerabilities", listRoutes([finding()]));
    await screen.findByRole("link", { name: /VULN-0001/ });
    await user.selectOptions(screen.getByLabelText("Fix"), "false");
    await user.selectOptions(screen.getByLabelText("Status"), "all");
    await user.type(screen.getByRole("searchbox"), "zlib{Enter}");
    await waitFor(() => {
      const last = callsTo(calls, "GET", "/api/v1/vulnerabilities").at(-1);
      expect(last?.query.get("fixable")).toBe("false");
      expect(last?.query.getAll("status")).toEqual([]);
      expect(last?.query.get("q")).toBe("zlib");
    });
  });

  it("renders scanner text as text, never markup", async () => {
    const hostile = finding({ title: '<img src=x onerror="alert(1)">', component: "<script>x</script>" });
    await renderAs("VIEWER", "/vulnerabilities", listRoutes([hostile]));
    expect(await screen.findByText(/<img src=x onerror="alert\(1\)">/)).toBeInTheDocument();
    expect(document.querySelector("img[src='x']")).toBeNull();
    expect(document.querySelector("main script")).toBeNull();
  });

  it("explains how to import the first scan", async () => {
    await renderAs("VIEWER", "/vulnerabilities", listRoutes([], { last_scan: null, active_total: 0 }));
    expect(await screen.findByText(/No scan imported yet/)).toBeInTheDocument();
    expect(screen.getByText("No findings match these filters.")).toBeInTheDocument();
  });

  it("marks package vulnerabilities that have no fix yet", async () => {
    const unfixable = finding({ category: "container", tool: "trivy", cve: "CVE-2026-76642", fixable: false, title: "util-linux" });
    await renderAs("VIEWER", "/vulnerabilities", listRoutes([unfixable]));
    expect(await screen.findByText("Awaiting an upstream fix", { selector: "span" })).toBeInTheDocument();
  });
});

// --- Finding detail ------------------------------------------------------------------------------

describe("Finding detail", () => {
  it("offers only the moves the server allows, and requires a note for a false positive", async () => {
    const user = userEvent.setup();
    const calls = await renderAs("SECURITY_ENGINEER", `/vulnerabilities/${VID}`, {
      [`/api/v1/vulnerabilities/${VID}`]: () => jsonResponse(detail()),
      [`POST /api/v1/vulnerabilities/${VID}/status`]: () =>
        jsonResponse(detail({ status: "false_positive", version: 2, allowed_statuses: ["open"], can_accept_risk: false })),
    });
    await screen.findByRole("heading", { name: "SQL text built from a formatted string" });
    expect(screen.queryByRole("button", { name: "Back to open" })).toBeNull();

    await user.click(screen.getByRole("button", { name: "Mark false positive" }));
    expect(screen.getByRole("alert")).toHaveTextContent("at least 10 characters");
    expect(callsTo(calls, "POST", `/api/v1/vulnerabilities/${VID}/status`)).toHaveLength(0);

    await user.type(screen.getByLabelText("Note"), "Test fixture, never deployed");
    await user.click(screen.getByRole("button", { name: "Mark false positive" }));
    await waitFor(() => expect(callsTo(calls, "POST", `/api/v1/vulnerabilities/${VID}/status`)).toHaveLength(1));
    expect(callsTo(calls, "POST", `/api/v1/vulnerabilities/${VID}/status`)[0]?.body).toEqual({
      status: "false_positive",
      version: 1,
      note: "Test fixture, never deployed",
    });
    expect(await screen.findByRole("button", { name: "Back to open" })).toBeInTheDocument();
  });

  it("a stale version asks to reload", async () => {
    const user = userEvent.setup();
    await renderAs("DEVELOPER", `/vulnerabilities/${VID}`, {
      [`/api/v1/vulnerabilities/${VID}`]: () =>
        jsonResponse(detail({ allowed_statuses: ["in_progress"], can_accept_risk: false })),
      [`POST /api/v1/vulnerabilities/${VID}/status`]: () =>
        apiError(409, "stale_version", "The finding changed since you loaded it."),
    });
    await user.click(await screen.findByRole("button", { name: "Start work" }));
    expect(await screen.findByText(/Someone changed this finding/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reload" })).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Accept the risk" })).toBeNull();
  });

  it("a viewer reads the finding but has no actions", async () => {
    await renderAs("VIEWER", `/vulnerabilities/${VID}`, {
      [`/api/v1/vulnerabilities/${VID}`]: () =>
        jsonResponse(detail({ allowed_statuses: [], can_accept_risk: false })),
    });
    await screen.findByRole("heading", { name: "SQL text built from a formatted string" });
    const main = screen.getByRole("main");
    expect(within(main).queryByRole("heading", { name: "Status" })).toBeNull();
    expect(within(main).queryByRole("button")).toBeNull();
  });

  it("links only https references", async () => {
    await renderAs("VIEWER", `/vulnerabilities/${VID}`, {
      [`/api/v1/vulnerabilities/${VID}`]: () => jsonResponse(detail({ allowed_statuses: [], can_accept_risk: false })),
    });
    const safe = await screen.findByRole("link", { name: "https://owasp.org/Top10/A03_2021-Injection/" });
    expect(safe).toHaveAttribute("rel", "noopener noreferrer");
    expect(screen.queryByRole("link", { name: "javascript:alert(1)" })).toBeNull();
    expect(screen.getByText("javascript:alert(1)")).toBeInTheDocument();
  });

  it("a lead accepts the risk within the severity's limit", async () => {
    const user = userEvent.setup();
    const accepted = detail({
      status: "accepted_risk",
      version: 2,
      allowed_statuses: [],
      can_accept_risk: false,
      can_revoke_acceptance: true,
      acceptances: [
        {
          id: "cccccccc-0000-4000-8000-000000000001",
          reference: "ACC-0001",
          justification: "Only reachable from the internal network today.",
          compensating_control: "Edge allow-list in front of the endpoint.",
          approver_label: "lead@example.com",
          created_at: NOW,
          expires_at: "2026-11-01T23:59:59+00:00",
          ended_at: null,
          end_reason: null,
          ended_by_label: null,
          in_force: true,
        },
      ],
    });
    const calls = await renderAs("SECURITY_ENGINEER", `/vulnerabilities/${VID}`, {
      [`/api/v1/vulnerabilities/${VID}`]: () => jsonResponse(detail()),
      [`POST /api/v1/vulnerabilities/${VID}/acceptances`]: () => jsonResponse(accepted, 201),
      [`POST /api/v1/vulnerabilities/${VID}/acceptances/cccccccc-0000-4000-8000-000000000001/revoke`]: () =>
        jsonResponse(detail({ version: 3 })),
    });
    const form = await screen.findByRole("form", { name: "Accept the risk" });
    expect(within(form).getByText(/at most 30 days/)).toBeInTheDocument();
    const expires = within(form).getByLabelText("Expires on");
    expect(expires).toHaveAttribute("max");
    await user.type(within(form).getByLabelText("Justification"), "Only reachable from the internal network today.");
    await user.type(within(form).getByLabelText("Compensating control"), "Edge allow-list in front of the endpoint.");
    await user.click(within(form).getByRole("button", { name: "Accept the risk" }));
    await waitFor(() => expect(callsTo(calls, "POST", `/api/v1/vulnerabilities/${VID}/acceptances`)).toHaveLength(1));
    const body = callsTo(calls, "POST", `/api/v1/vulnerabilities/${VID}/acceptances`)[0]?.body as Record<string, unknown>;
    expect(body.version).toBe(1);
    expect(body.expires_on).toMatch(/^\d{4}-\d{2}-\d{2}$/);

    expect(await screen.findByText("In force")).toBeInTheDocument();
    const revoke = screen.getByRole("button", { name: "Revoke" });
    expect(revoke).toBeDisabled();
    await user.type(screen.getByLabelText("Reason for revoking"), "Control removed");
    await user.click(revoke);
    await waitFor(() =>
      expect(
        callsTo(calls, "POST", `/api/v1/vulnerabilities/${VID}/acceptances/cccccccc-0000-4000-8000-000000000001/revoke`),
      ).toHaveLength(1),
    );
  });
});

// --- SBOM ------------------------------------------------------------------------------------------

const sbomSummary = (over: Partial<SbomSummary> = {}): SbomSummary => ({
  id: "dddddddd-0000-4000-8000-000000000001",
  application: APP,
  scan: SCAN,
  artifact: "api",
  format: "CycloneDX",
  spec_version: "1.6",
  subject: "sentineledge-api:scan",
  subject_version: "sha256:abc",
  component_count: 2,
  document_sha256: "f".repeat(64),
  created_at: NOW,
  ...over,
});

describe("SBOM page", () => {
  it("lists SBOMs, searches components and downloads the document", async () => {
    const user = userEvent.setup();
    const sbomId = "dddddddd-0000-4000-8000-000000000001";
    const components: SbomDetail = {
      ...sbomSummary(),
      components: [
        { name: "fastapi", version: "0.142.0", type: "library", purl: "pkg:pypi/fastapi@0.142.0", licenses: ["MIT"] },
        { name: "<b>bold</b>", version: null, type: null, purl: null, licenses: [] },
      ],
      components_total: 2,
    };
    const createUrl = vi.fn(() => "blob:http://localhost/sbom");
    const revokeUrl = vi.fn();
    Object.assign(URL, { createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const calls = await renderAs("DEVELOPER", "/sbom", {
      "/api/v1/sboms": () => jsonResponse({ items: [sbomSummary(), sbomSummary({ id: "e".repeat(8) + "-0000-4000-8000-000000000001", artifact: "web" })] }),
      [`/api/v1/sboms/${sbomId}`]: () => jsonResponse(components),
      [`/api/v1/sboms/${sbomId}/document`]: () =>
        new Response('{"bomFormat":"CycloneDX"}', { headers: { "Content-Type": "application/vnd.cyclonedx+json" } }),
    });
    expect(await screen.findByText("pkg:pypi/fastapi@0.142.0")).toBeInTheDocument();
    expect(screen.getByText("<b>bold</b>")).toBeInTheDocument(); // text, not markup
    expect(screen.getByRole("button", { name: /^api/ })).toHaveAttribute("aria-pressed", "true");

    await user.type(screen.getByRole("searchbox"), "fast{Enter}");
    await waitFor(() => expect(callsTo(calls, "GET", `/api/v1/sboms/${sbomId}`).at(-1)?.query.get("q")).toBe("fast"));

    await user.click(screen.getByRole("button", { name: "Download CycloneDX" }));
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
    expect(createUrl).toHaveBeenCalledTimes(1);
    expect(revokeUrl).toHaveBeenCalledWith("blob:http://localhost/sbom");
    expect(callsTo(calls, "GET", `/api/v1/sboms/${sbomId}/document`)).toHaveLength(1);
  });

  it("explains how to produce the first SBOM", async () => {
    await renderAs("VIEWER", "/sbom", { "/api/v1/sboms": () => jsonResponse({ items: [] }) });
    expect(await screen.findByText(/No SBOM imported yet/)).toBeInTheDocument();
  });
});

// --- Threats: scan events link to their finding ----------------------------------------------

describe("Scan events on the Threats page", () => {
  it("render, and link to the finding they report", async () => {
    const user = userEvent.setup();
    const event = {
      id: "ffffffff-0000-4000-8000-000000000002",
      seq: 7,
      occurred_at: NOW,
      provenance: "LOCAL",
      source: "appsec",
      category: "vulnerable_dependency",
      severity: "high",
      outcome: "detected",
      title: "New high finding: libpatched1: fixed upstream",
      rule_id: "CVE-2099-1001",
      source_ip: null,
      method: null,
      endpoint: null,
      status_code: null,
      actor_label: "cli:owner@example.com",
      incident_id: null,
    };
    await renderAs("ANALYST", "/threats?source=appsec", {
      "/api/v1/security-events": () => jsonResponse({ items: [event], next_before_seq: null }),
      [`/api/v1/security-events/${event.id}`]: () =>
        jsonResponse({
          ...event,
          user_agent: null,
          correlation_id: null,
          evidence: { vulnerability: "VULN-0012", vulnerability_id: VID, application: "sentineledge" },
        }),
    });
    await user.click(await screen.findByRole("button", { name: /libpatched1/ }));
    expect(await screen.findByRole("link", { name: "Open the finding" })).toHaveAttribute("href", `/vulnerabilities/${VID}`);
  });
});

// --- Contracts ------------------------------------------------------------------------------------

describe("Phase 8 contracts", () => {
  it("validators reject malformed findings and overviews", () => {
    expect(isVulnerabilityDetail(detail())).toBe(true);
    expect(isVulnerabilityDetail({ ...detail(), status: "deleted" })).toBe(false);
    expect(isVulnerabilityDetail({ ...detail(), allowed_statuses: ["fixed", 3] })).toBe(false);
    expect(isVulnerabilityOverview(overviewOf())).toBe(true);
    expect(isVulnerabilityOverview({ ...overviewOf(), active: { critical: 1 } })).toBe(false);
  });

  it("security events from scans are accepted (source appsec, new categories)", () => {
    const event = {
      id: "ffffffff-0000-4000-8000-000000000001",
      seq: 1,
      occurred_at: NOW,
      provenance: "LOCAL",
      source: "appsec",
      category: "exposed_secret",
      severity: "critical",
      outcome: "detected",
      title: "New critical finding: AWS access key",
      rule_id: "aws-access-token",
      source_ip: null,
      method: null,
      endpoint: null,
      status_code: null,
      actor_label: "cli:owner@example.com",
      incident_id: null,
    };
    expect(isEventSummary(event)).toBe(true);
    expect(isEventSummary({ ...event, category: "code_weakness" })).toBe(true);
  });
});
