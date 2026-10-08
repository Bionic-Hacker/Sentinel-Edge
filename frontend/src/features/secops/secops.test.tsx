import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../app/App";
import { isIncidentDetail, isOverview } from "../../lib/api/secopsValidators";
import type {
  Application,
  IncidentDetail,
  IncidentSummary,
  Overview,
  Person,
  Role,
  SecurityEventDetail,
  SecurityEventSummary,
  SimulationRun,
  WafRuleList,
} from "../../lib/types";
import { authenticated, CAPS, jsonResponse, mockApi, profile } from "../../test/fixtures";
import { renderSettled } from "../../test/render";

// --- Harness ----------------------------------------------------------------------------------

type Handler = (init: RequestInit | undefined) => Response | Promise<Response>;

interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
}

const USER_ID = "00000000-0000-4000-8000-000000000001";
const NOW = "2026-10-07T20:00:00+00:00";

/** Render the app at `path` signed in as `role`, recording every API call. */
async function renderAs(role: Role, path: string, routes: Record<string, Handler> = {}) {
  const calls: Call[] = [];
  const api = mockApi({
    "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(profile({ role, mfa_enabled: true }))),
    "/api/v1/health": () => jsonResponse({ status: "ok", version: "0.4.0" }),
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
const never = () => new Promise<Response>(() => undefined);

/** The <dd> value of a StatTile, found by its label. */
function tile(label: string) {
  const term = screen.getAllByText(label).find((el) => el.tagName === "DT");
  if (!term?.parentElement) throw new Error(`No stat tile "${label}"`);
  return term.parentElement;
}

// --- Fixtures ---------------------------------------------------------------------------------

const person = (over: Partial<Person> = {}): Person => ({ id: USER_ID, display_name: "Ana Lyst", role: "ANALYST", ...over });

function overview(view: "live" | "simulated", over: Partial<Overview> = {}): Overview {
  const live = view === "live";
  return {
    view,
    window_hours: 24,
    generated_at: NOW,
    status: { level: "attention", reasons: ["1 open incident is unassigned"] },
    incidents: {
      open: 3,
      unassigned: 1,
      by_severity: { high: 2, medium: 1 },
      by_status: { DETECTED: 1, INVESTIGATING: 2 },
      closed_in_window: 1,
      mean_minutes_to_triage: 42,
      mean_minutes_to_close: 300,
    },
    recent_incidents: [
      {
        id: "inc-1",
        reference: "INC-0001",
        title: live ? "Injection campaign from 127.0.0.1" : "Simulated credential stuffing",
        severity: "high",
        status: "DETECTED",
        detected_at: NOW,
      },
    ],
    events: {
      total: 58,
      detections: 4,
      stopped: 40,
      reached_app: 6,
      by_category: { sql_injection: 30, credential_stuffing: 28 },
      by_severity: { high: 20, medium: 38 },
      by_outcome: { rejected: 40, detected: 18 },
    },
    series: [
      { hour: "2026-10-07T18:00:00+00:00", events: 20, detections: 1, high_or_critical: 5 },
      { hour: "2026-10-07T19:00:00+00:00", events: 38, detections: 3, high_or_critical: 15 },
    ],
    top_sources: [
      {
        source_ip: live ? "127.0.0.1" : "203.0.113.7",
        events: 58,
        max_severity: "high",
        categories: ["sql_injection"],
        country: live ? null : "NL",
        last_seen: NOW,
      },
    ],
    top_rules: [{ rule_id: "SQLI-001", events: 30 }],
    countries: live ? [] : [{ country: "NL", events: 58 }],
    traffic: {
      source: live ? "api_metrics" : "simulator",
      requests: 1200,
      allowed: 1100,
      rejected: 100,
      blocked_at_edge: live ? 0 : 30,
      errors: 0,
      unknown_paths: 4,
      by_method: { GET: 1000, POST: 200 },
      series: [{ hour: "2026-10-07T19:00:00+00:00", requests: 1200, rejected: 100, errors: 0 }],
      top_endpoints: live ? [{ method: "POST", endpoint: "/api/v1/auth/login", requests: 400 }] : [],
    },
    controls: {
      detection: { status: "measured", summary: "17 HTTP rules and 7 correlation rules active", values: { rules: 24 } },
      waf: { status: live ? "planned" : "simulated", summary: "AWS WAF arrives in Phase 5", values: {} },
    },
    ...over,
  };
}

function eventSummary(over: Partial<SecurityEventSummary> = {}): SecurityEventSummary {
  return {
    id: "evt-1",
    seq: 101,
    occurred_at: NOW,
    provenance: "LOCAL",
    source: "http_analysis",
    category: "xss",
    severity: "medium",
    outcome: "detected",
    title: "Cross-site scripting pattern in a request",
    rule_id: "XSS-001",
    source_ip: "127.0.0.1",
    method: "GET",
    endpoint: "/api/v1/users",
    status_code: 401,
    actor_label: null,
    incident_id: null,
    ...over,
  };
}

const SNIPPET = '<script>alert("pwned")</script>';

function eventDetail(over: Partial<SecurityEventDetail> = {}): SecurityEventDetail {
  return {
    ...eventSummary(),
    user_agent: "curl/8.9",
    correlation_id: "req-abc",
    evidence: {
      findings: [
        { rule_id: "XSS-001", description: "Script tag", location: "query", field: "q", snippet: SNIPPET },
      ],
    },
    ...over,
  };
}

function incidentSummary(over: Partial<IncidentSummary> = {}): IncidentSummary {
  return {
    id: "inc-1",
    reference: "INC-0001",
    title: "Injection campaign from 127.0.0.1",
    severity: "high",
    category: "sql_injection",
    status: "DETECTED",
    resolution: null,
    provenance: "LOCAL",
    source_ip: "127.0.0.1",
    detection_rule: "COR-003",
    owner: null,
    event_count: 12,
    detected_at: NOW,
    created_at: NOW,
    updated_at: NOW,
    closed_at: null,
    ...over,
  };
}

const NO_PERMISSIONS: IncidentDetail["permissions"] = {
  can_edit: false,
  can_change_severity: false,
  can_assign: false,
  can_take: false,
  can_add_note: false,
  can_link_events: false,
  moves: [],
};

function incidentDetail(over: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    ...incidentSummary(),
    summary: "Repeated SQL injection patterns from one address.",
    remediation: null,
    version: 3,
    created_by_label: "system",
    trigger_event: null,
    events: [eventSummary({ incident_id: "inc-1" })],
    timeline: [
      { id: "tl-1", at: NOW, actor_label: "system", kind: "created", from_status: null, to_status: "DETECTED", body: null, details: { rule: "COR-003" } },
      { id: "tl-2", at: NOW, actor_label: "system", kind: "events_linked", from_status: null, to_status: null, body: null, details: { count: 12 } },
      { id: "tl-3", at: NOW, actor_label: "ana@example.com", kind: "note", from_status: null, to_status: null, body: "Looking now.", details: {} },
    ],
    risk: { score: 70, factors: [{ reason: "High severity", points: 40 }, { reason: "Attack served (2xx)", points: 30 }] },
    integrity: { verified: true, entries_checked: 3, first_mismatch: null },
    permissions: {
      can_edit: true,
      can_change_severity: false,
      can_assign: false,
      can_take: true,
      can_add_note: true,
      can_link_events: true,
      moves: [
        { to_status: "TRIAGED", label: "Move to Triaged", resolutions: [], note_required: false },
        { to_status: "CLOSED", label: "Close as not an incident", resolutions: ["false_positive", "duplicate"], note_required: true },
      ],
    },
    ...over,
  };
}

const measure = (status: "measured" | "not_connected" | "planned", value: number | null, note: string) => ({ status, value, note });

function application(over: Partial<Application> = {}): Application {
  return {
    id: "5e7e1ed6-0000-4000-8000-000000000001",
    slug: "sentineledge",
    name: "SentinelEdge",
    description: "This platform.",
    owner: null,
    environment: "local",
    criticality: "critical",
    domain: null,
    status: "active",
    is_platform: true,
    version: 1,
    created_at: NOW,
    updated_at: NOW,
    api_count: measure("measured", 45, "From the API inventory"),
    open_incidents: measure("measured", 3, "Live"),
    security_events_24h: measure("measured", 58, "Live"),
    waf_status: measure("planned", null, "Phase 5"),
    certificate_status: measure("planned", null, "Phase 5"),
    security_score: measure("planned", null, "Phase 10"),
    last_scan: measure("planned", null, "Phase 8"),
    vulnerability_count: measure("planned", null, "Phase 8"),
    ...over,
  };
}

const WAF_RULES: WafRuleList = {
  web_acl: "sentineledge-simulated-acl",
  note: "Changing a rule here affects simulations only.",
  items: [
    {
      rule_id: "SQLI-001",
      description: "SQL injection: boolean tautology",
      category: "sql_injection",
      severity: "high",
      comparable_group: "AWSManagedRulesSQLiRuleSet",
      mode: "block",
      matches_24h: 12,
      updated_at: null,
      updated_by_label: null,
    },
  ],
};

function run(over: Partial<SimulationRun> = {}): SimulationRun {
  return {
    id: "run-1",
    reference: "SIM-0001",
    scenario: "sql_injection",
    started_by_label: "admin@example.com",
    started_at: NOW,
    completed_at: NOW,
    seed: 7,
    summary: {
      requests: { total: 40, blocked_by_waf: 30, counted_by_waf: 0, reached_app: 2, benign: 8 },
      events: 32,
      detections: [{ rule_id: "COR-003", title: "Injection campaign", severity: "high" }],
      incidents: [{ id: "inc-2", reference: "INC-0002", title: "Injection campaign", severity: "high", opened: true }],
    },
    ...over,
  };
}

// --- Dashboard ----------------------------------------------------------------------------------

describe("security dashboard", () => {
  it("renders the status line, KPIs and the hourly chart from the overview", async () => {
    const calls = await renderAs("ANALYST", "/", { "/api/v1/security/overview": () => jsonResponse(overview("live")) });
    expect(await screen.findByText("1 open incident is unassigned")).toBeInTheDocument();
    expect(screen.getByText("Needs attention")).toBeInTheDocument();
    expect(tile("Open incidents")).toHaveTextContent("3");
    expect(tile("Open incidents")).toHaveTextContent("2 high or critical, 1 unassigned");
    expect(tile("Mean time to triage")).toHaveTextContent("42 min");
    const chart = screen.getByRole("slider", { name: "Security events per hour (live)" });
    expect(chart).toHaveAttribute("aria-valuetext", expect.stringContaining("38 events"));
    expect(screen.getByRole("link", { name: /INC-0001/ })).toHaveAttribute("href", "/incidents/inc-1");
    expect(screen.queryByText("Simulated data.")).not.toBeInTheDocument();
    expect(callsTo(calls, "GET", "/api/v1/security/overview")[0]?.query.get("view")).toBe("live");
  });

  it("labels the simulated view and asks for simulated data", async () => {
    const calls = await renderAs("VIEWER", "/?view=simulated", {
      "/api/v1/security/overview": () => jsonResponse(overview("simulated")),
    });
    expect(await screen.findByText("Simulated credential stuffing", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("Simulated data.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Simulated traffic" })).toBeInTheDocument();
    expect(callsTo(calls, "GET", "/api/v1/security/overview")[0]?.query.get("view")).toBe("simulated");
  });

  it("never shows live data under the simulated banner while the other view loads", async () => {
    let simulatedRequested = false;
    await renderAs("ANALYST", "/", {
      "/api/v1/security/overview": () => {
        if (!simulatedRequested) return jsonResponse(overview("live"));
        return never();
      },
    });
    expect(await screen.findByRole("heading", { name: "API traffic" })).toBeInTheDocument();
    simulatedRequested = true;
    await userEvent.click(screen.getByRole("radio", { name: "Simulated" }));
    expect(screen.getByText("Simulated data.")).toBeInTheDocument();
    expect(screen.getByText("Loading the security overview…")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "API traffic" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Injection campaign from 127\.0\.0\.1/)).not.toBeInTheDocument();
  });

  it("shows a developer no security operations data", async () => {
    const calls = await renderAs("DEVELOPER", "/");
    expect(screen.getByText(/Security operations data is available to/)).toBeInTheDocument();
    expect(callsTo(calls, "GET", "/api/v1/security/overview")).toHaveLength(0);
  });
});

// --- Threats ------------------------------------------------------------------------------------

describe("threats", () => {
  const routes = (over: Record<string, Handler> = {}): Record<string, Handler> => ({
    "/api/v1/security-events": () => jsonResponse({ items: [eventSummary()], next_before_seq: null }),
    "/api/v1/security-events/evt-1": () => jsonResponse(eventDetail()),
    ...over,
  });

  it("takes its filters from the URL", async () => {
    const calls = await renderAs(
      "VIEWER",
      "/threats?view=simulated&category=sql_injection&min_severity=high&source_ip=203.0.113.7",
      routes(),
    );
    await screen.findByRole("button", { name: eventSummary().title });
    const query = callsTo(calls, "GET", "/api/v1/security-events")[0]?.query;
    expect(query?.get("view")).toBe("simulated");
    expect(query?.get("category")).toBe("sql_injection");
    expect(query?.get("min_severity")).toBe("high");
    expect(query?.get("source_ip")).toBe("203.0.113.7");
    expect(screen.getByLabelText("Category")).toHaveValue("sql_injection");
    expect(screen.getByLabelText("Source IP")).toHaveValue("203.0.113.7");
    expect(screen.getByText("Simulated data.")).toBeInTheDocument();
  });

  it("shows the HTTP analysis of the selected event and renders attack snippets as text", async () => {
    await renderAs("ANALYST", "/threats", routes());
    await userEvent.click(await screen.findByRole("button", { name: eventSummary().title }));
    const detail = await screen.findByRole("complementary", { name: "Event detail" });
    expect(await within(detail).findByRole("heading", { name: "HTTP analysis" })).toBeInTheDocument();
    expect(within(detail).getByText("GET /api/v1/users")).toBeInTheDocument();
    expect(within(detail).getByText("curl/8.9")).toBeInTheDocument();
    // The attacker's snippet is shown verbatim as text and never becomes markup.
    const snippet = within(detail).getByText(SNIPPET);
    expect(snippet.tagName).toBe("CODE");
    expect(document.querySelectorAll("script")).toHaveLength(0);
  });

  it("opens an incident from an event and goes to it", async () => {
    const calls = await renderAs(
      "ANALYST",
      "/threats",
      routes({
        "POST /api/v1/incidents": () => jsonResponse(incidentDetail({ id: "inc-9", title: "XSS from the event" }), 201),
        "/api/v1/incidents/inc-9": () => jsonResponse(incidentDetail({ id: "inc-9", title: "XSS from the event" })),
      }),
    );
    await userEvent.click(await screen.findByRole("button", { name: eventSummary().title }));
    await userEvent.click(await screen.findByRole("button", { name: "Open an incident from this event" }));
    expect(await screen.findByRole("heading", { level: 1, name: "XSS from the event" })).toBeInTheDocument();
    expect(callsTo(calls, "POST", "/api/v1/incidents")[0]?.body).toMatchObject({ event_ids: ["evt-1"], severity: "medium" });
  });

  it("keeps the event on screen when opening an incident fails", async () => {
    await renderAs(
      "ANALYST",
      "/threats",
      routes({
        "POST /api/v1/incidents": () => apiError(409, "event_already_linked", "That event already belongs to an incident."),
      }),
    );
    await userEvent.click(await screen.findByRole("button", { name: eventSummary().title }));
    await userEvent.click(await screen.findByRole("button", { name: "Open an incident from this event" }));
    expect(await screen.findByText("That event already belongs to an incident.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "HTTP analysis" })).toBeInTheDocument();
  });

  it("offers a viewer no incident action", async () => {
    await renderAs("VIEWER", "/threats", routes());
    await userEvent.click(await screen.findByRole("button", { name: eventSummary().title }));
    expect(await screen.findByText("Not part of an incident.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open an incident from this event" })).not.toBeInTheDocument();
  });
});

// --- Incidents list -----------------------------------------------------------------------------

describe("incidents list", () => {
  it("filters by state, owner and severity from the URL and the controls", async () => {
    const calls = await renderAs("ANALYST", "/incidents?state=all&owner=me&min_severity=high", {
      "/api/v1/incidents": () => jsonResponse({ items: [incidentSummary()], next_before_number: null }),
    });
    expect(await screen.findByRole("link", { name: /INC-0001/ })).toBeInTheDocument();
    const first = callsTo(calls, "GET", "/api/v1/incidents")[0]?.query;
    expect(first?.get("state")).toBe("all");
    expect(first?.get("owner")).toBe("me");
    expect(first?.get("min_severity")).toBe("high");

    await userEvent.selectOptions(screen.getByLabelText("Owner"), "unassigned");
    await waitFor(() => expect(callsTo(calls, "GET", "/api/v1/incidents")).toHaveLength(2));
    expect(callsTo(calls, "GET", "/api/v1/incidents")[1]?.query.get("owner")).toBe("unassigned");
  });

  it("loads older incidents page by page", async () => {
    let pages = 0;
    const calls = await renderAs("VIEWER", "/incidents", {
      "/api/v1/incidents": () => {
        pages += 1;
        return pages > 1
          ? jsonResponse({ items: [incidentSummary({ id: "inc-0", reference: "INC-0000", title: "Older one" })], next_before_number: null })
          : jsonResponse({ items: [incidentSummary()], next_before_number: 1 });
      },
    });
    await userEvent.click(await screen.findByRole("button", { name: "Load older incidents" }));
    expect(await screen.findByRole("link", { name: /Older one/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /INC-0001/ })).toBeInTheDocument();
    expect(callsTo(calls, "GET", "/api/v1/incidents")[1]?.query.get("before_number")).toBe("1");
    expect(screen.queryByRole("button", { name: "Load older incidents" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New incident" })).not.toBeInTheDocument();
  });

  it("creates an incident and goes to its page", async () => {
    const calls = await renderAs("ANALYST", "/incidents", {
      "GET /api/v1/incidents": () => jsonResponse({ items: [], next_before_number: null }),
      "POST /api/v1/incidents": () => jsonResponse(incidentDetail({ id: "inc-5", title: "Suspicious exports" }), 201),
      "/api/v1/incidents/inc-5": () => jsonResponse(incidentDetail({ id: "inc-5", title: "Suspicious exports" })),
    });
    expect(await screen.findByText("No incidents match these filters.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "New incident" }));
    const form = screen.getByRole("form", { name: "New incident" });
    await userEvent.type(within(form).getByLabelText("Title"), "Suspicious exports");
    await userEvent.click(within(form).getByRole("button", { name: "Open incident" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Suspicious exports" })).toBeInTheDocument();
    expect(callsTo(calls, "POST", "/api/v1/incidents")[0]?.body).toEqual({ title: "Suspicious exports", severity: "medium" });
  });
});

// --- Incident detail ----------------------------------------------------------------------------

describe("incident detail", () => {
  it("offers exactly the moves the API allows and sends the version with them", async () => {
    const calls = await renderAs("ANALYST", "/incidents/inc-1", {
      "GET /api/v1/incidents/inc-1": () => jsonResponse(incidentDetail()),
      "POST /api/v1/incidents/inc-1/transitions": () =>
        jsonResponse(incidentDetail({ status: "TRIAGED", version: 4, permissions: NO_PERMISSIONS })),
    });
    const actions = (await screen.findByRole("heading", { name: "Actions" })).parentElement as HTMLElement;
    expect(within(actions).getAllByRole("button").map((b) => b.textContent)).toEqual([
      "Move to Triaged",
      "Close as not an incident",
      "Take this incident",
    ]);
    await userEvent.click(within(actions).getByRole("button", { name: "Move to Triaged" }));
    await waitFor(() =>
      expect(screen.getByRole("navigation", { name: "Incident workflow" }).querySelector("[aria-current=step]")).toHaveTextContent(
        "Triaged",
      ),
    );
    expect(callsTo(calls, "POST", "/api/v1/incidents/inc-1/transitions")[0]?.body).toEqual({ version: 3, to_status: "TRIAGED" });
  });

  it("will not send a move that needs a note without one", async () => {
    const calls = await renderAs("SECURITY_ENGINEER", "/incidents/inc-1", {
      "GET /api/v1/incidents/inc-1": () => jsonResponse(incidentDetail()),
      "POST /api/v1/incidents/inc-1/transitions": () =>
        jsonResponse(incidentDetail({ status: "CLOSED", resolution: "false_positive", version: 4, permissions: NO_PERMISSIONS })),
    });
    await userEvent.click(await screen.findByRole("button", { name: "Close as not an incident" }));
    const form = screen.getByRole("form", { name: "Close as not an incident" });
    await userEvent.click(within(form).getByRole("button", { name: "Close as not an incident" }));
    expect(within(form).getByRole("alert")).toHaveTextContent("Add a note explaining this decision.");
    expect(callsTo(calls, "POST", "/api/v1/incidents/inc-1/transitions")).toHaveLength(0);

    await userEvent.type(within(form).getByLabelText("Note"), "Our own load test.");
    await userEvent.click(within(form).getByRole("button", { name: "Close as not an incident" }));
    expect(await screen.findByText("False positive (not an attack)")).toBeInTheDocument();
    expect(callsTo(calls, "POST", "/api/v1/incidents/inc-1/transitions")[0]?.body).toEqual({
      version: 3,
      to_status: "CLOSED",
      note: "Our own load test.",
      resolution: "false_positive",
    });
  });

  it("asks to reload when someone else changed the incident", async () => {
    let loads = 0;
    const calls = await renderAs("ANALYST", "/incidents/inc-1", {
      "GET /api/v1/incidents/inc-1": () => {
        loads += 1;
        return jsonResponse(incidentDetail(loads > 1 ? { version: 5, title: "Renamed by a lead" } : {}));
      },
      "POST /api/v1/incidents/inc-1/transitions": () =>
        apiError(409, "stale_version", "The incident changed since you loaded it. Reload and try again."),
    });
    await userEvent.click(await screen.findByRole("button", { name: "Move to Triaged" }));
    const prompt = await screen.findByText(/changed since you loaded it, so your change was not saved/);
    expect(prompt.closest("[role=alert]")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Reload" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Renamed by a lead" })).toBeInTheDocument();
    expect(screen.queryByText(/so your change was not saved/)).not.toBeInTheDocument();
    expect(callsTo(calls, "GET", "/api/v1/incidents/inc-1")).toHaveLength(2);
  });

  it("shows whether the timeline matches the audit log", async () => {
    await renderAs("VIEWER", "/incidents/inc-1", {
      "/api/v1/incidents/inc-1": () => jsonResponse(incidentDetail({ permissions: NO_PERMISSIONS })),
    });
    const verified = (await screen.findByRole("heading", { name: "Evidence integrity" })).parentElement as HTMLElement;
    expect(verified).toHaveTextContent("Verified.");
    expect(verified).toHaveTextContent("All 3 timeline entries match");
  });

  it("raises an alert when a timeline entry does not match", async () => {
    await renderAs("VIEWER", "/incidents/inc-1", {
      "/api/v1/incidents/inc-1": () =>
        jsonResponse(
          incidentDetail({ permissions: NO_PERMISSIONS, integrity: { verified: false, entries_checked: 3, first_mismatch: "tl-2" } }),
        ),
    });
    const panel = (await screen.findByRole("heading", { name: "Evidence integrity" })).parentElement as HTMLElement;
    expect(within(panel).getByRole("alert")).toHaveTextContent("Mismatch.");
    expect(within(panel).getByText("tl-2")).toBeInTheDocument();
  });

  it("gives a viewer a read-only incident", async () => {
    await renderAs("VIEWER", "/incidents/inc-1", {
      "/api/v1/incidents/inc-1": () => jsonResponse(incidentDetail({ permissions: NO_PERMISSIONS })),
    });
    expect(await screen.findByText(/You can read this incident/)).toBeInTheDocument();
    expect(screen.getByText("Looking now.")).toBeInTheDocument();
    for (const name of ["Move to Triaged", "Take this incident", "Edit details", "Add note"]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
  });

  it("marks a simulated incident", async () => {
    await renderAs("ANALYST", "/incidents/inc-1", {
      "/api/v1/incidents/inc-1": () => jsonResponse(incidentDetail({ provenance: "SIMULATED" })),
    });
    expect(await screen.findByText(/opened from attack-simulator output/)).toBeInTheDocument();
  });
});

// --- Applications -------------------------------------------------------------------------------

describe("applications", () => {
  it("shows a developer only the applications they own, with no editing", async () => {
    const own = application({
      id: "app-2",
      slug: "storefront",
      name: "Storefront",
      is_platform: false,
      owner: person({ display_name: "Dee Veloper", role: "DEVELOPER" }),
    });
    const calls = await renderAs("DEVELOPER", "/applications", {
      "/api/v1/applications": () => jsonResponse({ items: [own] }),
    });
    expect(await screen.findByRole("heading", { name: /Storefront/ })).toBeInTheDocument();
    expect(screen.getByText(/You see the applications you own/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register an application" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
    expect(callsTo(calls, "GET", "/api/v1/applications/owners")).toHaveLength(0);
  });

  it("validates the slug and hostname before registering, with owners from the API", async () => {
    let registered = false;
    const calls = await renderAs("ADMIN", "/applications", {
      "GET /api/v1/applications": () =>
        jsonResponse({ items: registered ? [application(), application({ id: "app-3", slug: "shop", name: "Shop", is_platform: false })] : [application()] }),
      "/api/v1/applications/owners": () =>
        jsonResponse({ items: [person({ id: "dev-1", display_name: "Dee Veloper", role: "DEVELOPER" })] }),
      "POST /api/v1/applications": () => {
        registered = true;
        return jsonResponse(application({ id: "app-3", slug: "shop", name: "Shop", is_platform: false }), 201);
      },
    });
    await userEvent.click(await screen.findByRole("button", { name: "Register an application" }));
    const form = screen.getByRole("form", { name: "Register an application" });
    const owner = within(form).getByLabelText("Owner");
    await waitFor(() => expect(within(owner).getByRole("option", { name: "Dee Veloper (developer)" })).toBeInTheDocument());

    await userEvent.type(within(form).getByLabelText("Name"), "Shop");
    await userEvent.type(within(form).getByLabelText("Slug"), "My Shop");
    await userEvent.type(within(form).getByLabelText("Domain"), "https://shop.example.com/admin");
    await userEvent.click(within(form).getByRole("button", { name: "Register" }));
    expect(within(form).getByText(/lowercase letters, digits and hyphens/)).toBeInTheDocument();
    expect(within(form).getByText(/without a scheme, port or path/)).toBeInTheDocument();
    expect(within(form).getByLabelText("Slug")).toHaveAttribute("aria-invalid", "true");
    expect(callsTo(calls, "POST", "/api/v1/applications")).toHaveLength(0);

    await userEvent.clear(within(form).getByLabelText("Slug"));
    await userEvent.type(within(form).getByLabelText("Slug"), "shop");
    await userEvent.clear(within(form).getByLabelText("Domain"));
    await userEvent.type(within(form).getByLabelText("Domain"), "shop.example.com");
    await userEvent.selectOptions(owner, "dev-1");
    await userEvent.click(within(form).getByRole("button", { name: "Register" }));
    expect(await screen.findByText("Shop registered.")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: /^Shop/ })).toBeInTheDocument();
    expect(callsTo(calls, "POST", "/api/v1/applications")[0]?.body).toMatchObject({
      slug: "shop",
      name: "Shop",
      domain: "shop.example.com",
      owner_id: "dev-1",
    });
  });

  it("shows planned measures as planned, not as numbers", async () => {
    await renderAs("VIEWER", "/applications", { "/api/v1/applications": () => jsonResponse({ items: [application()] }) });
    expect(await screen.findByRole("heading", { name: /SentinelEdge/ })).toBeInTheDocument();
    expect(tile("API endpoints")).toHaveTextContent("45");
    expect(tile("Security score")).toHaveTextContent("Phase 10");
  });
});

// --- WAF ----------------------------------------------------------------------------------------

describe("simulated WAF", () => {
  const routes = (over: Record<string, Handler> = {}): Record<string, Handler> => ({
    "/api/v1/simulator/waf-rules": () => jsonResponse(WAF_RULES),
    "/api/v1/security-events": () => jsonResponse({ items: [], next_before_seq: null }),
    ...over,
  });

  it("lets a lead change a rule's mode", async () => {
    const calls = await renderAs(
      "SECURITY_ENGINEER",
      "/waf",
      routes({ "PUT /api/v1/simulator/waf-rules/SQLI-001": () => jsonResponse({ mode: "count" }) }),
    );
    const mode = await screen.findByRole("combobox", { name: "Mode for SQLI-001" });
    await userEvent.selectOptions(mode, "count");
    await waitFor(() => expect(mode).toHaveValue("count"));
    expect(callsTo(calls, "PUT", "/api/v1/simulator/waf-rules/SQLI-001")[0]?.body).toEqual({ mode: "count" });
    expect(screen.getByText("Simulated data.")).toBeInTheDocument();
    expect(callsTo(calls, "GET", "/api/v1/security-events")[0]?.query.get("view")).toBe("simulated");
  });

  it("shows an analyst the rules read-only", async () => {
    await renderAs("ANALYST", "/waf", routes());
    expect(await screen.findByText("SQL injection: boolean tautology")).toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Mode for SQLI-001" })).not.toBeInTheDocument();
    expect(screen.getByText("Block")).toBeInTheDocument();
    expect(screen.getByText("Simulated data.")).toBeInTheDocument();
  });
});

// --- Automation ---------------------------------------------------------------------------------

describe("attack simulator", () => {
  const routes = (over: Record<string, Handler> = {}): Record<string, Handler> => ({
    "/api/v1/simulator/scenarios": () =>
      jsonResponse({
        items: [
          {
            scenario: "sql_injection",
            name: "SQL injection",
            description: "Injection payloads against search and sign-in.",
            demonstrates: "HTTP analysis, WAF block versus count",
          },
        ],
      }),
    "GET /api/v1/simulator/runs": () => jsonResponse({ items: [] }),
    ...over,
  });

  it("runs a scenario and shows its result with links to the incidents", async () => {
    const calls = await renderAs("ADMIN", "/automation", routes({ "POST /api/v1/simulator/runs": () => jsonResponse(run(), 201) }));
    expect(await screen.findByText("No simulations have been run yet.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Run simulation" }));
    const result = await screen.findByRole("status", { name: "SIM-0001: SQL injection" });
    expect(result).toHaveTextContent("40 simulated requests: 30 blocked at the edge");
    expect(within(result).getByText("COR-003")).toBeInTheDocument();
    expect(within(result).getByRole("link", { name: "INC-0002 (opened)" })).toHaveAttribute("href", "/incidents/inc-2");
    expect(callsTo(calls, "POST", "/api/v1/simulator/runs")[0]?.body).toEqual({ scenario: "sql_injection" });
    expect(screen.getByRole("table", { name: "Recent simulation runs" })).toHaveTextContent("SIM-0001");
  });

  it("does not let an analyst run simulations", async () => {
    await renderAs("ANALYST", "/automation", routes({ "GET /api/v1/simulator/runs": () => jsonResponse({ items: [run()] }) }));
    expect(await screen.findByText("SQL injection", { selector: "h3" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run simulation" })).not.toBeInTheDocument();
    expect(screen.getByText(/you can review their results/)).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Recent simulation runs" })).toHaveTextContent("INC-0002");
  });
});

// --- Audit log labels ---------------------------------------------------------------------------

describe("audit log", () => {
  it("offers the Phase 7 actions as filters", async () => {
    await renderAs("ADMIN", "/audit-logs", {
      "/api/v1/audit-logs": () => jsonResponse({ items: [], next_before_id: null }),
    });
    const action = await screen.findByLabelText(/Action/);
    for (const name of ["incident.status_changed", "simulator.waf_rule_changed", "application.created"]) {
      expect(within(action).getByRole("option", { name })).toBeInTheDocument();
    }
  });
});

// --- Validators ---------------------------------------------------------------------------------

describe("response validators", () => {
  it("accept well-formed responses", () => {
    expect(isOverview(overview("live"))).toBe(true);
    expect(isIncidentDetail(incidentDetail())).toBe(true);
  });

  it("reject a malformed overview", () => {
    const noTraffic: Record<string, unknown> = { ...overview("live") };
    delete noTraffic.traffic;
    expect(isOverview(noTraffic)).toBe(false);
    expect(isOverview({ ...overview("live"), view: "all" })).toBe(false);
    expect(isOverview({ ...overview("live"), series: [{ hour: NOW, events: "many" }] })).toBe(false);
  });

  it("reject a malformed incident", () => {
    const detail = incidentDetail();
    expect(isIncidentDetail({ ...detail, status: "PAUSED" })).toBe(false);
    expect(isIncidentDetail({ ...detail, permissions: { ...detail.permissions, can_edit: "yes" } })).toBe(false);
    expect(
      isIncidentDetail({ ...detail, permissions: { ...detail.permissions, moves: [{ to_status: "CLOSED", label: "Close" }] } }),
    ).toBe(false);
    expect(isIncidentDetail({ ...detail, integrity: { verified: true } })).toBe(false);
  });
});
