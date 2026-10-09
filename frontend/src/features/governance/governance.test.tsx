import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../app/App";
import { isPosture, isThreatModelDetail } from "../../lib/api/governanceValidators";
import type {
  ChangeDetail,
  ExceptionDetail,
  Posture,
  Role,
  Threat,
  ThreatModelDetail,
  ThreatModelSummary,
} from "../../lib/types";
import { authenticated, CAPS, jsonResponse, mockApi, profile } from "../../test/fixtures";
import { renderSettled } from "../../test/render";

type Handler = (init: RequestInit | undefined) => Response | Promise<Response>;
interface Call {
  method: string;
  path: string;
  body: unknown;
}

const NOW = "2026-10-08T12:00:00+00:00";
const APP = { id: "5e7e1ed6-0000-4000-8000-000000000001", slug: "sentineledge", name: "SentinelEdge" };
const ME = "00000000-0000-4000-8000-000000000001";
const MODEL_ID = "cccccccc-0000-4000-8000-000000000001";
const EXC_ID = "dddddddd-0000-4000-8000-000000000001";
const CHG_ID = "eeeeeeee-0000-4000-8000-000000000001";

async function renderAs(role: Role, path: string, routes: Record<string, Handler> = {}) {
  const calls: Call[] = [];
  const api = mockApi({
    "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(profile({ id: ME, role, mfa_enabled: true }))),
    "/api/v1/health": () => jsonResponse({ status: "ok", version: "0.6.0" }),
    "/api/v1/platform/capabilities": () => jsonResponse({ items: CAPS }),
    ...routes,
  });
  vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(raw, "http://localhost");
    const body = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    calls.push({ method: (init?.method ?? "GET").toUpperCase(), path: url.pathname, body });
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

afterEach(() => {
  vi.restoreAllMocks();
});

const COUNTS = { open: 0, planned: 0, partly_mitigated: 0, mitigated: 0, accepted: 0, not_exposed: 0, closed: 0 };

function summary(over: Partial<ThreatModelSummary> = {}): ThreatModelSummary {
  return {
    id: MODEL_ID,
    reference: "TM-0001",
    name: "SentinelEdge",
    application: APP,
    method: "stride",
    origin: "catalogue",
    status: "active",
    version_label: "0.6",
    threat_count: 1,
    by_status: { ...COUNTS, mitigated: 1 },
    highest_open_risk: 0,
    updated_at: NOW,
    version: 1,
    ...over,
  };
}

function threat(over: Partial<Threat> = {}): Threat {
  return {
    id: "ffffffff-0000-4000-8000-000000000001",
    ref: "T-ID-01",
    title: "Credential stuffing <script>alert(1)</script>",
    stride: "S",
    owasp: "API2",
    group: "TB3 — Browser session → API",
    boundaries: ["TB3"],
    likelihood: 3,
    impact: 3,
    risk: 9,
    mitigation: "Lockout, MFA, limits",
    status: "mitigated",
    status_text: "Mitigated (P2, P6)",
    phases: [2, 6],
    controls: [
      { ref: "C-ID-05", title: "Lockout", status: "implemented", phase: 2 },
      { ref: "C-WAF-03", title: "Rate-based rules", status: "planned", phase: 5 },
    ],
    retired: false,
    version: 3,
    ...over,
  };
}

function model(over: Partial<ThreatModelDetail> = {}): ThreatModelDetail {
  return {
    id: MODEL_ID,
    reference: "TM-0001",
    name: "SentinelEdge",
    application: APP,
    method: "stride",
    origin: "catalogue",
    status: "active",
    scope: "SentinelEdge itself.",
    version_label: "0.6",
    pasta: {},
    elements: [
      { id: "e1", kind: "asset", ref: "A1", name: "User credentials", description: "Account takeover", boundaries: [], threats: [], retired: false },
      { id: "e2", kind: "boundary", ref: "TB3", name: "Browser session → API", description: "", boundaries: [], threats: [], retired: false },
    ],
    threats: [threat()],
    stats: {
      by_status: { ...COUNTS, mitigated: 1 },
      by_stride: { S: 1 },
      matrix: [3, 2, 1].flatMap((likelihood) => [1, 2, 3].map((impact) => ({ likelihood, impact, count: 0 }))),
      unmapped: [],
      only_planned_controls: [],
    },
    permissions: { can_edit: false, maintained_as_code: true, can_archive: false, can_delete: false },
    created_by_label: "system:governance",
    created_at: NOW,
    updated_at: NOW,
    version: 2,
    ...over,
  };
}

function posture(): Posture {
  return {
    overall: 61,
    built_scope: 86,
    categories: [
      {
        key: "identity",
        label: "Identity and access",
        score: 100,
        state: "measured",
        implemented: 9,
        planned: 0,
        factors: [{ kind: "coverage", label: "9 of 9 controls implemented", points: 100, refs: [], link: "/compliance?tab=controls&families=ID" }],
      },
      {
        key: "vulnerability",
        label: "Vulnerability management",
        score: 85,
        state: "measured",
        implemented: 6,
        planned: 0,
        factors: [
          { kind: "coverage", label: "6 of 6 controls implemented", points: 100, refs: [], link: null },
          { kind: "signal", label: "1 critical finding past the SLA", points: -10, refs: ["VULN-0042"], link: "/vulnerabilities?overdue=true" },
          { kind: "signal", label: "1 high finding past the SLA", points: -5, refs: ["VULN-0043"], link: "/vulnerabilities?overdue=true" },
        ],
      },
      {
        key: "ai",
        label: "AI security",
        score: 0,
        state: "planned",
        implemented: 0,
        planned: 6,
        factors: [{ kind: "coverage", label: "0 of 6 controls implemented", points: 0, refs: ["C-AI-01", "C-AI-02"], link: null }],
      },
    ],
    method: "Every number traces to something a reviewer can open.",
    trend: [
      { taken_at: "2026-10-07T12:00:00+00:00", overall: 58, built_scope: 84 },
      { taken_at: NOW, overall: 61, built_scope: 86 },
    ],
    computed_at: NOW,
  };
}

function exception(over: Partial<ExceptionDetail> = {}): ExceptionDetail {
  return {
    id: EXC_ID,
    reference: "EXC-0003",
    title: "Hold a library on its current major version",
    application: APP,
    scope: "dependency",
    scope_ref: "frontend: example-lib",
    risk_level: "high",
    status: "requested",
    requester_label: "lead@example.com",
    approver_label: null,
    expires_on: "2026-12-07",
    days_left: null,
    imported: false,
    version: 1,
    gate_match: null,
    risk: "No feature updates upstream.",
    justification: "The next major breaks required lint rules.",
    compensating_control: "npm audit gates every CI run.",
    control_refs: ["C-CICD-02"],
    implementation: "",
    exit_criteria: "",
    decided_at: null,
    decision_note: null,
    ended_at: null,
    end_note: null,
    max_days: 90,
    created_at: NOW,
    permissions: { can_decide: true, can_close: true, separation_of_duties: false },
    history: [{ seq: 10, occurred_at: NOW, action: "exception.requested", actor_label: "lead@example.com", note: null }],
    ...over,
  };
}

function change(over: Partial<ChangeDetail> = {}): ChangeDetail {
  return {
    id: CHG_ID,
    reference: "CHG-0001",
    title: "Tighten the session idle timeout",
    application: APP,
    change_type: "configuration",
    risk_level: "medium",
    status: "approved",
    requester_label: "lead@example.com",
    approver_label: "admin@example.com",
    created_at: NOW,
    updated_at: NOW,
    version: 2,
    description: "Reduce the refresh-token idle timeout.",
    impact: "Idle users sign in again.",
    rollback_plan: "Revert the pull request.",
    validation_plan: "Confirm a 401 after the timeout.",
    target: null,
    previous_state: null,
    decided_at: NOW,
    decision_note: null,
    implemented_at: null,
    implemented_by_label: null,
    implementation_ref: null,
    closed_at: null,
    closing_note: null,
    available_moves: ["implemented"],
    separation_of_duties: false,
    history: [],
    ...over,
  };
}

describe("Threat Modeling", () => {
  it("lists models and offers a new one to leads only", async () => {
    const routes = { "/api/v1/threat-models": () => jsonResponse({ items: [summary()] }) };
    await renderAs("VIEWER", "/threat-modeling", routes);
    expect(await screen.findByRole("link", { name: "TM-0001: SentinelEdge" })).toBeInTheDocument();
    expect(screen.getByText(/maintained as code, v0.6/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "New threat model" })).not.toBeInTheDocument();
  });

  it("shows SentinelEdge's own model read-only, with threats as text", async () => {
    const routes = { [`/api/v1/threat-models/${MODEL_ID}`]: () => jsonResponse(model()) };
    await renderAs("ADMIN", `/threat-modeling/${MODEL_ID}`, routes);
    expect(await screen.findByText(/Maintained as code/)).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Threats in this model" });
    expect(within(table).getByText("Credential stuffing <script>alert(1)</script>")).toBeInTheDocument();
    expect(within(table).getByText("C-WAF-03")).toBeInTheDocument();
    expect(within(table).queryByRole("combobox")).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Add a threat" })).not.toBeInTheDocument();
  });

  it("lets a lead re-rate a threat in an application model, sending the version it read", async () => {
    const editable = model({ origin: "app", permissions: { can_edit: true, maintained_as_code: false, can_archive: true, can_delete: true } });
    const updated = model({ ...editable, threats: [threat({ status: "open", version: 4 })] });
    const calls = await renderAs("SECURITY_ENGINEER", `/threat-modeling/${MODEL_ID}`, {
      [`GET /api/v1/threat-models/${MODEL_ID}`]: () => jsonResponse(editable),
      [`PATCH /api/v1/threat-models/${MODEL_ID}/threats/${threat().id}`]: () => jsonResponse(updated),
    });
    const select = await screen.findByRole("combobox", { name: "Status of T-ID-01" });
    await userEvent.selectOptions(select, "open");
    await waitFor(() =>
      expect(callsTo(calls, "PATCH", `/api/v1/threat-models/${MODEL_ID}/threats/${threat().id}`)[0]?.body).toEqual({
        version: 3,
        status: "open",
      }),
    );
    expect(await screen.findByRole("heading", { name: "Add a threat" })).toBeInTheDocument();
  });
});

describe("Removing a threat model", () => {
  const appModel = (can_archive: boolean, can_delete: boolean) =>
    model({ origin: "app", name: "Payments API", reference: "TM-0002", status: "draft", permissions: { can_edit: can_delete, maintained_as_code: false, can_archive, can_delete } });

  it("shows no Delete button to a viewer", async () => {
    await renderAs("VIEWER", `/threat-modeling/${MODEL_ID}`, {
      [`/api/v1/threat-models/${MODEL_ID}`]: () => jsonResponse(appModel(false, false)),
    });
    expect(await screen.findByRole("heading", { name: "TM-0002: Payments API" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
  });

  it("offers a developer only Archive, and archives with the version it read", async () => {
    const calls = await renderAs("DEVELOPER", `/threat-modeling/${MODEL_ID}`, {
      [`GET /api/v1/threat-models/${MODEL_ID}`]: () => jsonResponse(appModel(true, false)),
      [`POST /api/v1/threat-models/${MODEL_ID}/archive`]: () =>
        jsonResponse({ ...appModel(false, false), status: "archived", version: 3 }),
    });
    await userEvent.click(await screen.findByRole("button", { name: "Delete" }));
    const dialog = screen.getByRole("alertdialog", { name: "Remove TM-0002?" });
    expect(within(dialog).queryByRole("button", { name: "Delete permanently" })).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Archive" }));
    await waitFor(() =>
      expect(callsTo(calls, "POST", `/api/v1/threat-models/${MODEL_ID}/archive`)[0]?.body).toEqual({ version: 2 }),
    );
    expect(await screen.findByText(/Archived: kept with its history/)).toBeInTheDocument();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("lets a lead delete permanently, then returns to the list", async () => {
    const calls = await renderAs("ADMIN", `/threat-modeling/${MODEL_ID}`, {
      [`GET /api/v1/threat-models/${MODEL_ID}`]: () => jsonResponse(appModel(true, true)),
      [`DELETE /api/v1/threat-models/${MODEL_ID}`]: () => new Response(null, { status: 204 }),
      "GET /api/v1/threat-models": () => jsonResponse({ items: [summary()] }),
    });
    await userEvent.click(await screen.findByRole("button", { name: "Delete" }));
    const dialog = screen.getByRole("alertdialog", { name: "Remove TM-0002?" });
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(within(dialog).getByRole("button", { name: "Archive" })).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete permanently" }));
    await waitFor(() => expect(callsTo(calls, "DELETE", `/api/v1/threat-models/${MODEL_ID}`)).toHaveLength(1));
    expect(await screen.findByRole("heading", { name: "Threat Modeling" })).toBeInTheDocument();
  });
});

describe("Compliance", () => {
  it("explains the posture score, category by category", async () => {
    await renderAs("VIEWER", "/compliance", { "/api/v1/governance/posture": () => jsonResponse(posture()) });
    expect(await screen.findByText("Overall posture")).toBeInTheDocument();
    expect(screen.getByText("61")).toBeInTheDocument();
    expect(screen.getByText("What is built")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "1 critical finding past the SLA" })).toHaveAttribute("href", "/vulnerabilities?overdue=true");
    expect(screen.getByText("VULN-0042")).toBeInTheDocument();
    expect(screen.getByText("Planned")).toBeInTheDocument();
    expect(screen.getByText(/Still planned: C-AI-01, C-AI-02/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Record a snapshot now" })).not.toBeInTheDocument();
  });

  it("lets a developer request an exception with every required field", async () => {
    const calls = await renderAs("DEVELOPER", "/compliance?tab=exceptions", {
      "GET /api/v1/exceptions": () =>
        jsonResponse({ items: [], counts: { requested: 0, approved: 0, rejected: 0, withdrawn: 0, expired: 0, closed: 0, expiring_30d: 0 } }),
      "POST /api/v1/exceptions": () => jsonResponse(exception(), 201),
    });
    const form = (await screen.findByRole("heading", { name: "Request an exception" })).closest("section");
    if (!form) throw new Error("form not found");
    const field = (name: string) => within(form).getByLabelText(name);
    await userEvent.type(field("Title"), "Hold a library on its current major version");
    await userEvent.type(field("What it covers"), "frontend: example-lib");
    await userEvent.selectOptions(field("Risk level"), "high");
    await userEvent.type(field("Expires on"), "2026-12-07");
    await userEvent.type(field("Risk"), "No feature updates upstream for now.");
    await userEvent.type(field("Business justification"), "The next major breaks required lint rules.");
    await userEvent.type(field("Compensating control"), "npm audit gates every CI run, always.");
    await userEvent.type(field("Catalogue controls (optional)"), "c-cicd-02");
    await userEvent.click(within(form).getByRole("button", { name: "Request exception" }));
    await waitFor(() => expect(callsTo(calls, "POST", "/api/v1/exceptions")).toHaveLength(1));
    expect(callsTo(calls, "POST", "/api/v1/exceptions")[0]?.body).toMatchObject({
      scope: "dependency",
      risk_level: "high",
      expires_on: "2026-12-07",
      control_refs: ["C-CICD-02"],
    });
    expect(await screen.findByText("Requested EXC-0003.")).toBeInTheDocument();
  });
});

describe("Exception and change request decisions", () => {
  it("tells the requester someone else must decide, and offers no approval", async () => {
    const mine = exception({ permissions: { can_decide: false, can_close: true, separation_of_duties: true } });
    await renderAs("SECURITY_ENGINEER", `/compliance/exceptions/${EXC_ID}`, {
      [`/api/v1/exceptions/${EXC_ID}`]: () => jsonResponse(mine),
    });
    expect(await screen.findByRole("note")).toHaveTextContent(/another lead must decide it/);
    expect(screen.queryByRole("button", { name: /Approve/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Withdraw request" })).toBeInTheDocument();
  });

  it("sends another lead's approval with the version it read", async () => {
    const approved = exception({ status: "approved", approver_label: "admin@example.com", version: 2, permissions: { can_decide: false, can_close: true, separation_of_duties: false } });
    const calls = await renderAs("ADMIN", `/compliance/exceptions/${EXC_ID}`, {
      [`GET /api/v1/exceptions/${EXC_ID}`]: () => jsonResponse(exception()),
      [`POST /api/v1/exceptions/${EXC_ID}/decision`]: () => jsonResponse(approved),
    });
    await userEvent.click(await screen.findByRole("button", { name: "Approve until 2026-12-07" }));
    await waitFor(() =>
      expect(callsTo(calls, "POST", `/api/v1/exceptions/${EXC_ID}/decision`)[0]?.body).toEqual({ approve: true, note: "", version: 1 }),
    );
    expect(await screen.findByText(/Approved by admin@example.com/)).toBeInTheDocument();
  });

  it("offers only the moves the server allows and reports a stale version", async () => {
    const calls = await renderAs("SECURITY_ENGINEER", `/compliance/changes/${CHG_ID}`, {
      [`GET /api/v1/change-requests/${CHG_ID}`]: () => jsonResponse(change()),
      [`POST /api/v1/change-requests/${CHG_ID}/transition`]: () =>
        jsonResponse({ error: { code: "stale_version", message: "The change request changed since you loaded it." } }, 409),
    });
    expect(await screen.findByRole("button", { name: "Mark implemented" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Implemented by (pull request URL or commit)"), "https://github.com/x/y/pull/9");
    await userEvent.click(screen.getByRole("button", { name: "Mark implemented" }));
    await waitFor(() =>
      expect(callsTo(calls, "POST", `/api/v1/change-requests/${CHG_ID}/transition`)[0]?.body).toEqual({
        to: "implemented",
        note: "",
        version: 2,
        implementation_ref: "https://github.com/x/y/pull/9",
      }),
    );
    expect(await screen.findByText("Reload the page to see the latest version.")).toBeInTheDocument();
  });
});

describe("governance response validation", () => {
  it("refuses values the backend does not define", () => {
    expect(isPosture(posture())).toBe(true);
    const bad = posture();
    (bad.categories[0] as unknown as Record<string, unknown>).state = "bogus";
    expect(isPosture(bad)).toBe(false);
    expect(isThreatModelDetail(model())).toBe(true);
    expect(isThreatModelDetail({ ...model(), origin: "imported" })).toBe(false);
  });
});
