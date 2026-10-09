import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../app/App";
import { isAiAnalysisDetail, isAiProposal } from "../../lib/api/aiValidators";
import type { AiAnalysisDetail, AiProposal, AiStatus, Role } from "../../lib/types";
import { authenticated, CAPS, jsonResponse, mockApi, profile } from "../../test/fixtures";
import { renderSettled } from "../../test/render";
import { AnalyzePanel } from "./ai";

type Handler = (init: RequestInit | undefined) => Response | Promise<Response>;
interface Call {
  method: string;
  path: string;
  body: unknown;
}

const NOW = "2026-10-09T12:00:00+00:00";
const ANALYSIS_ID = "aaaaaaaa-0000-4000-8000-000000000001";
const PROPOSAL_ID = "bbbbbbbb-0000-4000-8000-000000000001";
const EVENT_ID = "cccccccc-0000-4000-8000-000000000001";
const SCRIPT = "<script>alert(1)</script>";

function spy(routes: Record<string, Handler>): Call[] {
  const calls: Call[] = [];
  const api = mockApi(routes);
  vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(raw, "http://localhost");
    const body = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    calls.push({ method: (init?.method ?? "GET").toUpperCase(), path: url.pathname, body });
    return api(input, init);
  });
  return calls;
}

async function renderAs(role: Role, path: string, routes: Record<string, Handler> = {}) {
  const calls = spy({
    "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(profile({ role, mfa_enabled: true }))),
    "/api/v1/health": () => jsonResponse({ status: "ok", version: "0.7.0" }),
    "/api/v1/platform/capabilities": () => jsonResponse({ items: CAPS }),
    ...routes,
  });
  await renderSettled(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes />
    </MemoryRouter>,
  );
  return calls;
}

afterEach(() => {
  vi.restoreAllMocks();
});

function status(over: Partial<AiStatus> = {}): AiStatus {
  return {
    enabled: true,
    provider: "offline",
    model: "sentineledge-offline-1",
    provenance: "LOCAL",
    can_analyse: true,
    requests_today: 3,
    requests_per_day: 20,
    tokens_today: 4200,
    tokens_per_day: 200000,
    max_output_tokens: 800,
    ...over,
  };
}

function proposal(over: Partial<AiProposal> = {}): AiProposal {
  return {
    id: PROPOSAL_ID,
    reference: "AIP-0001",
    analysis_id: ANALYSIS_ID,
    analysis_reference: "AI-0001",
    subject: { type: "security_event", id: EVENT_ID, reference: "SQLI-001 event" },
    action_type: "open_incident",
    payload: { type: "open_incident", title: "SQL injection against /api/v1/users", severity: "high" },
    rationale: "A high-severity injection reached the application and no incident tracks it yet.",
    status: "proposed",
    input_risk: 20,
    note_required: false,
    can_decide: true,
    decided_by_label: null,
    decided_at: null,
    decision_note: null,
    result_ref: null,
    created_at: NOW,
    version: 1,
    ...over,
  };
}

function analysis(over: Partial<AiAnalysisDetail> = {}): AiAnalysisDetail {
  return {
    id: ANALYSIS_ID,
    reference: "AI-0001",
    subject: { type: "security_event", id: EVENT_ID, reference: "SQLI-001 event" },
    application: null,
    provenance: "LOCAL",
    status: "completed",
    provider: "offline",
    model: "sentineledge-offline-1",
    prompt_risk: 65,
    risk_level: "high",
    classification: "sql_injection",
    severity: "high",
    proposals: 1,
    requested_by_label: "analyst@example.com",
    created_at: NOW,
    failure: null,
    risk_signals: ["instruction_override", "output_steering"],
    input_sha256: "a".repeat(64),
    input_chars: 2400,
    input_tokens: 600,
    output_tokens: 250,
    duration_ms: 12,
    output: {
      summary: "A UNION-based SQL injection probe against /api/v1/users.",
      classification: "sql_injection",
      severity: "high",
      confidence: 0.8,
      observed_evidence: [
        { field: "evidence.snippet", quote: "union select password" },
        { field: "user_agent", quote: SCRIPT },
      ],
      inference: "The attacker is trying to read the users table through the id filter.",
      recommendations: [{ text: "Keep parameterised queries everywhere.", controls: ["C-API-04"] }],
      proposed_actions: [
        {
          type: "open_incident",
          title: "SQL injection against /api/v1/users",
          severity: "high",
          rationale: "A high-severity injection reached the application and no incident tracks it yet.",
        },
      ],
    },
    disagreements: [],
    proposal_items: [proposal()],
    ...over,
  };
}

describe("AI Security page", () => {
  it("says when AI is switched off", async () => {
    await renderAs("ADMIN", "/ai-security", {
      "/api/v1/ai/status": () => jsonResponse(status({ enabled: false, provider: "disabled", model: null, provenance: null })),
      "/api/v1/ai/analyses": () => jsonResponse({ items: [] }),
      "/api/v1/ai/proposals": () => jsonResponse({ items: [], counts: { proposed: 0, approved: 0, rejected: 0 } }),
    });
    expect(await screen.findByText(/AI analysis is switched off/)).toBeInTheDocument();
    expect(screen.getByText("No analyses yet.", { exact: false })).toBeInTheDocument();
  });

  it("shows usage against the limits, waiting proposals and recent analyses", async () => {
    await renderAs("SECURITY_ENGINEER", "/ai-security", {
      "/api/v1/ai/status": () => jsonResponse(status()),
      "/api/v1/ai/analyses": () => jsonResponse({ items: [analysis()] }),
      "/api/v1/ai/proposals": () => jsonResponse({ items: [proposal()], counts: { proposed: 1, approved: 2, rejected: 0 } }),
    });
    expect(await screen.findByText("3 / 20")).toBeInTheDocument();
    expect(screen.getByText("4,200 / 200,000")).toBeInTheDocument();
    const card = screen.getByRole("article", { name: /AIP-0001/ });
    expect(within(card).getByText(/Open incident "SQL injection against \/api\/v1\/users" \(high\)/)).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Recent AI analyses" });
    expect(within(table).getByText("Prompt risk 65 · High")).toBeInTheDocument();
  });
});

describe("An analysis", () => {
  it("keeps quoted evidence apart from inference and renders attacker text as text", async () => {
    await renderAs("ANALYST", `/ai-security/analyses/${ANALYSIS_ID}`, {
      [`/api/v1/ai/analyses/${ANALYSIS_ID}`]: () => jsonResponse(analysis({ proposal_items: [proposal({ can_decide: false })] })),
    });
    const evidence = await screen.findByRole("region", { name: "Observed evidence" });
    expect(within(evidence).getByText(SCRIPT)).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
    const inference = screen.getByRole("region", { name: "Inference" });
    expect(within(inference).getByText(/not a fact/)).toBeInTheDocument();
    // The input's injection signals are named, and an analyst cannot decide.
    expect(screen.getByText("Tries to override instructions")).toBeInTheDocument();
    expect(screen.getByText(/Awaiting a decision by an admin or security engineer/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve and run" })).not.toBeInTheDocument();
  });

  it("shows a rejected answer as rejected, with nothing from it", async () => {
    await renderAs("ADMIN", `/ai-security/analyses/${ANALYSIS_ID}`, {
      [`/api/v1/ai/analyses/${ANALYSIS_ID}`]: () =>
        jsonResponse(
          analysis({
            status: "rejected",
            output: null,
            failure: "evidence item 1 is not a verbatim quote of field 'title'",
            proposals: 0,
            proposal_items: [],
          }),
        ),
    });
    expect(await screen.findByText(/broke the output contract and was rejected/)).toBeInTheDocument();
    expect(screen.getByText(/not a verbatim quote/)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Observed evidence" })).not.toBeInTheDocument();
  });

  it("shows a disagreement with the platform without acting on it", async () => {
    await renderAs("ADMIN", `/ai-security/analyses/${ANALYSIS_ID}`, {
      [`/api/v1/ai/analyses/${ANALYSIS_ID}`]: () =>
        jsonResponse(analysis({ disagreements: ["The platform rated this high; the AI says low."] })),
    });
    const note = await screen.findByRole("note");
    expect(within(note).getByText(/the AI says low/)).toBeInTheDocument();
    expect(within(note).getByText(/verdict is unchanged/)).toBeInTheDocument();
  });

  it("a lead approves a proposal; a high-risk one needs a reason first", async () => {
    const risky = proposal({ note_required: true, input_risk: 65 });
    const calls = await renderAs("ADMIN", `/ai-security/analyses/${ANALYSIS_ID}`, {
      [`/api/v1/ai/analyses/${ANALYSIS_ID}`]: () => jsonResponse(analysis({ proposal_items: [risky] })),
      [`POST /api/v1/ai/proposals/${PROPOSAL_ID}/decision`]: () =>
        jsonResponse(
          proposal({
            status: "approved",
            version: 2,
            can_decide: false,
            decided_by_label: "admin@example.com",
            decided_at: NOW,
            decision_note: "Checked the snippet: real injection.",
            result_ref: "INC-0007",
          }),
        ),
    });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Approve and run" }));
    expect(screen.getByRole("alert")).toHaveTextContent(/high-risk input/);
    expect(calls.filter((c) => c.path.endsWith("/decision"))).toHaveLength(0);

    await user.type(screen.getByLabelText("Reason (required)"), "Checked the snippet: real injection.");
    await user.click(screen.getByRole("button", { name: "Approve and run" }));
    expect(await screen.findByText("INC-0007")).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST" && c.path.endsWith("/decision"));
    expect(post?.body).toEqual({ version: 1, decision: "approve", note: "Checked the snippet: real injection." });
  });

  it("rejecting needs a reason", async () => {
    const calls = await renderAs("SECURITY_ENGINEER", `/ai-security/analyses/${ANALYSIS_ID}`, {
      [`/api/v1/ai/analyses/${ANALYSIS_ID}`]: () => jsonResponse(analysis()),
      [`POST /api/v1/ai/proposals/${PROPOSAL_ID}/decision`]: () =>
        jsonResponse(proposal({ status: "rejected", version: 2, can_decide: false, decided_by_label: "se@example.com", decided_at: NOW, decision_note: "Already tracked as INC-0003." })),
    });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Reject" }));
    expect(screen.getByRole("alert")).toHaveTextContent(/Say why you reject it/);
    await user.type(screen.getByLabelText("Reason (required to reject)"), "Already tracked as INC-0003.");
    await user.click(screen.getByRole("button", { name: "Reject" }));
    await waitFor(() => expect(screen.getByText(/Rejected by se@example.com/)).toBeInTheDocument());
    expect(calls.find((c) => c.path.endsWith("/decision"))?.body).toEqual({
      version: 1,
      decision: "reject",
      note: "Already tracked as INC-0003.",
    });
  });
});

describe("Analyze with AI", () => {
  async function renderPanel(routes: Record<string, Handler>) {
    const calls = spy(routes);
    await act(async () => {
      render(
        <MemoryRouter initialEntries={["/subject"]}>
          <Routes>
            <Route path="/subject" element={<AnalyzePanel subjectType="security_event" subjectId={EVENT_ID} />} />
            <Route path="/ai-security/analyses/:analysisId" element={<p>Analysis page</p>} />
          </Routes>
        </MemoryRouter>,
      );
    });
    return calls;
  }

  it("runs an analysis of this record and opens it", async () => {
    const calls = await renderPanel({
      "/api/v1/ai/status": () => jsonResponse(status()),
      "/api/v1/ai/analyses": () => jsonResponse({ items: [analysis()] }),
      "POST /api/v1/ai/analyses": () => jsonResponse(analysis(), 201),
    });
    expect(await screen.findByRole("link", { name: "AI-0001" })).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Analyze with AI" }));
    expect(await screen.findByText("Analysis page")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ subject_type: "security_event", subject_id: EVENT_ID });
  });

  it("shows the quota message when the limit is reached", async () => {
    await renderPanel({
      "/api/v1/ai/status": () => jsonResponse(status()),
      "/api/v1/ai/analyses": () => jsonResponse({ items: [] }),
      "POST /api/v1/ai/analyses": () =>
        jsonResponse({ error: { code: "ai_quota_exceeded", message: "AI quota reached: 20 analyses per user per day." } }, 429),
    });
    await userEvent.setup().click(await screen.findByRole("button", { name: "Analyze with AI" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("AI quota reached");
  });

  it("is absent when AI is off, and has no button for read-only roles", async () => {
    spy({ "/api/v1/ai/status": () => jsonResponse(status({ enabled: false })) });
    await act(async () => {
      render(
        <MemoryRouter>
          <AnalyzePanel subjectType="incident" subjectId={EVENT_ID} />
        </MemoryRouter>,
      );
    });
    expect(screen.queryByRole("region", { name: "AI analysis" })).not.toBeInTheDocument();
    vi.restoreAllMocks();

    spy({
      "/api/v1/ai/status": () => jsonResponse(status({ can_analyse: false })),
      "/api/v1/ai/analyses": () => jsonResponse({ items: [] }),
    });
    await act(async () => {
      render(
        <MemoryRouter>
          <AnalyzePanel subjectType="incident" subjectId={EVENT_ID} />
        </MemoryRouter>,
      );
    });
    expect(await screen.findByRole("region", { name: "AI analysis" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Analyze with AI" })).not.toBeInTheDocument();
  });
});

describe("AI validators", () => {
  it("accept a well-formed analysis and proposal", () => {
    expect(isAiAnalysisDetail(analysis())).toBe(true);
    expect(isAiProposal(proposal())).toBe(true);
  });

  it("refuse an action the contract does not allow, so the page never shows it", () => {
    const weakening = proposal({
      action_type: "raise_change_request",
      payload: { type: "raise_change_request", rule_id: "SQLI-001", mode: "count" },
    });
    expect(isAiProposal(weakening)).toBe(false);
    const mismatched = proposal({ action_type: "add_threat" });
    expect(isAiProposal(mismatched)).toBe(false);
    const unknownClass = analysis({ classification: "totally_fine" as never });
    expect(isAiAnalysisDetail(unknownClass)).toBe(false);
  });
});
