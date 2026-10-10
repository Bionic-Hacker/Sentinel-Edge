import { screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { authenticated, CAPS, jsonResponse, mockApi } from "../test/fixtures";
import { renderSettled } from "../test/render";
import { AppRoutes } from "./App";
import { MODULES } from "./modules";

const SPEC_NAV = [
  "Dashboard", "Applications", "APIs", "WAF", "Edge Security", "Threats", "Incidents",
  "Vulnerabilities", "Threat Modeling", "Certificates", "AI Security", "SBOM", "Compliance",
  "Audit Logs", "Automation", "Settings",
];

async function renderAt(path: string, caps = CAPS) {
  vi.spyOn(globalThis, "fetch").mockImplementation(
    mockApi({
      "POST /api/v1/auth/refresh": () => jsonResponse(authenticated()),
      "/api/v1/health": () => jsonResponse({ status: "ok", version: "0.1.0" }),
      "/api/v1/platform/capabilities": () => jsonResponse({ items: caps }),
    }),
  );
  const view = await renderSettled(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes />
    </MemoryRouter>,
  );
  await screen.findByText(/API online/); // let async effects settle
  return view;
}

describe("navigation", () => {
  it("matches the spec's navigation order exactly", async () => {
    await renderAt("/");
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).getAllByRole("link").map((l) => l.textContent)).toEqual(SPEC_NAV);
    expect(MODULES.map((m) => m.label)).toEqual(SPEC_NAV);
  });

  it("states that no AWS resources are connected", async () => {
    await renderAt("/");
    expect(screen.getByText(/No AWS resources are connected/)).toBeInTheDocument();
  });
});

describe("dashboard", () => {
  it("shows live API status and the capability register with provenance", async () => {
    await renderAt("/");
    expect(await screen.findByText(/API online/)).toBeInTheDocument();
    const table = await screen.findByRole("table");
    expect(within(table).getByText("Health endpoint")).toBeInTheDocument();
    expect(within(table).getByText("Simulated")).toBeInTheDocument();
    expect(within(table).getByText("Real AWS")).toBeInTheDocument();
  });

  it("shows completed phases and marks the next one", async () => {
    await renderAt("/");
    expect(screen.getByText(/Phase 2, complete/)).toBeInTheDocument();
    expect(screen.getByText(/Phase 6, complete/)).toBeInTheDocument();
    expect(screen.getByText(/Phase 7, complete/)).toBeInTheDocument();
    expect(screen.getByText(/Phase 8, complete/)).toBeInTheDocument();
    expect(screen.getByText(/Phase 10, complete/)).toBeInTheDocument();
    expect(screen.getByText(/Phase 9, complete/)).toBeInTheDocument();
    expect(screen.getByText(/Phase 3, complete/)).toBeInTheDocument();
    expect(screen.getByText(/Phase 4, next/).closest("li")).toHaveAttribute("aria-current", "step");
  });
});

describe("module pages", () => {
  it("show only the module's own capabilities and no fabricated data", async () => {
    // Edge Security is still a placeholder (Phase 5); WAF, Threats and the rest now have pages.
    const edge = {
      key: "aws.edge",
      name: "CloudFront edge",
      area: "Edge",
      provenance: "REAL_AWS",
      status: "planned",
      phase: 5,
      note: "Terraform.",
    } as const;
    await renderAt("/edge", [...CAPS, edge]);
    expect(screen.getByRole("heading", { level: 1, name: "Edge Security" })).toBeInTheDocument();
    const table = await screen.findByRole("table");
    expect(within(table).getByText("CloudFront edge")).toBeInTheDocument();
    expect(within(table).getByText("Real AWS")).toBeInTheDocument();
    expect(within(table).queryByText("Health endpoint")).not.toBeInTheDocument();
    expect(within(table).queryByText("AWS WAF on CloudFront")).not.toBeInTheDocument();
    expect(screen.getByText(/shows no data until then/)).toBeInTheDocument();
  });

  it("renders an actionable error when the API is down", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(
      mockApi({
        "POST /api/v1/auth/refresh": () => jsonResponse(authenticated()),
        "/api/v1/health": () => {
          throw new TypeError("Failed to fetch");
        },
        "/api/v1/platform/capabilities": () => {
          throw new TypeError("Failed to fetch");
        },
      }),
    );
    await renderSettled(
      <MemoryRouter initialEntries={["/apis"]}>
        <AppRoutes />
      </MemoryRouter>,
    );
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The API could not be reached");
    expect(alert).toHaveTextContent("make dev");
  });

  it("handles unknown routes", async () => {
    await renderAt("/does-not-exist");
    expect(screen.getByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });
});
