import { act, fireEvent, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../app/App";
import type { Theme } from "../lib/types";
import { authenticated, CAPS, jsonResponse, mockApi, profile } from "../test/fixtures";
import { renderSettled } from "../test/render";

const rootTheme = () => document.documentElement.dataset.theme ?? "light";

async function renderAs(theme: Theme, save: (init: RequestInit | undefined) => Response) {
  const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(
    mockApi({
      "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(profile({ theme }))),
      "PUT /api/v1/auth/me/theme": save,
      "/api/v1/health": () => jsonResponse({ status: "ok", version: "0.1.0" }),
      "/api/v1/platform/capabilities": () => jsonResponse({ items: CAPS }),
      "/api/v1/platform/environment": () => jsonResponse({ environment: "local", deployed: false, region: null }),
    }),
  );
  await renderSettled(
    <MemoryRouter initialEntries={["/settings"]}>
      <AppRoutes />
    </MemoryRouter>,
  );
  await screen.findByText(/API online/);
  return fetchSpy;
}

afterEach(() => {
  delete document.documentElement.dataset.theme;
});

describe("theme toggle", () => {
  it("shows the light theme by default, beside the signed-in user", async () => {
    await renderAs("light", () => jsonResponse(profile({ theme: "dark" })));
    const toggle = screen.getByRole("switch", { name: "Dark theme" });
    expect(toggle).toHaveAttribute("aria-checked", "false");
    expect(rootTheme()).toBe("light");
  });

  it("opens in the theme saved with the user's account", async () => {
    await renderAs("dark", () => jsonResponse(profile({ theme: "dark" })));
    expect(screen.getByRole("switch", { name: "Dark theme" })).toHaveAttribute("aria-checked", "true");
    expect(rootTheme()).toBe("dark");
  });

  it("switches at once and saves the choice with the account, not the browser", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const fetchSpy = await renderAs("light", () => jsonResponse(profile({ theme: "dark" })));
    await act(async () => {
      fireEvent.click(screen.getByRole("switch", { name: "Dark theme" }));
    });
    expect(rootTheme()).toBe("dark");
    expect(screen.getByRole("switch", { name: "Dark theme" })).toHaveAttribute("aria-checked", "true");
    const put = fetchSpy.mock.calls.find(([, init]) => init?.method === "PUT");
    expect(put?.[1]?.body).toBe(JSON.stringify({ theme: "dark" }));
    expect(setItem).not.toHaveBeenCalled();
  });

  it("switches back and says so if the choice cannot be saved", async () => {
    await renderAs("light", () =>
      jsonResponse({ error: { code: "internal_error", message: "Something went wrong." } }, 500),
    );
    await act(async () => {
      fireEvent.click(screen.getByRole("switch", { name: "Dark theme" }));
    });
    expect(await screen.findByRole("alert")).toHaveTextContent("Theme not saved");
    expect(rootTheme()).toBe("light");
    expect(screen.getByRole("switch", { name: "Dark theme" })).toHaveAttribute("aria-checked", "false");
  });
});
