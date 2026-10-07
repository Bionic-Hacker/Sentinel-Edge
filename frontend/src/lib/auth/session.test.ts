import { describe, expect, it, vi } from "vitest";
import { authenticated, jsonResponse, mockApi, unauthorized } from "../../test/fixtures";
import { apiGet, ApiError } from "../api/client";
import { isUserProfile } from "../api/validators";
import { endSession, getAccessToken, refreshSession, startSession } from "./session";

const authHeader = (init: RequestInit | undefined) =>
  (init?.headers as Record<string, string> | undefined)?.Authorization ?? null;

describe("session token handling", () => {
  it("keeps the access token in memory only, never in web storage", () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    startSession(authenticated());
    expect(getAccessToken()).toBe("access.token.one");
    expect(setItem).not.toHaveBeenCalled();
    expect(document.cookie).not.toContain("access.token.one");
    endSession();
    expect(getAccessToken()).toBeNull();
  });

  it("attaches the bearer token and the CSRF header to API calls", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(mockApi({ "/api/v1/auth/me": () => jsonResponse(authenticated().user) }));
    startSession(authenticated());
    await apiGet("/api/v1/auth/me", isUserProfile);
    const headers = fetchMock.mock.calls[0]?.[1]?.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer access.token.one");
    expect(headers["X-SentinelEdge-CSRF"]).toBe("1");
  });
});

describe("refresh on 401", () => {
  it("refreshes once and retries the request with the new token", async () => {
    const seen: (string | null)[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(
      mockApi({
        "/api/v1/auth/me": (init) => {
          seen.push(authHeader(init));
          return seen.length === 1 ? unauthorized() : jsonResponse(authenticated().user);
        },
        "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(undefined, "access.token.two")),
      }),
    );
    startSession(authenticated());
    await apiGet("/api/v1/auth/me", isUserProfile);
    expect(seen).toEqual(["Bearer access.token.one", "Bearer access.token.two"]);
  });

  it("retries at most once, then surfaces the 401", async () => {
    let calls = 0;
    vi.spyOn(globalThis, "fetch").mockImplementation(
      mockApi({
        "/api/v1/auth/me": () => {
          calls += 1;
          return unauthorized();
        },
        "POST /api/v1/auth/refresh": () => jsonResponse(authenticated()),
      }),
    );
    startSession(authenticated());
    await expect(apiGet("/api/v1/auth/me", isUserProfile)).rejects.toMatchObject({ status: 401 });
    expect(calls).toBe(2);
  });

  it("signs out locally when the refresh is refused", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(
      mockApi({ "/api/v1/auth/me": unauthorized, "POST /api/v1/auth/refresh": unauthorized }),
    );
    startSession(authenticated());
    await expect(apiGet("/api/v1/auth/me", isUserProfile)).rejects.toBeInstanceOf(ApiError);
    expect(getAccessToken()).toBeNull();
  });

  it("shares one refresh between concurrent callers (no refresh-token reuse)", async () => {
    let refreshes = 0;
    vi.spyOn(globalThis, "fetch").mockImplementation(
      mockApi({
        "POST /api/v1/auth/refresh": async () => {
          refreshes += 1;
          await new Promise((resolve) => setTimeout(resolve, 10));
          return jsonResponse(authenticated());
        },
      }),
    );
    await Promise.all([refreshSession(), refreshSession(), refreshSession()]);
    expect(refreshes).toBe(1);
  });

  it("never sends the bearer token on the refresh call itself", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(mockApi({ "POST /api/v1/auth/refresh": () => jsonResponse(authenticated()) }));
    startSession(authenticated());
    await refreshSession();
    expect(authHeader(fetchMock.mock.calls[0]?.[1])).toBeNull();
    expect(fetchMock.mock.calls[0]?.[1]?.credentials).toBe("same-origin");
  });
});
