import { describe, expect, it, vi } from "vitest";
import { jsonResponse } from "../../test/fixtures";
import { ApiError, apiGet, assertSafePath } from "./client";
import { isHealth } from "./platform";

describe("assertSafePath", () => {
  it.each([
    "https://evil.example/api/v1/health",
    "//evil.example/api/v1/health",
    "/api/v1/../../admin",
    "/admin",
    "javascript:alert(1)",
    "/api/v1/health?redirect=https://evil.example",
  ])("refuses %s", (path) => {
    expect(() => assertSafePath(path)).toThrow(ApiError);
  });

  it("accepts versioned relative API paths", () => {
    expect(() => assertSafePath("/api/v1/platform/capabilities")).not.toThrow();
  });
});

describe("apiGet", () => {
  it("sends a same-origin request that refuses redirects", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ status: "ok", version: "0.1.0" }));
    await apiGet("/api/v1/health", isHealth);
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.credentials).toBe("same-origin");
    expect(init?.redirect).toBe("error");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("rejects a response that fails validation", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ status: "ok", version: 1, injected: "<img>" }));
    await expect(apiGet("/api/v1/health", isHealth)).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("surfaces the server error envelope with its correlation id", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ error: { code: "internal_error", message: "An internal error occurred", correlation_id: "abc-12345678" } }, 500),
    );
    await expect(apiGet("/api/v1/health", isHealth)).rejects.toMatchObject({
      status: 500,
      code: "internal_error",
      correlationId: "abc-12345678",
    });
  });

  it("does not display raw non-JSON error bodies", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("<html>nginx stack trace /etc/nginx</html>", { status: 502, headers: { "X-Request-ID": "req-12345678" } }),
    );
    const error = await apiGet("/api/v1/health", isHealth).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).message).not.toContain("nginx");
    expect((error as ApiError).correlationId).toBe("req-12345678");
  });

  it("reports network failures without leaking details", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("getaddrinfo ENOTFOUND api.internal"));
    await expect(apiGet("/api/v1/health", isHealth)).rejects.toMatchObject({ code: "network_error" });
  });

  it("reports timeouts distinctly", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new DOMException("timed out", "TimeoutError"));
    await expect(apiGet("/api/v1/health", isHealth)).rejects.toMatchObject({ code: "timeout" });
  });
});
