import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../app/App";
import { authenticated, CAPS, jsonResponse, mockApi, profile, unauthorized } from "../../test/fixtures";
import { renderSettled } from "../../test/render";

const health = () => jsonResponse({ status: "ok", version: "0.5.0" });
const caps = () => jsonResponse({ items: CAPS });

// renderSettled waits, inside act(), for the initial silent sign-in to finish, so React state
// updates never happen outside act() on any runtime.
async function renderAt(path: string, routes: Parameters<typeof mockApi>[0]) {
  const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(
    mockApi({ "/api/v1/health": health, "/api/v1/platform/capabilities": caps, ...routes }),
  );
  await renderSettled(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes />
    </MemoryRouter>,
  );
  return fetchMock;
}

describe("route guards", () => {
  it("sends anonymous visitors to sign in", async () => {
    await renderAt("/settings", { "POST /api/v1/auth/refresh": unauthorized });
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("restores the session silently from the refresh cookie", async () => {
    await renderAt("/", { "POST /api/v1/auth/refresh": () => jsonResponse(authenticated()) });
    expect(await screen.findByText("Ana Lyst")).toBeInTheDocument();
  });

  it("holds users with pending setup at the setup page", async () => {
    const user = profile({ role: "ADMIN", pending_steps: ["password_change"] });
    await renderAt("/audit-logs", { "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(user)) });
    expect(await screen.findByRole("heading", { name: "Set your own password" })).toBeInTheDocument();
  });
});

describe("sign in", () => {
  it("completes a password + TOTP sign-in", async () => {
    const user = userEvent.setup();
    const fetchMock = await renderAt("/login", {
      "POST /api/v1/auth/refresh": unauthorized,
      "POST /api/v1/auth/login": () =>
        jsonResponse({ status: "mfa_required", challenge_token: "challenge.jwt.value", expires_in: 300 }),
      "POST /api/v1/auth/mfa/verify": () => jsonResponse(authenticated(profile({ role: "SECURITY_ENGINEER", mfa_enabled: true }))),
    });

    await user.type(await screen.findByLabelText("Email"), "eng@example.com");
    await user.type(screen.getByLabelText("Password"), "a long passphrase here");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await user.type(await screen.findByLabelText("Authentication code"), "123456");
    await user.click(screen.getByRole("button", { name: "Verify" }));

    expect(await screen.findByText("Platform status")).toBeInTheDocument();
    const verifyCall = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/mfa/verify"));
    expect(JSON.parse(String(verifyCall?.[1]?.body))).toEqual({
      challenge_token: "challenge.jwt.value",
      code: "123456",
    });
  });

  it("shows the server's generic error and keeps the user on the form", async () => {
    const user = userEvent.setup();
    await renderAt("/login", {
      "POST /api/v1/auth/refresh": unauthorized,
      "POST /api/v1/auth/login": () =>
        jsonResponse({ error: { code: "invalid_credentials", message: "Invalid email or password" } }, 401),
    });
    await user.type(await screen.findByLabelText("Email"), "x@example.com");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password");
  });

  it("ignores off-site redirect targets after sign-in", async () => {
    const user = userEvent.setup();
    vi.spyOn(globalThis, "fetch").mockImplementation(
      mockApi({
        "/api/v1/health": health,
        "/api/v1/platform/capabilities": caps,
        "POST /api/v1/auth/refresh": unauthorized,
        "POST /api/v1/auth/login": () => jsonResponse(authenticated()),
      }),
    );
    await renderSettled(
      <MemoryRouter initialEntries={[{ pathname: "/login", state: { from: "//evil.example/phish" } }]}>
        <AppRoutes />
      </MemoryRouter>,
    );
    await user.type(await screen.findByLabelText("Email"), "a@example.com");
    await user.type(screen.getByLabelText("Password"), "a long passphrase here");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Platform status")).toBeInTheDocument();
  });
});

describe("password reset", () => {
  it("reads the token from the fragment and removes it from the address bar", async () => {
    const user = userEvent.setup();
    window.history.replaceState(null, "", "/reset-password#token=abcdefghijklmnopqrstuvwxyz012345");
    const fetchMock = await renderAt("/reset-password", {
      "POST /api/v1/auth/refresh": unauthorized,
      "POST /api/v1/auth/password/reset": () => new Response(null, { status: 204 }),
    });

    await waitFor(() => expect(window.location.hash).toBe(""));
    await user.type(await screen.findByLabelText("New password"), "a fresh long passphrase");
    await user.type(screen.getByLabelText("Confirm new password"), "a fresh long passphrase");
    await user.click(screen.getByRole("button", { name: "Set password" }));

    expect(await screen.findByRole("status")).toHaveTextContent("Password updated");
    const call = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/password/reset"));
    expect(JSON.parse(String(call?.[1]?.body)).token).toBe("abcdefghijklmnopqrstuvwxyz012345");
  });

  it("explains a missing or malformed token instead of showing the form", async () => {
    window.history.replaceState(null, "", "/reset-password#token=<script>");
    await renderAt("/reset-password", { "POST /api/v1/auth/refresh": unauthorized });
    expect(await screen.findByRole("heading", { name: "Link not valid" })).toBeInTheDocument();
  });

  it("gives the same answer whether or not the account exists", async () => {
    const user = userEvent.setup();
    await renderAt("/forgot-password", {
      "POST /api/v1/auth/refresh": unauthorized,
      "POST /api/v1/auth/password/forgot": () => jsonResponse({ status: "accepted" }, 202),
    });
    await user.type(await screen.findByLabelText("Email"), "anyone@example.com");
    await user.click(screen.getByRole("button", { name: "Send reset link" }));
    expect(await screen.findByRole("status")).toHaveTextContent("If an account uses that email");
  });
});

describe("role-aware pages", () => {
  it("shows user management only to administrators", async () => {
    await renderAt("/settings", { "POST /api/v1/auth/refresh": () => jsonResponse(authenticated()) });
    expect(await screen.findByRole("heading", { name: "Your account" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Users" })).not.toBeInTheDocument();
  });

  it("lists users for administrators", async () => {
    const admin = profile({ role: "ADMIN", mfa_enabled: true, display_name: "Ada Admin" });
    await renderAt("/settings", {
      "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(admin)),
      "/api/v1/users": () =>
        jsonResponse({
          items: [
            {
              id: admin.id,
              email: admin.email,
              display_name: "Ada Admin",
              role: "ADMIN",
              is_active: true,
              mfa_enabled: true,
              must_change_password: false,
              locked: false,
              last_login_at: null,
              created_at: "2026-10-07T00:00:00Z",
            },
          ],
        }),
    });
    const table = await screen.findByRole("table", { name: "Users and their roles" });
    expect(within(table).getByText("(you)")).toBeInTheDocument();
    // An admin cannot change their own role from the UI (the API refuses it too).
    expect(within(table).getByLabelText(`Role for ${admin.email}`)).toBeDisabled();
  });

  it("asks for confirmation before permanently deleting a user", async () => {
    const user = userEvent.setup();
    const admin = profile({ role: "ADMIN", mfa_enabled: true, display_name: "Ada Admin", email: "ada@example.com" });
    const managed = (id: string, email: string, role: string) => ({
      id,
      email,
      display_name: email.split("@")[0],
      role,
      is_active: true,
      mfa_enabled: role === "ADMIN",
      must_change_password: false,
      locked: false,
      last_login_at: null,
      created_at: "2026-10-07T00:00:00Z",
    });
    const analystId = "00000000-0000-4000-8000-0000000000bb";
    let deleted = false;
    const fetchMock = await renderAt("/settings", {
      "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(admin)),
      "/api/v1/users": () =>
        jsonResponse({
          items: [
            managed(admin.id, admin.email, "ADMIN"),
            ...(deleted ? [] : [managed(analystId, "analyst@example.com", "ANALYST")]),
          ],
        }),
      [`DELETE /api/v1/users/${analystId}`]: () => {
        deleted = true;
        return new Response(null, { status: 204 });
      },
    });
    const deleteCalls = () =>
      fetchMock.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === "DELETE");

    const table = await screen.findByRole("table", { name: "Users and their roles" });
    // No trash can on your own row: an admin cannot delete themselves.
    expect(within(table).queryByRole("button", { name: `Delete ${admin.email}` })).not.toBeInTheDocument();
    const trash = within(table).getByRole("button", { name: "Delete analyst@example.com" });

    // Opening the warning deletes nothing, and focus starts on Cancel.
    await user.click(trash);
    const dialog = screen.getByRole("alertdialog", { name: "Delete user account?" });
    expect(dialog).toHaveTextContent("Are you sure you want to permanently delete the user account analyst@example.com?");
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(deleteCalls()).toHaveLength(0);

    // Enter on the focused Cancel, and Escape, both back out without deleting.
    await user.keyboard("{Enter}");
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    await user.click(trash);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(deleteCalls()).toHaveLength(0);

    // Only the explicit "Delete permanently" button deletes.
    await user.click(trash);
    await user.click(screen.getByRole("button", { name: "Delete permanently" }));
    expect(await screen.findByText(/analyst@example.com was permanently deleted/)).toHaveAttribute("role", "status");
    expect(deleteCalls()).toHaveLength(1);
    expect(String(deleteCalls()[0]?.[0])).toContain(`/api/v1/users/${analystId}`);
    await waitFor(() =>
      expect(within(table).queryByRole("button", { name: "Delete analyst@example.com" })).not.toBeInTheDocument(),
    );
  });

  it("tells non-auditors they have no access to audit logs", async () => {
    await renderAt("/audit-logs", { "POST /api/v1/auth/refresh": () => jsonResponse(authenticated()) });
    expect(await screen.findByText(/available to administrators and security engineers/)).toBeInTheDocument();
  });

  it("renders audit details as text, never as markup", async () => {
    const user = userEvent.setup();
    const auditor = profile({ role: "SECURITY_ENGINEER", mfa_enabled: true });
    await renderAt("/audit-logs", {
      "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(auditor)),
      "/api/v1/audit-logs": () =>
        jsonResponse({
          items: [
            {
              seq: 1,
              id: "00000000-0000-4000-8000-0000000000aa",
              occurred_at: "2026-10-07T08:00:00.000000+00:00",
              actor_id: null,
              actor_label: "<img src=x onerror=alert(1)>@example.com",
              action: "auth.login",
              resource_type: null,
              resource_id: null,
              result: "failure",
              source_ip: "203.0.113.7",
              correlation_id: "abc-123",
              details: { reason: "<script>alert(1)</script>" },
              prev_hash: "0".repeat(64),
              record_hash: "a".repeat(64),
            },
          ],
          next_before_seq: null,
        }),
    });
    const table = await screen.findByRole("table", { name: "Audit records" });
    await user.click(await within(table).findByRole("button", { name: "Details" }));
    expect(within(table).getByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
    expect(document.querySelector("img[src='x']")).toBeNull();
  });
});
