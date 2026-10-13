import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../app/App";
import { authenticated, CAPS, jsonResponse, mockApi, profile, unauthorized } from "../../test/fixtures";
import { renderSettled } from "../../test/render";

const health = () => jsonResponse({ status: "ok", version: "0.7.0" });
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

/** Administrators see Change password and Users as closed panels; open Users. */
async function openUsers() {
  await userEvent.setup().click(await screen.findByRole("button", { name: "Users" }));
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

describe("account recovery (ADR-0028)", () => {
  it("sends people who forgot their password to an administrator, not to an email link", async () => {
    await renderAt("/login", { "POST /api/v1/auth/refresh": unauthorized });
    expect(await screen.findByText("Forgot your password? Ask an administrator to reset it.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /forgot/i })).not.toBeInTheDocument();
  });

  it("shows an administrator the temporary password once, for creating and for resetting", async () => {
    const user = userEvent.setup();
    const admin = profile({ role: "ADMIN", mfa_enabled: true, display_name: "Ada Admin", email: "ada@example.com" });
    const analystId = "00000000-0000-4000-8000-0000000000cc";
    const row = (id: string, email: string, role: string, expires: string | null) => ({
      id,
      email,
      display_name: email.split("@")[0],
      role,
      is_active: true,
      mfa_enabled: role === "ADMIN",
      must_change_password: expires !== null,
      temporary_password_expires_at: expires,
      locked: false,
      last_login_at: null,
      created_at: "2026-10-07T00:00:00Z",
    });
    const later = new Date(Date.now() + 72 * 3600 * 1000).toISOString();
    let created = false;
    const fetchMock = await renderAt("/settings", {
      "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(admin)),
      "/api/v1/users": () =>
        jsonResponse({
          items: [
            row(admin.id, admin.email, "ADMIN", null),
            ...(created ? [row(analystId, "new@example.com", "ANALYST", later)] : []),
          ],
        }),
      "POST /api/v1/users": () => {
        created = true;
        return jsonResponse(
          {
            user: row(analystId, "new@example.com", "ANALYST", later),
            temporary_password: "k7m2x-p9qra-4tz8h-cw3ny",
            expires_at: later,
          },
          201,
        );
      },
      [`POST /api/v1/users/${analystId}/password/reset`]: () =>
        jsonResponse({
          user: row(analystId, "new@example.com", "ANALYST", later),
          temporary_password: "b3n8q-x2wkd-7hzrm-p5cvt",
          expires_at: later,
        }),
    });

    await openUsers();
    await screen.findByRole("table", { name: "Users and their roles" });
    await user.type(screen.getByLabelText("Email"), "new@example.com");
    await user.type(screen.getByLabelText("Name"), "New Analyst");
    await user.click(screen.getByRole("button", { name: "Create user" }));
    expect(await screen.findByTestId("temporary-password")).toHaveTextContent("k7m2x-p9qra-4tz8h-cw3ny");
    expect(screen.getByRole("heading", { name: "new@example.com was created" })).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Users and their roles" });
    expect(await within(table).findByText("Awaiting first sign-in")).toBeInTheDocument();

    // Dismissed, it is gone for good: nothing in the page can show it again.
    await user.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByTestId("temporary-password")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("k7m2x-p9qra-4tz8h-cw3ny");

    // A reset asks first, then shows the new one.
    const resets = () => fetchMock.mock.calls.filter(([url]) => String(url).endsWith("/password/reset"));
    await user.click(within(table).getByRole("button", { name: "Reset password" }));
    const dialog = screen.getByRole("alertdialog", { name: "Reset password?" });
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(resets()).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "Reset password" }));
    expect(await screen.findByTestId("temporary-password")).toHaveTextContent("b3n8q-x2wkd-7hzrm-p5cvt");
    expect(screen.getByRole("heading", { name: "Password reset for new@example.com" })).toBeInTheDocument();
    expect(resets()).toHaveLength(1);
  });
});

describe("role-aware pages", () => {
  it("shows user management only to administrators", async () => {
    await renderAt("/settings", { "POST /api/v1/auth/refresh": () => jsonResponse(authenticated()) });
    expect(await screen.findByRole("heading", { name: "Your account" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Users" })).not.toBeInTheDocument();
  });

  it("keeps Change password and Users closed for administrators until opened", async () => {
    const admin = profile({ role: "ADMIN", mfa_enabled: true });
    await renderAt("/settings", {
      "POST /api/v1/auth/refresh": () => jsonResponse(authenticated(admin)),
      "/api/v1/users": () => jsonResponse({ items: [] }),
    });
    const password = await screen.findByRole("button", { name: "Change password" });
    const users = screen.getByRole("button", { name: "Users" });
    expect(password).toHaveAttribute("aria-expanded", "false");
    expect(users).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByLabelText("Current password")).not.toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "Users and their roles" })).not.toBeInTheDocument();

    await userEvent.setup().click(password);
    expect(password).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByLabelText("Current password")).toBeInTheDocument();
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
              temporary_password_expires_at: null,
              locked: false,
              last_login_at: null,
              created_at: "2026-10-07T00:00:00Z",
            },
          ],
        }),
    });
    await openUsers();
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
      temporary_password_expires_at: null,
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

    await openUsers();
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
