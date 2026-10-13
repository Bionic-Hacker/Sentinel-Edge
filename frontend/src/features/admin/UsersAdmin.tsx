import { useEffect, useState, type FormEvent } from "react";
import { ConfirmDialog, TrashIcon } from "../../components/ConfirmDialog";
import { Button, Field, FormError, Notice } from "../../components/forms";
import { createUser, deleteUser, listUsers, resetUserMfa, resetUserPassword, updateUser } from "../../lib/api/admin";
import type { ApiError } from "../../lib/api/client";
import { ROLES, type ManagedUser, type Role, type TemporaryPasswordIssued } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

const ROLE_LABEL: Record<Role, string> = {
  ADMIN: "Admin",
  SECURITY_ENGINEER: "Security engineer",
  DEVELOPER: "Developer",
  ANALYST: "Analyst",
  VIEWER: "Viewer",
};

export function UsersAdmin({ currentUserId }: { currentUserId: string }) {
  const [users, setUsers] = useState<ManagedUser[] | null>(null);
  // When the list was loaded: temporary-password expiry is judged against it, not each render.
  const [loadedAt, setLoadedAt] = useState(0);
  const [error, setError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const [pendingDelete, setPendingDelete] = useState<ManagedUser | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [pendingReset, setPendingReset] = useState<ManagedUser | null>(null);
  const [resetting, setResetting] = useState(false);
  // Held in memory only, until the admin dismisses it: the API never returns it again.
  const [issued, setIssued] = useState<{ result: TemporaryPasswordIssued; reason: "created" | "reset" } | null>(null);
  const reload = () => setVersion((v) => v + 1);

  useEffect(() => {
    const controller = new AbortController();
    listUsers(controller.signal)
      .then((items) => {
        setUsers(items);
        setLoadedAt(Date.now());
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      });
    return () => controller.abort();
  }, [version]);

  async function act(action: () => Promise<unknown>, message: string) {
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(message);
      reload();
    } catch (err) {
      setError(asApiError(err));
    }
  }

  async function confirmDelete(user: ManagedUser) {
    setDeleting(true);
    await act(() => deleteUser(user.id), `${user.email} was permanently deleted. Their audit history is kept.`);
    setDeleting(false);
    setPendingDelete(null);
  }

  async function confirmReset(user: ManagedUser) {
    setResetting(true);
    setError(null);
    setNotice(null);
    setIssued(null);
    try {
      setIssued({ result: await resetUserPassword(user.id), reason: "reset" });
      reload();
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setResetting(false);
      setPendingReset(null);
    }
  }

  return (
    <div className="space-y-5">
      {pendingReset && (
        <ConfirmDialog
          title="Reset password?"
          confirmLabel="Reset password"
          busy={resetting}
          onCancel={() => setPendingReset(null)}
          onConfirm={() => void confirmReset(pendingReset)}
        >
          <p>
            Issue a new temporary password for{" "}
            <strong className="break-words text-ink">{pendingReset.email}</strong>?
          </p>
          <p>
            Their current password stops working and they are signed out everywhere. You will see the temporary
            password once; they must replace it at their next sign-in. Their two-factor setup is kept.
          </p>
        </ConfirmDialog>
      )}
      {pendingDelete && (
        <ConfirmDialog
          title="Delete user account?"
          confirmLabel="Delete permanently"
          busy={deleting}
          onCancel={() => setPendingDelete(null)}
          onConfirm={() => void confirmDelete(pendingDelete)}
        >
          <p>
            Are you sure you want to permanently delete the user account{" "}
            <strong className="break-words text-ink">{pendingDelete.email}</strong>?
          </p>
          <p>
            They are signed out everywhere and their password and two-factor setup are removed. This
            cannot be undone. Their audit history is kept.
          </p>
          <p>To block access but keep the account, cancel and use Deactivate instead.</p>
        </ConfirmDialog>
      )}
      <CreateUserForm
        onCreated={(result) => {
          setNotice(null);
          setIssued({ result, reason: "created" });
          reload();
        }}
      />
      {issued && <TemporaryPassword issued={issued.result} reason={issued.reason} onDone={() => setIssued(null)} />}
      <FormError error={error} />
      {notice && <Notice>{notice}</Notice>}
      {users === null ? (
        <p className="text-sm text-ink-muted">Loading users…</p>
      ) : (
        <div className="overflow-x-auto rounded-md border border-line">
          <table className="w-full min-w-[720px] text-left text-sm">
            <caption className="sr-only">Users and their roles</caption>
            <thead className="bg-raised text-ink-muted">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">User</th>
                <th scope="col" className="px-3 py-2 font-medium">Role</th>
                <th scope="col" className="px-3 py-2 font-medium">Status</th>
                <th scope="col" className="px-3 py-2 font-medium">Two-factor</th>
                <th scope="col" className="px-3 py-2 font-medium"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {users.map((u) => {
                const self = u.id === currentUserId;
                return (
                  <tr key={u.id}>
                    <td className="px-3 py-2.5">
                      <div className="font-medium text-ink">{u.display_name}{self && <span className="text-ink-muted"> (you)</span>}</div>
                      <div className="text-ink-muted">{u.email}</div>
                    </td>
                    <td className="px-3 py-2.5">
                      <select
                        aria-label={`Role for ${u.email}`}
                        value={u.role}
                        disabled={self}
                        className="rounded border border-line bg-canvas px-2 py-1"
                        onChange={(e) =>
                          void act(() => updateUser(u.id, { role: e.target.value as Role }), `${u.email} is now ${ROLE_LABEL[e.target.value as Role]}. Their sessions were ended.`)
                        }
                      >
                        {ROLES.map((r) => (
                          <option key={r} value={r}>{ROLE_LABEL[r]}</option>
                        ))}
                      </select>
                    </td>
                    <td className="px-3 py-2.5">
                      <UserStatus user={u} now={loadedAt} />
                    </td>
                    <td className="px-3 py-2.5 text-ink-muted">{u.mfa_enabled ? "On" : "Off"}</td>
                    <td className="space-x-2 whitespace-nowrap px-3 py-2.5 text-right">
                      {!self && (
                        <Button variant="secondary" onClick={() => setPendingReset(u)}>
                          Reset password
                        </Button>
                      )}
                      {!self && u.mfa_enabled && (
                        <Button variant="secondary" onClick={() => void act(() => resetUserMfa(u.id), `Two-factor reset for ${u.email}. They'll set it up again at next sign-in.`)}>
                          Reset 2FA
                        </Button>
                      )}
                      {!self && (
                        <Button
                          variant={u.is_active ? "danger" : "secondary"}
                          onClick={() => void act(() => updateUser(u.id, { is_active: !u.is_active }), u.is_active ? `${u.email} deactivated and signed out.` : `${u.email} reactivated.`)}
                        >
                          {u.is_active ? "Deactivate" : "Reactivate"}
                        </Button>
                      )}
                      {!self && (
                        <Button
                          variant="danger"
                          aria-label={`Delete ${u.email}`}
                          title="Delete user permanently"
                          className="px-2.5 align-middle"
                          onClick={() => setPendingDelete(u)}
                        >
                          <TrashIcon />
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function UserStatus({ user, now }: { user: ManagedUser; now: number }) {
  if (!user.is_active) return <span className="text-fail">Deactivated</span>;
  if (user.locked) return <span className="text-prov-sim">Locked</span>;
  const expires = user.temporary_password_expires_at;
  if (expires !== null) {
    return new Date(expires).getTime() <= now ? (
      <span className="text-fail">Temporary password expired</span>
    ) : (
      <span className="text-ink-muted">Awaiting first sign-in</span>
    );
  }
  if (user.must_change_password) return <span className="text-ink-muted">Must change password</span>;
  return <span className="text-ok">Active</span>;
}

/** Shown once, then gone: the platform keeps only a hash of it. */
function TemporaryPassword({
  issued,
  reason,
  onDone,
}: {
  issued: TemporaryPasswordIssued;
  reason: "created" | "reset";
  onDone: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const expires = new Date(issued.expires_at).toLocaleString();

  async function copy() {
    try {
      await navigator.clipboard.writeText(issued.temporary_password);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section
      aria-labelledby="temporary-password-title"
      className="space-y-3 rounded-md border border-accent/60 bg-raised p-4"
    >
      <h3 id="temporary-password-title" className="font-medium text-ink">
        {reason === "created" ? `${issued.user.email} was created` : `Password reset for ${issued.user.email}`}
      </h3>
      <p className="text-sm text-ink-muted">
        Give them this temporary password through a channel you trust. It is shown only now, works until {expires},
        and must be replaced at their first sign-in.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <code
          data-testid="temporary-password"
          className="select-all rounded border border-line bg-canvas px-3 py-2 font-mono text-base tracking-wide text-ink"
        >
          {issued.temporary_password}
        </code>
        <Button variant="secondary" onClick={() => void copy()}>
          {copied ? "Copied" : "Copy"}
        </Button>
        <Button onClick={onDone}>Done</Button>
      </div>
    </section>
  );
}

function CreateUserForm({ onCreated }: { onCreated: (result: TemporaryPasswordIssued) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    setBusy(true);
    setError(null);
    try {
      const result = await createUser({
        email: String(form.get("email")),
        display_name: String(form.get("name")),
        role: String(form.get("role")) as Role,
      });
      formElement.reset();
      onCreated(result);
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="grid gap-3 rounded-md border border-line p-4 sm:grid-cols-[1fr_1fr_auto_auto] sm:items-end">
      <Field label="Email" name="email" type="email" required maxLength={254} />
      <Field label="Name" name="name" required maxLength={100} />
      <div className="space-y-1">
        <label htmlFor="new-user-role" className="block text-sm font-medium">Role</label>
        <select id="new-user-role" name="role" defaultValue="VIEWER" className="w-full rounded border border-line bg-canvas px-2 py-2 text-sm">
          {ROLES.map((r) => (
            <option key={r} value={r}>{ROLE_LABEL[r]}</option>
          ))}
        </select>
      </div>
      <Button type="submit" busy={busy}>Create user</Button>
      <div className="sm:col-span-4">
        <FormError error={error} />
        <p className="text-xs text-ink-muted">
          You get a temporary password to hand over, shown once. They replace it at first sign-in. No email is sent.
        </p>
      </div>
    </form>
  );
}
