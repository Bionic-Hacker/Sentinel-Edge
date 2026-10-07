import { useEffect, useState, type FormEvent } from "react";
import { Button, Field, FormError, Notice } from "../../components/forms";
import { inviteUser, listUsers, resetUserMfa, updateUser } from "../../lib/api/admin";
import type { ApiError } from "../../lib/api/client";
import { ROLES, type ManagedUser, type Role } from "../../lib/types";
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
  const [error, setError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const reload = () => setVersion((v) => v + 1);

  useEffect(() => {
    const controller = new AbortController();
    listUsers(controller.signal)
      .then(setUsers)
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

  return (
    <div className="space-y-5">
      <InviteForm
        onInvited={(email) => {
          setNotice(`Invitation sent to ${email}. Running locally? Use make outbox to see it.`);
          reload();
        }}
      />
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
                      {!u.is_active ? <span className="text-fail">Deactivated</span> : u.locked ? <span className="text-prov-sim">Locked</span> : u.must_change_password ? <span className="text-ink-muted">Invited</span> : <span className="text-ok">Active</span>}
                    </td>
                    <td className="px-3 py-2.5 text-ink-muted">{u.mfa_enabled ? "On" : "Off"}</td>
                    <td className="space-x-2 whitespace-nowrap px-3 py-2.5 text-right">
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

function InviteForm({ onInvited }: { onInvited: (email: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    setBusy(true);
    setError(null);
    try {
      const user = await inviteUser({
        email: String(form.get("email")),
        display_name: String(form.get("name")),
        role: String(form.get("role")) as Role,
      });
      formElement.reset();
      onInvited(user.email);
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
        <label htmlFor="invite-role" className="block text-sm font-medium">Role</label>
        <select id="invite-role" name="role" defaultValue="VIEWER" className="w-full rounded border border-line bg-canvas px-2 py-2 text-sm">
          {ROLES.map((r) => (
            <option key={r} value={r}>{ROLE_LABEL[r]}</option>
          ))}
        </select>
      </div>
      <Button type="submit" busy={busy}>Invite</Button>
      <div className="sm:col-span-4">
        <FormError error={error} />
        <p className="text-xs text-ink-muted">The invitee sets their own password from a one-time link. You never see it.</p>
      </div>
    </form>
  );
}
