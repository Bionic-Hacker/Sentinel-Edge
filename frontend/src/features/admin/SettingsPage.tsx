import { useAuth, useCurrentUser } from "../../app/auth-context";
import { Notice, Panel } from "../../components/forms";
import { ChangePasswordForm } from "../auth/ChangePasswordForm";
import { MfaEnrollment } from "../auth/MfaEnrollment";
import { UsersAdmin } from "./UsersAdmin";

export function SettingsPage() {
  const user = useCurrentUser();
  const { reloadUser } = useAuth();

  return (
    <div className="max-w-5xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-ink-muted">Your account, and user access for administrators.</p>
      </header>

      <Panel title="Your account">
        <dl className="grid max-w-md grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-sm">
          <dt className="text-ink-muted">Name</dt>
          <dd>{user.display_name}</dd>
          <dt className="text-ink-muted">Email</dt>
          <dd>{user.email}</dd>
          <dt className="text-ink-muted">Role</dt>
          <dd>{user.role}</dd>
        </dl>
      </Panel>

      <Panel title="Two-factor authentication">
        {user.mfa_enabled ? (
          <Notice>On. If you lose your authenticator, sign in with a recovery code, or ask an administrator to reset it.</Notice>
        ) : (
          <MfaEnrollment onComplete={() => void reloadUser()} />
        )}
      </Panel>

      <Panel title="Change password">
        <ChangePasswordForm />
      </Panel>

      {user.role === "ADMIN" && (
        <Panel title="Users">
          <UsersAdmin currentUserId={user.id} />
        </Panel>
      )}
    </div>
  );
}
