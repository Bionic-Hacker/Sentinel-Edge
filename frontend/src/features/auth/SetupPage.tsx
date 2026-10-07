import { useAuth, useCurrentUser } from "../../app/auth-context";
import { AuthCard } from "../../app/RequireAuth";
import { Button } from "../../components/forms";
import { ChangePasswordForm } from "./ChangePasswordForm";
import { MfaEnrollment } from "./MfaEnrollment";

/** Finish-setup flow: the API refuses everything else until these steps are done. */
export function SetupPage() {
  const user = useCurrentUser();
  const { reloadUser, logout } = useAuth();
  const step = user.pending_steps.includes("password_change") ? "password" : "mfa";

  return (
    <AuthCard title={step === "password" ? "Set your own password" : "Turn on two-factor authentication"}>
      <p className="mb-5 text-sm text-ink-muted">
        {step === "password"
          ? "You signed in with a one-time password. Choose a new one to continue."
          : `Your role (${user.role.replace("_", " ").toLowerCase()}) can change security settings, so it requires a second factor.`}
      </p>
      {step === "password" ? (
        <ChangePasswordForm onChanged={() => void reloadUser()} />
      ) : (
        <MfaEnrollment onComplete={() => void reloadUser()} />
      )}
      <div className="mt-6 border-t border-line pt-4">
        <Button variant="secondary" onClick={() => void logout()}>
          Sign out
        </Button>
      </div>
    </AuthCard>
  );
}
