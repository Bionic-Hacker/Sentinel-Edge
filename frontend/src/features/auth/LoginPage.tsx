import { useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../../app/auth-context";
import { AuthCard } from "../../app/RequireAuth";
import { Button, Field, FormError } from "../../components/forms";
import { ApiError } from "../../lib/api/client";

function asApiError(error: unknown): ApiError {
  return error instanceof ApiError ? error : new ApiError(0, "unexpected", "Something went wrong. Try again.", null);
}

/** Only follow same-app paths after login (no open redirect via router state). */
function safeDestination(state: unknown): string {
  const from = typeof state === "object" && state !== null && "from" in state ? (state as { from: unknown }).from : null;
  return typeof from === "string" && from.startsWith("/") && !from.startsWith("//") ? from : "/";
}

export function LoginPage() {
  const { login, verifyMfa } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [challenge, setChallenge] = useState<string | null>(null);
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const result = await login(String(form.get("email")), String(form.get("password")));
      if (result.kind === "mfa") setChallenge(result.challengeToken);
      else navigate(safeDestination(location.state), { replace: true });
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!challenge) return;
    const code = String(new FormData(event.currentTarget).get("code")).trim();
    setBusy(true);
    setError(null);
    try {
      await verifyMfa(challenge, code);
      navigate(safeDestination(location.state), { replace: true });
    } catch (err) {
      const apiError = asApiError(err);
      setError(apiError);
      // An expired challenge cannot be retried: go back to the password step.
      if (apiError.code === "invalid_mfa" && apiError.message.includes("expired")) setChallenge(null);
    } finally {
      setBusy(false);
    }
  }

  if (challenge) {
    return (
      <AuthCard title="Two-factor authentication">
        <form onSubmit={submitCode} className="space-y-4" noValidate>
          {useRecovery ? (
            <Field
              key="recovery"
              label="Recovery code"
              name="code"
              autoComplete="off"
             
              required
              placeholder="xxxx-xxxx-xxxx"
              hint="Each recovery code works once."
            />
          ) : (
            <Field
              key="totp"
              label="Authentication code"
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
             
              required
              hint="The 6-digit code from your authenticator app."
            />
          )}
          <FormError error={error} />
          <Button type="submit" busy={busy} className="w-full">
            Verify
          </Button>
          <button
            type="button"
            className="w-full text-sm text-accent underline-offset-2 hover:underline"
            onClick={() => {
              setUseRecovery(!useRecovery);
              setError(null);
            }}
          >
            {useRecovery ? "Use your authenticator app" : "Use a recovery code instead"}
          </button>
        </form>
      </AuthCard>
    );
  }

  return (
    <AuthCard title="Sign in">
      <form onSubmit={submitPassword} className="space-y-4">
        <Field label="Email" name="email" type="email" autoComplete="username" required maxLength={254} />
        <Field label="Password" name="password" type="password" autoComplete="current-password" required maxLength={128} />
        <FormError error={error} />
        <Button type="submit" busy={busy} className="w-full">
          Sign in
        </Button>
        <p className="text-center text-sm">
          <Link to="/forgot-password" className="text-accent underline-offset-2 hover:underline">
            Forgot your password?
          </Link>
        </p>
      </form>
    </AuthCard>
  );
}

export { asApiError };
