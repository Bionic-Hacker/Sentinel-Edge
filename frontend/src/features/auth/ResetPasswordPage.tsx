import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { AuthCard } from "../../app/RequireAuth";
import { Button, Field, FormError, Notice } from "../../components/forms";
import { resetPassword } from "../../lib/api/auth";
import { ApiError } from "../../lib/api/client";
import { asApiError } from "./LoginPage";

/** Read the token from the URL fragment once. Fragments never reach servers or logs. */
function readTokenFromFragment(): string | null {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const token = params.get("token");
  return token && /^[A-Za-z0-9_-]{20,128}$/.test(token) ? token : null;
}

export function ResetPasswordPage() {
  const [token] = useState(readTokenFromFragment);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    // Strip the token from the address bar and history so it can't be copied or reused later.
    if (window.location.hash) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token) return;
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password"));
    if (password !== String(form.get("confirm"))) {
      setError(new ApiError(400, "mismatch", "The two passwords don't match.", null));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await resetPassword(token, password);
      setDone(true);
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <AuthCard title="Link not valid">
        <p className="mb-4 text-sm text-ink-muted">This reset link is incomplete or has already been used.</p>
        <Link to="/forgot-password" className="text-sm text-accent underline-offset-2 hover:underline">
          Request a new link
        </Link>
      </AuthCard>
    );
  }

  return (
    <AuthCard title="Choose a new password">
      {done ? (
        <div className="space-y-4">
          <Notice>Password updated. You've been signed out everywhere else.</Notice>
          <Link to="/login" className="block text-sm text-accent underline-offset-2 hover:underline">
            Sign in
          </Link>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <Field
            label="New password"
            name="password"
            type="password"
            autoComplete="new-password"
           
            required
            minLength={12}
            maxLength={128}
            hint="At least 12 characters. A long phrase works well."
          />
          <Field label="Confirm new password" name="confirm" type="password" autoComplete="new-password" required maxLength={128} />
          <FormError error={error} />
          <Button type="submit" busy={busy} className="w-full">
            Set password
          </Button>
        </form>
      )}
    </AuthCard>
  );
}
