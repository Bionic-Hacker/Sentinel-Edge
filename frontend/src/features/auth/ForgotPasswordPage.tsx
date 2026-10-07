import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { AuthCard } from "../../app/RequireAuth";
import { Button, Field, FormError, Notice } from "../../components/forms";
import { requestPasswordReset } from "../../lib/api/auth";
import type { ApiError } from "../../lib/api/client";
import { asApiError } from "./LoginPage";

export function ForgotPasswordPage() {
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await requestPasswordReset(String(new FormData(event.currentTarget).get("email")));
      setSent(true);
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthCard title="Reset your password">
      {sent ? (
        <div className="space-y-4">
          {/* Same message whether or not the account exists (no account enumeration). */}
          <Notice>If an account uses that email, a reset link is on its way. It expires in 30 minutes.</Notice>
          <p className="text-sm text-ink-muted">
            Running locally? Email isn't sent: run <code className="font-mono text-ink">make outbox</code> to see the link.
          </p>
          <Link to="/login" className="block text-sm text-accent underline-offset-2 hover:underline">
            Back to sign in
          </Link>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <Field label="Email" name="email" type="email" autoComplete="username" required maxLength={254} />
          <FormError error={error} />
          <Button type="submit" busy={busy} className="w-full">
            Send reset link
          </Button>
          <Link to="/login" className="block text-center text-sm text-accent underline-offset-2 hover:underline">
            Back to sign in
          </Link>
        </form>
      )}
    </AuthCard>
  );
}
