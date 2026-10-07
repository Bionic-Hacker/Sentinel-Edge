import { useState, type FormEvent } from "react";
import { Button, Field, FormError, Notice } from "../../components/forms";
import { changePassword } from "../../lib/api/auth";
import { ApiError } from "../../lib/api/client";
import { asApiError } from "./LoginPage";

export function ChangePasswordForm({ onChanged }: { onChanged?: () => void }) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const next = String(form.get("new"));
    if (next !== String(form.get("confirm"))) {
      setError(new ApiError(400, "mismatch", "The two new passwords don't match.", null));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await changePassword(String(form.get("current")), next);
      formElement.reset();
      setDone(true);
      onChanged?.();
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="max-w-sm space-y-4">
      <Field label="Current password" name="current" type="password" autoComplete="current-password" required maxLength={128} />
      <Field
        label="New password"
        name="new"
        type="password"
        autoComplete="new-password"
        required
        minLength={12}
        maxLength={128}
        hint="At least 12 characters. Your other sessions will be signed out."
      />
      <Field label="Confirm new password" name="confirm" type="password" autoComplete="new-password" required maxLength={128} />
      <FormError error={error} />
      {done && <Notice>Password changed. Other sessions have been signed out.</Notice>}
      <Button type="submit" busy={busy}>
        Change password
      </Button>
    </form>
  );
}
