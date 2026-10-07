import { useState, type FormEvent } from "react";
import { Button, Field, FormError } from "../../components/forms";
import { QrCode } from "../../components/QrCode";
import { confirmMfaEnrollment, startMfaEnrollment } from "../../lib/api/auth";
import type { ApiError } from "../../lib/api/client";
import { asApiError } from "./LoginPage";

type Stage =
  | { name: "intro" }
  | { name: "scan"; secret: string; uri: string }
  | { name: "codes"; codes: string[] };

/** Three steps: start → scan and confirm a code → save recovery codes (shown once). */
export function MfaEnrollment({ onComplete }: { onComplete: () => void }) {
  const [stage, setStage] = useState<Stage>({ name: "intro" });
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function begin() {
    setBusy(true);
    setError(null);
    try {
      const { secret, otpauth_uri } = await startMfaEnrollment();
      setStage({ name: "scan", secret, uri: otpauth_uri });
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const code = String(new FormData(event.currentTarget).get("code")).trim();
      const { recovery_codes } = await confirmMfaEnrollment(code);
      setStage({ name: "codes", codes: recovery_codes });
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  if (stage.name === "intro") {
    return (
      <div className="max-w-prose space-y-4">
        <p className="text-sm text-ink-muted">
          You'll need an authenticator app such as 1Password, Google Authenticator, or Aegis. After this, signing in asks
          for a 6-digit code as well as your password.
        </p>
        <FormError error={error} />
        <Button onClick={() => void begin()} busy={busy}>
          Set up two-factor authentication
        </Button>
      </div>
    );
  }

  if (stage.name === "scan") {
    return (
      <form onSubmit={confirm} className="space-y-4">
        <p className="max-w-prose text-sm text-ink-muted">Scan this code with your authenticator app, then enter the 6-digit code it shows.</p>
        <QrCode value={stage.uri} label="QR code for your authenticator app" />
        <details className="text-sm">
          <summary className="cursor-pointer text-accent">Can't scan? Enter the key manually</summary>
          <code className="mt-2 block break-all font-mono text-ink">{stage.secret}</code>
        </details>
        <div className="max-w-xs">
          <Field
            label="Authentication code"
            name="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            required
           
          />
        </div>
        <FormError error={error} />
        <Button type="submit" busy={busy}>
          Confirm and turn on
        </Button>
      </form>
    );
  }

  return (
    <div className="max-w-prose space-y-4">
      <p className="text-sm text-ink">
        Two-factor authentication is on. Save these recovery codes somewhere safe. Each one signs you in once if you lose your
        authenticator. <strong>They won't be shown again.</strong>
      </p>
      <ul className="grid grid-cols-2 gap-x-6 gap-y-1 rounded border border-line bg-canvas p-4 font-mono text-sm" aria-label="Recovery codes">
        {stage.codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="secondary" onClick={() => void navigator.clipboard?.writeText(stage.codes.join("\n"))}>
          Copy codes
        </Button>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          I've saved my recovery codes
        </label>
      </div>
      <Button onClick={onComplete} disabled={!saved}>
        Continue
      </Button>
    </div>
  );
}
