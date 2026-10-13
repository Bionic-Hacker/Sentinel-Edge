import { useId, useState, type ComponentProps, type InputHTMLAttributes, type ReactNode } from "react";
import type { ApiError } from "../lib/api/client";

interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
}

export function Field({ label, hint, className = "", ...input }: FieldProps) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="block text-sm font-medium text-ink">
        {label}
      </label>
      <input
        id={id}
        aria-describedby={hintId}
        className={`w-full rounded border border-line bg-canvas px-3 py-2 text-sm text-ink placeholder:text-ink-muted/60 focus:border-accent focus:outline-none ${className}`}
        {...input}
      />
      {hint && (
        <p id={hintId} className="text-xs text-ink-muted">
          {hint}
        </p>
      )}
    </div>
  );
}

type Variant = "primary" | "secondary" | "danger";
const VARIANTS: Record<Variant, string> = {
  primary: "bg-accent text-canvas hover:bg-accent/90",
  secondary: "border border-line text-ink hover:bg-raised",
  danger: "border border-fail/60 text-fail hover:bg-fail/10",
};

export function Button({
  variant = "primary",
  busy = false,
  children,
  className = "",
  disabled,
  ...rest
}: ComponentProps<"button"> & { variant?: Variant; busy?: boolean }) {
  return (
    <button
      className={`inline-flex items-center justify-center rounded px-3 py-2 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-60 ${VARIANTS[variant]} ${className}`}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {children}
    </button>
  );
}

/** Shows an API error's safe message and its correlation ID for log lookup. */
export function FormError({ error }: { error: ApiError | null }) {
  if (!error) return null;
  return (
    <div role="alert" className="rounded border border-fail/50 bg-fail/10 px-3 py-2 text-sm text-ink">
      {error.message}
      {error.correlationId && error.status >= 500 && (
        <span className="mt-1 block text-xs text-ink-muted">
          Reference <code className="font-mono">{error.correlationId}</code>
        </span>
      )}
    </div>
  );
}

export function Notice({ children }: { children: ReactNode }) {
  return (
    <div role="status" className="rounded border border-ok/40 bg-ok/10 px-3 py-2 text-sm text-ink">
      {children}
    </div>
  );
}

export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-md border border-line bg-surface p-5">
      <h2 className="mb-4 text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

/** A panel that starts closed: its title is a button, and the content mounts only once opened. */
export function CollapsiblePanel({ title, children }: { title: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <section className="rounded-md border border-line bg-surface">
      <h2 className="text-base font-semibold">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={id}
          onClick={() => setOpen((v) => !v)}
          className="flex w-full items-center justify-between rounded-md px-5 py-4 text-left hover:bg-raised"
        >
          {title}
          <svg
            aria-hidden="true"
            viewBox="0 0 20 20"
            className={`h-4 w-4 text-ink-muted transition-transform ${open ? "rotate-180" : ""}`}
          >
            <path d="M5 7.5l5 5 5-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>
      </h2>
      {open && (
        <div id={id} className="px-5 pb-5">
          {children}
        </div>
      )}
    </section>
  );
}
