/**
 * Shared pieces for the security operations screens (Phase 7): severity and status badges, the
 * live/simulated view switch, and formatting. Anything that renders event data renders it as
 * text: evidence is attacker-influenced.
 */
import { useId, type ReactNode } from "react";
import type { DataView, EventCategory, IncidentStatus, Outcome, Severity } from "../lib/types";

/** Same visual language as risk on the API Security page: red, amber, blue, muted. */
const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "border-fail/60 bg-fail/10 text-fail",
  high: "border-prov-sim/60 bg-prov-sim/10 text-prov-sim",
  medium: "border-prov-local/50 bg-prov-local/10 text-prov-local",
  low: "border-line text-ink-muted",
  info: "border-line text-ink-muted",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex rounded-sm border px-1.5 py-0.5 text-xs font-medium capitalize ${SEVERITY_STYLE[severity]}`}>
      {severity}
    </span>
  );
}

const STATUS_LABEL: Record<IncidentStatus, string> = {
  DETECTED: "Detected",
  TRIAGED: "Triaged",
  INVESTIGATING: "Investigating",
  CONTAINMENT: "Containment",
  REMEDIATION: "Remediation",
  VALIDATION: "Validation",
  CLOSED: "Closed",
};

export const statusLabel = (status: IncidentStatus) => STATUS_LABEL[status];

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  const tone =
    status === "CLOSED"
      ? "border-line text-ink-muted"
      : status === "DETECTED"
        ? "border-fail/50 text-fail"
        : "border-accent/50 text-accent";
  return <span className={`inline-flex rounded-sm border px-1.5 py-0.5 text-xs font-medium ${tone}`}>{STATUS_LABEL[status]}</span>;
}

const CATEGORY_LABEL: Record<EventCategory, string> = {
  sql_injection: "SQL injection",
  xss: "Cross-site scripting",
  path_traversal: "Path traversal",
  command_injection: "Command injection",
  ssrf: "SSRF",
  scanner: "Scanner",
  recon: "Reconnaissance",
  bot: "Bot activity",
  auth_failure: "Failed authentication",
  brute_force: "Brute force",
  credential_stuffing: "Credential stuffing",
  token_theft: "Token theft",
  bola: "BOLA attempt",
  bfla: "BFLA attempt",
  privilege_change: "Privilege change",
  rate_limit: "Rate-limit violation",
  api_abuse: "API abuse",
  audit_tampering: "Audit tampering",
  suspicious_auth: "Suspicious sign-in",
  certificate: "Certificate",
  vulnerable_dependency: "Vulnerable dependency",
};

export const categoryLabel = (category: string) =>
  (CATEGORY_LABEL as Record<string, string>)[category] ?? category.replaceAll("_", " ");

const OUTCOME_LABEL: Record<Outcome, string> = {
  allowed: "Served",
  rejected: "Rejected",
  throttled: "Throttled",
  blocked: "Blocked at edge",
  detected: "Detected",
};
const OUTCOME_TONE: Record<Outcome, string> = {
  allowed: "text-fail",
  rejected: "text-ok",
  throttled: "text-ok",
  blocked: "text-ok",
  detected: "text-ink-muted",
};

/** What the control did. "Served" is the worrying one: the request got a success response. */
export function OutcomeText({ outcome }: { outcome: Outcome }) {
  return <span className={OUTCOME_TONE[outcome]}>{OUTCOME_LABEL[outcome]}</span>;
}

/** "2026-10-07 18:22 UTC": security tooling speaks UTC. */
export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function ViewToggle({ value, onChange }: { value: DataView; onChange: (view: DataView) => void }) {
  const name = useId();
  const options: { value: DataView; label: string; hint: string }[] = [
    { value: "live", label: "Live", hint: "Real activity against this platform" },
    { value: "simulated", label: "Simulated", hint: "Attack simulator output only" },
  ];
  return (
    <fieldset className="inline-flex rounded border border-line p-0.5">
      <legend className="sr-only">Data shown</legend>
      {options.map((o) => (
        <label
          key={o.value}
          title={o.hint}
          className={`cursor-pointer rounded px-3 py-1 text-sm has-[:focus-visible]:outline has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent ${
            value === o.value
              ? o.value === "simulated"
                ? "bg-prov-sim/15 text-prov-sim"
                : "bg-raised text-ink"
              : "text-ink-muted hover:text-ink"
          }`}
        >
          <input
            type="radio"
            name={name}
            value={o.value}
            checked={value === o.value}
            onChange={() => onChange(o.value)}
            className="sr-only"
          />
          {o.label}
        </label>
      ))}
    </fieldset>
  );
}

/** Shown above any screen that is displaying simulated data. */
export function SimulatedBanner({ children }: { children?: ReactNode }) {
  return (
    <div role="note" className="rounded-md border border-prov-sim/50 bg-prov-sim/10 px-4 py-2.5 text-sm text-ink">
      <span className="font-semibold text-prov-sim">Simulated data.</span>{" "}
      {children ??
        "Generated by the attack simulator: no real attack occurred, no network traffic was sent and no AWS resource was changed."}
    </div>
  );
}

export function StatTile({
  label,
  value,
  note,
  tone,
}: {
  label: string;
  value: ReactNode;
  note?: string;
  tone?: "fail" | "warn" | "ok";
}) {
  const color = tone === "fail" ? "text-fail" : tone === "warn" ? "text-prov-sim" : tone === "ok" ? "text-ok" : "text-ink";
  return (
    <div className="rounded-md border border-line bg-surface px-4 py-3">
      <dt className="text-xs text-ink-muted">{label}</dt>
      {/* Proportional figures for standalone values; tabular figures only in columns. */}
      <dd className={`mt-1 text-2xl font-semibold [font-feature-settings:'tnum'_0] ${color}`}>{value}</dd>
      {note && <dd className="mt-0.5 text-xs text-ink-muted">{note}</dd>}
    </div>
  );
}

/** Plain-text rendering of untrusted evidence: JSON, indented, never interpreted as markup. */
export function EvidenceText({ value }: { value: unknown }) {
  return (
    <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded border border-line bg-canvas p-3 font-mono text-xs text-ink">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}
