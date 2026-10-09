/**
 * Shared pieces for threat modeling and governance (Phase 10). Everything people typed (threats,
 * justifications, notes) is rendered as text. Charts are SVG with geometry in attributes: the
 * CSP forbids inline styles.
 */
import { useId, type ReactNode } from "react";
import { formatTime } from "../../components/secops";
import type {
  ChangeStatus,
  ControlStatus,
  ExceptionStatus,
  HistoryEntry,
  RiskCell,
  RiskLevel,
  Role,
  ThreatStatus,
} from "../../lib/types";

export const LEADS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER"];
export const REQUESTERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "DEVELOPER"];

const BADGE = "inline-flex whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-xs font-medium";
const TONE = {
  bad: "border-fail/50 text-fail",
  warn: "border-prov-sim/60 text-prov-sim",
  busy: "border-accent/50 text-accent",
  good: "border-ok/50 text-ok",
  quiet: "border-line text-ink-muted",
} as const;
type Tone = keyof typeof TONE;

function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`${BADGE} ${TONE[tone]}`}>{children}</span>;
}

const THREAT: Record<ThreatStatus, [string, Tone]> = {
  open: ["Open", "bad"],
  planned: ["Planned", "warn"],
  partly_mitigated: ["Partly mitigated", "busy"],
  mitigated: ["Mitigated", "good"],
  accepted: ["Accepted", "warn"],
  not_exposed: ["Not exposed", "quiet"],
  closed: ["Closed", "quiet"],
};
export const threatStatusLabel = (s: ThreatStatus) => THREAT[s][0];
export const ThreatStatusBadge = ({ status }: { status: ThreatStatus }) => (
  <Badge tone={THREAT[status][1]}>{THREAT[status][0]}</Badge>
);

export const ControlStatusBadge = ({ status }: { status: ControlStatus }) =>
  status === "implemented" ? <Badge tone="good">Implemented</Badge> : <Badge tone="quiet">Planned</Badge>;

const RISK: Record<RiskLevel, Tone> = { low: "quiet", medium: "busy", high: "warn", critical: "bad" };
export const RiskBadge = ({ level }: { level: RiskLevel }) => (
  <Badge tone={RISK[level]}>
    <span className="capitalize">{level}</span>
  </Badge>
);

const EXCEPTION: Record<ExceptionStatus, [string, Tone]> = {
  requested: ["Requested", "busy"],
  approved: ["Approved", "warn"],
  rejected: ["Rejected", "quiet"],
  withdrawn: ["Withdrawn", "quiet"],
  expired: ["Expired", "quiet"],
  closed: ["Closed", "good"],
};
export const exceptionStatusLabel = (s: ExceptionStatus) => EXCEPTION[s][0];
export const ExceptionStatusBadge = ({ status }: { status: ExceptionStatus }) => (
  <Badge tone={EXCEPTION[status][1]}>{EXCEPTION[status][0]}</Badge>
);

const CHANGE: Record<ChangeStatus, [string, Tone]> = {
  submitted: ["Submitted", "busy"],
  approved: ["Approved", "busy"],
  rejected: ["Rejected", "quiet"],
  cancelled: ["Cancelled", "quiet"],
  implemented: ["Implemented", "warn"],
  validated: ["Validated", "good"],
  rolled_back: ["Rolled back", "bad"],
};
export const changeStatusLabel = (s: ChangeStatus) => CHANGE[s][0];
export const ChangeStatusBadge = ({ status }: { status: ChangeStatus }) => (
  <Badge tone={CHANGE[status][1]}>{CHANGE[status][0]}</Badge>
);

/** "Move to Approved", "Roll back" and so on, for change request buttons. */
export const MOVE_LABEL: Record<ChangeStatus, string> = {
  submitted: "Submit",
  approved: "Approve",
  rejected: "Reject",
  cancelled: "Cancel the request",
  implemented: "Mark implemented",
  validated: "Mark validated",
  rolled_back: "Roll back",
};

const LEVELS = ["", "Low", "Medium", "High"];

/** L x I matrix of threats still carrying risk, with a table twin for screen readers. */
export function RiskMatrix({ cells }: { cells: RiskCell[] }) {
  const titleId = useId();
  const max = Math.max(1, ...cells.map((c) => c.count));
  const size = 56;
  const pad = 70;
  const fill = (risk: number, count: number) =>
    count === 0 ? "fill-raised" : risk >= 6 ? "fill-fail" : risk >= 3 ? "fill-prov-sim" : "fill-accent";
  return (
    <figure className="space-y-2">
      <svg
        role="img"
        aria-labelledby={titleId}
        viewBox={`0 0 ${pad + size * 3} ${size * 3 + 44}`}
        className="h-auto w-full max-w-xs"
      >
        <title id={titleId}>Open threats by likelihood and impact</title>
        {cells.map((c) => {
          const x = pad + (c.impact - 1) * size;
          const y = (3 - c.likelihood) * size;
          return (
            <g key={`${c.likelihood}-${c.impact}`}>
              <rect
                x={x + 2}
                y={y + 2}
                width={size - 4}
                height={size - 4}
                rx={4}
                className={fill(c.likelihood * c.impact, c.count)}
                opacity={c.count ? 0.35 + 0.65 * (c.count / max) : 1}
              />
              <text x={x + size / 2} y={y + size / 2 + 5} textAnchor="middle" className="fill-ink text-sm font-semibold">
                {c.count}
              </text>
            </g>
          );
        })}
        {[1, 2, 3].map((n) => (
          <g key={n}>
            <text x={pad - 6} y={(3 - n) * size + size / 2 + 4} textAnchor="end" className="fill-ink-muted text-[10px]">
              {LEVELS[n]}
            </text>
            <text x={pad + (n - 1) * size + size / 2} y={size * 3 + 16} textAnchor="middle" className="fill-ink-muted text-[10px]">
              {LEVELS[n]}
            </text>
          </g>
        ))}
        <text x={pad + (size * 3) / 2} y={size * 3 + 36} textAnchor="middle" className="fill-ink-muted text-[10px]">
          Impact
        </text>
        <text x={10} y={(size * 3) / 2} textAnchor="middle" transform={`rotate(-90 10 ${(size * 3) / 2})`} className="fill-ink-muted text-[10px]">
          Likelihood
        </text>
      </svg>
      <details className="text-xs text-ink-muted">
        <summary className="cursor-pointer">As a table</summary>
        <table className="mt-2 text-left">
          <thead>
            <tr>
              <th scope="col" className="pr-3">Likelihood</th>
              <th scope="col" className="pr-3">Impact</th>
              <th scope="col">Open threats</th>
            </tr>
          </thead>
          <tbody>
            {cells.map((c) => (
              <tr key={`${c.likelihood}-${c.impact}`}>
                <td className="pr-3">{LEVELS[c.likelihood]}</td>
                <td className="pr-3">{LEVELS[c.impact]}</td>
                <td className="tabular-nums">{c.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}

/** A small line of past scores (0-100); nothing when there is a single point. */
export function TrendLine({ points, label }: { points: { taken_at: string; value: number }[]; label: string }) {
  const titleId = useId();
  if (points.length < 2) return <p className="text-xs text-ink-muted">The trend appears after the second snapshot.</p>;
  const w = 240;
  const h = 48;
  const step = w / (points.length - 1);
  const xy = points.map((p, i) => `${(i * step).toFixed(1)},${(h - (p.value / 100) * h).toFixed(1)}`).join(" ");
  return (
    <svg role="img" aria-labelledby={titleId} viewBox={`0 -2 ${w} ${h + 4}`} className="h-12 w-60">
      <title id={titleId}>
        {label}: {points.map((p) => `${p.taken_at.slice(0, 10)} ${p.value}`).join(", ")}
      </title>
      <polyline points={xy} fill="none" strokeWidth={2} className="stroke-accent" />
    </svg>
  );
}

/** The record's history, read from the hash-chained audit log. */
export function History({ entries }: { entries: HistoryEntry[] }) {
  return (
    <section aria-labelledby="history-heading" className="space-y-2">
      <h2 id="history-heading" className="text-base font-semibold">
        History
      </h2>
      <p className="text-xs text-ink-muted">From the hash-chained audit log: it cannot be edited without breaking the chain.</p>
      <ol className="space-y-2 border-l border-line pl-4">
        {entries.map((e) => (
          <li key={e.seq} className="text-sm">
            <span className="font-medium">{e.action.split(".")[1]?.replace("_", " ") ?? e.action}</span>{" "}
            <span className="text-ink-muted">
              by {e.actor_label}, {formatTime(e.occurred_at)}
            </span>
            {e.note && <span className="mt-0.5 block whitespace-pre-wrap break-words text-ink-muted">{e.note}</span>}
          </li>
        ))}
      </ol>
    </section>
  );
}

export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-ink-muted">{label}</dt>
      <dd className="mt-0.5 whitespace-pre-wrap break-words text-sm">{children}</dd>
    </div>
  );
}

export const textArea = "w-full rounded border border-line bg-canvas px-3 py-2 text-sm text-ink focus:border-accent focus:outline-none";
export const selectBox = "rounded border border-line bg-canvas px-2 py-1.5 text-sm";
