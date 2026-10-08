/**
 * Shared pieces for vulnerability management (Phase 8). Scanner output is third-party text:
 * rendered as text, and links only for https URLs.
 */
import { useState } from "react";
import type { FindingCategory, ScanTool, VulnStatus } from "../../lib/types";

const STATUS_LABEL: Record<VulnStatus, string> = {
  open: "Open",
  in_progress: "In progress",
  fixed: "Fixed",
  accepted_risk: "Accepted risk",
  false_positive: "False positive",
};
const STATUS_TONE: Record<VulnStatus, string> = {
  open: "border-fail/50 text-fail",
  in_progress: "border-accent/50 text-accent",
  fixed: "border-ok/50 text-ok",
  accepted_risk: "border-prov-sim/60 text-prov-sim",
  false_positive: "border-line text-ink-muted",
};

export const vulnStatusLabel = (status: VulnStatus) => STATUS_LABEL[status];

export function VulnStatusBadge({ status }: { status: VulnStatus }) {
  return (
    <span className={`inline-flex whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-xs font-medium ${STATUS_TONE[status]}`}>
      {STATUS_LABEL[status]}
    </span>
  );
}

const CATEGORY_LABEL: Record<FindingCategory, string> = {
  sast: "Source code",
  sca: "Dependency",
  secret: "Secret",
  container: "Container image",
  iac: "Configuration",
  dast: "Running app",
};
export const findingCategoryLabel = (category: FindingCategory) => CATEGORY_LABEL[category];

const TOOL_LABEL: Record<ScanTool, string> = {
  semgrep: "Semgrep",
  bandit: "Bandit",
  trivy: "Trivy",
  gitleaks: "Gitleaks",
  checkov: "Checkov",
  zap: "ZAP",
};
export const toolLabel = (tool: ScanTool) => TOOL_LABEL[tool];

const DAY_MS = 24 * 3600 * 1000;

/** "Due in 12 days", "3 days overdue", or no SLA (info findings). */
export function SlaText({ due, overdue, active }: { due: string | null; overdue: boolean; active: boolean }) {
  const [now] = useState(() => Date.now()); // read once: rendering stays pure
  if (!due) return <span className="text-ink-muted">No SLA</span>;
  if (!active) return <span className="text-ink-muted">{due.slice(0, 10)}</span>;
  const days = Math.round((new Date(due).getTime() - now) / DAY_MS);
  if (overdue) {
    const late = Math.max(1, -days);
    return <span className="font-medium text-fail">{late === 1 ? "1 day overdue" : `${late} days overdue`}</span>;
  }
  return <span className={days <= 3 ? "text-prov-sim" : "text-ink"}>{days <= 0 ? "Due today" : days === 1 ? "Due in 1 day" : `Due in ${days} days`}</span>;
}

/** A scanner-supplied reference: a link only for https URLs (never javascript: or data:). */
export function ReferenceLink({ value }: { value: string }) {
  if (/^https:\/\/[^\s]+$/.test(value)) {
    return (
      <a href={value} target="_blank" rel="noopener noreferrer" className="break-all text-accent hover:underline">
        {value}
      </a>
    );
  }
  return <span className="break-all">{value}</span>;
}

export const ACTIVE: readonly VulnStatus[] = ["open", "in_progress"];
