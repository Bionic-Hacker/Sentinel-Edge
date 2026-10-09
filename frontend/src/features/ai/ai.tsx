/**
 * Shared pieces for the AI security engine (Phase 9). Everything the AI wrote, and every quote it
 * took from attacker-controlled data, is rendered as text only (T-AI-03). Buttons follow what the
 * server allows: `can_analyse` from the status, `can_decide` and `note_required` per proposal.
 */
import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button, FormError } from "../../components/forms";
import { getAiStatus, listAnalyses, runAnalysis } from "../../lib/api/ai";
import type { ApiError } from "../../lib/api/client";
import type {
  AiAnalysisStatus,
  AiAnalysisSummary,
  AiClassification,
  AiProposalStatus,
  AiProposalType,
  AiRiskLevel,
  AiStatus,
  AiSubjectRef,
  AiSubjectType,
} from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

const BADGE = "inline-flex whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-xs font-medium";
const TONE = {
  bad: "border-fail/50 text-fail",
  warn: "border-prov-sim/60 text-prov-sim",
  good: "border-ok/50 text-ok",
  quiet: "border-line text-ink-muted",
} as const;
type Tone = keyof typeof TONE;

export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`${BADGE} ${TONE[tone]}`}>{children}</span>;
}

const ANALYSIS: Record<AiAnalysisStatus, [string, Tone]> = {
  completed: ["Completed", "good"],
  rejected: ["Rejected: broke the contract", "bad"],
  failed: ["Failed: no answer", "warn"],
};
export const AnalysisStatusBadge = ({ status }: { status: AiAnalysisStatus }) => (
  <Badge tone={ANALYSIS[status][1]}>{ANALYSIS[status][0]}</Badge>
);

const PROPOSAL: Record<AiProposalStatus, [string, Tone]> = {
  proposed: ["Awaiting a decision", "warn"],
  approved: ["Approved", "good"],
  rejected: ["Rejected", "quiet"],
};
export const ProposalStatusBadge = ({ status }: { status: AiProposalStatus }) => (
  <Badge tone={PROPOSAL[status][1]}>{PROPOSAL[status][0]}</Badge>
);

const RISK: Record<AiRiskLevel, [string, Tone]> = {
  low: ["Low", "good"],
  medium: ["Medium", "warn"],
  high: ["High", "bad"],
};
export const PromptRiskBadge = ({ level, score }: { level: AiRiskLevel; score: number }) => (
  <Badge tone={RISK[level][1]}>
    Prompt risk {score} · {RISK[level][0]}
  </Badge>
);

const CLASSIFICATION: Record<AiClassification, string> = {
  sql_injection: "SQL injection",
  xss: "Cross-site scripting",
  path_traversal: "Path traversal",
  command_injection: "Command injection",
  ssrf: "Server-side request forgery",
  credential_attack: "Credential attack",
  authorization_abuse: "Authorization abuse",
  api_abuse: "API abuse",
  reconnaissance: "Reconnaissance",
  vulnerable_component: "Vulnerable component",
  code_weakness: "Code weakness",
  exposed_secret: "Exposed secret",
  design_threat: "Design threat",
  benign: "Benign",
  unknown: "Unknown",
};
export const classificationLabel = (c: AiClassification) => CLASSIFICATION[c];

const SIGNAL: Record<string, string> = {
  instruction_override: "Tries to override instructions",
  role_play: "Tries to change the AI's role",
  role_marker: "Contains chat role markers",
  delimiter_spoof: "Imitates the data delimiters",
  output_steering: "Tries to dictate the answer",
  forged_answer: "Contains a ready-made answer",
  action_injection: "Names AI actions",
  encoded_payload: "Contains an encoded payload",
  exfiltration: "Asks to send data elsewhere",
  invisible_characters: "Had invisible characters (removed)",
};
export const signalLabel = (s: string) => SIGNAL[s] ?? s.replaceAll("_", " ");

export const SUBJECT_LABEL: Record<AiSubjectType, string> = {
  security_event: "Security event",
  incident: "Incident",
  vulnerability: "Finding",
  threat_model: "Threat model",
};

/** Where the analysed record lives in the app. Events open on the Threats page. */
export function subjectPath(subject: AiSubjectRef): string {
  switch (subject.type) {
    case "incident":
      return `/incidents/${encodeURIComponent(subject.id)}`;
    case "vulnerability":
      return `/vulnerabilities/${encodeURIComponent(subject.id)}`;
    case "threat_model":
      return `/threat-modeling/${encodeURIComponent(subject.id)}`;
    default:
      return "/threats";
  }
}

/** Where an approved action's result can be found, from its reference. */
export function resultPath(ref: string): string {
  if (ref.startsWith("INC-")) return "/incidents";
  if (ref.startsWith("CHG-")) return "/compliance?tab=changes";
  return "/threat-modeling";
}

export const ACTION_LABEL: Record<AiProposalType, string> = {
  open_incident: "Open an incident",
  raise_change_request: "Raise a WAF change request",
  add_threat: "Add a threat to the model",
};

const str = (v: unknown) => (typeof v === "string" || typeof v === "number" ? String(v) : "");

/** What approving the action would do, in plain words. */
export function describeAction(payload: Record<string, unknown>): string {
  switch (payload.type) {
    case "open_incident":
      return `Open incident "${str(payload.title)}" (${str(payload.severity)}) with this event as evidence.`;
    case "raise_change_request":
      return `Raise a change request to set simulated WAF rule ${str(payload.rule_id)} to block. Another lead must still approve the change.`;
    case "add_threat": {
      const controls = Array.isArray(payload.controls) ? payload.controls.map(str).join(", ") : "";
      return `Add threat "${str(payload.title)}" (STRIDE ${str(payload.stride)}, likelihood ${str(payload.likelihood)} × impact ${str(payload.impact)}), mitigated by ${controls}.`;
    }
    default:
      return "Unknown action.";
  }
}

/** The AI's status, loaded once per page. */
export function useAiStatus(): AiStatus | null {
  const [status, setStatus] = useState<AiStatus | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    getAiStatus(controller.signal)
      .then(setStatus)
      .catch(() => {
        // No status means no button: the rest of the page does not depend on it.
      });
    return () => controller.abort();
  }, []);
  return status;
}

/**
 * "Analyze with AI" for one record, with its earlier analyses. Shown only when the engine is on
 * and the server says this user may run analyses.
 */
export function AnalyzePanel({ subjectType, subjectId }: { subjectType: AiSubjectType; subjectId: string }) {
  const status = useAiStatus();
  const navigate = useNavigate();
  const [earlier, setEarlier] = useState<AiAnalysisSummary[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!status?.enabled) return;
    const controller = new AbortController();
    listAnalyses({ subject_type: subjectType, subject_id: subjectId }, controller.signal)
      .then((list) => setEarlier(list.items))
      .catch(() => setEarlier([]));
    return () => controller.abort();
  }, [status?.enabled, subjectType, subjectId]);

  if (!status?.enabled) return null;

  async function analyse() {
    setBusy(true);
    setError(null);
    try {
      const analysis = await runAnalysis(subjectType, subjectId);
      void navigate(`/ai-security/analyses/${analysis.id}`);
    } catch (err) {
      setError(asApiError(err));
      setBusy(false);
    }
  }

  return (
    <section aria-label="AI analysis" className="space-y-2 rounded-md border border-line bg-surface p-4">
      <div className="flex flex-wrap items-center gap-3">
        {status.can_analyse && (
          <Button variant="secondary" busy={busy} onClick={() => void analyse()}>
            {busy ? "Analyzing…" : "Analyze with AI"}
          </Button>
        )}
        <span className="text-xs text-ink-muted">
          Advisory only: the AI explains and may propose an action; nothing happens until a lead approves it.
        </span>
      </div>
      {earlier.length > 0 && (
        <p className="text-sm">
          Earlier analyses:{" "}
          {earlier.slice(0, 5).map((a, i) => (
            <span key={a.id}>
              {i > 0 && ", "}
              <Link to={`/ai-security/analyses/${a.id}`} className="text-accent hover:underline">
                {a.reference}
              </Link>
            </span>
          ))}
        </p>
      )}
      <FormError error={error} />
    </section>
  );
}
