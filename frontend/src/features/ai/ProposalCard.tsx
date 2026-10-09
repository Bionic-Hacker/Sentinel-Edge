import { useId, useState } from "react";
import { Link } from "react-router-dom";
import { Button, FormError } from "../../components/forms";
import { formatTime } from "../../components/secops";
import { decideProposal } from "../../lib/api/ai";
import type { ApiError } from "../../lib/api/client";
import type { AiProposal } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";
import { textArea } from "../governance/governance";
import { ACTION_LABEL, ProposalStatusBadge, describeAction, resultPath, subjectPath } from "./ai";

const NOTE_MIN = 10;

/**
 * One action the AI proposed. Approving runs it through the normal workflow as the approving
 * lead; rejecting records why. The AI's rationale is its own text, shown as text.
 */
export function ProposalCard({
  proposal: p,
  onDecided,
  showSource = false,
}: {
  proposal: AiProposal;
  onDecided: (updated: AiProposal) => void;
  showSource?: boolean;
}) {
  const noteId = useId();
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  async function decide(decision: "approve" | "reject") {
    const needsNote = decision === "reject" || p.note_required;
    if (needsNote && note.trim().length < NOTE_MIN) {
      setProblem(
        decision === "reject"
          ? `Say why you reject it (at least ${NOTE_MIN} characters).`
          : `This proposal comes from a high-risk input: say why you approve it (at least ${NOTE_MIN} characters).`,
      );
      return;
    }
    setProblem(null);
    setError(null);
    setBusy(decision);
    try {
      const trimmed = note.trim();
      onDecided(await decideProposal(p.id, { version: p.version, decision, ...(trimmed ? { note: trimmed } : {}) }));
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <article aria-label={`${p.reference}: ${ACTION_LABEL[p.action_type]}`} className="space-y-3 rounded-md border border-line bg-surface p-4">
      <header className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm">{p.reference}</span>
        <span className="font-medium">{ACTION_LABEL[p.action_type]}</span>
        <ProposalStatusBadge status={p.status} />
        {showSource && (
          <span className="text-xs text-ink-muted">
            from{" "}
            <Link to={`/ai-security/analyses/${p.analysis_id}`} className="text-accent hover:underline">
              {p.analysis_reference}
            </Link>{" "}
            on{" "}
            <Link to={subjectPath(p.subject)} className="text-accent hover:underline">
              {p.subject.reference}
            </Link>
          </span>
        )}
      </header>
      <p className="text-sm">{describeAction(p.payload)}</p>
      <div className="text-sm">
        <span className="text-xs text-ink-muted">The AI's reasoning (its own words, not verified)</span>
        <p className="mt-0.5 whitespace-pre-wrap break-words">{p.rationale}</p>
      </div>
      {p.note_required && p.status === "proposed" && (
        <p className="rounded border border-fail/50 bg-fail/10 px-3 py-2 text-sm">
          The input behind this proposal scored {p.input_risk} for prompt-injection signals. Check the evidence before
          approving: approval needs a written reason.
        </p>
      )}

      {p.status !== "proposed" ? (
        <p className="text-sm text-ink-muted">
          {p.status === "approved" ? "Approved" : "Rejected"} by {p.decided_by_label}
          {p.decided_at ? `, ${formatTime(p.decided_at)}` : ""}
          {p.result_ref && (
            <>
              {" "}
              · created{" "}
              <Link to={resultPath(p.result_ref)} className="text-accent hover:underline">
                {p.result_ref}
              </Link>
            </>
          )}
          {p.decision_note && <span className="mt-1 block whitespace-pre-wrap break-words text-ink">{p.decision_note}</span>}
        </p>
      ) : p.can_decide ? (
        <div className="space-y-2">
          <label htmlFor={noteId} className="block text-xs text-ink-muted">
            {p.note_required ? "Reason (required)" : "Reason (required to reject)"}
          </label>
          <textarea
            id={noteId}
            rows={2}
            maxLength={2000}
            className={textArea}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
          {problem && (
            <p role="alert" className="text-sm text-fail">
              {problem}
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <Button busy={busy === "approve"} disabled={busy !== null} onClick={() => void decide("approve")}>
              Approve and run
            </Button>
            <Button variant="secondary" busy={busy === "reject"} disabled={busy !== null} onClick={() => void decide("reject")}>
              Reject
            </Button>
          </div>
          <FormError error={error} />
        </div>
      ) : (
        <p className="text-sm text-ink-muted">Awaiting a decision by an admin or security engineer.</p>
      )}
    </article>
  );
}
