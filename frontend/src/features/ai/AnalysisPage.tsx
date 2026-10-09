import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { FormError } from "../../components/forms";
import { ProvenanceBadge } from "../../components/ProvenanceBadge";
import { SeverityBadge, formatTime } from "../../components/secops";
import { getAnalysis } from "../../lib/api/ai";
import type { ApiError } from "../../lib/api/client";
import type { AiAnalysisDetail, AiProposal } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";
import { Fact } from "../governance/governance";
import {
  AnalysisStatusBadge,
  PromptRiskBadge,
  SUBJECT_LABEL,
  classificationLabel,
  signalLabel,
  subjectPath,
} from "./ai";
import { ProposalCard } from "./ProposalCard";

const number = new Intl.NumberFormat("en-US");

export function AnalysisPage() {
  const { analysisId = "" } = useParams();
  const [analysis, setAnalysis] = useState<AiAnalysisDetail | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    getAnalysis(analysisId, controller.signal)
      .then(setAnalysis)
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      });
    return () => controller.abort();
  }, [analysisId]);

  if (error) return <FormError error={error} />;
  if (!analysis) return <p className="text-sm text-ink-muted">Loading the analysis…</p>;
  const a = analysis;
  const out = a.output;

  function decided(updated: AiProposal) {
    setAnalysis((current) =>
      current
        ? { ...current, proposal_items: current.proposal_items.map((p) => (p.id === updated.id ? updated : p)) }
        : current,
    );
  }

  return (
    <div className="max-w-5xl space-y-6">
      <nav aria-label="Breadcrumb" className="text-sm">
        <Link to="/ai-security" className="text-accent hover:underline">
          AI Security
        </Link>{" "}
        <span className="text-ink-muted">/ {a.reference}</span>
      </nav>

      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <AnalysisStatusBadge status={a.status} />
          <ProvenanceBadge provenance={a.provenance} />
          <PromptRiskBadge level={a.risk_level} score={a.prompt_risk} />
        </div>
        <h1 className="break-words text-2xl font-semibold tracking-tight">
          {a.reference}: analysis of{" "}
          <Link to={subjectPath(a.subject)} className="text-accent hover:underline">
            {a.subject.reference}
          </Link>
        </h1>
        <p className="text-sm text-ink-muted">
          {SUBJECT_LABEL[a.subject.type]}
          {a.application ? ` · ${a.application.name}` : ""}
        </p>
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Fact label="Model">
            <code className="font-mono text-xs">{a.model}</code> ({a.provider})
          </Fact>
          <Fact label="Requested">
            {a.requested_by_label}, {formatTime(a.created_at)}
          </Fact>
          <Fact label="Tokens">
            {number.format(a.input_tokens)} in, {number.format(a.output_tokens)} out, {number.format(a.duration_ms)} ms
          </Fact>
          <Fact label="Input fingerprint">
            <code className="break-all font-mono text-xs" title={a.input_sha256}>
              {a.input_sha256.slice(0, 16)}…
            </code>
          </Fact>
        </dl>
      </header>

      {a.risk_signals.length > 0 && (
        <section
          aria-labelledby="risk-heading"
          className={`space-y-1 rounded-md border px-4 py-3 text-sm ${a.risk_level === "high" ? "border-fail/50 bg-fail/10" : "border-line bg-surface"}`}
        >
          <h2 id="risk-heading" className="font-medium">
            The data sent contained prompt-injection signals
          </h2>
          <ul className="list-inside list-disc text-ink-muted">
            {a.risk_signals.map((s) => (
              <li key={s}>{signalLabel(s)}</li>
            ))}
          </ul>
          <p className="text-ink-muted">
            It was sent as delimited data, never as instructions.
            {a.risk_level === "high" && " Approving anything this analysis proposes needs a written reason."}
          </p>
        </section>
      )}

      {!out && (
        <section role="alert" className="space-y-1 rounded-md border border-fail/50 bg-fail/10 px-4 py-3 text-sm">
          <h2 className="font-medium">
            {a.status === "rejected"
              ? "The answer broke the output contract and was rejected. Nothing from it was used."
              : "The AI provider did not answer."}
          </h2>
          {a.failure && <p className="whitespace-pre-wrap break-words">{a.failure}</p>}
        </section>
      )}

      {out && (
        <>
          <section aria-labelledby="summary-heading" className="space-y-2">
            <h2 id="summary-heading" className="text-base font-semibold">
              Summary
            </h2>
            <p className="whitespace-pre-wrap break-words">{out.summary}</p>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span>{classificationLabel(out.classification)}</span>
              <SeverityBadge severity={out.severity} />
              <span className="text-ink-muted">Confidence {Math.round(out.confidence * 100)}%</span>
            </div>
          </section>

          {a.disagreements.length > 0 && (
            <section role="note" className="space-y-1 rounded-md border border-prov-sim/60 px-4 py-3 text-sm">
              <h2 className="font-medium">The AI disagrees with the platform</h2>
              <ul className="list-inside list-disc text-ink-muted">
                {a.disagreements.map((d) => (
                  <li key={d}>{d}</li>
                ))}
              </ul>
              <p className="text-ink-muted">Shown for review only: the platform's own verdict is unchanged.</p>
            </section>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            <section aria-labelledby="evidence-heading" className="space-y-2 rounded-md border border-line bg-surface p-4">
              <h2 id="evidence-heading" className="text-base font-semibold">
                Observed evidence
              </h2>
              <p className="text-xs text-ink-muted">
                Verbatim quotes from the data sent, each checked against it. Attacker-written text is shown as text.
              </p>
              <ul className="space-y-2">
                {out.observed_evidence.map((e, i) => (
                  <li key={`${e.field}-${i}`} className="text-sm">
                    <span className="font-mono text-xs text-ink-muted">{e.field}</span>
                    <code className="mt-0.5 block whitespace-pre-wrap break-all rounded bg-canvas px-2 py-1 font-mono text-xs">
                      {e.quote}
                    </code>
                  </li>
                ))}
              </ul>
            </section>
            <section aria-labelledby="inference-heading" className="space-y-2 rounded-md border border-line bg-surface p-4">
              <h2 id="inference-heading" className="text-base font-semibold">
                Inference
              </h2>
              <p className="text-xs text-ink-muted">The model's interpretation: not a fact, not verified.</p>
              <p className="whitespace-pre-wrap break-words text-sm">{out.inference}</p>
            </section>
          </div>

          {out.recommendations.length > 0 && (
            <section aria-labelledby="recs-heading" className="space-y-2">
              <h2 id="recs-heading" className="text-base font-semibold">
                Recommendations
              </h2>
              <ul className="space-y-2">
                {out.recommendations.map((r, i) => (
                  <li key={i} className="text-sm">
                    <span className="whitespace-pre-wrap break-words">{r.text}</span>
                    {r.controls.length > 0 && (
                      <span className="ml-2 inline-flex flex-wrap gap-1">
                        {r.controls.map((c) => (
                          <code key={c} className="rounded border border-line px-1 font-mono text-xs">
                            {c}
                          </code>
                        ))}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}
        </>
      )}

      {a.proposal_items.length > 0 && (
        <section aria-labelledby="proposals-heading" className="space-y-3">
          <h2 id="proposals-heading" className="text-base font-semibold">
            Proposed actions
          </h2>
          <p className="text-sm text-ink-muted">
            The AI cannot act. A proposal runs only when an admin or security engineer approves it, as that person, through
            the normal workflow.
          </p>
          {a.proposal_items.map((p) => (
            <ProposalCard key={p.id} proposal={p} onDecided={decided} />
          ))}
        </section>
      )}
    </div>
  );
}
