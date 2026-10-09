import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { FormError } from "../../components/forms";
import { ProvenanceBadge } from "../../components/ProvenanceBadge";
import { formatTime, StatTile } from "../../components/secops";
import { listAnalyses, listProposals } from "../../lib/api/ai";
import type { ApiError } from "../../lib/api/client";
import type { AiAnalysisSummary, AiProposal, AiProposalList } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";
import {
  AnalysisStatusBadge,
  PromptRiskBadge,
  SUBJECT_LABEL,
  classificationLabel,
  subjectPath,
  useAiStatus,
} from "./ai";
import { ProposalCard } from "./ProposalCard";

const number = new Intl.NumberFormat("en-US");

export function AiSecurityPage() {
  const status = useAiStatus();
  const [analyses, setAnalyses] = useState<AiAnalysisSummary[] | null>(null);
  const [proposals, setProposals] = useState<AiProposalList | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([listAnalyses({}, controller.signal), listProposals("proposed", controller.signal)])
      .then(([a, p]) => {
        setAnalyses(a.items);
        setProposals(p);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      });
    return () => controller.abort();
  }, []);

  const decided = useCallback((updated: AiProposal) => {
    setProposals((current) =>
      current
        ? {
            items: current.items.map((p) => (p.id === updated.id ? updated : p)),
            counts: {
              ...current.counts,
              proposed: current.counts.proposed - 1,
              [updated.status]: current.counts[updated.status] + 1,
            },
          }
        : current,
    );
  }, []);

  return (
    <div className="max-w-6xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">AI Security</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          The AI explains security events, incidents, findings and threat models, and may propose an action. It never acts
          on its own: an admin or security engineer approves or rejects every proposal. Attacker-controlled text is sent
          as delimited data, scored for prompt-injection signals, and every answer must quote its evidence verbatim or it
          is rejected.
        </p>
      </header>

      {status && !status.enabled && (
        <p role="status" className="rounded-md border border-line bg-surface px-4 py-3 text-sm">
          AI analysis is switched off. Set <code className="font-mono">SENTINEL_AI_PROVIDER=offline</code> for the free,
          deterministic local analyser, or <code className="font-mono">bedrock</code> for Amazon Bedrock (see{" "}
          <code className="font-mono">docs/bedrock-setup.md</code>).
        </p>
      )}
      {status?.enabled && (
        <section aria-label="Engine status" className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span>
              Provider <span className="font-medium">{status.provider}</span>, model{" "}
              <code className="font-mono">{status.model}</code>
            </span>
            {status.provenance && <ProvenanceBadge provenance={status.provenance} />}
          </div>
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatTile label="Your analyses today" value={`${status.requests_today} / ${status.requests_per_day}`} />
            <StatTile
              label="Platform tokens today"
              value={`${number.format(status.tokens_today)} / ${number.format(status.tokens_per_day)}`}
            />
            <StatTile label="Awaiting a decision" value={proposals?.counts.proposed ?? "-"} />
            <StatTile label="Approved" value={proposals?.counts.approved ?? "-"} tone="ok" />
          </dl>
          {!status.can_analyse && (
            <p className="text-sm text-ink-muted">Your role can read analyses; running them needs another role.</p>
          )}
        </section>
      )}

      <FormError error={error} />

      <section aria-labelledby="proposals-heading" className="space-y-3">
        <h2 id="proposals-heading" className="text-base font-semibold">
          Proposals awaiting a decision
        </h2>
        {proposals && proposals.items.length === 0 && <p className="text-sm text-ink-muted">Nothing is waiting.</p>}
        {proposals?.items.map((p) => (
          <ProposalCard key={p.id} proposal={p} onDecided={decided} showSource />
        ))}
      </section>

      <section aria-labelledby="analyses-heading" className="space-y-3">
        <h2 id="analyses-heading" className="text-base font-semibold">
          Recent analyses
        </h2>
        {!analyses && !error && <p className="text-sm text-ink-muted">Loading analyses…</p>}
        {analyses && analyses.length === 0 && (
          <p className="text-sm text-ink-muted">
            No analyses yet. Use <span className="font-medium">Analyze with AI</span> on an event, incident, finding or
            threat model.
          </p>
        )}
        {analyses && analyses.length > 0 && (
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full min-w-[44rem] text-left text-sm">
              <caption className="sr-only">Recent AI analyses</caption>
              <thead className="bg-surface text-xs text-ink-muted">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">Analysis</th>
                  <th scope="col" className="px-3 py-2 font-medium">Subject</th>
                  <th scope="col" className="px-3 py-2 font-medium">Result</th>
                  <th scope="col" className="px-3 py-2 font-medium">Input</th>
                  <th scope="col" className="px-3 py-2 text-right font-medium">Proposals</th>
                  <th scope="col" className="px-3 py-2 font-medium">When</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {analyses.map((a) => (
                  <tr key={a.id}>
                    <td className="px-3 py-2">
                      <Link to={`/ai-security/analyses/${a.id}`} className="font-mono text-accent hover:underline">
                        {a.reference}
                      </Link>
                      <span className="block text-xs text-ink-muted">{a.model}</span>
                    </td>
                    <td className="px-3 py-2">
                      <Link to={subjectPath(a.subject)} className="hover:underline">
                        {a.subject.reference}
                      </Link>
                      <span className="block text-xs text-ink-muted">
                        {SUBJECT_LABEL[a.subject.type]}
                        {a.provenance === "SIMULATED" ? " · simulated" : ""}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <AnalysisStatusBadge status={a.status} />
                      {a.classification && (
                        <span className="block text-xs text-ink-muted">
                          {classificationLabel(a.classification)}
                          {a.severity ? `, ${a.severity}` : ""}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <PromptRiskBadge level={a.risk_level} score={a.prompt_risk} />
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums">{a.proposals}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums text-ink-muted">
                      {formatTime(a.created_at)}
                      <span className="block">{a.requested_by_label}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
