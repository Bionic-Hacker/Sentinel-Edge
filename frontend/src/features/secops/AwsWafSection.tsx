import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { BarList } from "../../components/charts";
import { Button, FormError } from "../../components/forms";
import { ProvenanceBadge } from "../../components/ProvenanceBadge";
import { SeverityBadge, StatTile, categoryLabel, formatTime } from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import { getEdgeStatus, syncEdge, type EdgeStatus } from "../../lib/api/edge";
import { listEvents } from "../../lib/api/secops";
import type { SecurityEventSummary } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

/** AWS WAF as SentinelEdge reads it back: real blocks from its CloudWatch log (ADR-0029). */
export function AwsWafSection({ canSync }: { canSync: boolean }) {
  const [status, setStatus] = useState<EdgeStatus | null>(null);
  const [blocks, setBlocks] = useState<SecurityEventSummary[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      getEdgeStatus(controller.signal),
      listEvents({ provenance: "REAL_AWS", source: "waf", limit: 25 }, controller.signal),
    ])
      .then(([s, page]) => {
        setStatus(s);
        setBlocks(page.items);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      });
    return () => controller.abort();
  }, [version]);

  async function sync() {
    setSyncing(true);
    setError(null);
    try {
      await syncEdge();
      setVersion((v) => v + 1);
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setSyncing(false);
    }
  }

  return (
    <section aria-labelledby="aws-waf" className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <h2 id="aws-waf" className="text-lg font-semibold">
          AWS WAF on CloudFront
        </h2>
        <ProvenanceBadge provenance="REAL_AWS" />
      </div>
      <FormError error={error} />
      {status && !status.waf_logs_enabled && (
        <p className="max-w-prose text-sm text-ink-muted">
          AWS WAF runs only in the AWS deploy window, in front of CloudFront. This environment reads no WAF log, so there
          are no real blocks to show here; the simulated WAF below works everywhere.
        </p>
      )}
      {status?.waf_logs_enabled && (
        <>
          <p className="max-w-prose text-sm text-ink-muted">
            Every request AWS WAF blocks is read from its log{" "}
            <code className="font-mono text-xs">{status.waf_log_group}</code> every{" "}
            {Math.round(status.sync_interval_seconds / 60)} minutes and stored as a real security event, so it appears on the
            Threats page and goes through correlation. Rules change only through Terraform.
          </p>
          <dl className="grid gap-3 sm:grid-cols-3">
            <StatTile label="Blocked, last 24 h" value={status.waf_blocks_24h} />
            <StatTile label="Rules that blocked" value={status.waf_blocks_by_rule.length} />
            <StatTile
              label="Last sync"
              value={status.last_sync?.finished_at ? formatTime(status.last_sync.finished_at) : "Not yet"}
              note={status.last_sync?.errors.length ? status.last_sync.errors.join("; ") : undefined}
              tone={status.last_sync?.errors.length ? "fail" : undefined}
            />
          </dl>
          {canSync && (
            <Button variant="secondary" busy={syncing} onClick={() => void sync()}>
              Sync now
            </Button>
          )}
          {status.waf_blocks_by_rule.length > 0 && (
            <div className="max-w-xl">
              <h3 className="mb-2 text-sm font-medium">Blocks by rule, last 24 h</h3>
              <BarList
                label="AWS WAF blocks by rule, last 24 hours"
                items={status.waf_blocks_by_rule.map((r) => ({ key: r.rule, label: r.rule, value: r.count }))}
              />
            </div>
          )}
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Recent requests blocked by AWS WAF</caption>
              <thead className="bg-surface text-xs text-ink-muted">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">Time</th>
                  <th scope="col" className="px-3 py-2 font-medium">Blocked</th>
                  <th scope="col" className="px-3 py-2 font-medium">Severity</th>
                  <th scope="col" className="px-3 py-2 font-medium">Source</th>
                  <th scope="col" className="px-3 py-2 font-medium">Request</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {blocks.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-3 py-4 text-center text-ink-muted">
                      No blocks recorded yet.
                    </td>
                  </tr>
                )}
                {blocks.map((e) => (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-muted">{formatTime(e.occurred_at)}</td>
                    <td className="px-3 py-2">
                      <span className="text-ink">{e.title}</span>
                      <span className="block text-xs text-ink-muted">{categoryLabel(e.category)}</span>
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={e.severity} />
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{e.source_ip ?? "—"}</td>
                    <td className="max-w-xs truncate px-3 py-2 font-mono text-xs" title={e.endpoint ?? ""}>
                      {e.method} {e.endpoint}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-sm">
            <Link to="/threats" className="text-accent underline-offset-2 hover:underline">
              Investigate these on the Threats page
            </Link>{" "}
            <span className="text-ink-muted">(the Live view shows real AWS events next to the platform's own).</span>
          </p>
        </>
      )}
    </section>
  );
}
