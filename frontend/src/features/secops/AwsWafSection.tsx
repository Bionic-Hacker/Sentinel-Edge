import { Section } from "../../components/page";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { BarList } from "../../components/charts";
import { Button, FormError } from "../../components/forms";
import { ProvenanceBadge } from "../../components/ProvenanceBadge";
import { StatTile, formatTime } from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import { getEdgeStatus, syncEdge, type EdgeStatus } from "../../lib/api/edge";
import { asApiError } from "../auth/LoginPage";

/** AWS WAF as SentinelEdge reads it back: real blocks from its CloudWatch log (ADR-0029). */
export function AwsWafSection({ canSync }: { canSync: boolean }) {
  const [status, setStatus] = useState<EdgeStatus | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    getEdgeStatus(controller.signal)
      .then(setStatus)
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
    <Section title="AWS WAF on CloudFront" id="aws-waf" meta={<ProvenanceBadge provenance="REAL_AWS" />}>
      <div className="space-y-5">
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
            {Math.round(status.sync_interval_seconds / 60)} minutes and stored as a real security event, so it appears in the
            WAF logs and on the Threats page and goes through correlation. Rules change only through Terraform.
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
          <p className="text-sm">
            <Link to="/audit-logs?tab=waf" className="text-accent underline-offset-2 hover:underline">
              Read the blocked requests in Audit Logs, WAF logs
            </Link>{" "}
            <span className="text-ink-muted">or investigate them on the Threats page.</span>
          </p>
        </>
      )}
      </div>
    </Section>
  );
}
