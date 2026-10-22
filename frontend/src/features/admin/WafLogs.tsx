import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { BarList } from "../../components/charts";
import { FormError } from "../../components/forms";
import { Section } from "../../components/page";
import { ProvenanceBadge } from "../../components/ProvenanceBadge";
import { SeverityBadge, SimulatedBanner, StatTile, categoryLabel, formatTime } from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import { listEvents } from "../../lib/api/secops";
import type { Role, SecurityEventSummary } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

// Real WAF records are security events: readable by every security operations role, viewers included.
export const WAF_LOG_READERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
// The simulator's records follow the simulator's own access.
const SIM_READERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST"];

/**
 * WAF log records, on the Audit Logs page beside the audit trail. They are security events read from
 * the WAF's log, not entries in the hash-chained audit trail; rule changes are audited there.
 */
export function WafLogs({ role }: { role: Role }) {
  return (
    <div className="space-y-6">
      <p className="max-w-prose text-sm text-ink-muted">
        What each WAF logged, newest first. These records come from the WAF's own log and are stored as security events;
        they are not part of the hash-chained audit trail. Changes to WAF rules are in the audit trail (action{" "}
        <code className="font-mono text-xs">simulator.waf_rule_changed</code>), and the rules themselves are on the{" "}
        <Link to="/waf" className="text-accent underline-offset-2 hover:underline">
          WAF page
        </Link>
        .
      </p>
      <AwsWafLog />
      {SIM_READERS.includes(role) && <SimulatedWafLog />}
    </div>
  );
}

function useWafEvents(query: Parameters<typeof listEvents>[0]) {
  const [events, setEvents] = useState<SecurityEventSummary[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const key = JSON.stringify(query);
  useEffect(() => {
    const controller = new AbortController();
    listEvents(JSON.parse(key) as Parameters<typeof listEvents>[0], controller.signal)
      .then((page) => {
        setEvents(page.items);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      });
    return () => controller.abort();
  }, [key]);
  return { events, error };
}

function AwsWafLog() {
  const { events, error } = useWafEvents({ provenance: "REAL_AWS", source: "waf", limit: 100 });
  return (
    <Section title="AWS WAF log" id="aws-waf-log" count={events?.length} meta={<ProvenanceBadge provenance="REAL_AWS" />}>
      <div className="space-y-4">
        <FormError error={error} />
        <p className="max-w-prose text-sm text-ink-muted">
          Requests AWS WAF blocked in front of CloudFront, read from its CloudWatch log during a deploy window. Outside a
          window there is no real WAF, so this log is empty.
        </p>
        <div className="overflow-x-auto rounded-md border border-line">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Requests blocked by AWS WAF</caption>
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
              {events?.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-4 text-center text-ink-muted">
                    No blocks recorded.
                  </td>
                </tr>
              )}
              {events?.map((e) => (
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
        {!!events?.length && (
          <p className="text-sm">
            <Link to="/threats" className="text-accent underline-offset-2 hover:underline">
              Investigate these on the Threats page
            </Link>{" "}
            <span className="text-ink-muted">(the Live view shows real AWS events next to the platform's own).</span>
          </p>
        )}
      </div>
    </Section>
  );
}

function SimulatedWafLog() {
  const { events, error } = useWafEvents({ view: "simulated", source: "waf", limit: 100 });
  const logs = events ?? [];
  const blocked = logs.filter((e) => e.outcome === "blocked").length;
  const counted = logs.length - blocked;
  const tally = (pick: (e: SecurityEventSummary) => string | null | undefined) => {
    const m = new Map<string, number>();
    for (const e of logs) {
      const k = pick(e);
      if (k) m.set(k, (m.get(k) ?? 0) + 1);
    }
    return [...m.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([key, value]) => ({ key, label: key, value }));
  };

  return (
    <Section title="Simulated WAF log" id="sim-waf-log" count={events?.length}>
      <div className="space-y-4">
        <SimulatedBanner>Records from the attack simulator's WAF. They never mix with real AWS data.</SimulatedBanner>
        <FormError error={error} />
        <dl className="grid grid-cols-2 gap-3 md:grid-cols-3">
          <StatTile label="Log records shown" value={logs.length} note="Most recent 100" />
          <StatTile label="Blocked" value={blocked} tone="ok" />
          <StatTile label="Counted, not blocked" value={counted} {...(counted ? { tone: "warn" as const } : {})} />
        </dl>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="space-y-2">
            <h3 className="text-sm font-medium">By rule</h3>
            <BarList
              label="Simulated WAF records by rule"
              items={tally((e) => e.rule_id)}
              empty="Run a simulation to generate WAF records."
            />
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-medium">By source address</h3>
            <BarList
              label="Simulated WAF records by source address"
              items={tally((e) => e.source_ip)}
              empty="No simulated WAF records yet."
            />
          </div>
        </div>
        {logs.length > 0 && (
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Recent simulated WAF log records</caption>
              <thead className="bg-surface text-xs text-ink-muted">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">Time</th>
                  <th scope="col" className="px-3 py-2 font-medium">Action</th>
                  <th scope="col" className="px-3 py-2 font-medium">Rule</th>
                  <th scope="col" className="px-3 py-2 font-medium">Request</th>
                  <th scope="col" className="px-3 py-2 font-medium">Source</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {logs.map((e) => (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums text-ink-muted">
                      {formatTime(e.occurred_at)}
                    </td>
                    <td className={`px-3 py-2 text-xs ${e.outcome === "blocked" ? "text-ok" : "text-prov-sim"}`}>
                      {e.outcome === "blocked" ? "BLOCK" : "COUNT"}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{e.rule_id}</td>
                    <td className="px-3 py-2 text-xs">
                      {e.method} {e.endpoint}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{e.source_ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Section>
  );
}
