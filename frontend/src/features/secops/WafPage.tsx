import { useEffect, useState } from "react";
import { useCapabilities } from "../../app/capabilities-context";
import { useCurrentUser } from "../../app/auth-context";
import { MODULES } from "../../app/modules";
import { BarList } from "../../components/charts";
import { CapabilityTable } from "../../components/CapabilityTable";
import { FormError } from "../../components/forms";
import { SeverityBadge, SimulatedBanner, StatTile, categoryLabel, formatTime } from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import { listEvents, listWafRules, setWafRuleMode } from "../../lib/api/secops";
import { WAF_MODES, type Role, type SecurityEventSummary, type WafMode, type WafRuleList } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

const VIEWERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const OPERATORS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER"];
const MODULE = MODULES.find((m) => m.path === "/waf");
const MODE_LABEL: Record<WafMode, string> = { block: "Block", count: "Count only", off: "Off" };

export function WafPage() {
  const user = useCurrentUser();
  return (
    <div className="max-w-7xl space-y-8">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">WAF</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          AWS WAF on CloudFront arrives in Phase 5, with rules changed only through reviewed Terraform pull requests. Until
          then, a simulated WAF runs inside the attack simulator, using SentinelEdge's own detection rules.
        </p>
      </header>
      {VIEWERS.includes(user.role) ? (
        <SimulatedWaf canChange={OPERATORS.includes(user.role)} />
      ) : (
        <p className="max-w-prose text-ink-muted">
          The simulated WAF is available to administrators, security engineers and analysts.
        </p>
      )}
      <ModuleCapabilities />
    </div>
  );
}

function SimulatedWaf({ canChange }: { canChange: boolean }) {
  const [rules, setRules] = useState<WafRuleList | null>(null);
  const [logs, setLogs] = useState<SecurityEventSummary[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [saving, setSaving] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      listWafRules(controller.signal),
      listEvents({ view: "simulated", source: "waf", limit: 100 }, controller.signal),
    ])
      .then(([r, page]) => {
        setRules(r);
        setLogs(page.items);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      });
    return () => controller.abort();
  }, []);

  async function change(ruleId: string, mode: WafMode) {
    setSaving(ruleId);
    setError(null);
    try {
      await setWafRuleMode(ruleId, mode);
      setRules((current) =>
        current ? { ...current, items: current.items.map((r) => (r.rule_id === ruleId ? { ...r, mode } : r)) } : current,
      );
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setSaving(null);
    }
  }

  const blocked = logs.filter((e) => e.outcome === "blocked").length;
  const counted = logs.length - blocked;
  const byRule = new Map<string, number>();
  const bySource = new Map<string, number>();
  for (const e of logs) {
    if (e.rule_id) byRule.set(e.rule_id, (byRule.get(e.rule_id) ?? 0) + 1);
  }
  // Countries come from the WAF log record (evidence), which the list view does not carry; the
  // dashboard's simulated view shows them. Here we count by source address instead.
  for (const e of logs) {
    if (e.source_ip) bySource.set(e.source_ip, (bySource.get(e.source_ip) ?? 0) + 1);
  }
  const sorted = (m: Map<string, number>) =>
    [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([key, value]) => ({ key, label: key, value }));

  return (
    <section aria-labelledby="sim-waf" className="space-y-6">
      <h2 id="sim-waf" className="text-lg font-semibold">
        Simulated WAF
      </h2>
      <SimulatedBanner>
        {rules?.note ??
          "Changing a rule here affects simulations only. Real AWS WAF rules change through Terraform (ADR-0008, Phase 5)."}
      </SimulatedBanner>
      {error && <FormError error={error} />}
      {rules && (
        <>
          <p className="text-sm text-ink-muted">
            Web ACL <code className="font-mono text-xs">{rules.web_acl}</code>. A rule in block mode stops a matching request
            at the edge; in count mode it is logged and the request continues to SentinelEdge, where the application's own
            detection records it too. Run a simulation after a change to see the difference.
          </p>
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Simulated WAF rules and their modes</caption>
              <thead className="bg-surface text-xs text-ink-muted">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">Rule</th>
                  <th scope="col" className="px-3 py-2 font-medium">Severity</th>
                  <th scope="col" className="px-3 py-2 font-medium">Comparable AWS managed group</th>
                  <th scope="col" className="px-3 py-2 font-medium">Matches (24 h)</th>
                  <th scope="col" className="px-3 py-2 font-medium">Mode</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rules.items.map((r) => (
                  <tr key={r.rule_id}>
                    <td className="px-3 py-2">
                      <span className="font-mono text-xs">{r.rule_id}</span> {r.description}
                      <span className="block text-xs text-ink-muted">{categoryLabel(r.category)}</span>
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={r.severity} />
                    </td>
                    <td className="px-3 py-2 text-xs text-ink-muted">{r.comparable_group}</td>
                    <td className="px-3 py-2 tabular-nums">{r.matches_24h}</td>
                    <td className="px-3 py-2">
                      {canChange ? (
                        <label>
                          <span className="sr-only">Mode for {r.rule_id}</span>
                          <select
                            value={r.mode}
                            disabled={saving === r.rule_id}
                            onChange={(e) => void change(r.rule_id, e.target.value as WafMode)}
                            className="rounded border border-line bg-canvas px-2 py-1 text-sm"
                          >
                            {WAF_MODES.map((m) => (
                              <option key={m} value={m}>
                                {MODE_LABEL[m]}
                              </option>
                            ))}
                          </select>
                        </label>
                      ) : (
                        MODE_LABEL[r.mode]
                      )}
                      {r.updated_by_label && r.updated_at && (
                        <span className="block text-xs text-ink-muted">
                          {r.updated_by_label}, {formatTime(r.updated_at)}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <section aria-labelledby="waf-events" className="space-y-4">
        <h3 id="waf-events" className="text-base font-semibold">
          Simulated WAF events
        </h3>
        <dl className="grid grid-cols-2 gap-3 md:grid-cols-3">
          <StatTile label="Log records shown" value={logs.length} note="Most recent 100" />
          <StatTile label="Blocked" value={blocked} tone="ok" />
          <StatTile label="Counted, not blocked" value={counted} {...(counted ? { tone: "warn" as const } : {})} />
        </dl>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="space-y-2">
            <h4 className="text-sm font-medium">By rule</h4>
            <BarList label="Simulated WAF events by rule" items={sorted(byRule)} empty="Run a simulation to generate WAF events." />
          </div>
          <div className="space-y-2">
            <h4 className="text-sm font-medium">By source address</h4>
            <BarList label="Simulated WAF events by source address" items={sorted(bySource)} empty="No simulated WAF events yet." />
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
                {logs.slice(0, 25).map((e) => (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums text-ink-muted">{formatTime(e.occurred_at)}</td>
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
      </section>
    </section>
  );
}

function ModuleCapabilities() {
  const caps = useCapabilities();
  if (!MODULE || caps.state !== "ready") return null;
  const items = caps.data.filter((c) => MODULE.capabilityKeys.includes(c.key));
  if (!items.length) return null;
  return (
    <section aria-labelledby="waf-caps" className="space-y-3">
      <h2 id="waf-caps" className="text-lg font-semibold">
        Capabilities
      </h2>
      <CapabilityTable caption="WAF capabilities: real AWS and simulated" items={items} />
    </section>
  );
}
