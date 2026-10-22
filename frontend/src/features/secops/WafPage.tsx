import { PageHeader, Section } from "../../components/page";
import { useEffect, useState } from "react";
import { useCapabilities } from "../../app/capabilities-context";
import { useCurrentUser } from "../../app/auth-context";
import { MODULES } from "../../app/modules";
import { Link } from "react-router-dom";
import { CapabilityTable } from "../../components/CapabilityTable";
import { FormError } from "../../components/forms";
import { SeverityBadge, SimulatedBanner, categoryLabel, formatTime } from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import { listWafRules, setWafRuleMode } from "../../lib/api/secops";
import { WAF_MODES, type Role, type WafMode, type WafRuleList } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";
import { AwsWafSection } from "./AwsWafSection";

const VIEWERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST"];
// Real security events are readable by every security operations role, viewers included.
const READERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const OPERATORS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER"];
const MODULE = MODULES.find((m) => m.path === "/waf");
const MODE_LABEL: Record<WafMode, string> = { block: "Block", count: "Count only", off: "Off" };

export function WafPage() {
  const user = useCurrentUser();
  return (
    <div className="max-w-7xl space-y-8">
      <PageHeader
        title="WAF"
        summary="AWS WAF at the edge and the simulator's WAF rules. Their log records are in Audit Logs."
        about={
          <p>
            AWS WAF protects the platform on CloudFront, with rules changed only through reviewed Terraform pull requests; what it blocks is read back here. A simulated WAF runs inside the attack simulator everywhere, using SentinelEdge's own detection rules.
          </p>
        }
      />
      {READERS.includes(user.role) && <AwsWafSection canSync={OPERATORS.includes(user.role)} />}
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
  const [error, setError] = useState<ApiError | null>(null);
  const [saving, setSaving] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    listWafRules(controller.signal)
      .then((r) => {
        setRules(r);
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

  return (
    <Section title="Simulated WAF rules" id="sim-waf">
      <SimulatedBanner>
        {rules?.note ??
          "Changing a rule here affects simulations only. Real AWS WAF rules change through Terraform (ADR-0008)."}
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

      <p className="text-sm">
        <Link to="/audit-logs?tab=waf" className="text-accent underline-offset-2 hover:underline">
          Read what these rules logged in Audit Logs, WAF logs
        </Link>
      </p>
    </Section>
  );
}

function ModuleCapabilities() {
  const caps = useCapabilities();
  if (!MODULE || caps.state !== "ready") return null;
  const items = caps.data.filter((c) => MODULE.capabilityKeys.includes(c.key));
  if (!items.length) return null;
  return (
    <section className="space-y-3">
      <CapabilityTable caption="WAF capabilities: real AWS and simulated" items={items} />
    </section>
  );
}
