import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useCapabilities } from "../../app/capabilities-context";
import { useCurrentUser } from "../../app/auth-context";
import { MODULES } from "../../app/modules";
import { CapabilityTable } from "../../components/CapabilityTable";
import { Button, FormError } from "../../components/forms";
import { SeverityBadge, SimulatedBanner, formatTime } from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import { listRuns, listScenarios, runScenario } from "../../lib/api/secops";
import type { Role, Scenario, SimulationRun } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

const VIEWERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const OPERATORS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER"];
const MODULE = MODULES.find((m) => m.path === "/automation");

export function AutomationPage() {
  const user = useCurrentUser();
  return (
    <div className="max-w-7xl space-y-8">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Automation</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          The attack simulator runs labelled attack scenarios against SentinelEdge itself. Security automation tools and
          interview demo scenarios follow in Phases 11 and 12.
        </p>
      </header>
      {VIEWERS.includes(user.role) ? (
        <Simulator canRun={OPERATORS.includes(user.role)} />
      ) : (
        <p className="max-w-prose text-ink-muted">The attack simulator is available to administrators, security engineers and analysts.</p>
      )}
      <ModuleCapabilities />
    </div>
  );
}

function Simulator({ canRun }: { canRun: boolean }) {
  const [scenarios, setScenarios] = useState<Scenario[] | null>(null);
  const [runs, setRuns] = useState<SimulationRun[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [latest, setLatest] = useState<SimulationRun | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([listScenarios(controller.signal), listRuns(controller.signal)])
      .then(([s, r]) => {
        setScenarios(s);
        setRuns(r);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      });
    return () => controller.abort();
  }, []);

  async function run(scenario: string) {
    setRunning(scenario);
    setError(null);
    try {
      const result = await runScenario(scenario);
      setLatest(result);
      setRuns((current) => [result, ...current].slice(0, 25));
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setRunning(null);
    }
  }

  const names = new Map(scenarios?.map((s) => [s.scenario, s.name]) ?? []);

  return (
    <section aria-labelledby="simulator-heading" className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <h2 id="simulator-heading" className="text-lg font-semibold">
          Attack simulator
        </h2>
        <div className="flex gap-4 text-sm">
          <Link to="/?view=simulated" className="text-accent hover:underline">
            Dashboard, simulated view
          </Link>
          <Link to="/waf" className="text-accent hover:underline">
            Simulated WAF rules
          </Link>
        </div>
      </div>
      <SimulatedBanner>
        Scenarios send no network traffic and take no target: they build synthetic requests in memory and run them through
        SentinelEdge's real detection rules, a simulated WAF and the correlation engine. Addresses come from the IETF
        documentation ranges and names from the reserved .example domain. Everything produced is labelled simulated and
        never mixes with live data.
      </SimulatedBanner>
      {!canRun && <p className="text-sm text-ink-muted">Security engineers and administrators run simulations; you can review their results.</p>}
      {error && <FormError error={error} />}
      {latest && <RunResult run={latest} name={names.get(latest.scenario) ?? latest.scenario} />}
      {!scenarios && !error && <p className="text-sm text-ink-muted">Loading scenarios…</p>}
      {scenarios && (
        <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {scenarios.map((s) => (
            <li key={s.scenario} className="flex flex-col justify-between gap-3 rounded-md border border-line bg-surface p-4">
              <div>
                <h3 className="text-sm font-semibold">{s.name}</h3>
                <p className="mt-1 text-sm text-ink-muted">{s.description}</p>
                <p className="mt-2 text-xs text-ink-muted">
                  <span className="font-medium text-ink">Demonstrates:</span> {s.demonstrates}
                </p>
              </div>
              {canRun && (
                <Button
                  variant="secondary"
                  busy={running === s.scenario}
                  disabled={running !== null && running !== s.scenario}
                  onClick={() => void run(s.scenario)}
                >
                  Run simulation
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      <section aria-labelledby="runs-heading" className="space-y-3">
        <h3 id="runs-heading" className="text-base font-semibold">
          Recent runs
        </h3>
        {runs.length ? (
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Recent simulation runs</caption>
              <thead className="bg-surface text-xs text-ink-muted">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">Run</th>
                  <th scope="col" className="px-3 py-2 font-medium">Scenario</th>
                  <th scope="col" className="px-3 py-2 font-medium">Events</th>
                  <th scope="col" className="px-3 py-2 font-medium">Detections</th>
                  <th scope="col" className="px-3 py-2 font-medium">Incidents</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {runs.map((r) => (
                  <tr key={r.id}>
                    <td className="px-3 py-2">
                      <span className="font-mono text-xs">{r.reference}</span>
                      <span className="block text-xs text-ink-muted">
                        {r.started_by_label}, {formatTime(r.started_at)}
                      </span>
                    </td>
                    <td className="px-3 py-2">{names.get(r.scenario) ?? r.scenario}</td>
                    <td className="px-3 py-2 tabular-nums">{r.summary.events ?? 0}</td>
                    <td className="px-3 py-2 tabular-nums">{r.summary.detections?.length ?? 0}</td>
                    <td className="px-3 py-2">
                      {r.summary.incidents?.length
                        ? r.summary.incidents.map((i) => (
                            <Link key={i.id} to={`/incidents/${i.id}`} className="mr-2 font-mono text-xs text-accent hover:underline">
                              {i.reference}
                            </Link>
                          ))
                        : "–"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-ink-muted">No simulations have been run yet.</p>
        )}
      </section>
    </section>
  );
}

function RunResult({ run, name }: { run: SimulationRun; name: string }) {
  const requests = run.summary.requests ?? {};
  return (
    <section aria-labelledby="run-result" role="status" className="space-y-3 rounded-md border border-prov-sim/50 bg-surface p-5">
      <h3 id="run-result" className="text-base font-semibold">
        {run.reference}: {name}
      </h3>
      <p className="text-sm text-ink-muted">
        {requests.total ? `${requests.total} simulated requests: ${requests.blocked_by_waf ?? 0} blocked at the edge, ` +
          `${requests.counted_by_waf ?? 0} counted, ${requests.reached_app ?? 0} reached the application, ${requests.benign ?? 0} benign. ` : ""}
        {run.summary.events ?? 0} events recorded.
      </p>
      {run.summary.detections?.length ? (
        <ul className="space-y-1 text-sm">
          {run.summary.detections.map((d) => (
            <li key={`${d.rule_id}-${d.title}`} className="flex items-center gap-2">
              <SeverityBadge severity={d.severity} />
              <span className="font-mono text-xs">{d.rule_id}</span>
              <span>{d.title}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-ink-muted">No correlation rule fired.</p>
      )}
      {run.summary.incidents?.length ? (
        <p className="text-sm">
          Incidents:{" "}
          {run.summary.incidents.map((i) => (
            <Link key={i.id} to={`/incidents/${i.id}`} className="mr-3 text-accent hover:underline">
              {i.reference} {i.opened ? "(opened)" : "(updated)"}
            </Link>
          ))}
        </p>
      ) : (
        <p className="text-sm text-ink-muted">No incident was opened: nothing met the incident policy.</p>
      )}
    </section>
  );
}

function ModuleCapabilities() {
  const caps = useCapabilities();
  if (!MODULE || caps.state !== "ready") return null;
  const items = caps.data.filter((c) => MODULE.capabilityKeys.includes(c.key));
  if (!items.length) return null;
  return (
    <section aria-labelledby="automation-caps" className="space-y-3">
      <h2 id="automation-caps" className="text-lg font-semibold">
        Capabilities
      </h2>
      <CapabilityTable caption="Automation capabilities" items={items} />
    </section>
  );
}
