import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useCapabilities } from "../app/capabilities-context";
import { useCurrentUser } from "../app/auth-context";
import { BarList, ColumnChart, type ColumnPoint } from "../components/charts";
import { CapabilityTable } from "../components/CapabilityTable";
import { Button, FormError } from "../components/forms";
import { PROVENANCE_ORDER, ProvenanceBadge, provenanceDescription } from "../components/ProvenanceBadge";
import {
  IncidentStatusBadge,
  SeverityBadge,
  SimulatedBanner,
  StatTile,
  ViewToggle,
  categoryLabel,
  formatTime,
} from "../components/secops";
import type { ApiError } from "../lib/api/client";
import { getOverview } from "../lib/api/secops";
import type { DataView, Overview, Role } from "../lib/types";
import { asApiError } from "../features/auth/LoginPage";
import { ErrorPanel } from "./ErrorPanel";

const SECOPS_READERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];

export function Dashboard() {
  const user = useCurrentUser();
  return (
    <div className="max-w-7xl space-y-12">
      {SECOPS_READERS.includes(user.role) ? (
        <SecurityOverview />
      ) : (
        <header>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="mt-1 max-w-prose text-ink-muted">
            Security operations data is available to administrators, security engineers, analysts and viewers.
            Developers have the API Security Center and the applications they own.
          </p>
        </header>
      )}
      <PlatformStatus />
    </div>
  );
}

// --- Security overview (spec §12) ---------------------------------------------------------------

const WINDOWS = [
  { hours: 24, label: "Last 24 hours" },
  { hours: 168, label: "Last 7 days" },
] as const;

function SecurityOverview() {
  const [params, setParams] = useSearchParams();
  const view: DataView = params.get("view") === "simulated" ? "simulated" : "live";
  const hours = params.get("hours") === "168" ? 168 : 24;
  const [version, setVersion] = useState(0);
  // Every response is tagged with the request that produced it, so "loading" is derived (no setState
  // in the effect body) and a slow response can never be shown as the answer to a newer request.
  const key = `${view}:${hours}:${version}`;
  const [latest, setLatest] = useState<Overview | null>(null);
  const [outcome, setOutcome] = useState<{ key: string; error: ApiError | null } | null>(null);
  const loading = outcome?.key !== key;
  const error = outcome?.key === key ? outcome.error : null;
  // While a refresh is in flight the previous overview stays (dimmed) only if it belongs to the view on
  // screen: live data must never appear under the simulated banner, or the reverse.
  const data = latest?.view === view ? latest : null;

  useEffect(() => {
    const controller = new AbortController();
    getOverview(view, hours, controller.signal)
      .then((overview) => {
        setLatest(overview);
        setOutcome({ key, error: null });
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setOutcome({ key, error: asApiError(err) });
      });
    return () => controller.abort();
  }, [view, hours, key]);

  function update(next: { view?: DataView; hours?: number }) {
    const merged = new URLSearchParams(params);
    if (next.view) merged.set("view", next.view);
    if (next.hours) merged.set("hours", String(next.hours));
    setParams(merged, { replace: true });
  }

  return (
    <section aria-labelledby="overview-heading" className="space-y-6">
      <header className="space-y-3">
        <div>
          <h1 id="overview-heading" className="text-2xl font-semibold tracking-tight">
            Security dashboard
          </h1>
          <p className="mt-1 max-w-prose text-ink-muted">
            Incidents, attack activity and traffic for SentinelEdge itself. Live and simulated data are never combined:
            switch views to see the attack simulator's output.
          </p>
        </div>
        {/* One filter row, above everything it scopes. */}
        <div className="flex flex-wrap items-center gap-3">
          <ViewToggle value={view} onChange={(v) => update({ view: v })} />
          <label className="flex items-center gap-2 text-sm text-ink-muted">
            Window
            <select
              value={hours}
              onChange={(e) => update({ hours: Number(e.target.value) })}
              className="rounded border border-line bg-canvas px-2 py-1 text-sm text-ink"
            >
              {WINDOWS.map((w) => (
                <option key={w.hours} value={w.hours}>
                  {w.label}
                </option>
              ))}
            </select>
          </label>
          <Button variant="secondary" onClick={() => setVersion((n) => n + 1)} busy={loading}>
            Refresh
          </Button>
          {data && <span className="text-xs text-ink-muted">Generated {formatTime(data.generated_at)}</span>}
        </div>
      </header>

      {view === "simulated" && <SimulatedBanner />}
      {error && <FormError error={error} />}
      {!data && !error && <p className="text-sm text-ink-muted">Loading the security overview…</p>}
      {data && (
        // Refetch keeps the frame: the previous render stays, dimmed, until new data arrives.
        <div className={`space-y-8 transition-opacity ${loading ? "opacity-60" : ""}`} aria-busy={loading}>
          <StatusLine data={data} />
          <Kpis data={data} />
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            <Card title="Activity">
              <ColumnChart
                title={`Security events per hour (${data.view})`}
                labelEvery={data.window_hours > 24 ? 24 : 6}
                points={data.series.map((p): ColumnPoint => ({
                  key: p.hour,
                  label: p.hour.slice(11, 16),
                  value: p.events,
                  readout: `${formatTime(p.hour)}: ${p.events} events, ${p.detections} detections, ${p.high_or_critical} high or critical`,
                }))}
              />
            </Card>
            <Card title="Threats by category">
              <BarList
                label="Security events by category"
                items={Object.entries(data.events.by_category).map(([category, n]) => ({
                  key: category,
                  label: categoryLabel(category),
                  value: n,
                }))}
              />
            </Card>
          </div>
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Card title="Open incidents">
              <Incidents data={data} />
            </Card>
            <Card title="Top sources">
              <Sources data={data} />
            </Card>
          </div>
          <Card title={data.traffic.source === "api_metrics" ? "API traffic" : "Simulated traffic"}>
            <TrafficPanel data={data} />
          </Card>
          <Controls data={data} />
        </div>
      )}
    </section>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-md border border-line bg-surface p-5">
      <h2 className="mb-4 text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

const LEVEL = {
  ok: { label: "No action needed", className: "border-ok/50 bg-ok/10 text-ok" },
  attention: { label: "Needs attention", className: "border-prov-sim/60 bg-prov-sim/10 text-prov-sim" },
  critical: { label: "Critical", className: "border-fail/60 bg-fail/10 text-fail" },
} as const;

function StatusLine({ data }: { data: Overview }) {
  const level = LEVEL[data.status.level];
  return (
    <div className="flex flex-wrap items-start gap-3" role="status">
      <span className={`rounded-sm border px-2 py-1 text-sm font-semibold ${level.className}`}>{level.label}</span>
      <ul className="space-y-0.5 text-sm text-ink-muted">
        {data.status.reasons.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
    </div>
  );
}

function minutes(value: number | null): string {
  if (value === null) return "–";
  return value < 120 ? `${Math.round(value)} min` : `${(value / 60).toFixed(1)} h`;
}

function Kpis({ data }: { data: Overview }) {
  const { incidents, events } = data;
  const severe = (incidents.by_severity.critical ?? 0) + (incidents.by_severity.high ?? 0);
  return (
    <dl className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <StatTile
        label="Open incidents"
        value={incidents.open}
        note={`${severe} high or critical, ${incidents.unassigned} unassigned`}
        {...(severe ? { tone: "fail" as const } : {})}
      />
      <StatTile label="Detections" value={events.detections} note="Correlation rules that fired" />
      <StatTile label="Security events" value={events.total} note={`Last ${data.window_hours} h`} />
      <StatTile label="Attacks stopped" value={events.stopped} note="Blocked, rejected or throttled" tone="ok" />
      <StatTile
        label="Not stopped at that layer"
        value={events.reached_app}
        note="Attack patterns served or only counted"
        {...(events.reached_app ? { tone: "warn" as const } : {})}
      />
      <StatTile
        label="Mean time to triage"
        value={minutes(incidents.mean_minutes_to_triage)}
        note={`To close: ${minutes(incidents.mean_minutes_to_close)}`}
      />
    </dl>
  );
}

function Incidents({ data }: { data: Overview }) {
  if (!data.recent_incidents.length) return <p className="text-sm text-ink-muted">No open incidents in this view.</p>;
  return (
    <div className="space-y-4">
      <ul className="divide-y divide-line">
        {data.recent_incidents.map((i) => (
          <li key={i.id} className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1 py-2">
            <div className="min-w-0 flex-1 basis-56">
              <Link to={`/incidents/${i.id}`} className="block text-sm text-accent hover:underline">
                {i.reference}: {i.title}
              </Link>
              <span className="text-xs text-ink-muted">Detected {formatTime(i.detected_at)}</span>
            </div>
            <div className="flex shrink-0 gap-2">
              <SeverityBadge severity={i.severity} />
              <IncidentStatusBadge status={i.status} />
            </div>
          </li>
        ))}
      </ul>
      <BarList
        label="Open incidents by workflow status"
        items={Object.entries(data.incidents.by_status)
          .filter(([, n]) => n > 0)
          .map(([status, n]) => ({ key: status, label: status.charAt(0) + status.slice(1).toLowerCase(), value: n }))}
      />
      <Link to={`/incidents?view=${data.view}`} className="text-sm text-accent hover:underline">
        All incidents
      </Link>
    </div>
  );
}

function Sources({ data }: { data: Overview }) {
  if (!data.top_sources.length) return <p className="text-sm text-ink-muted">No attack sources in this window.</p>;
  return (
    <div className="overflow-x-auto">
    <table className="w-full text-left text-sm">
      <caption className="sr-only">Addresses with the most security events</caption>
      <thead className="text-xs text-ink-muted">
        <tr>
          <th scope="col" className="pb-2 pr-4 font-medium">Source</th>
          <th scope="col" className="pb-2 pr-4 text-right font-medium">Events</th>
          <th scope="col" className="pb-2 pr-4 font-medium">Worst</th>
          <th scope="col" className="pb-2 font-medium">Activity</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-line">
        {data.top_sources.map((s) => (
          <tr key={s.source_ip}>
            <td className="whitespace-nowrap py-2 pr-4 font-mono text-xs">
              <Link
                to={`/threats?source_ip=${encodeURIComponent(s.source_ip)}&view=${data.view}`}
                className="text-accent hover:underline"
              >
                {s.source_ip}
              </Link>
              {s.country && <span className="ml-1 text-ink-muted">({s.country})</span>}
            </td>
            <td className="py-2 pr-4 text-right tabular-nums">{s.events}</td>
            <td className="py-2 pr-4">
              <SeverityBadge severity={s.max_severity} />
            </td>
            <td className="min-w-48 py-2 text-xs text-ink-muted">{s.categories.map(categoryLabel).join(", ")}</td>
          </tr>
        ))}
      </tbody>
    </table>
    </div>
  );
}

function TrafficPanel({ data }: { data: Overview }) {
  const t = data.traffic;
  const live = t.source === "api_metrics";
  return (
    <div className="space-y-5">
      <p className="text-sm text-ink-muted">
        {live
          ? "Every API request, from the per-endpoint counters (Phase 6). These counters keep no IP addresses or payloads."
          : "Requests generated by simulation runs in this window, through the simulated WAF."}
      </p>
      <dl className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatTile label="Requests" value={t.requests.toLocaleString()} />
        <StatTile label={live ? "Served" : "Benign"} value={t.allowed.toLocaleString()} />
        <StatTile
          label={live ? "Rejected (401, 403, 429)" : "Reached the app"}
          value={t.rejected.toLocaleString()}
        />
        <StatTile
          label="Blocked at the edge"
          value={live ? "–" : t.blocked_at_edge.toLocaleString()}
          note={live ? "AWS WAF arrives in Phase 5" : "By the simulated WAF"}
        />
        <StatTile
          label={live ? "Unknown-path requests" : "Server errors"}
          value={(live ? t.unknown_paths : t.errors).toLocaleString()}
          {...(live ? { note: "Probing for undocumented endpoints" } : {})}
        />
      </dl>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <ColumnChart
          title={live ? "API requests per hour" : "Simulated requests per hour"}
          labelEvery={data.window_hours > 24 ? 24 : 6}
          points={t.series.map((p) => ({
            key: p.hour,
            label: p.hour.slice(11, 16),
            value: p.requests,
            readout: `${formatTime(p.hour)}: ${p.requests} requests, ${p.rejected} ${live ? "rejected" : "blocked"}${live ? `, ${p.errors} server errors` : ""}`,
          }))}
        />
        {live ? (
          <div className="space-y-4">
            <h3 className="text-sm font-medium">Busiest endpoints</h3>
            <BarList
              label="Requests per endpoint"
              items={t.top_endpoints.map((e) => ({ key: `${e.method} ${e.endpoint}`, label: `${e.method} ${e.endpoint}`, value: e.requests }))}
            />
          </div>
        ) : (
          <div className="space-y-4">
            <h3 className="text-sm font-medium">Countries in simulated WAF logs</h3>
            <BarList
              label="Simulated events by country"
              items={data.countries.map((c) => ({ key: c.country, label: c.country, value: c.events }))}
            />
          </div>
        )}
      </div>
    </div>
  );
}

const CONTROL_NAMES: Record<string, string> = {
  detection: "Detection",
  api: "API protection",
  waf: "WAF",
  certificates: "Certificates",
  vulnerabilities: "Vulnerabilities",
};
const CONTROL_STATUS = {
  measured: "border-ok/50 text-ok",
  simulated: "border-prov-sim/60 text-prov-sim",
  planned: "border-line text-ink-muted",
  not_connected: "border-line text-ink-muted",
} as const;
const CONTROL_STATUS_LABEL = {
  measured: "Measured",
  simulated: "Simulated",
  planned: "Planned",
  not_connected: "No data yet",
} as const;
// Controls whose detail lives on their own page.
const CONTROL_LINKS: Record<string, string> = { api: "/api-security", vulnerabilities: "/vulnerabilities" };

function Controls({ data }: { data: Overview }) {
  return (
    <section aria-labelledby="controls-heading" className="space-y-3">
      <h2 id="controls-heading" className="text-base font-semibold">
        Controls
      </h2>
      <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {Object.entries(data.controls).map(([key, c]) => (
          <li key={key} className="rounded-md border border-line bg-surface p-4">
            <div className="flex items-center justify-between gap-2">
              {CONTROL_LINKS[key] ? (
                <Link to={CONTROL_LINKS[key]} className="text-sm font-medium text-accent hover:underline">
                  {CONTROL_NAMES[key] ?? key}
                </Link>
              ) : (
                <span className="text-sm font-medium">{CONTROL_NAMES[key] ?? key}</span>
              )}
              <span className={`rounded-sm border px-1.5 py-0.5 text-xs ${CONTROL_STATUS[c.status]}`}>
                {CONTROL_STATUS_LABEL[c.status]}
              </span>
            </div>
            <p className="mt-2 text-xs text-ink-muted">{c.summary}</p>
          </li>
        ))}
      </ul>
      {data.top_rules.length > 0 && (
        <p className="text-xs text-ink-muted">
          Most matched rules: {data.top_rules.map((r) => `${r.rule_id} (${r.events})`).join(", ")}.
        </p>
      )}
    </section>
  );
}

// --- Platform status (phases and the capability register) ---------------------------------------

const PHASE_NAMES: Record<number, string> = {
  1: "Architecture",
  2: "App foundation",
  3: "AWS foundation",
  4: "AWS deploy",
  5: "Edge, WAF, TLS",
  6: "API security",
  7: "Security ops",
  8: "AppSec scanning",
  9: "AI security",
  10: "Threat model & governance",
  11: "Automation",
  12: "Hardening",
};
// Local-first order (ADR-0016): everything that runs locally is built first; the AWS phases are
// grouped near the end so cloud resources exist for as short a time as possible.
const BUILD_ORDER = [1, 2, 6, 7, 8, 10, 9, 3, 4, 5, 11, 12];
const COMPLETE = new Set([1, 2, 3, 6, 7, 8, 9, 10]);
const NEXT = BUILD_ORDER.find((n) => !COMPLETE.has(n));

function PlatformStatus() {
  const caps = useCapabilities();

  return (
    <section aria-labelledby="platform-heading" className="space-y-8">
      <header>
        <h2 id="platform-heading" className="text-xl font-semibold tracking-tight">
          Platform status
        </h2>
        <p className="mt-1 max-w-prose text-ink-muted">
          What SentinelEdge does today, and what is real, local, simulated, or demo data.
        </p>
      </header>

      <section aria-labelledby="build-heading">
        <h3 id="build-heading" className="mb-1 text-sm font-medium text-ink-muted">
          Build phases
        </h3>
        <p className="mb-3 text-xs text-ink-muted">
          In build order: local work first, AWS phases grouped late to keep cloud costs down.
        </p>
        <ol className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-line bg-line sm:grid-cols-4 lg:grid-cols-6">
          {BUILD_ORDER.map((n) => {
            const done = COMPLETE.has(n);
            const next = n === NEXT;
            return (
              <li key={n} aria-current={next ? "step" : undefined} className={`px-3 py-2.5 ${next ? "bg-raised" : "bg-surface"}`}>
                <span className={`block text-xs tabular-nums ${done ? "text-ok" : next ? "text-accent" : "text-ink-muted"}`}>
                  Phase {n}
                  {done ? ", complete" : next ? ", next" : ""}
                </span>
                <span className={`block text-sm ${done || next ? "text-ink" : "text-ink-muted"}`}>{PHASE_NAMES[n]}</span>
              </li>
            );
          })}
        </ol>
      </section>

      <section aria-labelledby="register-heading" className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <h3 id="register-heading" className="text-lg font-semibold">
            Capability register
          </h3>
          <dl className="flex flex-wrap gap-x-5 gap-y-2 text-sm">
            {PROVENANCE_ORDER.map((p) => {
              const count = caps.state === "ready" ? caps.data.filter((c) => c.provenance === p).length : null;
              return (
                <div key={p} className="flex items-center gap-2" title={provenanceDescription(p)}>
                  <dt>
                    <ProvenanceBadge provenance={p} />
                  </dt>
                  <dd className="tabular-nums text-ink-muted">{count ?? "–"}</dd>
                </div>
              );
            })}
          </dl>
        </div>
        {caps.state === "loading" && <p className="text-sm text-ink-muted">Loading capabilities…</p>}
        {caps.state === "error" && <ErrorPanel error={caps.error} />}
        {caps.state === "ready" && (
          <CapabilityTable
            caption="All SentinelEdge capabilities with provenance, status, and delivery phase"
            items={[...caps.data].sort((a, b) => a.phase - b.phase || a.name.localeCompare(b.name))}
          />
        )}
      </section>
    </section>
  );
}
