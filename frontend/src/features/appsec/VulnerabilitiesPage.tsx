import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Button, FormError } from "../../components/forms";
import { SeverityBadge, StatTile, formatTime } from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import {
  getVulnerabilityOverview,
  listScans,
  listVulnerabilities,
  type VulnerabilityFilters,
} from "../../lib/api/vulnerabilities";
import {
  FINDING_CATEGORIES,
  SCAN_TOOLS,
  SEVERITIES,
  VULN_STATUSES,
  type FindingCategory,
  type ScanList,
  type ScanTool,
  type Severity,
  type VulnStatus,
  type VulnerabilityOverview,
  type VulnerabilitySummary,
} from "../../lib/types";
import { asApiError } from "../auth/LoginPage";
import { ACTIVE, SlaText, VulnStatusBadge, findingCategoryLabel, toolLabel, vulnStatusLabel } from "./appsec";

const STATES = ["active", "all", ...VULN_STATUSES] as const;
type State = (typeof STATES)[number];

export function VulnerabilitiesPage() {
  return (
    <div className="max-w-7xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Vulnerabilities</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          Findings from code, dependency, secret, container, configuration and running-application scans, de-duplicated
          across scans and tracked to closure. A scan that no longer reports a finding marks it fixed; nobody does by hand.
        </p>
      </header>
      <Overview />
      <FindingList />
      <RecentScans />
    </div>
  );
}

// --- Overview -------------------------------------------------------------------------------------

function Overview() {
  const [result, setResult] = useState<{ data: VulnerabilityOverview | null; error: ApiError | null } | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    getVulnerabilityOverview(controller.signal)
      .then((data) => setResult({ data, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setResult({ data: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, []);

  if (result?.error) return <FormError error={result.error} />;
  const data = result?.data;
  if (!data) return <p className="text-sm text-ink-muted">Loading the overview…</p>;
  const scan = data.last_scan;
  return (
    <section aria-labelledby="vuln-overview" className="space-y-3">
      <h2 id="vuln-overview" className="sr-only">
        Overview
      </h2>
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-7">
        <StatTile label="Open findings" value={data.active_total} note="Open or in progress" />
        <StatTile label="Critical" value={data.active.critical} {...(data.active.critical ? { tone: "fail" as const } : {})} />
        <StatTile label="High" value={data.active.high} {...(data.active.high ? { tone: "warn" as const } : {})} />
        <StatTile label="Past SLA" value={data.overdue} tone={data.overdue ? "fail" : "ok"} />
        <StatTile label="Awaiting a fix" value={data.awaiting_fix} note="No fixed version published" />
        <StatTile label="Accepted risk" value={data.accepted} />
        <StatTile label="Fixed, 30 days" value={data.fixed_30d} {...(data.fixed_30d ? { tone: "ok" as const } : {})} />
      </dl>
      {scan ? (
        <p className="text-sm text-ink-muted">
          Last scan <span className="font-medium text-ink">{scan.reference}</span> of {scan.application.name},
          imported {formatTime(scan.imported_at)} ({scan.source === "ci" ? "CI" : "local"}
          {scan.commit_sha ? `, commit ${scan.commit_sha.slice(0, 7)}` : ""}):{" "}
          <span className={scan.gate_passed ? "text-ok" : "font-medium text-fail"}>
            gate {scan.gate_passed ? "passed" : "failed"}
          </span>
          .
        </p>
      ) : (
        <p className="rounded-md border border-line bg-surface px-4 py-3 text-sm text-ink-muted">
          No scan imported yet. Run <code className="font-mono text-ink">make scan</code>, then{" "}
          <code className="font-mono text-ink">make scan-import</code>.
        </p>
      )}
    </section>
  );
}

// --- Findings ---------------------------------------------------------------------------------------

interface Filters {
  state: State;
  min_severity: Severity | "";
  category: FindingCategory | "";
  tool: ScanTool | "";
  fixable: "true" | "false" | "";
  overdue: boolean;
  q: string;
}

const pick = <T extends string>(values: readonly T[], value: string | null): T | "" =>
  value && (values as readonly string[]).includes(value) ? (value as T) : "";

function filtersFrom(params: URLSearchParams): Filters {
  const fixable = params.get("fixable");
  return {
    state: pick(STATES, params.get("state")) || "active",
    min_severity: pick(SEVERITIES, params.get("min_severity")),
    category: pick(FINDING_CATEGORIES, params.get("category")),
    tool: pick(SCAN_TOOLS, params.get("tool")),
    fixable: fixable === "true" || fixable === "false" ? fixable : "",
    overdue: params.get("overdue") === "true",
    q: (params.get("q") ?? "").slice(0, 100),
  };
}

function query(f: Filters, before?: number): VulnerabilityFilters {
  const status: readonly VulnStatus[] = f.state === "active" ? ACTIVE : f.state === "all" ? [] : [f.state];
  return {
    status,
    min_severity: f.min_severity,
    category: f.category,
    tool: f.tool,
    fixable: f.fixable,
    overdue: f.overdue ? "true" : "",
    ...(f.q ? { q: f.q } : {}),
    ...(before ? { before } : {}),
  };
}

interface Page {
  key: string;
  items: VulnerabilitySummary[];
  nextBefore: number | null;
  error: ApiError | null;
}

function FindingList() {
  const [params, setParams] = useSearchParams();
  const key = params.toString();
  const filters = filtersFrom(params);
  // Each result is tagged with the filter key that produced it: a filter change never shows rows
  // that belong to the previous filters.
  const [first, setFirst] = useState<Page | null>(null);
  const [older, setOlder] = useState<(Page & { busy: boolean }) | null>(null);
  const current = first?.key === key ? first : null;
  const more = older?.key === key ? older : null;
  const loading = current === null;
  const items = [...(current?.items ?? []), ...(more?.items ?? [])];
  const nextBefore = more && more.items.length ? more.nextBefore : (current?.nextBefore ?? null);
  const error = more?.error ?? current?.error ?? null;

  useEffect(() => {
    const controller = new AbortController();
    listVulnerabilities(query(filtersFrom(new URLSearchParams(key))), controller.signal)
      .then((page) => setFirst({ key, items: page.items, nextBefore: page.next_before, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setFirst({ key, items: [], nextBefore: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, [key]);

  function set(name: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(name, value);
    else next.delete(name);
    setParams(next, { replace: true });
  }

  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    set("q", String(new FormData(event.currentTarget).get("q") ?? "").trim());
  }

  async function loadOlder(before: number) {
    const base = more ?? { key, items: [], nextBefore: before, busy: false, error: null };
    setOlder({ ...base, busy: true, error: null });
    try {
      const page = await listVulnerabilities(query(filters, before));
      setOlder({ key, items: [...base.items, ...page.items], nextBefore: page.next_before, busy: false, error: null });
    } catch (err) {
      setOlder({ ...base, busy: false, error: asApiError(err) });
    }
  }

  const select = "rounded border border-line bg-canvas px-2 py-1.5 text-sm";
  return (
    <section aria-labelledby="findings-heading" className="space-y-4">
      <h2 id="findings-heading" className="text-base font-semibold">
        Findings
      </h2>
      <div className="flex flex-wrap items-end gap-3">
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Status</span>
          <select value={filters.state} onChange={(e) => set("state", e.target.value)} className={select}>
            <option value="active">Open or in progress</option>
            <option value="all">All</option>
            {VULN_STATUSES.map((s) => (
              <option key={s} value={s}>
                {vulnStatusLabel(s)}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Minimum severity</span>
          <select value={filters.min_severity} onChange={(e) => set("min_severity", e.target.value)} className={`${select} capitalize`}>
            <option value="">Any</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Found in</span>
          <select value={filters.category} onChange={(e) => set("category", e.target.value)} className={select}>
            <option value="">Anything</option>
            {FINDING_CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {findingCategoryLabel(c)}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Scanner</span>
          <select value={filters.tool} onChange={(e) => set("tool", e.target.value)} className={select}>
            <option value="">Any</option>
            {SCAN_TOOLS.map((t) => (
              <option key={t} value={t}>
                {toolLabel(t)}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Fix</span>
          <select value={filters.fixable} onChange={(e) => set("fixable", e.target.value)} className={select}>
            <option value="">Any</option>
            <option value="true">Fixable now</option>
            <option value="false">Awaiting an upstream fix</option>
          </select>
        </label>
        <label className="flex items-center gap-2 pb-1.5 text-sm">
          <input type="checkbox" checked={filters.overdue} onChange={(e) => set("overdue", e.target.checked ? "true" : "")} />
          Past SLA only
        </label>
        <form onSubmit={search} role="search" className="flex items-end gap-2">
          <label className="space-y-1 text-sm">
            <span className="block text-ink-muted">Search</span>
            <input
              key={filters.q}
              name="q"
              type="search"
              defaultValue={filters.q}
              maxLength={100}
              placeholder="Title, package, rule or CVE"
              className="w-56 rounded border border-line bg-canvas px-2 py-1.5 text-sm"
            />
          </label>
          <Button type="submit" variant="secondary">
            Search
          </Button>
        </form>
      </div>
      {error && <FormError error={error} />}

      <div className="overflow-x-auto rounded-md border border-line">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Findings, newest first</caption>
          <thead className="bg-surface text-xs text-ink-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Finding</th>
              <th scope="col" className="px-3 py-2 font-medium">Severity</th>
              <th scope="col" className="px-3 py-2 font-medium">Found in</th>
              <th scope="col" className="px-3 py-2 font-medium">Status</th>
              <th scope="col" className="px-3 py-2 font-medium">SLA</th>
              <th scope="col" className="px-3 py-2 font-medium">Last seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {items.map((v) => (
              <tr key={v.id}>
                <td className="max-w-md px-3 py-2">
                  <Link to={`/vulnerabilities/${v.id}`} className="break-words text-accent hover:underline">
                    {v.reference}: {v.title}
                  </Link>
                  <span className="mt-0.5 block break-all font-mono text-xs text-ink-muted">{v.component}</span>
                  {!v.fixable && <span className="mt-0.5 block text-xs text-prov-sim">Awaiting an upstream fix</span>}
                  {v.fixable && v.fixed_version && (
                    <span className="mt-0.5 block text-xs text-ink-muted">Fixed in {v.fixed_version}</span>
                  )}
                </td>
                <td className="px-3 py-2">
                  <SeverityBadge severity={v.severity} />
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-ink-muted">
                  {findingCategoryLabel(v.category)}
                  <span className="block text-xs">{toolLabel(v.tool)}</span>
                </td>
                <td className="px-3 py-2">
                  <VulnStatusBadge status={v.status} />
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-xs">
                  <SlaText due={v.sla_due_at} overdue={v.overdue} active={ACTIVE.includes(v.status)} />
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums text-ink-muted">{formatTime(v.last_seen_at)}</td>
              </tr>
            ))}
            {loading && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-ink-muted">
                  Loading findings…
                </td>
              </tr>
            )}
            {!items.length && !loading && !error && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-ink-muted">
                  No findings match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {nextBefore !== null && (
          <div className="border-t border-line p-3">
            <Button variant="secondary" busy={more?.busy ?? false} onClick={() => void loadOlder(nextBefore)}>
              Load older findings
            </Button>
          </div>
        )}
      </div>
    </section>
  );
}

// --- Scans ------------------------------------------------------------------------------------------

function count(summary: Record<string, unknown>, key: string): number {
  const value = summary[key];
  return typeof value === "number" ? value : 0;
}

function RecentScans() {
  const [result, setResult] = useState<{ data: ScanList | null; error: ApiError | null } | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    listScans(5, controller.signal)
      .then((data) => setResult({ data, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setResult({ data: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, []);

  const scans = result?.data?.items ?? [];
  return (
    <section aria-labelledby="scans-heading" className="space-y-3">
      <h2 id="scans-heading" className="text-base font-semibold">
        Recent scans
      </h2>
      {result?.error && <FormError error={result.error} />}
      {result?.data && !scans.length && <p className="text-sm text-ink-muted">No scans imported yet.</p>}
      {scans.length > 0 && (
        <div className="overflow-x-auto rounded-md border border-line">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">The last five scan imports</caption>
            <thead className="bg-surface text-xs text-ink-muted">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">Scan</th>
                <th scope="col" className="px-3 py-2 font-medium">Imported</th>
                <th scope="col" className="px-3 py-2 font-medium">Commit</th>
                <th scope="col" className="px-3 py-2 font-medium">Gate</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Findings</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">New</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Fixed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {scans.map((s) => (
                <tr key={s.id}>
                  <td className="px-3 py-2">
                    {s.reference}
                    <span className="block text-xs text-ink-muted">
                      {s.application.name}, {s.source === "ci" ? "CI" : "local"}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums text-ink-muted">{formatTime(s.imported_at)}</td>
                  <td className="px-3 py-2 font-mono text-xs text-ink-muted">
                    {s.commit_sha ? s.commit_sha.slice(0, 7) : "-"}
                    {s.branch && <span className="block font-sans">{s.branch}</span>}
                  </td>
                  <td className={`px-3 py-2 ${s.gate_passed ? "text-ok" : "font-medium text-fail"}`}>
                    {s.gate_passed ? "Passed" : "Failed"}
                  </td>
                  <td className="px-3 py-2 text-right tabular-nums">{count(s.summary, "total")}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{count(s.summary, "new")}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{count(s.summary, "fixed")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
